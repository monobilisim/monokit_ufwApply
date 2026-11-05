package main

import (
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	lib "github.com/monobilisim/monokit_lib"
	"github.com/rs/zerolog"
)

func FetchRulesets(logger zerolog.Logger, tmpDir string) []string {
	logger.Debug().Msgf("RuleSources: %v", lib.UfwApplyConfig.RuleSources)

	var changedRulesets []string
	seenFileNames := make(map[string]bool)

	for _, ruleset := range lib.UfwApplyConfig.RuleSources {
		logger.Info().Msgf("Fetching ruleset from %s", ruleset.Url)

		if ruleset.Url == "" {
			logger.Warn().Msg("Empty ruleset URL, skipping...")
			continue
		}

		if ruleset.Protocol != "tcp" && ruleset.Protocol != "udp" && ruleset.Protocol != "all" {
			logger.Warn().Msgf("Invalid protocol %s for ruleset %s, skipping...", ruleset.Protocol, ruleset.Url)
			continue
		}

		if ruleset.Port == "" {
			logger.Warn().Msgf("Empty port for ruleset %s, skipping...", ruleset.Url)
			continue
		}

		ruleset.Url = strings.TrimSuffix(ruleset.Url, "/")

		fileName := rulesetFileName(ruleset.Url)

		if seenFileNames[fileName] {
			logger.Warn().Msgf("Another ruleset already uses the file name %s, skipping %s...", fileName, ruleset.Url)
			continue
		}
		seenFileNames[fileName] = true

		response, err := http.Get(ruleset.Url)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to fetch ruleset from %s", ruleset.Url)
			continue
		}

		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			logger.Error().Msgf("Failed to fetch ruleset from %s: status code %d", ruleset.Url, response.StatusCode)
			continue
		}

		responseText, err := io.ReadAll(response.Body)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to read response body from %s", ruleset.Url)
			continue
		}

		lines := strings.Split(string(responseText), "\n")
		var newLines []string

		for _, line := range lines {
			// only get the ip part
			if strings.Contains(line, "#") {
				line = strings.Split(line, "#")[0]
			}

			line = strings.TrimSpace(line)

			if line == "" {
				continue
			}

			rule := Rule{
				IP:       line,
				Protocol: ruleset.Protocol,
				Port:     ruleset.Port,
				Comment:  ruleset.Comment,
			}

			newLines = append(newLines, rule.line())
		}

		content := []byte(strings.Join(newLines, "\n"))

		changed, err := rulesetChanged(filepath.Join(lib.UfwApplyConfig.RulesDir, fileName), content)
		if err != nil {
			logger.Warn().Err(err).Msgf("Failed to compare ruleset %s with last applied copy, reapplying...", fileName)
		}

		if !changed {
			logger.Info().Msgf("Ruleset from %s is unchanged since last apply, skipping...", ruleset.Url)
			continue
		}

		err = os.WriteFile(filepath.Join(tmpDir, fileName), content, 0644)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to write ruleset to file from %s", ruleset.Url)
			continue
		}

		changedRulesets = append(changedRulesets, fileName)

		logger.Info().Msgf("Successfully fetched ruleset from %s", ruleset.Url)
	}

	logger.Info().Msgf("%d ruleset(s) changed since last apply", len(changedRulesets))

	return changedRulesets
}

func rulesetFileName(url string) string {
	splitUrl := strings.Split(strings.TrimSuffix(url, "/"), "/")
	return splitUrl[len(splitUrl)-1]
}

func RemovedRulesets(logger zerolog.Logger) []string {
	configuredFileNames := make(map[string]bool)

	for _, ruleset := range lib.UfwApplyConfig.RuleSources {
		if ruleset.Url != "" {
			configuredFileNames[rulesetFileName(ruleset.Url)] = true
		}
	}

	entries, err := os.ReadDir(lib.UfwApplyConfig.RulesDir)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to read rules directory, skipping cleanup of removed rulesets")
		return nil
	}

	var removedRulesets []string

	for _, entry := range entries {
		if entry.IsDir() || configuredFileNames[entry.Name()] {
			continue
		}

		removedRulesets = append(removedRulesets, entry.Name())
	}

	logger.Info().Msgf("%d ruleset(s) removed from config since last apply: %v", len(removedRulesets), removedRulesets)

	return removedRulesets
}

func staticRulesPath() string {
	return filepath.Join(lib.UfwApplyConfig.RulesetDir, staticRulesFileName)
}

// StaleRules returns the rules in the last applied copies of the static rules and of the changed and removed
// rulesets that no static rule or ruleset needs after this run. It has to run before the applied copies are
// saved, so the dry run and the apply see the same rules.
func StaleRules(logger zerolog.Logger, tmpDir string, changedRulesets []string, removedRulesets []string) ([]Rule, error) {
	appliedPaths := []string{staticRulesPath()}
	for _, fileName := range slices.Concat(changedRulesets, removedRulesets) {
		appliedPaths = append(appliedPaths, filepath.Join(lib.UfwApplyConfig.RulesDir, fileName))
	}

	var appliedRules []Rule

	for _, path := range appliedPaths {
		rules, err := readRuleset(logger, path)
		// new rulesets and static rules on the first run have no applied copy yet
		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			return nil, err
		}

		appliedRules = append(appliedRules, rules...)
	}

	if len(appliedRules) == 0 {
		return nil, nil
	}

	wanted := make(map[string]bool)

	for _, rule := range staticRules() {
		wanted[rule.key()] = true
	}

	// changed rulesets are wanted with their new content, the others with their applied copy
	var wantedPaths []string
	for _, fileName := range changedRulesets {
		wantedPaths = append(wantedPaths, filepath.Join(tmpDir, fileName))
	}

	entries, err := os.ReadDir(lib.UfwApplyConfig.RulesDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || slices.Contains(changedRulesets, entry.Name()) || slices.Contains(removedRulesets, entry.Name()) {
			continue
		}

		wantedPaths = append(wantedPaths, filepath.Join(lib.UfwApplyConfig.RulesDir, entry.Name()))
	}

	for _, path := range wantedPaths {
		rules, err := readRuleset(logger, path)
		if err != nil {
			return nil, err
		}

		for _, rule := range rules {
			wanted[rule.key()] = true
		}
	}

	var staleRules []Rule
	staleKeys := make(map[string]bool)

	for _, rule := range appliedRules {
		if wanted[rule.key()] || staleKeys[rule.key()] {
			continue
		}

		staleKeys[rule.key()] = true
		staleRules = append(staleRules, rule)
	}

	logger.Info().Msgf("%d rule(s) are no longer in any ruleset or static rule", len(staleRules))

	return staleRules, nil
}

func DeleteRules(logger zerolog.Logger, rules []Rule, dryRun bool) error {
	for _, rule := range rules {
		logger.Info().Msgf("Deleting rule %s, no ruleset or static rule needs it anymore (dry run: %v)", rule.key(), dryRun)

		err := runCommand(logger, rule.DeleteCommand(dryRun))
		if err != nil {
			return err
		}
	}

	return nil
}

// saveAppliedCopies runs once every rule is added and every stale rule is deleted, so a run that fails
// before it keeps the last applied copies and the next run retries the same changes
func saveAppliedCopies(logger zerolog.Logger, tmpDir string, changedRulesets []string, removedRulesets []string) {
	for _, fileName := range changedRulesets {
		err := saveAppliedRuleset(filepath.Join(tmpDir, fileName), filepath.Join(lib.UfwApplyConfig.RulesDir, fileName))
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to save applied ruleset %s, it will be reapplied on the next run", fileName)
		}
	}

	for _, fileName := range removedRulesets {
		err := os.Remove(filepath.Join(lib.UfwApplyConfig.RulesDir, fileName))
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to remove applied ruleset %s, its rules will be deleted again on the next run", fileName)
		}
	}

	err := saveStaticRules()
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to save applied static rules to %s, static rules dropped from config since the last save may stay in ufw", staticRulesPath())
	}
}

func saveStaticRules() error {
	rules := staticRules()

	if len(rules) == 0 {
		err := os.Remove(staticRulesPath())
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}

	var lines []string
	for _, rule := range rules {
		lines = append(lines, rule.line())
	}

	return os.WriteFile(staticRulesPath(), []byte(strings.Join(lines, "\n")), 0644)
}

func readRuleset(logger zerolog.Logger, path string) ([]Rule, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parseRuleset(logger, filepath.Base(path), content), nil
}

func parseRuleset(logger zerolog.Logger, fileName string, content []byte) []Rule {
	var rules []Rule

	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			logger.Warn().Msg("Empty line, skipping...")
			continue
		}

		var Comment string = ""
		if strings.Contains(line, "#") {
			splitLine := strings.Split(line, "#")
			line = strings.TrimSpace(splitLine[0])
			Comment = strings.TrimSpace(splitLine[1])
		}

		lineParts := strings.Split(line, " ")
		if len(lineParts) < 3 {
			logger.Warn().Msgf("Malformed line %q in %s, skipping...", line, fileName)
			continue
		}

		rules = append(rules, Rule{
			IP:       lineParts[0],
			Protocol: lineParts[1],
			Port:     lineParts[2],
			Comment:  Comment,
		})
	}

	return rules
}

func rulesetChanged(appliedPath string, content []byte) (bool, error) {
	applied, err := os.ReadFile(appliedPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}

	if err != nil {
		return true, err
	}

	return sha256.Sum256(applied) != sha256.Sum256(content), nil
}

func saveAppliedRuleset(tmpPath string, appliedPath string) error {
	err := os.Rename(tmpPath, appliedPath)
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}

	content, err := os.ReadFile(tmpPath)
	if err != nil {
		return err
	}

	return os.WriteFile(appliedPath, content, 0644)
}
