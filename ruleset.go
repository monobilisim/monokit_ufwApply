package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
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

			line = fmt.Sprintf("%s %s", line, ruleset.Protocol)

			line = fmt.Sprintf("%s %s", line, ruleset.Port)

			if ruleset.Comment != "" {
				line = fmt.Sprintf("%s # %s", line, ruleset.Comment)
			}

			newLines = append(newLines, line)
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

func RemoveRulesets(logger zerolog.Logger, removedRulesets []string, dryRun bool) error {
	if len(removedRulesets) == 0 {
		return nil
	}

	wantedRules, err := wantedRules(logger, removedRulesets)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to read the rules that are still needed")
		return err
	}

	for _, fileName := range removedRulesets {
		logger.Info().Msgf("Removing rules of ruleset %s, it is no longer in rule-sources (dry run: %v)", fileName, dryRun)

		appliedPath := filepath.Join(lib.UfwApplyConfig.RulesDir, fileName)

		fileContent, err := os.ReadFile(appliedPath)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to read applied ruleset %s", fileName)
			return err
		}

		for _, rule := range parseRuleset(logger, fileName, fileContent) {
			if wantedRules[rule.key()] {
				logger.Info().Msgf("Keeping rule %s, a static rule or another ruleset still needs it", rule.key())
				continue
			}

			command := rule.DeleteCommand(dryRun)

			_, err := command.CombinedOutput()
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to execute command: %s", command)
				return err
			}
		}

		if dryRun {
			continue
		}

		err = os.Remove(appliedPath)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to remove applied ruleset %s, its rules will be deleted again on the next run", fileName)
		}
	}

	return nil
}

func wantedRules(logger zerolog.Logger, removedRulesets []string) (map[string]bool, error) {
	wanted := make(map[string]bool)

	for _, staticRule := range lib.UfwApplyConfig.StaticRules {
		wanted[Rule{IP: staticRule.IP, Protocol: staticRule.Protocol, Port: staticRule.Port}.key()] = true
	}

	entries, err := os.ReadDir(lib.UfwApplyConfig.RulesDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || slices.Contains(removedRulesets, entry.Name()) {
			continue
		}

		fileContent, err := os.ReadFile(filepath.Join(lib.UfwApplyConfig.RulesDir, entry.Name()))
		if err != nil {
			return nil, err
		}

		for _, rule := range parseRuleset(logger, entry.Name(), fileContent) {
			wanted[rule.key()] = true
		}
	}

	return wanted, nil
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

func saveAppliedRuleset(tmpPath string, appliedPath string, content []byte) error {
	err := os.Rename(tmpPath, appliedPath)
	if errors.Is(err, syscall.EXDEV) {
		return os.WriteFile(appliedPath, content, 0644)
	}

	return err
}
