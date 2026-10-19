package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

		splitUrl := strings.Split(ruleset.Url, "/")
		fileName := splitUrl[len(splitUrl)-1]

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
