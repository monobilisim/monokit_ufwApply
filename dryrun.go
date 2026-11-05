package main

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
)

func UfwApplyDryRun(logger zerolog.Logger, tmpDir string, rulesets []string, removedRulesets []string) error {
	staleRules, err := StaleRules(logger, tmpDir, rulesets, removedRulesets)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to find the rules that are no longer needed")
		return err
	}

	for _, rule := range staticRules() {
		logger.Info().Msgf("Dry running static rule %s", rule.IP)

		err := runCommand(logger, rule.AllowCommand(true))
		if err != nil {
			return err
		}
	}

	for _, fileName := range rulesets {
		logger.Info().Msgf("Dry running ruleset %s", fileName)

		fileContent, err := os.ReadFile(filepath.Join(tmpDir, fileName))
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to read tmp file %s", fileName)
			return err
		}

		for _, rule := range parseRuleset(logger, fileName, fileContent) {
			err := runCommand(logger, rule.AllowCommand(true))
			if err != nil {
				return err
			}
		}
	}

	return DeleteRules(logger, staleRules, true)
}
