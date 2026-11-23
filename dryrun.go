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

	reattributedRules, err := ReattributedRules(logger, tmpDir, rulesets, removedRulesets)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to find the rules that need another comment")
		return err
	}

	wanted, err := wantedRules(logger, tmpDir, rulesets)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to find which comment every rule gets")
		return err
	}

	for _, rule := range staticRules() {
		logger.Info().Msgf("Dry running static rule %s", rule.IP)

		rule.Comment = wanted[rule.key()].Comment

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
			rule.Comment = wanted[rule.key()].Comment

			err := runCommand(logger, rule.AllowCommand(true))
			if err != nil {
				return err
			}
		}
	}

	for _, rule := range reattributedRules {
		logger.Info().Msgf("Dry running rule %s again with comment %q", rule.key(), rule.Comment)

		err := runCommand(logger, rule.AllowCommand(true))
		if err != nil {
			return err
		}
	}

	return DeleteRules(logger, staleRules, true)
}
