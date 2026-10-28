package main

import (
	"os"
	"path/filepath"

	lib "github.com/monobilisim/monokit_lib"
	"github.com/rs/zerolog"
)

func UfwApplyDryRun(logger zerolog.Logger, tmpDir string, rulesets []string, removedRulesets []string) error {
	if len(lib.UfwApplyConfig.StaticRules) > 0 {
		for _, staticRule := range lib.UfwApplyConfig.StaticRules {
			logger.Info().Msgf("Dry running static rule %s", staticRule.IP)

			rule := Rule{
				IP:       staticRule.IP,
				Protocol: staticRule.Protocol,
				Port:     staticRule.Port,
				Comment:  staticRule.Comment,
			}

			command := rule.AllowCommand(true)

			_, err := command.CombinedOutput()
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to execute command: %s", command)
				return err
			}
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
			command := rule.AllowCommand(true)

			_, err := command.CombinedOutput()
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to execute command: %s", command)
				return err
			}
		}
	}

	return RemoveRulesets(logger, removedRulesets, true)
}
