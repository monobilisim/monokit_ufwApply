package main

import (
	"os"
	"strings"

	lib "github.com/monobilisim/monokit_lib"
	"github.com/rs/zerolog"
)

func UfwApplyDryRun(logger zerolog.Logger, rulesets []string) error {
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

		fileContent, err := os.ReadFile(lib.UfwApplyConfig.RulesetDir + "/tmp/" + fileName)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to read tmp file %s", fileName)
			return err
		}

		lines := strings.Split(string(fileContent), "\n")

		for _, line := range lines {
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

			rule := Rule{
				IP:       lineParts[0],
				Protocol: lineParts[1],
				Port:     lineParts[2],
				Comment:  Comment,
			}

			command := rule.AllowCommand(true)

			_, err := command.CombinedOutput()
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to execute command: %s", command)
				return err
			}
		}
	}

	return nil
}
