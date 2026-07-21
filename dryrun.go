package main

import (
	"os"
	"os/exec"
	"strings"

	lib "github.com/monobilisim/monokit_lib"
	"github.com/rs/zerolog"
)

func UfwApplyDryRun(logger zerolog.Logger) error {
	if len(lib.UfwApplyConfig.StaticRules) > 0 {
		for _, staticRule := range lib.UfwApplyConfig.StaticRules {
			logger.Info().Msgf("Dry running static rule %s", staticRule.IP)

			IP := staticRule.IP
			Protocol := staticRule.Protocol
			Port := staticRule.Port
			Comment := staticRule.Comment

			command := exec.Command("ufw", "--dry-run", "allow", "from", IP)
			if Port == "all" {
				command.Args = append(command.Args, "to")
				command.Args = append(command.Args, "any")
			} else {
				command.Args = append(command.Args, "to")
				command.Args = append(command.Args, "any")
				command.Args = append(command.Args, "port")
				command.Args = append(command.Args, Port)
			}

			if Protocol != "all" {
				command.Args = append(command.Args, "proto")
				command.Args = append(command.Args, Protocol)
			}

			if Comment != "" {
				command.Args = append(command.Args, "comment")
				command.Args = append(command.Args, Comment)
			}

			_, err := command.CombinedOutput()
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to execute command: %s", command)
				return err
			}
		}
	}

	tmpFiles, err := os.ReadDir(lib.UfwApplyConfig.RulesetDir + "/tmp")
	if err != nil {
		logger.Error().Err(err).Msg("Failed to read tmp directory")
		return err
	}

	for _, file := range tmpFiles {
		logger.Info().Msgf("Dry running ruleset %s", file.Name())

		fileContent, err := os.ReadFile(lib.UfwApplyConfig.RulesetDir + "/tmp/" + file.Name())
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to read tmp file %s", file.Name())
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

			IP := lineParts[0]
			Protocol := lineParts[1]
			Port := lineParts[2]

			command := exec.Command("ufw", "--dry-run", "allow", "from", IP)
			if Port == "all" {
				command.Args = append(command.Args, "to")
				command.Args = append(command.Args, "any")
			} else {
				command.Args = append(command.Args, "to")
				command.Args = append(command.Args, "any")
				command.Args = append(command.Args, "port")
				command.Args = append(command.Args, Port)
			}

			if Protocol != "all" {
				command.Args = append(command.Args, "proto")
				command.Args = append(command.Args, Protocol)
			}

			if Comment != "" {
				command.Args = append(command.Args, "comment")
				command.Args = append(command.Args, Comment)
			}

			_, err := command.CombinedOutput()
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to execute command: %s", command)
				return err
			}
		}
	}

	return nil
}
