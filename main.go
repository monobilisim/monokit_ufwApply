package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	lib "github.com/monobilisim/monokit_lib"
	"github.com/rs/zerolog"
)

// comes from -ldflags "-X 'main.version=version'" flag in ci build
var version string
var pluginName string = "ufwApply"
var up string = "up"
var down string = "down"
var configFiles []string = []string{"ufw.yml"}

func main() {
	if len(os.Args) > 1 {
		lib.HandleCommonPluginArgs(os.Args, version, configFiles)
		return
	}

	lib.InitConfig(configFiles...)

	logger, err := lib.InitLogger()
	if err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}

	lib.InitializeDatabase()

	logger.Info().Msg("Starting ufw Applier plugin...")

	err = os.MkdirAll(lib.UfwApplyConfig.RulesetDir, os.ModePerm)
	if err != nil {
		fmt.Errorf("Failed to create ruleset directory: %v", err)
		logger.Fatal().Err(err).Msg("Failed to create ruleset directory")
		return
	}

	err = os.MkdirAll(lib.UfwApplyConfig.RulesetDir+"/tmp", os.ModePerm)
	if err != nil {
		fmt.Errorf("Failed to create tmp directory: %v", err)
		logger.Fatal().Err(err).Msg("Failed to create tmp directory")
		return
	}

	err = os.MkdirAll(lib.UfwApplyConfig.RulesetDir+"/rules", os.ModePerm)
	if err != nil {
		fmt.Errorf("Failed to create rules directory: %v", err)
		logger.Fatal().Err(err).Msg("Failed to create rules directory")
		return
	}

	logger.Debug().Msgf("RuleSources: %v", lib.UfwApplyConfig.RuleSources)

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

		splitUrl := strings.Split(ruleset.Url, "/")

		outputFile, err := os.Create(lib.UfwApplyConfig.RulesetDir + "/tmp/" + splitUrl[len(splitUrl)-1])
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to create file for ruleset from %s", ruleset.Url)
			continue
		}
		defer outputFile.Close()

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

		_, err = outputFile.WriteString(strings.Join(newLines, "\n"))
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to write ruleset to file from %s", ruleset.Url)
			continue
		}

		logger.Info().Msgf("Successfully fetched ruleset from %s", ruleset.Url)
	}

	alarmMessage := ""

	var moduleName string = "dryrun"
	err = UfwApplyDryRun(logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to dry run ufw rules")

		alarmMessage = fmt.Sprintf("[ufwApply] - %s - Failed to dry run ufw rules: %s", lib.GlobalConfig.Hostname, err.Error())

		lib.SendZulipAlarm(alarmMessage, pluginName, moduleName, down)

		return
	}

	lastAlarm, err := lib.GetLastZulipAlarm(pluginName, moduleName)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get last dry run alarm from database")
		return
	}

	if lastAlarm.Status == down {
		alarmMessage = fmt.Sprintf("[ufwApply] - %s - UFW dry run successfully after previous failure", lib.GlobalConfig.Hostname)

		lib.SendZulipAlarm(alarmMessage, pluginName, moduleName, up)
	}

	moduleName = "apply"
	err = UfwApply(logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to apply ufw rules")

		alarmMessage = fmt.Sprintf("[ufwApply] - %s - Failed to apply ufw rules: %s", lib.GlobalConfig.Hostname, err.Error())

		lib.SendZulipAlarm(alarmMessage, pluginName, moduleName, down)

		return
	}

	lastAlarm, err = lib.GetLastZulipAlarm(pluginName, moduleName)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get last apply alarm from database")
		return
	}

	if lastAlarm.Status == down {
		logger.Info().Msg("UFW apply succeeded after previous failure")

		alarmMessage = fmt.Sprintf("[ufwApply] - %s - UFW apply successfully after previous failure", lib.GlobalConfig.Hostname)

		lib.SendZulipAlarm(alarmMessage, pluginName, moduleName, up)
	}
}

func UfwApply(logger zerolog.Logger) error {
	if len(lib.UfwApplyConfig.StaticRules) > 0 {
		for _, staticRule := range lib.UfwApplyConfig.StaticRules {
			logger.Info().Msgf("Running static rule %s", staticRule.IP)

			rule := Rule{
				IP:       staticRule.IP,
				Protocol: staticRule.Protocol,
				Port:     staticRule.Port,
				Comment:  staticRule.Comment,
			}

			command := rule.AllowCommand(false)

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
		logger.Info().Msgf("Running ruleset %s", file.Name())

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
			if len(lineParts) < 3 {
				logger.Warn().Msgf("Malformed line %q in %s, skipping...", line, file.Name())
				continue
			}

			rule := Rule{
				IP:       lineParts[0],
				Protocol: lineParts[1],
				Port:     lineParts[2],
				Comment:  Comment,
			}

			command := rule.AllowCommand(false)

			_, err := command.CombinedOutput()
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to execute command: %s", command)
				return err
			}
		}
	}

	return nil
}
