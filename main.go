package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	lib "github.com/monobilisim/monokit_lib"
	"github.com/rs/zerolog"
)

// comes from -ldflags "-X 'main.version=version'" flag in ci build
var version string
var pluginName string = "ufwApply"
var up string = "up"
var down string = "down"
var configFiles []string = []string{"ufw.yml"}
var defaultRulesetDir string = "/etc/mono/ufw-rulesets"

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

	setDefaultDirs()

	err = os.MkdirAll(lib.UfwApplyConfig.RulesDir, os.ModePerm)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create rules directory")
		return
	}

	err = os.MkdirAll(lib.UfwApplyConfig.TmpDirBase, os.ModePerm)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create tmp directory")
		return
	}

	tmpDir, err := os.MkdirTemp(lib.UfwApplyConfig.TmpDirBase, time.Now().Format("20060102150405")+"-*")
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create tmp directory for this run")
		return
	}

	// logger.Fatal exits without running deferred calls, so the tmp directory is also removed before each Fatal below
	defer removeTmpDir(logger, tmpDir)

	changedRulesets := FetchRulesets(logger, tmpDir)

	alarmMessage := ""

	var moduleName string = "dryrun"
	err = UfwApplyDryRun(logger, tmpDir, changedRulesets)
	if err != nil {
		alarmMessage = fmt.Sprintf("[ufwApply] - %s - Failed to dry run ufw rules: %s", lib.GlobalConfig.Hostname, err.Error())

		alarmErr := lib.SendZulipAlarm(alarmMessage, pluginName, moduleName, down)

		removeTmpDir(logger, tmpDir)
		logger.Fatal().Err(err).AnErr("alarm_error", alarmErr).Msg("Failed to dry run ufw rules")

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
	err = UfwApply(logger, tmpDir, changedRulesets)
	if err != nil {
		alarmMessage = fmt.Sprintf("[ufwApply] - %s - Failed to apply ufw rules: %s", lib.GlobalConfig.Hostname, err.Error())

		alarmErr := lib.SendZulipAlarm(alarmMessage, pluginName, moduleName, down)

		removeTmpDir(logger, tmpDir)
		logger.Fatal().Err(err).AnErr("alarm_error", alarmErr).Msg("Failed to apply ufw rules")

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

// rules-dir and tmp-dir-base default to subdirectories of ruleset-dir when they are not set in ufw.yml
func setDefaultDirs() {
	if lib.UfwApplyConfig.RulesetDir == "" {
		lib.UfwApplyConfig.RulesetDir = defaultRulesetDir
	}

	if lib.UfwApplyConfig.RulesDir == "" {
		lib.UfwApplyConfig.RulesDir = filepath.Join(lib.UfwApplyConfig.RulesetDir, "rules")
	}

	if lib.UfwApplyConfig.TmpDirBase == "" {
		lib.UfwApplyConfig.TmpDirBase = filepath.Join(lib.UfwApplyConfig.RulesetDir, "tmp")
	}
}

func removeTmpDir(logger zerolog.Logger, tmpDir string) {
	err := os.RemoveAll(tmpDir)
	if err != nil {
		logger.Warn().Err(err).Msgf("Failed to remove tmp directory %s", tmpDir)
	}
}

func UfwApply(logger zerolog.Logger, tmpDir string, rulesets []string) error {
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

	for _, fileName := range rulesets {
		logger.Info().Msgf("Running ruleset %s", fileName)

		fileContent, err := os.ReadFile(filepath.Join(tmpDir, fileName))
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

			command := rule.AllowCommand(false)

			_, err := command.CombinedOutput()
			if err != nil {
				logger.Error().Err(err).Msgf("Failed to execute command: %s", command)
				return err
			}
		}

		err = saveAppliedRuleset(filepath.Join(tmpDir, fileName), filepath.Join(lib.UfwApplyConfig.RulesDir, fileName), fileContent)
		if err != nil {
			logger.Error().Err(err).Msgf("Failed to save applied ruleset %s, it will be reapplied on the next run", fileName)
		}
	}

	return nil
}
