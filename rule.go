package main

import (
	"fmt"
	"os/exec"
	"slices"
	"strings"

	lib "github.com/monobilisim/monokit_lib"
	"github.com/rs/zerolog"
)

type Rule struct {
	IP       string
	Protocol string
	Port     string
	Comment  string
}

func staticRules() []Rule {
	var rules []Rule

	for _, staticRule := range lib.UfwApplyConfig.StaticRules {
		rules = append(rules, Rule{
			IP:       staticRule.IP,
			Protocol: staticRule.Protocol,
			Port:     staticRule.Port,
			Comment:  staticRule.Comment,
		})
	}

	return rules
}

func (rule Rule) AllowCommand(dryRun bool) *exec.Cmd {
	return rule.command(dryRun, "allow")
}

func (rule Rule) DeleteCommand(dryRun bool) *exec.Cmd {
	rule.Comment = ""
	return rule.command(dryRun, "delete", "allow")
}

func (rule Rule) command(dryRun bool, action ...string) *exec.Cmd {
	command := exec.Command("ufw")
	if dryRun {
		command.Args = append(command.Args, "--dry-run")
	}

	command.Args = append(command.Args, action...)
	command.Args = append(command.Args, "from", rule.IP, "to", "any")

	if rule.Port != "all" {
		command.Args = append(command.Args, "port", rule.Port)
	}

	if rule.Protocol != "all" {
		command.Args = append(command.Args, "proto", rule.Protocol)
	}

	if rule.Comment != "" {
		command.Args = append(command.Args, "comment", rule.Comment)
	}

	return command
}

func (rule Rule) key() string {
	return strings.TrimSuffix(rule.IP, "/32") + " " + rule.Protocol + " " + rule.Port
}

// command-output defaults to true when it is not set in ufw.yml
func commandOutput() bool {
	return lib.UfwApplyConfig.CommandOutput == nil || *lib.UfwApplyConfig.CommandOutput
}

// runCommand puts ufw's output in the error so it reaches the alarm. A dry run prints the whole
// generated ruleset, so only its command is logged.
func runCommand(logger zerolog.Logger, command *exec.Cmd) error {
	output, err := command.CombinedOutput()
	result := strings.TrimSpace(string(output))

	if err != nil {
		if result != "" {
			err = fmt.Errorf("%s: %w: %s", command, err, result)
		} else {
			err = fmt.Errorf("%s: %w", command, err)
		}

		logger.Error().Err(err).Msg("Failed to execute ufw command")
		return err
	}

	if !commandOutput() {
		return nil
	}

	if slices.Contains(command.Args, "--dry-run") {
		logger.Info().Msg(command.String())
		return nil
	}

	logger.Info().Msgf("%s: %s", command, result)
	return nil
}

// line is the rule as it is written to an applied copy, parseRuleset reads it back
func (rule Rule) line() string {
	line := rule.IP + " " + rule.Protocol + " " + rule.Port

	if rule.Comment != "" {
		line += " # " + rule.Comment
	}

	return line
}
