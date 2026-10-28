package main

import (
	"os/exec"
	"strings"
)

type Rule struct {
	IP       string
	Protocol string
	Port     string
	Comment  string
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
