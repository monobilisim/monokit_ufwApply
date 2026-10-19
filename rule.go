package main

import "os/exec"

type Rule struct {
	IP       string
	Protocol string
	Port     string
	Comment  string
}

func (rule Rule) AllowCommand(dryRun bool) *exec.Cmd {
	command := exec.Command("ufw")
	if dryRun {
		command.Args = append(command.Args, "--dry-run")
	}

	command.Args = append(command.Args, "allow", "from", rule.IP, "to", "any")

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
