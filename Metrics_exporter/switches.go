package main

import (
	"fmt"
	"regexp"
	"os/exec"
	"strings"
)

func GetSwitches() []string {
	cmd := exec.Command("sh","-c", "ovs-vsctl show | grep Bridge")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error running command:", err)
		return nil
	}

	lines := strings.Split(string(output), "\n")
	var switches []string

	switchRegex := regexp.MustCompile(`Bridge (s\d+)`)

	for _, line := range lines {
		matches := switchRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			switches = append(switches, matches[1])
		}
	}

	return switches
	
}