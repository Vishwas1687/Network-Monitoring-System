package main

import (
	"fmt"
	"regexp"
	"os/exec"
	"strings"
)

func GetInterfaces() []string {
	cmd := exec.Command("sh","-c", "ovs-vsctl show | grep Interface")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error running command:", err)
		return nil
	}

	lines := strings.Split(string(output), "\n")
	var interfaces []string

	interfaceRegex := regexp.MustCompile(`Interface (s\d+-eth\d+)`)

	for _, line := range lines {
		matches := interfaceRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			interfaces = append(interfaces, matches[1])
		}
	}

	return interfaces
	
}