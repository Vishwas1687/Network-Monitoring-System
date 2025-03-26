package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	resource_utilization = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ovs_resource_utilization",
			Help: "Helps to find the resource utilization of the ovs-vswitchd process",
		},
		[]string{},
	)
)

func parseResourceUtilization(memory string, process_memory string) {
	match := strings.Fields(process_memory)
	value, err := strconv.ParseFloat(match[0], 64)
	if err != nil {
		fmt.Println("Error in parsing", match[0])
	}

	scanner := bufio.NewScanner(strings.NewReader(memory))
	memoryRegex := regexp.MustCompile(`MemTotal:\s*(\d+)`)

	var system_memory float64

	for scanner.Scan() {
		line := scanner.Text()
		if match = memoryRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				system_memory = value
			}
		}
	}

	metric := (value / system_memory) * 100
	resource_utilization.WithLabelValues().Set(metric)
}
func ResourceUtilization() {
	for {
		command := `ps -o rss= -C ovs-vswitchd`
		cmd := exec.Command("sh", "-c", command)
		process_memory, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println("Error in command:", command)
		}

		command = `grep MemTotal /proc/meminfo`
		cmd = exec.Command("sh", "-c", command)
		memory, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println("Error in command:", command)
		}

		parseResourceUtilization(string(memory), string(process_memory))
		time.Sleep(10 * time.Second)
	}
}
