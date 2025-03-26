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
	average_packets_per_flow = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ovs_average_packets_per_flow",
			Help: "Helps to find the average packets per flow",
		},
		[]string{"switch"},
	)
)

func parsePacketsPerFlow(num_flows string, data string, sw string) {
	match := strings.Fields(num_flows)
	var n_flows, sum_packets float64
	value, err := strconv.ParseFloat(match[0], 64)
	if err == nil {
		n_flows = value - 1
	}

	scanner := bufio.NewScanner(strings.NewReader(data))

	for scanner.Scan() {
		line := scanner.Text()
		packetsRegex := regexp.MustCompile(`n_packets=(\d+)`)
		if match := packetsRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				sum_packets += value
			}
		}
	}
	metric := sum_packets / n_flows
	if n_flows == 0 {
		metric = 0
	}
	average_packets_per_flow.WithLabelValues(sw).Set(metric)
}
func AveragePacketsPerFlow() {
	for {
		switches := GetSwitches()
		for _, sw := range switches {
			command := `ovs-ofctl dump-flows ` + sw + ` | wc -l`
			cmd := exec.Command("sh", "-c", command)
			flowCount, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println("Error in command:", command)
			}
			command = `ovs-ofctl dump-flows ` + sw + `| grep n_packets`
			cmd = exec.Command("sh", "-c", command)
			flowOutput, err := cmd.CombinedOutput()
			if err != nil {
				if string(flowCount) == "1\n" {
					average_packets_per_flow.WithLabelValues(sw).Set(0)
				} else {
					fmt.Println("Error in command:", command)
				}
			}
			parsePacketsPerFlow(string(flowCount), string(flowOutput), sw)
		}
		time.Sleep(10 * time.Second)
	}
}
