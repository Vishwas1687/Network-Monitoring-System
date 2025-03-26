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
	packet_in = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ovs_packet_in",
			Help: "Helps to find the number of packet in messages",
		},
		[]string{"switch"},
	)
)

func parsePacketIn(data string, sw string) {
	scanner := bufio.NewScanner(strings.NewReader(data))

	for scanner.Scan() {
		line := scanner.Text()
		bytesRegex := regexp.MustCompile(`n_bytes=(\d+)`)
		if match := bytesRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				packet_in.WithLabelValues(sw).Set(value)
			}
		}
	}

}
func PacketIn() {
	switches := GetSwitches()
	for _, sw := range switches {
		command := `ovs-ofctl add-flow ` + sw + ` "priority=1, actions=controller"`
		cmd := exec.Command("sh", "-c", command)
		_, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println("Error in command:", command)
		}
	}

	for {
		switches := GetSwitches()
		for _, sw := range switches {
			command := `ovs-ofctl dump-flows ` + sw + ` | grep CONTROLLER`
			cmd := exec.Command("sh", "-c", command)
			output, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println("Error in command:", command)
			}
			parsePacketIn(string(output), sw)
		}
		time.Sleep(10 * time.Second)
	}
}
