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
	packet_errors = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ovs_packet_errors",
			Help: "Helps to find packet error rate of a port",
		},
		[]string{"interface"},
	)
)

func parsePacketErrorRate(data string, inter string) {
	scanner := bufio.NewScanner(strings.NewReader(data))

	var rx_errors, tx_errors float64

	for scanner.Scan() {
		line := scanner.Text()
		rxRegex := regexp.MustCompile(`rx_errors=(\d+)`)
		txRegex := regexp.MustCompile(`tx_errors=(\d+)`)

		if match := rxRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				rx_errors = value
			}
		}

		if match := txRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				tx_errors = value
			}
		}
	}
	packet_errors.WithLabelValues(inter).Set(rx_errors + tx_errors)
}
func PacketErrorRate() {
	for {
		interfaces := GetInterfaces()
		for _, inter := range interfaces {
			command := `ovs-vsctl list interface ` + inter + ` | grep statistics`
			cmd := exec.Command("sh", "-c", command)
			output, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println("Error in command:", command)
			}
			parsePacketErrorRate(string(output), inter)
		}
		time.Sleep(10 * time.Second)
	}
}
