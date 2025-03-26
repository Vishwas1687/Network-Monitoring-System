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
	packet_loss = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ovs_packet_loss",
			Help: "Helps to find packet loss rate of a port",
		},
		[]string{"interface"},
	)
)

func parsePacketLossRate(data string, inter string) {
	scanner := bufio.NewScanner(strings.NewReader(data))

	var rx_dropped, tx_dropped float64

	for scanner.Scan() {
		line := scanner.Text()
		rxRegex := regexp.MustCompile(`rx_dropped=(\d+)`)
		txRegex := regexp.MustCompile(`tx_dropped=(\d+)`)

		if match := rxRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				rx_dropped = value
			}
		}

		if match := txRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				tx_dropped = value
			}
		}
	}
	packet_loss.WithLabelValues(inter).Set(rx_dropped + tx_dropped)
}
func PacketLossRate() {
	for {
		interfaces := GetInterfaces()
		for _, inter := range interfaces {
			command := `ovs-vsctl list interface ` + inter + ` | grep statistics`
			cmd := exec.Command("sh", "-c", command)
			output, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println("Error in command:", command)
			}
			parsePacketLossRate(string(output), inter)
		}
		time.Sleep(10 * time.Second)
	}
}
