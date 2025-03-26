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
	interface_bytes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ovs_interface_bytes",
			Help: "Helps measure the interface bytes",
		},
		[]string{"interface"},
	)
	interface_link_speeds = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ovs_interface_link_speed",
			Help: "Helps measure the interface link speed",
		},
		[]string{"interface"},
	)
)

func getLinkSpeeds() {
	command := `sudo ovs-vsctl list interface | grep -E '\bname\b|link_speed'`
	cmd := exec.Command("sh", "-c", command)
	link_speed_string, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error in command:", command)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(link_speed_string)))
	var link_speed float64 = 0
	var i int = 1
	for scanner.Scan() {
		// Extract link speed
		line := scanner.Text()

		if i%2 == 1 {
			linkSpeedRegex := regexp.MustCompile(`link_speed\s*:\s*(\d+)`)
			if match := linkSpeedRegex.FindStringSubmatch(line); match != nil {
				if value, err := strconv.ParseFloat(match[1], 64); err == nil {
					link_speed = value
				}
				i += 1
			} else {
				i += 2
			}
		} else {
			// Extract interface name
			interfaceRegex := regexp.MustCompile(`name\s*:\s*(s\d+-eth\d+)`)
			if match := interfaceRegex.FindStringSubmatch(line); match != nil {
				interface_name := match[1]
				interface_link_speeds.WithLabelValues(interface_name).Set(link_speed)
				i += 1
			}
		}
	}
}

func InterfaceUtilization() {

	for {
		// Get link speeds of all interfaces
		getLinkSpeeds()

		switches := GetSwitches()
		for _, sw := range switches {
			command := `ovs-ofctl dump-ports ` + sw + ` | sed -n '/port/{N;s/\n/ /;p}' | grep port | sort -k2,2V`
			cmd := exec.Command("sh", "-c", command)
			ports_statistics_string, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println("Error in command:", command)
				continue
			}

			scanner := bufio.NewScanner(strings.NewReader(string(ports_statistics_string)))

			first_line := true
			var port_count int = 0

			for scanner.Scan() {
				line := scanner.Text()
				if first_line {
					first_line = false
					continue
				}

				port_count++
				interface_name := fmt.Sprintf("%s-eth%d", sw, port_count)

				lineRegex := regexp.MustCompile(`bytes=(\d+).*bytes=(\d+)`)
				if match := lineRegex.FindStringSubmatch(line); match != nil {
					rx_bytes, err1 := strconv.ParseFloat(match[1], 64)
					tx_bytes, err2 := strconv.ParseFloat(match[2], 64)

					if err1 == nil && err2 == nil {
						interface_bytes.WithLabelValues(interface_name).Set(rx_bytes + tx_bytes)
					}
				} else {
					lineRegex = regexp.MustCompile(`bytes=(\d+)`)
					if match := lineRegex.FindStringSubmatch(line); match != nil {
						rx_bytes, err := strconv.ParseFloat(match[1], 64)

						if err == nil {
							interface_bytes.WithLabelValues(interface_name).Set(rx_bytes)
						}
					}
				}

			}
		}
		time.Sleep(10 * time.Second)
	}
}
