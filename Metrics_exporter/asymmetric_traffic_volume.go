package main

import (
	"fmt"
	"strconv"
	"bufio"
	"math"
	"time"
	"os/exec"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	
)
var (
	inbound_outbound = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:"ovs_inbound_outbound",
			Help:"Helps to find traffic imbalance",
		},
		[]string{"interface"},
	)

	total_bytes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:"ovs_total_bytes_interface",
			Help:"Helps to find traffic imbalance",
		},
		[]string{"interface"},
	)
	
)

func parseAsymmetricTraffic(data string, inter string) {
	scanner := bufio.NewScanner(strings.NewReader(data))

	var rx_bytes, tx_bytes float64

	for scanner.Scan(){
		line := scanner.Text()
		rxRegex := regexp.MustCompile(`rx_bytes=(\d+)`)
		txRegex := regexp.MustCompile(`tx_bytes=(\d+)`)

		if match := rxRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				rx_bytes = value
			}
		}

		if match := txRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				tx_bytes = value
			}
		}
	}
	total_bytes.WithLabelValues(inter).Set(rx_bytes + tx_bytes)
	inbound_outbound.WithLabelValues(inter).Set(math.Abs(tx_bytes - rx_bytes))
}
func AsymmetricTraffic(){
	for {
		interfaces := GetInterfaces()
		for _, inter := range interfaces {
			command := `ovs-vsctl list interface ` + inter + ` | grep statistics`
		    cmd := exec.Command("sh","-c",command)
			output, err := cmd.CombinedOutput()
			if err != nil{
				fmt.Println("Error in command:",command)
			}
			parseAsymmetricTraffic(string(output), inter)
		}
		time.Sleep(10 * time.Second)
	}
}

