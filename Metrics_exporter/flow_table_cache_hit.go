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
	lookups_metric = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ovs_table_lookups",
			Help: "Helps measure the number of flow table hits",
		},
		[]string{"switch"},
	)

	matched_metric = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ovs_table_matched",
			Help: "Helps measure the number of flow table hits",
		},
		[]string{"switch"},
	)

)

func parseLookupsCacheHits(data string, sw string) float64 {
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan(){
		line := scanner.Text()
		lookupRegex := regexp.MustCompile(`lookup=(\d+)`)
		if match := lookupRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				return value
			}
		}
	}
	return 1
}

func parseMatchedCacheHits(data string, sw string) float64 {
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan(){
		line := scanner.Text()
		matchedRegex := regexp.MustCompile(`matched=(\d+)`)
		if match := matchedRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				return value
			}
		}
	}
	return 1
}

func FlowTableCacheHit() {

	for {
		switches := GetSwitches()
		for _, sw := range switches {
			command := `ovs-ofctl dump-tables `+sw+` | grep lookup | head -n 1`
			cmd := exec.Command("sh", "-c", command)
			lookup, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println("Error in command:", command)
				continue
			}
			lookups := parseLookupsCacheHits(string(lookup),sw)

			command = `ovs-ofctl dump-tables `+sw+` | grep matched | head -n 1`
			cmd = exec.Command("sh", "-c", command)
			matched, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println("Error in command:", command)
				continue
			}
			matches := parseMatchedCacheHits(string(matched),sw)
			lookups_metric.WithLabelValues(sw).Set(lookups)
			matched_metric.WithLabelValues(sw).Set(matches)
		}
		time.Sleep(10 * time.Second)
	}
}
