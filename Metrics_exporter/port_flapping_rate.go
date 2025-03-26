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
	portFlappingCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ovs_port_flapping",
			Help: "Helps to measure the total port status switches",
		},
		[]string{"switch"},
	)
)

var previousState map[string][]float64
var flapsCount float64

func parsePortFlaps(data string, sw string) {
	scanner := bufio.NewScanner(strings.NewReader(data))
	stateRegex := regexp.MustCompile(`state:\s*(\d+)|(LINK_DOWN)`)
	var portCount float64
	var currentState []float64

	for scanner.Scan() {
		line := scanner.Text()
		portCount++
		if match := stateRegex.FindStringSubmatch(line); match != nil {
			_, err := strconv.ParseFloat(match[1], 64)
			if err == nil {
				currentState = append(currentState, 0)
			} else {
				currentState = append(currentState, 1)
			}
		}
	}

	if previousState == nil {
		previousState = make(map[string][]float64)
	}

	if len(previousState[sw]) != 0 {
		for index, st1 := range currentState {
			if st1 != previousState[sw][index] {
				flapsCount++
			}
		}
	}
	previousState[sw] = currentState
	currentState = []float64{}
	portFlappingCount.WithLabelValues(sw).Set(flapsCount)
}
func PortFlappingCount() {
	for {
		switches := GetSwitches()
		for _, sw := range switches {
			command := `ovs-ofctl dump-ports-desc ` + sw + `|grep state`
			cmd := exec.Command("sh", "-c", command)
			flowOutput, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println("Error in command:", command)
			}
			parsePortFlaps(string(flowOutput), sw)
		}
		time.Sleep(10 * time.Second)
	}
}
