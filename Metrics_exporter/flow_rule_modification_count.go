package main

import (
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	flows_modification_count = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ovs_flows_modification",
			Help: "Helps to find the change in the flow entries over time",
		},
		[]string{"switch"},
	)
)

var previousFlowState map[string]float64
var flowsChange map[string]float64

func parseFlowsRuleModification(data string, sw string) {
	match := strings.Fields(data)
	if previousFlowState == nil {
		previousFlowState = make(map[string]float64)
	}
	if flowsChange == nil {
		flowsChange = make(map[string]float64)
	}
	var currentFlows float64
	value, err := strconv.ParseFloat(match[0], 64)
	if err == nil {
		currentFlows = value - 1
		flowsChange[sw] = flowsChange[sw] + math.Abs(currentFlows-previousFlowState[sw])
	}

	previousFlowState[sw] = currentFlows
	flows_modification_count.WithLabelValues(sw).Set(flowsChange[sw])
}
func FlowRuleModificationsCount() {
	for {
		switches := GetSwitches()
		for _, sw := range switches {
			command := `ovs-ofctl dump-flows ` + sw + ` | wc -l`
			cmd := exec.Command("sh", "-c", command)
			flowOutput, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println("Error in command:", command)
			}
			parseFlowsRuleModification(string(flowOutput), sw)
		}
		time.Sleep(10 * time.Second)
	}
}
