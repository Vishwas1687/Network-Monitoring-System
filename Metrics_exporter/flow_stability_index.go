package main

import (
	"fmt"
	"bufio"
	"strings"
	"regexp"
	"strconv"
	"time"
	"os/exec"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	
)
var (
	flowStabilityIndex = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:"ovs_flow_stability_index",
			Help:"Helps measure the number of long duration flows",
		},
		[]string{"switch"},
	)
)

func parseDuration(data string, sw string) {
	scanner := bufio.NewScanner(strings.NewReader(data))
	durationRegex := regexp.MustCompile(`duration=(\d+)`)
	var flowCount, elephantFLows float64
	var Threshold float64 = 10
	var skipFirstLine bool = true
	for scanner.Scan(){
		line := scanner.Text()
		if skipFirstLine{
			skipFirstLine = false
			continue
		}
		flowCount++
		if match := durationRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				if value > Threshold {
					elephantFLows++
				}
			}
		}
	}
	metric := 1 - elephantFLows / flowCount
	if flowCount == 0{
		metric = 1
	}
	flowStabilityIndex.WithLabelValues(sw).Set(metric)
}
func FlowStabilityIndex(){
	for {
		switches := GetSwitches()
		for _, sw := range switches {
			command := `ovs-ofctl dump-flows ` + sw
		    cmd := exec.Command("sh","-c",command)
			flowOutput, err := cmd.CombinedOutput()
			if err != nil{
				fmt.Println("Error in command ovs-ofctl dump-flows ", sw)
			}
			parseDuration(string(flowOutput), sw)
		}
		time.Sleep(10 * time.Second)
	}
}

