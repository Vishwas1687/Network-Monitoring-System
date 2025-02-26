package main

import (
	"fmt"
	"strconv"
	"bufio"
	"time"
	"os/exec"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	
)
var (
	flow_utilization = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:"ovs_flow_utilization",
			Help:"Helps to find the flow utilization percentage",
		},
		[]string{"switch"},
	)
)

func parseFlowUtilization(num_flows string, data string, sw string) {
	match := strings.Fields(num_flows)
	var n_flows,max_entries float64
	value, err := strconv.ParseFloat(match[0], 64)
	if err == nil {
		n_flows = value - 1
	}

	scanner := bufio.NewScanner(strings.NewReader(data))

	for scanner.Scan(){
		line := scanner.Text()
		packetsRegex := regexp.MustCompile(`max_entries=(\d+)`)
		if match := packetsRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				max_entries += value
			}
		}
	}
	metric := (n_flows/max_entries * 100)
	if n_flows == 0{
		metric = 0
	}
	flow_utilization.WithLabelValues(sw).Set(metric)
}
func FlowUtilization(){
	for {
		switches := GetSwitches()
		for _, sw := range switches {
			command := `ovs-ofctl dump-flows ` + sw + ` | wc -l`
		    cmd := exec.Command("sh","-c",command)
			flowCount, err := cmd.CombinedOutput()
			if err != nil{
				fmt.Println("Error in command:",command)
			}
			command = `ovs-ofctl dump-tables ` + sw +`| grep max_entries`
			cmd = exec.Command("sh","-c",command)
			flowOutput, err := cmd.CombinedOutput()
			if err != nil{
				if string(flowCount) == "1\n"{
					average_packets_per_flow.WithLabelValues(sw).Set(0)
				}else{
					fmt.Println("Error in command:",command)
				}
			}
			parseFlowUtilization(string(flowCount), string(flowOutput), sw)
		}
		time.Sleep(10 * time.Second)
	}
}

