package main

import (
	"fmt"
	"strconv"
	"time"
	"os/exec"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	
)
var (
	memory_per_bridge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:"ovs_memory_per_bridge",
			Help:"Helps to find the average memory per bridge",
		},
		[]string{},
	)
)

func parseMemoryPerBridge(num_bridges float64, memory string) {
	match := strings.Fields(memory)
	value, err := strconv.ParseFloat(match[0], 64)
	if err != nil {
		fmt.Println("Error in parsing", match[0])
	}

	metric := (value * 1000/num_bridges)/10e9
	memory_per_bridge.WithLabelValues().Set(metric)
}
func MemoryPerBridge(){
	for {
		switches := GetSwitches()

		var num_bridges float64 = float64(len(switches))
		command := `ps -o rss= -C ovs-vswitchd`
		cmd := exec.Command("sh","-c",command)
		memory, err := cmd.CombinedOutput()
		if err != nil{
			fmt.Println("Error in command:",command)
		}

		parseMemoryPerBridge(num_bridges, string(memory))
		time.Sleep(10 * time.Second)
	}
}

