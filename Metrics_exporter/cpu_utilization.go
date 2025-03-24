package main

import (
	"fmt"
	"strings"
	"strconv"
	"time"
	"os/exec"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	
)
var (
	cpu_utilization = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:"ovs_cpu_utilization",
			Help:"Helps measure the cpu utilization",
		},
		[]string{},
	)
)

func parseCPUUtilization(data string) {
	match := strings.Fields(data)
	value, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		fmt.Println("Error in parsing cpu utilization")
	}
	cpu_utilization.WithLabelValues().Set(value)
}
func CPUUtilization(){
	for {
		command := `sudo ps -C ovs-vswitchd -o %cpu`
		cmd := exec.Command("sh","-c",command)
		output, err := cmd.CombinedOutput()
		if err != nil{
			fmt.Println("Error in running command:",cmd)
		}
		parseCPUUtilization(string(output))
		time.Sleep(10 * time.Second)
	}
}

