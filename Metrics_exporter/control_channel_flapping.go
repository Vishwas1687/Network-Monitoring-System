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
	control_channel_flap = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:"ovs_channel_flap",
			Help:"Helps to find the rate of switch control channel flap",
		},
		[]string{},
	)
)

func parseControlChannelFlap(lines string) float64 {
	match := strings.Fields(lines)
	value, err := strconv.ParseFloat(match[0], 64)
	if err != nil {
		fmt.Println("Error in parsing", match[0])
	}
	return value
}
func ControlChannelFlap(){
	for {
		switches := GetSwitches()
		var count float64 = 0
		for _,sw := range switches{
			command := `ovs-vsctl get-controller ` + sw + ` | wc -l` 
			cmd := exec.Command("sh","-c",command)
			lines, err := cmd.CombinedOutput()
			if err != nil{
				fmt.Println("Error in command:",command)
			}

			count += parseControlChannelFlap(string(lines))
		}
		control_channel_flap.WithLabelValues().Set(count)
		time.Sleep(10 * time.Second)
	}
}

