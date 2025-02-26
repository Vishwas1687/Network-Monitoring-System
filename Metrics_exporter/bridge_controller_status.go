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
	bridge_controller_status = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:"ovs_bridge_controller_status",
			Help:"Helps to find if a bridge is connected to the controller or not",
		},
		[]string{"switch"},
	)
)

func parseBridgeControllerStatus(lines string, sw string) {
	match := strings.Fields(lines)
	value, err := strconv.ParseFloat(match[0], 64)
	if err != nil {
		fmt.Println("Error in parsing", match[0])
	}
	if value == 0 {
		bridge_controller_status.WithLabelValues(sw).Set(0)
	} else {
		bridge_controller_status.WithLabelValues(sw).Set(1)
	}
}
func BridgeControllerStatus(){
	for {
		switches := GetSwitches()
		for _,sw := range switches{
			command := `ovs-vsctl get-controller ` + sw + ` | wc -l` 
			cmd := exec.Command("sh","-c",command)
			lines, err := cmd.CombinedOutput()
			if err != nil{
				fmt.Println("Error in command:",command)
			}

			parseBridgeControllerStatus(string(lines), sw)
		}
		
		time.Sleep(10 * time.Second)
	}
}

