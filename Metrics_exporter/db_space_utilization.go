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
	db_space_utilization = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:"ovs_db_space_utilization",
			Help:"Helps measure the db space utilization",
		},
		[]string{},
	)
)

func parseDBSpaceUtilization(data string) {
	scanner := bufio.NewScanner(strings.NewReader(data))
	totalRegex := regexp.MustCompile(`Total:\s*(\d+)`)
	freeRegex := regexp.MustCompile(`Free:\s*(\d+)`)
	var total, free float64
	for scanner.Scan(){
		line := scanner.Text()
		if match := totalRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				total = value
			}
		}

		if match := freeRegex.FindStringSubmatch(line); match != nil {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				free = value
			}
		}
	}
	metric := (total-free)/total * 100
	db_space_utilization.WithLabelValues().Set(metric)
}
func DBSpaceUtilization(){
	for {
		command := `stat -f /etc/openvswitch/conf.db | grep Blocks`
		cmd := exec.Command("sh","-c",command)
		output, err := cmd.CombinedOutput()
		if err != nil{
			fmt.Println("Error in running command:",cmd)
		}
		parseDBSpaceUtilization(string(output))
		time.Sleep(10 * time.Second)
	}
}

