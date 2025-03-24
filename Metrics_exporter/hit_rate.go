package main

import (
	"fmt"
	"strconv"
	"time"
	"bufio"
	"regexp"
	"os/exec"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	
)
var (
	hit_rate = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:"ovs_hit_rate",
			Help:"Helps to find the hit rate in the network overall",
		},
		[]string{},
	)
)

func parseHitRate(data string) {
	scanner := bufio.NewScanner(strings.NewReader(data))
	hitRateRegex := regexp.MustCompile(`hit-rate:([\d]+\.[\d]+)%`)

	for scanner.Scan(){
		line := scanner.Text()
		if match := hitRateRegex.FindStringSubmatch(line) ; match != nil {
			if value, err := strconv.ParseFloat(match[1],64); err == nil{
				metric := value
				hit_rate.WithLabelValues().Set(metric)
			}
		}
	}
	
}
func HitRate(){
	for {
		command := `ovs-dpctl show | grep hit-rate`
		cmd := exec.Command("sh","-c",command)
		output, err := cmd.CombinedOutput()
		if err != nil{
			fmt.Println("Error in command:",command)
		}
		parseHitRate(string(output))
		time.Sleep(10 * time.Second)
	}
}

