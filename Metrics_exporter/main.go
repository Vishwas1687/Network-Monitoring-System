package main
import (
	"net/http"
	"log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main(){
	go FlowStabilityIndex()
	go PortFlappingCount()
	go FlowRuleModificationsCount()
	go InterfaceUtilization()
	go AverageFlowDuration()
	go AveragePacketsPerFlow()
	go FlowUtilization()
	go FlowTableCacheHit()
	go MemoryPerBridge()
	go ResourceUtilization()
	go HitRate()
	go BridgeControllerStatus()
	go DBSpaceUtilization()
	go CPUUtilization()
	go AsymmetricTraffic()
	go PacketIn()
	go PacketLossRate()
	go PacketErrorRate()
	go ControlChannelFlap()
	http.Handle("/metrics", promhttp.Handler())
	log.Println("Prometheus exporter running on :8080/metrics")
	log.Fatal(http.ListenAndServe(":8080", nil))
}