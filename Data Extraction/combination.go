package main

import (
	"encoding/json"
	"encoding/csv"
	"os"
	"sort"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)
duration = "5m"

duration := "5m" // Example duration, can be changed dynamically

	metrics := map[string]map[string]string{
		"infra_metrics": {
			"Resource Utilization":      "ovs_resource_utilization",
			"CPU Utilization":           "ovs_cpu_utilization",
			"Bridge Controller Status":  "ovs_bridge_controller_status",
			"Memory Per Bridge":         "ovs_memory_per_bridge",
			"Rate of control Channel Flap": "rate(ovs_control_channel_flap[" + duration + "])",
			"Database Space Utilization":      "ovs_db_space_utilization",
		},
		"switch_metrics": {
			"Flow Table Utilization":         "ovs_flow_table_utilization",
			"Rate of Flow Table Utilization": "rate(ovs_flow_modification_velocity[" + duration + "])",
			"Rate of Packet in Messages":     "rate(ovs_packet_in[" + duration + "])",
			"Average Packets Per Flow":       "ovs_average_packets_per_flow",
			"Average Flow Duration":          "ovs_average_flow_duration",
			"Flow Stablity Index":            "ovs_flow_stability_index",
			"Rate of Port Flapping":          "rate(ovs_port_flapping[" + duration + "])",
		},
		"interface_metrics": {
			"Asymmetric Traffic Volume":         "delta(ovs_inbound_outbound[" + duration + "]) / delta(ovs_total_bytes_interface[" + duration + "]) * 100)",
			"Interface Utilization Percentage":  "rate(ovs_interface_bytes[1m])/(ovs_interface_link_speed * 60) * 100",
		},
	}
func writeMapToCSV(data map[string][]string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Extract field names (keys) as column headers
	var headers []string
	for key := range data {
		if key != "timestamp" {
			headers = append(headers, key)
		}
	}

	// Sort keys alphabetically, but keep "timestamp" first
	sort.Strings(headers)
	headers = append([]string{"timestamp"}, headers...)

	// Write header row
	writer.Write(headers)

	// Determine number of rows
	numRows := 0
	for _, values := range data {
		if len(values) > numRows {
			numRows = len(values)
		}
	}

	// Write rows
	for i := 0; i < numRows; i++ {
		var row []string
		for _, key := range headers {
			if i < len(data[key]) {
				row = append(row, data[key][i])
			} else {
				row = append(row, "") // Empty value if data is missing
			}
		}
		writer.Write(row)
	}

	return nil
}

// PrometheusResponse represents the structure of the API response
 type PrometheusResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result    []struct {
			Metric map[string]string `json:"metric"`
			Values [][]interface{}   `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

func main() {
	url := "http://localhost:9090/api/v1/query_range?query=ovs_average_flow_duration&start=1742700300&end=1742700964&step=10s"
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching data:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	var data PrometheusResponse
	if err := json.Unmarshal(body, &data); err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return
	}

	if data.Status != "success" {
		fmt.Println("Query failed with status:", data.Status)
		return
	}

	// Segregating and printing the data in the required format
	var metrics map[string][]string = make(map[string][]string) // switch : [value], timestamp: [value]
	for i, result := range data.Data.Result {
		switchName := result.Metric["switch"]
		for _, value := range result.Values {
			timestamp := int64(value[0].(float64))
			metricValue := value[1].(string)
			timeStr := time.Unix(timestamp, 0).Format("2006-01-02 15:04:05")
			if i==0 {
				metrics["timestamp"]=append(metrics["timestamp"],timeStr)
			}
			metrics[switchName] = append(metrics[switchName],metricValue)
		}
	}

	filename := "ovs_flow_duration.csv"
	err = writeMapToCSV(metrics, filename)
	if err != nil {
		fmt.Println("Error writing to CSV:", err)
	} else {
		fmt.Println("CSV file successfully created:", filename)
	}
}
