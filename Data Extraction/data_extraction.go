package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

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

// Global metrics map
var duration = "5m"
var metrics = map[string]map[string]string{
	"infra_metrics": {
		"Resource Utilization":          "ovs_resource_utilization",
		"CPU Utilization":               "ovs_cpu_utilization",
		"Bridge Controller Status":      "ovs_bridge_controller_status",
		"Memory Per Bridge":             "ovs_memory_per_bridge",
		"Rate of control Channel Flap":  "rate(ovs_control_channel_flap[" + duration + "])",
		"Database Space Utilization":    "ovs_db_space_utilization",
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
		// Corrected parentheses in the complex queries
		"Asymmetric Traffic Volume":        "(delta(ovs_inbound_outbound[" + duration + "]) / delta(ovs_total_bytes_interface[" + duration + "])) * 100",
		"Interface Utilization Percentage": "(rate(ovs_interface_bytes[1m])/(ovs_interface_link_speed * 60)) * 100",
	},
}

// Function to fetch and process Prometheus data
func fetchMetrics() (map[string][]string, error) {
	metricsData := make(map[string][]string) // Will store {header: [values]}

	for category, metricGroup := range metrics {
		for metricName, query := range metricGroup {
			// Create dynamic Prometheus query URL with proper URL encoding
			encodedQuery := url.QueryEscape(query)
			queryURL := fmt.Sprintf("http://localhost:9090/api/v1/query_range?query=%s&start=1742700300&end=1742700964&step=10s", 
				encodedQuery)
			
			// Fetch data from Prometheus
			resp, err := http.Get(queryURL)
			if err != nil {
				fmt.Println("Error fetching data for", metricName, ":", err)
				continue
			}
			
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			
			if err != nil {
				fmt.Println("Error reading response for", metricName, ":", err)
				continue
			}

			// Check if response is empty or invalid before parsing
			if len(body) == 0 {
				fmt.Printf("Empty response body for %s\n", metricName)
				continue
			}

			// Try to remove any potential BOM or unexpected characters
			cleanBody := strings.TrimSpace(string(body))
			if !strings.HasPrefix(cleanBody, "{") {
				firstBrace := strings.Index(cleanBody, "{")
				if firstBrace > -1 {
					cleanBody = cleanBody[firstBrace:]
					body = []byte(cleanBody)
				} else {
					fmt.Printf("Invalid JSON format for %s (no opening brace found)\n", metricName)
					continue
				}
			}

			var data PrometheusResponse
			if err := json.Unmarshal(body, &data); err != nil {
				fmt.Printf("Error unmarshalling JSON for %s: %v\nResponse body: %s\n", 
					metricName, err, string(body[:min(100, len(body))]))
				continue
			}

			if data.Status != "success" {
				fmt.Println("Query failed for", metricName, "with status:", data.Status)
				continue
			}

			// Process timestamps only once
			if len(data.Data.Result) > 0 && len(data.Data.Result[0].Values) > 0 && len(metricsData["timestamp"]) == 0 {
				for _, value := range data.Data.Result[0].Values {
					timestamp := int64(value[0].(float64))
					timeStr := time.Unix(timestamp, 0).Format("2006-01-02 15:04:05")
					metricsData["timestamp"] = append(metricsData["timestamp"], timeStr)
				}
			}

			// Process the data and store it in `metricsData`
			if category == "switch_metrics" {
				for _, result := range data.Data.Result {
					switchName := result.Metric["switch"]
					header := fmt.Sprintf("%s - %s", metricName, switchName) // "Metric Name - Switch Name"
	
					for i, value := range result.Values {
						metricValue := value[1].(string)
						if i < len(metricsData["timestamp"]) {
							metricsData[header] = append(metricsData[header], metricValue)
						}
					}
				}
			} else if category == "interface_metrics" {
				for _, result := range data.Data.Result {
					// Get interface name safely with a fallback
					interfaceName := "unknown"
					if name, ok := result.Metric["interface"]; ok {
						interfaceName = name
					}
					
					header := fmt.Sprintf("%s - %s", metricName, interfaceName)
	
					for i, value := range result.Values {
						metricValue := value[1].(string)
						if i < len(metricsData["timestamp"]) {
							metricsData[header] = append(metricsData[header], metricValue)
						}
					}
				}
			} else if category == "infra_metrics" {
				for _, result := range data.Data.Result {
					header := metricName
					for i, value := range result.Values {
						metricValue := value[1].(string)
						if i < len(metricsData["timestamp"]) {
							metricsData[header] = append(metricsData[header], metricValue)
						}
					}
				}
			}
		}
	}

	return metricsData, nil
}

// Function to write data to a single CSV file
func writeMapToCSV(metricName string, data map[string][]string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Extract headers (metric names + switch names)
	var headers []string
	for key := range data {
		if key != "timestamp" {
			headers = append(headers, key)
		}
	}

	// Sort headers alphabetically, but keep "timestamp" first
	sort.Strings(headers)
	headers = append([]string{"timestamp"}, headers...)

	// Write headers
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("error writing CSV headers: %w", err)
	}

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
				row = append(row, "") // Empty value if missing
			}
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("error writing CSV row %d: %w", i, err)
		}
	}

	return nil
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Main function
func main() {
	metricsData, err := fetchMetrics()
	if err != nil {
		fmt.Println("Error fetching metrics:", err)
		return
	}

	filename := "ovs_metrics.csv"
	err = writeMapToCSV("All Metrics", metricsData, filename)
	if err != nil {
		fmt.Println("Error writing to CSV:", err)
	} else {
		fmt.Println("CSV file successfully created:", filename)
	}
}