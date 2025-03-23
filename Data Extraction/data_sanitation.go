package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

var infra_metrics = []string{
	"Resource Utilization", "CPU Utilization", "Bridge Controller Status",
	"Memory Per Bridge", "Rate of control Channel Flap", "Database Space Utilization",
}

var switch_name = "s4"

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func main() {
	file, err := os.Open("./ovs_metrics.csv")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Error reading CSV:", err)
		return
	}

	if len(records) < 1 {
		fmt.Println("CSV file is empty")
		return
	}

	header := records[0]
	var timestampIdx int
	metricIndices := make(map[string]int)

	for i, h := range header {
		if h == "timestamp" {
			timestampIdx = i
		} else if strings.Contains(h, switch_name) {
			metricIndices[h] = i
		} else if contains(infra_metrics, h) {
			metricIndices[h] = i
		}
	}

	timestamps := []string{}
	metricValues := make(map[string][]string)

	for _, row := range records[1:] {
		timestamps = append(timestamps, row[timestampIdx])
		for metric, idx := range metricIndices {
			metricValues[metric] = append(metricValues[metric], row[idx])
		}
	}

	outputRow := []string{switch_name, strings.Join(timestamps, ",")}
	interface_utilization := [][]string{}
	asymmetric_traffic_volume := [][]string{}

	for _, metric := range header {
		if strings.Contains(metric, "Interface Utilization Percentage - "+switch_name+"-") {
			interface_utilization = append(interface_utilization, metricValues[metric])
		} else if strings.Contains(metric, "Asymmetric Traffic Volume - "+switch_name+"-") {
			asymmetric_traffic_volume = append(asymmetric_traffic_volume, metricValues[metric])
		} else if (strings.Contains(metric, switch_name) && !strings.Contains(metric, switch_name+"-")) || contains(infra_metrics, metric) {
			outputRow = append(outputRow, fmt.Sprintf("[%s]", strings.Join(metricValues[metric], ",")))
		}
	}

	flattenedInterfaceUtilization := []string{}
	for _, row := range interface_utilization {
		flattenedInterfaceUtilization = append(flattenedInterfaceUtilization, fmt.Sprintf("[%s]", strings.Join(row, ",")))
	}

	flattenedAsymmetricTrafficVolume := []string{}
	for _, row := range asymmetric_traffic_volume {
		flattenedAsymmetricTrafficVolume = append(flattenedAsymmetricTrafficVolume, fmt.Sprintf("[%s]", strings.Join(row, ",")))
	}

	outputRow = append(outputRow, "["+strings.Join(flattenedInterfaceUtilization, ",")+"]")
	outputRow = append(outputRow, "["+strings.Join(flattenedAsymmetricTrafficVolume, ",")+"]")
	outputRow = append(outputRow, "1")

	outputFile, err := os.OpenFile("./processed_metrics.csv", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("Error opening/creating file:", err)
		return
	}
	defer outputFile.Close()

	fileStat, err := outputFile.Stat()
	if err != nil {
		fmt.Println("Error getting file info:", err)
		return
	}

	writer := csv.NewWriter(outputFile)
	defer writer.Flush()

	if fileStat.Size() == 0 {
		newHeader := []string{"switch", "timestamp"}
		for _, metric := range header {
			if (strings.Contains(metric, switch_name) && !strings.Contains(metric, switch_name+"-")) || contains(infra_metrics, metric) {
				values := strings.Split(metric, "-")
				newHeader = append(newHeader, values[0])
			}
		}
		newHeader = append(newHeader, "Interface Utilization", "Asymmetric Traffic Volume", "label")
		writer.Write(newHeader)
	}

	writer.Write(outputRow)
	fmt.Println("Processed CSV file has been updated successfully.")
}
