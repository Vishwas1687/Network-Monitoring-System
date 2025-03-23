package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

var infra_metrics []string = []string {"Resource Utilization", "CPU Utilization", "Bridge Controller Status", "Memory Per Bridge", "Rate of control Channel Flap", "Database Space Utilization"}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func main() {
	// Open the CSV file
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

	// Extract header
	header := records[0]
	var timestampIdx int
	metricIndices := make(map[string]int)
	
	for i, h := range header {
		if h == "timestamp" {
			timestampIdx = i
		} else if strings.Contains(h, "s3") {
			metricIndices[h] = i
		} else if contains(infra_metrics, h){
			metricIndices[h] = i
		}
	}

	// Maps to collect aggregated data
	timestamps := []string{}
	metricValues := make(map[string][]string)

	// Process each row
	for _, row := range records[1:] {
		timestamps = append(timestamps, row[timestampIdx])
		for metric, idx := range metricIndices {
			metricValues[metric] = append(metricValues[metric], row[idx])
		}
	}

	// Prepare the final row
	outputRow := []string{strings.Join(timestamps, ",")}
	for _, metric := range header {
		if strings.Contains(metric, "s3") {
			outputRow = append(outputRow, fmt.Sprintf("[%s]", strings.Join(metricValues[metric], ",")))
		} else if contains(infra_metrics, metric){
			outputRow = append(outputRow, fmt.Sprintf("[%s]", strings.Join(metricValues[metric], ",")))
		}
	}
	outputRow = append(outputRow, "1") // Label field

	// Write to a new CSV file
	outputFile, err := os.Create("./processed_metrics.csv")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer outputFile.Close()

	writer := csv.NewWriter(outputFile)
	defer writer.Flush()

	// Write header
	newHeader := []string{"timestamp"}
	for _, metric := range header {
		if strings.Contains(metric, "s3") {
			newHeader = append(newHeader, metric)
		} else if contains(infra_metrics, metric) {
			newHeader = append(newHeader, metric)
		}
	}
	newHeader = append(newHeader, "label")
	writer.Write(newHeader)

	// Write processed row
	writer.Write(outputRow)

	fmt.Println("Processed CSV file has been created successfully.")
}
