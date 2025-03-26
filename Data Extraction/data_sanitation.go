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

// The field value dictates the label of type of attack on the switch
// 0 - Normal , 1 - Dos Attack (SYN Flood, Push Flood, Port Scanning),
// 2 - Flow Table Exhaustion (Controller misconfiguration, controller compromised,
// control channel attack)
// 3 - Elephant Flow
// 4 - Bursty Flow
// 5 - Dos Attack and Flow Table Exhaustion

var switches map[string]string = map[string]string{
	"s2":  "0",
	"s3":  "0",
	"s4":  "1",
	"s5":  "1",
	"s6":  "0",
	"s7":  "1",
	"s8":  "0",
	"s9":  "0",
	"s10": "1",
}

// contains checks if a given item exists in a slice of strings.
func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// processSwitch takes a switch name and a label as arguments, opens the
// "ovs_metrics.csv" file, reads it into records, and processes each record
// by extracting the timestamp, metrics and their corresponding values,
// and then writes the processed records to a new CSV file named
// "processed_metrics.csv".
//
// If the file is empty, it prints an error message and exits.
//
// It also flattens the interface utilization and asymmetric traffic volume
// metrics by joining them with commas and surrounds them with square
// brackets.
//
// The function also adds a header to the new CSV file if it is empty.
//
// The function also appends the new processed records to the CSV file if it
// is not empty.
//
// The function prints a success message if the operation is successful.
func processSwitch(switch_name string, label string) {
	// Read from a raw data CSV file to a CSV file that can be ingested by a ML model
	file, err := os.Open("./ovs_metrics.csv")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	//  Reads all the records in the ovs_metrics CSV file
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Error reading CSV:", err)
		return
	}

	if len(records) < 1 {
		fmt.Println("CSV file is empty")
		return
	}

	// Reads all the headers in the ovs_metrics CSV file
	header := records[0]
	var timestampIdx int // Holds the column index for timestamp field

	// Gets hold of the column indices for the metrics.
	// Through this you know how to access all the values of that metric by looping
	// over the rows (i) and keeping index(j) as constant
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

	timestamps := []string{}                  // Stores a list of timestamps
	metricValues := make(map[string][]string) // Each Metric which is a key stores a list of values

	// This loop extracts the timestamps and values for each metric and stores
	// them as a list in their respective metric key's value.
	for _, row := range records[1:] {
		timestamps = append(timestamps, row[timestampIdx])
		for metric, idx := range metricIndices {
			metricValues[metric] = append(metricValues[metric], row[idx])
		}
	}

	//  This row is what creates the testcase and summarises the ovs_metrics.csv
	// file into a single row in the format that can be ingested by an ML model
	// in the format of list of values.
	outputRow := []string{switch_name, strings.Join(timestamps, ",")}

	// Two new columns are created which stores the values of different interfaces of a
	// switch as a list of list of values into one single column.
	interface_utilization := [][]string{}
	asymmetric_traffic_volume := [][]string{}

	// This loop is what merges the different interfaces metrics of a switch to one
	// metric per switch by joining the lists to a single 2D list.
	for _, metric := range header {
		if strings.Contains(metric, "Interface Utilization Percentage - "+switch_name+"-") {
			interface_utilization = append(interface_utilization, metricValues[metric])
		} else if strings.Contains(metric, "Asymmetric Traffic Volume - "+switch_name+"-") {
			asymmetric_traffic_volume = append(asymmetric_traffic_volume, metricValues[metric])
		} else if (strings.Contains(metric, switch_name) && !strings.Contains(metric, switch_name+"-")) || contains(infra_metrics, metric) {
			outputRow = append(outputRow, fmt.Sprintf("[%s]", strings.Join(metricValues[metric], ",")))
		}
	}

	// This loop flattens the 2D lists into a string of lists separated by commas
	// but two square brackets that enclose this string making a 2D list in the form of string
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

	// This loop appends the label to the end of the row to the last column
	outputRow = append(outputRow, label)

	// Open the processed_metrics.csv file to enter each test case row wise.
	// Appending to the last row for each testcase
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

	// Add the headers when the CSV file is empty.
	// Only first testcase requires setting up. Subsequent testcases are appended
	// to the csv file
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
	fmt.Println("Processed CSV file for switch ", switch_name, " has been updated successfully.")
}

// The main function iterates over the 'switches' map, calling the processSwitch
// function for each switch name and its corresponding label. This results in
// processing and updating the CSV file for each switch.
func main() {
	for switch_name, label := range switches {
		processSwitch(switch_name, label)
	}
}
