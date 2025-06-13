package parser

import (
	// ... (imports remain the same)
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"port-scanner/internal/models"
	"strconv"
	"strings"
)

// CreateTargets combines IPs and ports into a final list of ScanTarget.
func CreateTargets(ips []string, ports []int) []models.ScanTarget {
	var targets []models.ScanTarget
	for _, ip := range ips {
		for _, port := range ports {
			targets = append(targets, models.ScanTarget{IP: ip, Port: port})
		}
	}
	return targets
}

// ParseIPs parses IP input from CIDR, file, or comma-separated list.
func ParseIPs(input string) ([]string, error) {
	// ... (implementation is the same as the old parseIPs)
	if _, _, err := net.ParseCIDR(input); err == nil {
		return parseCIDR(input)
	}
	if fileExists(input) {
		return parseIPsFromFile(input)
	}
	// De-duplicate hosts from comma-separated list
	hosts := strings.Split(input, ",")
	seen := make(map[string]bool)
	uniqueHosts := []string{}
	for _, host := range hosts {
		trimmedHost := strings.TrimSpace(host)
		if !seen[trimmedHost] {
			seen[trimmedHost] = true
			uniqueHosts = append(uniqueHosts, trimmedHost)
		}
	}
	return uniqueHosts, nil
}

// ParsePorts parses port input from ranges, file, or comma-separated list.
func ParsePorts(input string) ([]int, error) {
	// ... (implementation is the same as the old parsePorts)
	if fileExists(input) {
		return parsePortsFromFile(input)
	}
	return parsePortRange(input)
}

// ParseTargets orchestrates the parsing of both IP and port inputs into a list of ScanTarget.
func ParseTargets(ipInput, portInput string) ([]models.ScanTarget, error) {
	ips, err := parseIPs(ipInput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IP input: %w", err)
	}
	ports, err := parsePorts(portInput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Port input: %w", err)
	}

	var targets []models.ScanTarget
	for _, ip := range ips {
		for _, port := range ports {
			targets = append(targets, models.ScanTarget{IP: ip, Port: port})
		}
	}
	return targets, nil
}

// parseIPs detects the input type (CIDR, file, list) and parses accordingly.
func parseIPs(input string) ([]string, error) {
	if _, _, err := net.ParseCIDR(input); err == nil {
		return parseCIDR(input)
	}
	if fileExists(input) {
		return parseIPsFromFile(input)
	}
	return strings.Split(input, ","), nil
}

// parsePorts detects the input type (range, file, list) and parses accordingly.
func parsePorts(input string) ([]int, error) {
	if fileExists(input) {
		return parsePortsFromFile(input)
	}
	return parsePortRange(input)
}

// parseCIDR expands a CIDR block into a list of individual IP addresses.
func parseCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); func(ip net.IP) {
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
	}(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) <= 2 { // Handle /32 and /31
		return ips, nil
	}
	return ips[1 : len(ips)-1], nil // Exclude network and broadcast
}

// parsePortRange parses comma-separated ports and ranges (e.g., "80,443,8000-8080").
func parsePortRange(rangeStr string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(rangeStr, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			subParts := strings.Split(part, "-")
			if len(subParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			start, err1 := strconv.Atoi(subParts[0])
			end, err2 := strconv.Atoi(subParts[1])
			if err1 != nil || err2 != nil || start > end {
				return nil, fmt.Errorf("invalid port range values: %s", part)
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

// parseIPsFromFile reads IPs from a CSV or a plain text file.
func parseIPsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	if strings.HasSuffix(strings.ToLower(filePath), ".csv") {
		reader := csv.NewReader(file)
		records, err := reader.ReadAll()
		if err != nil {
			return nil, err
		}
		for i, record := range records {
			if i == 0 {
				continue
			} // Skip header
			if len(record) > 0 {
				ips = append(ips, record[0])
			}
		}
	} else {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ips = append(ips, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	return ips, nil
}

// parsePortsFromFile reads ports from a CSV or a plain text file.
func parsePortsFromFile(filePath string) ([]int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ports []int
	if strings.HasSuffix(strings.ToLower(filePath), ".csv") {
		r := csv.NewReader(file)
		for {
			record, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if len(record) > 1 {
				portStr := strings.Split(record[1], "/")[0]
				if port, err := strconv.Atoi(portStr); err == nil {
					ports = append(ports, port)
				}
			}
		}
	} else {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if port, err := strconv.Atoi(scanner.Text()); err == nil {
				ports = append(ports, port)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	return ports, nil
}

// fileExists checks if a file exists.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
