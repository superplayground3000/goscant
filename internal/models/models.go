package models

import (
	"fmt"
	"time"
)

// ScanTarget represents a single IP:Port combination to be scanned.
type ScanTarget struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// ScanStatus represents the result of a port scan.
type ScanStatus string

const (
	StatusOpen     ScanStatus = "OPEN"
	StatusClosed   ScanStatus = "CLOSED"
	StatusFiltered ScanStatus = "FILTERED"
	StatusError    ScanStatus = "ERROR"
	StatusDryRun   ScanStatus = "DRYRUN"
)

// ScanResult holds the outcome of a single port scan attempt.
type ScanResult struct {
	Timestamp time.Time
	Target    ScanTarget
	Status    ScanStatus
	Latency   time.Duration
	Error     error
}

// ToCSVRow converts a ScanResult into a slice of strings for CSV writing.
func (r *ScanResult) ToCSVRow() []string {
	status := string(r.Status)
	if r.Status == StatusError && r.Error != nil {
		status = fmt.Sprintf("ERROR: %v", r.Error)
	}
	return []string{
		r.Timestamp.Format(time.RFC3339),
		r.Target.IP,
		fmt.Sprintf("%d", r.Target.Port),
		status,
		fmt.Sprintf("%.2f", r.Latency.Seconds()*1000), // Latency in ms
	}
}

// CSVHeader returns the header row for the results CSV file.
func CSVHeader() []string {
	return []string{"timestamp", "dst_ip", "dst_port", "status", "latency_ms"}
}
