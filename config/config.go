package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// Config holds all configuration settings for the application.
type Config struct {
	IPInput       string
	PortInput     string
	Workers       int
	Timeout       time.Duration
	Delay         time.Duration // Changed to time.Duration
	QueueSize     int
	DryRun        bool
	ResumeFile    string
	OutputFile    string
	LogFile       string
	ScanType      string // new
	Ping          bool   // new: to enable/disable pre-scan ping
	MinSourcePort int
	LogLevel      string // new: for slog level
}

// Load parses command-line flags and returns a populated Config struct.
func Load() (*Config, error) {
	ipInput := flag.String("ip", "", "Required: IPv4/CIDR/host list/CSV file with IP or Host info.")
	portInput := flag.String("port", "", "Required: Individual ports, ranges (8080-8090), or a CSV/TXT file.")

	workers := flag.Int("worker", 1, "Number of concurrent worker threads.")
	// Updated defaults to 100ms
	timeoutMs := flag.Int("timeout", 100, "Connection and ping timeout in milliseconds.")
	delayMs := flag.Int("delay", 100, "Per-probe delay in milliseconds.")
	queue := flag.Int("queue", 0, "Bounded task queue size (default: workers * 1024).")
	dryRun := flag.Bool("dryrun", false, "Perform a dry run without sending any packets.")
	resumeFile := flag.String("resume", "", "Resume scan from a checkpoint.json file.")
	outputFile := flag.String("output", "results.csv", "File to save scan results.")
	// New flags
	scanType := flag.String("scantype", "connect", "Scan type: 'connect' for TCP Connect, 'syn' for SYN Stealth scan.")
	ping := flag.Bool("ping", true, "Enable pre-scan ICMP check to filter for reachable hosts.")
	logLevel := flag.String("loglevel", "INFO", "Set the logging level (DEBUG, INFO, WARN, ERROR).")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "A robust, concurrent TCP port scanner with SYN and Connect modes.")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *ipInput == "" || *portInput == "" {
		flag.Usage()
		return nil, fmt.Errorf("missing required arguments: --ip and --port")
	}
	if *workers <= 0 {
		return nil, fmt.Errorf("--worker must be a positive integer")
	}
	if *scanType != "connect" && *scanType != "syn" {
		return nil, fmt.Errorf("--scantype must be either 'connect' or 'syn'")
	}

	queueSize := *queue
	if queueSize == 0 {
		queueSize = *workers * 1024
	}

	cfg := &Config{
		IPInput:       *ipInput,
		PortInput:     *portInput,
		Workers:       *workers,
		Timeout:       time.Duration(*timeoutMs) * time.Millisecond,
		Delay:         time.Duration(*delayMs) * time.Millisecond,
		QueueSize:     queueSize,
		DryRun:        *dryRun,
		ResumeFile:    *resumeFile,
		OutputFile:    *outputFile,
		ScanType:      *scanType,
		Ping:          *ping,
		LogFile:       "portRunner.log",
		MinSourcePort: 10000,
		LogLevel:      *logLevel,
	}

	return cfg, nil
}
