package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// Config holds all configuration settings for the application.
type Config struct {
	IPInput     string
	PortInput   string
	Workers     int
	Timeout     time.Duration
	Delay       int
	QueueSize   int
	DryRun      bool
	ResumeFile  string
	OutputFile  string
	LogFile     string
	MinSourcePort int
}

// Load parses command-line flags and returns a populated Config struct.
func Load() (*Config, error) {
	ipInput := flag.String("ip", "", "Required: IPv4/CIDR/host list/CSV file with IP or Host info.")
	portInput := flag.String("port", "", "Required: Individual ports, ranges (8080-8090), or a CSV/TXT file.")
	workers := flag.Int("worker", 1, "Number of concurrent worker threads.")
	timeoutSec := flag.Int("timeout", 2, "Connection timeout in seconds.")
	delay := flag.Int("delay", 0, "Per-probe delay in milliseconds.")
	queue := flag.Int("queue", 0, "Bounded task queue size (default: workers * 1024).")
	dryRun := flag.Bool("dryrun", false, "Perform a dry run without sending any packets.")
	resumeFile := flag.String("resume", "", "Resume scan from a checkpoint.json file.")
	outputFile := flag.String("output", "results.csv", "File to save scan results.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "A robust, concurrent TCP port scanner built in Go.")
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

	queueSize := *queue
	if queueSize == 0 {
		queueSize = *workers * 1024
	}

	cfg := &Config{
		IPInput:     *ipInput,
		PortInput:   *portInput,
		Workers:     *workers,
		Timeout:     time.Duration(*timeoutSec) * time.Second,
		Delay:       *delay,
		QueueSize:   queueSize,
		DryRun:      *dryRun,
		ResumeFile:  *resumeFile,
		OutputFile:  *outputFile,
		LogFile:     "portRunner.log",
		MinSourcePort: 10000,
	}

	return cfg, nil
}
