package config

import (
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

func setCommandFlags(args []string) {
	// Reset the flag set to avoid interference between tests
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = append([]string{"cmd"}, args...)
}

func TestLoad(t *testing.T) {
	originalArgs := os.Args
	defer func() {
		os.Args = originalArgs
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError) // Reset to default
	}()

	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
		expectedCfg *Config // Only check specific fields that are relevant to the test
	}{
		{
			name:        "Missing IP and Port",
			args:        []string{},
			expectError: true,
			errorMsg:    "missing required arguments: --ip and --port",
		},
		{
			name:        "Missing Port",
			args:        []string{"--ip=127.0.0.1"},
			expectError: true,
			errorMsg:    "missing required arguments: --ip and --port",
		},
		{
			name:        "Missing IP",
			args:        []string{"--port=80"},
			expectError: true,
			errorMsg:    "missing required arguments: --ip and --port",
		},
		{
			name:        "Invalid Worker Count (zero)",
			args:        []string{"--ip=127.0.0.1", "--port=80", "--worker=0"},
			expectError: true,
			errorMsg:    "--worker must be a positive integer",
		},
		{
			name:        "Invalid Worker Count (negative)",
			args:        []string{"--ip=127.0.0.1", "--port=80", "--worker=-1"},
			expectError: true,
			errorMsg:    "--worker must be a positive integer",
		},
		{
			name:        "Invalid Scan Type",
			args:        []string{"--ip=127.0.0.1", "--port=80", "--scantype=invalid"},
			expectError: true,
			errorMsg:    "--scantype must be either 'connect' or 'syn'",
		},
		{
			name: "Default Values",
			args: []string{"--ip=127.0.0.1", "--port=80"},
			expectedCfg: &Config{
				IPInput:       "127.0.0.1",
				PortInput:     "80",
				Workers:       1,
				Timeout:       100 * time.Millisecond,
				Delay:         100 * time.Millisecond,
				QueueSize:     1 * 1024, // Default workers * 1024
				DryRun:        false,
				ResumeFile:    "",
				OutputFile:    "results.csv",
				ScanType:      "connect",
				Ping:          true,
				LogFile:       "portRunner.log",
				MinSourcePort: 10000,
				LogLevel:      "INFO",
			},
		},
		{
			name: "Custom Values",
			args: []string{
				"--ip=10.0.0.0/24",
				"--port=22,80,443-445",
				"--worker=10",
				"--timeout=500",
				"--delay=50",
				"--queue=2000",
				"--dryrun=true",
				"--resume=backup.json",
				"--output=scan_out.csv",
				"--scantype=syn",
				"--ping=false",
				"--loglevel=DEBUG",
			},
			expectedCfg: &Config{
				IPInput:       "10.0.0.0/24",
				PortInput:     "22,80,443-445",
				Workers:       10,
				Timeout:       500 * time.Millisecond,
				Delay:         50 * time.Millisecond,
				QueueSize:     2000,
				DryRun:        true,
				ResumeFile:    "backup.json",
				OutputFile:    "scan_out.csv",
				ScanType:      "syn",
				Ping:          false,
				LogFile:       "portRunner.log", // This is hardcoded in Load()
				MinSourcePort: 10000,            // This is hardcoded in Load()
				LogLevel:      "DEBUG",
			},
		},
		{
			name: "QueueSize calculated from workers",
			args: []string{"--ip=127.0.0.1", "--port=80", "--worker=5"}, // queue not specified
			expectedCfg: &Config{
				IPInput:       "127.0.0.1",
				PortInput:     "80",
				Workers:       5,
				Timeout:       100 * time.Millisecond, // Default
				Delay:         100 * time.Millisecond, // Default
				QueueSize:     5 * 1024,               // Calculated: 5 * 1024
				DryRun:        false,                  // Default
				ResumeFile:    "",                     // Default
				OutputFile:    "results.csv",          // Default
				ScanType:      "connect",              // Default
				Ping:          true,                   // Default
				LogFile:       "portRunner.log",       // Hardcoded
				MinSourcePort: 10000,                  // Hardcoded
				LogLevel:      "INFO",                 // Default
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setCommandFlags(tt.args)
			cfg, err := Load()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', but got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
				if cfg == nil {
					t.Fatalf("Expected config to be non-nil")
				}
				if tt.expectedCfg == nil { // Should not happen if no error is expected
					t.Fatalf("expectedCfg is nil for a non-error test case: %s", tt.name)
				}

				// Direct comparisons assuming tt.expectedCfg is fully populated
				if cfg.IPInput != tt.expectedCfg.IPInput {
					t.Errorf("IPInput: got %q, want %q", cfg.IPInput, tt.expectedCfg.IPInput)
				}
				if cfg.PortInput != tt.expectedCfg.PortInput {
					t.Errorf("PortInput: got %q, want %q", cfg.PortInput, tt.expectedCfg.PortInput)
				}
				if cfg.Workers != tt.expectedCfg.Workers {
					t.Errorf("Workers: got %d, want %d", cfg.Workers, tt.expectedCfg.Workers)
				}
				if cfg.Timeout != tt.expectedCfg.Timeout {
					t.Errorf("Timeout: got %v, want %v", cfg.Timeout, tt.expectedCfg.Timeout)
				}
				if cfg.Delay != tt.expectedCfg.Delay {
					t.Errorf("Delay: got %v, want %v", cfg.Delay, tt.expectedCfg.Delay)
				}
				if cfg.QueueSize != tt.expectedCfg.QueueSize {
					t.Errorf("QueueSize: got %d, want %d", cfg.QueueSize, tt.expectedCfg.QueueSize)
				}
				if cfg.DryRun != tt.expectedCfg.DryRun {
					t.Errorf("DryRun: got %t, want %t", cfg.DryRun, tt.expectedCfg.DryRun)
				}
				if cfg.ResumeFile != tt.expectedCfg.ResumeFile {
					t.Errorf("ResumeFile: got %q, want %q", cfg.ResumeFile, tt.expectedCfg.ResumeFile)
				}
				if cfg.OutputFile != tt.expectedCfg.OutputFile {
					t.Errorf("OutputFile: got %q, want %q", cfg.OutputFile, tt.expectedCfg.OutputFile)
				}
				if cfg.ScanType != tt.expectedCfg.ScanType {
					t.Errorf("ScanType: got %q, want %q", cfg.ScanType, tt.expectedCfg.ScanType)
				}
				if cfg.Ping != tt.expectedCfg.Ping {
					t.Errorf("Ping: got %t, want %t", cfg.Ping, tt.expectedCfg.Ping)
				}
				if cfg.LogLevel != tt.expectedCfg.LogLevel {
					t.Errorf("LogLevel: got %q, want %q", cfg.LogLevel, tt.expectedCfg.LogLevel)
				}
				if cfg.LogFile != tt.expectedCfg.LogFile { // Hardcoded
					t.Errorf("LogFile: got %q, want %q", cfg.LogFile, tt.expectedCfg.LogFile)
				}
				if cfg.MinSourcePort != tt.expectedCfg.MinSourcePort { // Hardcoded
					t.Errorf("MinSourcePort: got %d, want %d", cfg.MinSourcePort, tt.expectedCfg.MinSourcePort)
				}
			}
		})
	}
}
