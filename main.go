package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"port-scanner/config"
	"port-scanner/internal/logger"
	"port-scanner/internal/models"
	"port-scanner/internal/parser"
	"port-scanner/internal/pinger"
	"port-scanner/internal/reporter"
	"port-scanner/internal/scanner"
	"port-scanner/pkg/checkpoint"
	"port-scanner/pkg/utils"
	"sync"
	"syscall"
	"time"
)

// main is the entry point for the port scanner application.
func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Assuming cfg.LogLevel is a string like "INFO", "DEBUG", etc.
	// This field would need to be added to your config.Config struct and loaded.
	// Example: cfg.LogLevel = "INFO"
	appLogger, closeLogFile := logger.New(cfg.LogFile, cfg.LogLevel)
	defer closeLogFile()

	// Set the global logger
	slog.SetDefault(appLogger)

	appLogger.Info("Configuration loaded.", "ScanType", cfg.ScanType, "Workers", cfg.Workers, "Ping", cfg.Ping)

	// Strict privilege check for SYN scan
	if cfg.ScanType == "syn" {
		utils.CheckPrivileges(appLogger) // utils.CheckPrivileges needs to accept *slog.Logger
	}

	var targets []models.ScanTarget

	// 4. Handle Resume
	if cfg.ResumeFile != "" {
		appLogger.Info("Attempting to resume scan", "file", cfg.ResumeFile)
		resumedTargets, err := checkpoint.LoadState(cfg.ResumeFile)
		if err != nil {
			appLogger.Warn("Failed to load checkpoint file, starting a new scan.", "file", cfg.ResumeFile, "error", err)
			// Optionally, you might want to os.Remove(cfg.ResumeFile) here if it's corrupted
			// or handle this error more strictly depending on requirements.
		} else {
			appLogger.Info("Successfully loaded targets from checkpoint.", "count", len(resumedTargets))

			targets = resumedTargets
			appLogger.Info("Resuming scan with targets.", "count", len(targets))
		}
	} else {
		appLogger.Info("No resume file provided. Starting a new scan.")
		utils.CheckFileDescriptorLimit(appLogger, cfg) // utils.CheckFileDescriptorLimit needs to accept *slog.Logger
		// 1. Parse IPs and Ports separately
		ips, err := parser.ParseIPs(cfg.IPInput)
		if err != nil {
			appLogger.Error("Error parsing IPs", "error", err)
			os.Exit(1)
		}
		appLogger.Debug("IPs parsed successfully.", "count", len(ips))

		ports, err := parser.ParsePorts(cfg.PortInput)
		if err != nil {
			appLogger.Error("Error parsing ports", "error", err)
			os.Exit(1)
		}
		appLogger.Debug("Ports parsed successfully.", "count", len(ports))

		// 2. (Optional) Filter for reachable hosts
		if cfg.Ping && !cfg.DryRun {
			appLogger.Debug("Pinging hosts to filter reachable ones.", "initial_ip_count", len(ips))
			ips = pinger.FilterReachableHosts(ips, cfg.Timeout, cfg.Workers, appLogger) // pinger.FilterReachableHosts needs to accept *slog.Logger
			appLogger.Debug("Finished pinging hosts.", "reachable_ip_count", len(ips))
		}

		// 3. Create final target list
		targets = parser.CreateTargets(ips, ports)
		appLogger.Debug("Initial target list created.", "count", len(targets))
	}

	if len(targets) == 0 {
		appLogger.Error("No targets to scan. Check host reachability and inputs.")
		os.Exit(1)
	}
	appLogger.Info("Total targets to scan.", "count", len(targets))

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	taskQueue := make(chan models.ScanTarget, cfg.QueueSize)
	resultsChan := make(chan models.ScanResult, cfg.QueueSize)
	var wg, reporterWg, interruptWg sync.WaitGroup

	reporterWg.Add(1)
	appLogger.Debug("Starting reporter goroutine.")
	go reporter.New(ctx, &reporterWg, resultsChan, cfg.OutputFile, appLogger).Run()

	// 5. Scanner Factory: Choose scan engine based on config
	for i := 1; i <= cfg.Workers; i++ {
		var scanEngine scanner.Scanner
		switch cfg.ScanType {
		case "syn":
			fallthrough
		case "connect":
			fallthrough
		default:
			scanEngine = scanner.NewConnectScanner(cfg.Timeout, appLogger)
		}
		wg.Add(1)
		appLogger.Debug("Starting scanner worker.", "worker_id", i, "scan_type", cfg.ScanType)
		go scanner.Worker(ctx, &wg, i, appLogger, scanEngine, taskQueue, resultsChan, cfg.Delay, cfg.DryRun)
	}

	interruptWg.Add(1)
	go func() {
		appLogger.Debug("Interrupt handler goroutine started.")
		defer interruptWg.Done()
		<-sigChan // Wait for interrupt signal
		appLogger.Info("Shutdown signal received. Saving state...")
		cancel() // Signal all goroutines to stop

		remaining := make([]models.ScanTarget, 0, len(taskQueue))
		for target := range taskQueue {
			remaining = append(remaining, target)
		}
		if len(remaining) > 0 && cfg.ResumeFile != "" { // Only save if resume is configured
			currentDir, err := os.Getwd()
			if err != nil {
				appLogger.Error("Failed to get current directory", "error", err)
			}
			checkpointFile := filepath.Join(currentDir, cfg.ResumeFile)
			if err := checkpoint.SaveState(remaining, checkpointFile); err != nil {
				appLogger.Error("Failed to save checkpoint", "error", err)
			} else {
				appLogger.Info("Checkpoint saved", "remaining_targets", len(remaining))
			}
		} else {
			appLogger.Debug("No remaining targets in taskQueue to save for checkpoint or resume file not configured.")
		}
	}()

	appLogger.Info("Starting scan...")
	startTime := time.Now()

	go func() {
		defer close(taskQueue)
		appLogger.Debug("Starting to feed targets into the task queue.")
		for _, target := range targets {
			select {
			case taskQueue <- target:
			case <-ctx.Done():
				appLogger.Debug("Context canceled while feeding targets. Stopping.")
				return
			}
		}
	}()

	wg.Wait()
	interruptWg.Wait()
	appLogger.Info("All scanner workers finished.")
	close(resultsChan)
	reporterWg.Wait()
	appLogger.Info("Reporter finished. Scan complete.", "duration", time.Since(startTime))
}
