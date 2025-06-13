package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
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

	log, closeLogFile := logger.New(cfg.LogFile)
	defer closeLogFile()
	log.Printf("[main] - Configuration loaded. ScanType: %s, Workers: %d, Ping: %t", cfg.ScanType, cfg.Workers, cfg.Ping)

	// Strict privilege check for SYN scan
	if cfg.ScanType == "syn" {
		utils.CheckPrivileges(log)
	}

	utils.CheckFileDescriptorLimit(log, cfg)
	// 1. Parse IPs and Ports separately
	ips, err := parser.ParseIPs(cfg.IPInput)
	if err != nil {
		log.Fatalf("[main] - Error parsing IPs: %v", err)
	}
	ports, err := parser.ParsePorts(cfg.PortInput)
	if err != nil {
		log.Fatalf("[main] - Error parsing ports: %v", err)
	}

	// 2. (Optional) Filter for reachable hosts
	if cfg.Ping && !cfg.DryRun {
		ips = pinger.FilterReachableHosts(ips, cfg.Timeout, cfg.Workers, log)
	}

	// 3. Create final target list
	targets := parser.CreateTargets(ips, ports)

	// 4. Handle Resume
	if cfg.ResumeFile != "" {
		log.Printf("[main] - Attempting to resume scan from: %s", cfg.ResumeFile)
		resumedTargets, err := checkpoint.LoadState(cfg.ResumeFile)
		if err != nil {
			log.Printf("[main] - WARNING: Failed to load checkpoint file %s: %v. Starting a new scan.", cfg.ResumeFile, err)
			// Optionally, you might want to os.Remove(cfg.ResumeFile) here if it's corrupted
			// or handle this error more strictly depending on requirements.
		} else {
			log.Printf("[main] - Successfully loaded %d targets from checkpoint.", len(resumedTargets))
			// Create a map of resumed targets for efficient lookup
			// This assumes ScanTarget has IP and Port fields that can uniquely identify it.
			resumedMap := make(map[string]bool)
			for _, t := range resumedTargets {
				resumedMap[fmt.Sprintf("%s:%d", t.IP, t.Port)] = true
			}

			// Filter the original targets list to keep only those present in the resumed set
			var newTargets []models.ScanTarget
			for _, t := range targets {
				if resumedMap[fmt.Sprintf("%s:%d", t.IP, t.Port)] {
					newTargets = append(newTargets, t)
				}
			}
			targets = newTargets
			log.Printf("[main] - Resuming scan with %d targets.", len(targets))

			if err := os.Remove(cfg.ResumeFile); err != nil {
				log.Printf("[main] - WARNING: Failed to remove checkpoint file %s after loading: %v", cfg.ResumeFile, err)
			} else {
				log.Printf("[main] - Removed checkpoint file %s after successful resume.", cfg.ResumeFile)
			}
		}
	}

	if len(targets) == 0 {
		log.Fatalf("[main] - No targets to scan. Check host reachability and inputs.")
	}
	log.Printf("[main] - Total targets to scan: %d", len(targets))

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	taskQueue := make(chan models.ScanTarget, cfg.QueueSize)
	resultsChan := make(chan models.ScanResult, cfg.QueueSize)
	var wg, reporterWg sync.WaitGroup

	reporterWg.Add(1)
	go reporter.New(ctx, &reporterWg, resultsChan, cfg.OutputFile, log).Run()

	// 5. Scanner Factory: Choose scan engine based on config
	for i := 1; i <= cfg.Workers; i++ {
		var scanEngine scanner.Scanner
		switch cfg.ScanType {
		case "syn":
			// Each worker gets a slightly different source port to avoid collisions
			scanEngine = scanner.NewSynScanner(cfg.Timeout, log, cfg.MinSourcePort+i)
		case "connect":
			fallthrough
		default:
			scanEngine = scanner.NewConnectScanner(cfg.Timeout, log)
		}
		wg.Add(1)
		go scanner.Worker(ctx, &wg, i, scanEngine, taskQueue, resultsChan, cfg.Delay, cfg.DryRun)
	}

	go func() {
		<-sigChan // Wait for interrupt signal
		log.Printf("[main] - Shutdown signal received. Saving state...")
		cancel() // Signal all goroutines to stop

		close(taskQueue) // Prevent new tasks
		remaining := make([]models.ScanTarget, 0, len(taskQueue))
		for target := range taskQueue {
			remaining = append(remaining, target)
		}
		if len(remaining) > 0 {
			if err := checkpoint.SaveState(remaining, "checkpoint.json"); err != nil {
				log.Printf("[main] - ERROR: Failed to save checkpoint: %v", err)
			} else {
				log.Printf("[main] - Checkpoint saved with %d remaining targets.", len(remaining))
			}
		}
	}()

	log.Printf("[main] - Starting scan...")
	startTime := time.Now()

	go func() {
		defer close(taskQueue)
		for _, target := range targets {
			select {
			case taskQueue <- target:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	log.Printf("[main] - All scanner workers finished.")
	close(resultsChan)
	reporterWg.Wait()
	log.Printf("[main] - Reporter finished. Scan complete in %v.", time.Since(startTime))
}
