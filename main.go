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
	log.Printf("[main] - Configuration loaded. Workers: %d, DryRun: %t", cfg.Workers, cfg.DryRun)

	utils.CheckPrivileges(log)
	utils.CheckFileDescriptorLimit(log, cfg)

	targets, err := parser.ParseTargets(cfg.IPInput, cfg.PortInput)
	if err != nil {
		log.Fatalf("[main] - Error parsing targets: %v", err)
	}

	if cfg.ResumeFile != "" {
		if resumedTargets, err := checkpoint.LoadState(cfg.ResumeFile); err != nil {
			log.Printf("[main] - WARNING: Could not resume from %s: %v", cfg.ResumeFile, err)
		} else {
			targets = resumedTargets
			log.Printf("[main] - Resumed from checkpoint. %d targets loaded.", len(targets))
		}
	}

	if len(targets) == 0 {
		log.Fatalf("[main] - No targets to scan.")
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

	scanEngine := scanner.NewConnectScanner(cfg.Timeout, log)
	for i := 1; i <= cfg.Workers; i++ {
		wg.Add(1)
		go scanner.Worker(ctx, &wg, i, scanEngine, taskQueue, resultsChan, time.Duration(cfg.Delay)*time.Millisecond, cfg.DryRun)
	}

	go func() {
		<-sigChan // Wait for interrupt signal
		log.Printf("[main] - Shutdown signal received. Saving state...")
		cancel()  // Signal all goroutines to stop

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
