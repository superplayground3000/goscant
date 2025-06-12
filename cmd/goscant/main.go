// File: cmd/goscant/main.go
package main

import (
    "context"
    "encoding/csv"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "path/filepath"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/google/gopacket/pcap"

    "goscant/internal/checkpoint"
    "goscant/internal/config"
    "goscant/internal/input"
    "goscant/internal/logger"
    "goscant/internal/prober"
    "goscant/internal/scanner"
    "goscant/internal/writer"
)

func main() {
    cfg := parseFlags()
    log := logger.New(cfg.LogPath)

    // Privilege / raw socket capability check (run-time)
    rawCapable := scanner.CheckRawSocketCapability()
    if !rawCapable {
        log.Warn("Raw socket not permitted – falling back to Dial mode")
    }

    // Build context that cancels on SIGINT/SIGTERM
    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()

    // Resolve targets (with ping pre‑filter)
    targets, err := input.ParseTargets(ctx, cfg)
    if err != nil {
        log.Fatal(err)
    }

    // Prepare CSV writer
    w, err := writer.New(cfg.OutputPath)
    if err != nil {
        log.Fatal(err)
    }

    // Build scanner factory
    scanEngine := scanner.NewFactory(cfg, rawCapable)

    // Launch worker pool
    wg := &sync.WaitGroup{}
    taskCh := make(chan input.ProbeTarget, cfg.QueueSize)

    // Producer goroutine – feeds taskCh then closes
    go func() {
        defer close(taskCh)
        for _, t := range targets {
            taskCh <- t
        }
    }()

    // Writer goroutine
    go w.Run()

    for i := 0; i < cfg.NumWorkers; i++ {
        worker := prober.New(i, scanEngine, w, cfg, log)
        wg.Add(1)
        go func() {
            defer wg.Done()
            worker.Run(ctx, taskCh)
        }()
    }

    // Graceful shutdown & checkpoint
    go checkpoint.Handle(ctx, cfg, taskCh, log)

    wg.Wait()
    w.Close()
    log.Info("Scan complete")
}

// parseFlags initialises Config from CLI flags.
func parseFlags() *config.Config {
    cfg := &config.Config{}

    flag.StringVar(&cfg.IPInput, "ip", "", "IPv4/CIDR/host list or CSV file (required)")
    flag.StringVar(&cfg.PortInput, "port", "", "Port list/range or CSV file (required)")
    flag.IntVar(&cfg.NumWorkers, "worker", 1, "Number of concurrent workers")
    flag.DurationVar(&cfg.Timeout, "timeout", 100*time.Millisecond, "Probe timeout")
    flag.DurationVar(&cfg.Delay, "delay", 100*time.Millisecond, "Inter‑probe delay per worker")
    flag.IntVar(&cfg.QueueSize, "queue", 1024, "Task queue size (bounded)")
    flag.BoolVar(&cfg.DryRun, "dryrun", false, "Dry‑run mode – no packets sent")
    flag.StringVar(&cfg.ResumeFile, "resume", "", "Checkpoint file to resume from")
    flag.StringVar(&cfg.OutputPath, "output", "result.csv", "CSV output path")

    flag.Parse()

    if cfg.IPInput == "" && cfg.ResumeFile == "" {
        fmt.Println("--ip or --resume is required")
        flag.Usage()
        os.Exit(1)
    }
    if cfg.PortInput == "" && cfg.ResumeFile == "" {
        fmt.Println("--port or --resume is required")
        flag.Usage()
        os.Exit(1)
    }

    cfg.LogPath = filepath.Join(".", "portRunner-"+time.Now().Format("2006-01-02")+".log")

    return cfg
}