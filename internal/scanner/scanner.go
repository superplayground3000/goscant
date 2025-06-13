package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"port-scanner/internal/models"
	"sync"
	"time"
)

// Scanner defines the interface for a port scanner engine.
type Scanner interface {
	Scan(target models.ScanTarget) models.ScanResult
}

// ConnectScanner implements a full TCP three-way handshake scan.
type ConnectScanner struct {
	Timeout time.Duration
	Logger  *log.Logger
}

// NewConnectScanner creates a new instance of a ConnectScanner.
func NewConnectScanner(timeout time.Duration, logger *log.Logger) *ConnectScanner {
	return &ConnectScanner{Timeout: timeout, Logger: logger}
}

// Scan performs a TCP connect scan on a single target.
func (s *ConnectScanner) Scan(target models.ScanTarget) models.ScanResult {
	startTime := time.Now()
	address := fmt.Sprintf("%s:%d", target.IP, target.Port)

	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	latency := time.Since(startTime)

	result := models.ScanResult{
		Timestamp: startTime,
		Target:    target,
		Latency:   latency,
	}

	if err != nil {
		result.Error = err
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.Status = models.StatusFiltered
		} else {
			result.Status = models.StatusClosed
		}
		return result
	}

	result.Status = models.StatusOpen
	conn.Close() // Gracefully close the connection (four-way handshake).
	return result
}

// Worker is a goroutine that pulls targets from a queue, scans them, and sends results.
func Worker(ctx context.Context, wg *sync.WaitGroup, id int, s Scanner, tasks <-chan models.ScanTarget, results chan<- models.ScanResult, delay time.Duration, dryRun bool) {
	defer wg.Done()
	threadLogger := log.New(log.Writer(), fmt.Sprintf("[Thread %d] ", id), log.Flags())
	threadLogger.Printf("- Worker started.")

	for {
		select {
		case target, ok := <-tasks:
			if !ok {
				threadLogger.Printf("- Task channel closed. Shutting down.")
				return
			}

			var result models.ScanResult
			if dryRun {
				threadLogger.Printf("- DRYRUN: %s:%d", target.IP, target.Port)
				result = models.ScanResult{
					Timestamp: time.Now(),
					Target:    target,
					Status:    models.StatusDryRun,
				}
			} else {
				threadLogger.Printf("- Scanning %s:%d...", target.IP, target.Port)
				result = s.Scan(target)
				threadLogger.Printf("- Result for %s:%d is %s (%.2fms)",
					target.IP, target.Port, result.Status, result.Latency.Seconds()*1000)
			}

			select {
			case results <- result:
			case <-ctx.Done():
				threadLogger.Printf("- Context canceled. Dropping result for %s:%d.", target.IP, target.Port)
				return
			}
			if delay > 0 { time.Sleep(delay) }
		case <-ctx.Done():
			threadLogger.Printf("- Shutdown signal received. Exiting.")
			return
		}
	}
}
