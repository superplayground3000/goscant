package scanner

import (
	"context"
	"fmt"
	"log/slog"
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
	Logger  *slog.Logger
}

// NewConnectScanner creates a new instance of a ConnectScanner.
func NewConnectScanner(timeout time.Duration, logger *slog.Logger) *ConnectScanner {
	return &ConnectScanner{Timeout: timeout, Logger: logger}
}

// Scan performs a TCP connect scan on a single target.
func (s *ConnectScanner) Scan(target models.ScanTarget) models.ScanResult {
	s.Logger.Debug("Scanning target", "scanner", "ConnectScanner", "ip", target.IP, "port", target.Port)
	startTime := time.Now()
	address := fmt.Sprintf("%s:%d", target.IP, target.Port)

	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	s.Logger.Debug("Dialing target", "scanner", "ConnectScanner", "address", address, "timeout", s.Timeout)
	latency := time.Since(startTime)

	result := models.ScanResult{
		Timestamp: startTime,
		Target:    target,
		Latency:   latency,
	}

	if err != nil {
		result.Error = err
		s.Logger.Debug("Error scanning target", "scanner", "ConnectScanner", "address", address, "error", err)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.Status = models.StatusFiltered
			s.Logger.Debug("Target filtered (timeout)", "scanner", "ConnectScanner", "address", address)
		} else {
			result.Status = models.StatusClosed
			s.Logger.Debug("Target closed (error)", "scanner", "ConnectScanner", "address", address, "error", err)
		}
		return result
	}

	result.Status = models.StatusOpen
	s.Logger.Debug("Target open", "scanner", "ConnectScanner", "address", address)
	conn.Close() // Gracefully close the connection (four-way handshake).
	return result
}

// Worker is a goroutine that pulls targets from a queue, scans them, and sends results.
func Worker(ctx context.Context, wg *sync.WaitGroup, id int, parentLogger *slog.Logger, s Scanner, tasks <-chan models.ScanTarget, results chan<- models.ScanResult, delay time.Duration, dryRun bool) {
	defer wg.Done()
	// Create a child logger for this specific worker
	workerLogger := parentLogger.With(slog.Int("worker_id", id))
	workerLogger.Debug("Worker started.")

	for {
		select {
		case target, ok := <-tasks:
			if !ok {
				workerLogger.Debug("Task channel closed. Shutting down.")
				return
			}

			var result models.ScanResult
			if dryRun {
				workerLogger.Info("Dry run for target", "ip", target.IP, "port", target.Port)
				result = models.ScanResult{
					Timestamp: time.Now(),
					Target:    target,
					Status:    models.StatusDryRun,
				}
			} else {
				workerLogger.Debug("Scanning target", "ip", target.IP, "port", target.Port)
				result = s.Scan(target)
				workerLogger.Debug("Scan result",
					"ip", target.IP, "port", target.Port, "status", result.Status, "latency_ms", result.Latency.Seconds()*1000)
			}

			select {
			case results <- result:
			case <-ctx.Done():
				workerLogger.Warn("Context canceled. Dropping result for target.", "ip", target.IP, "port", target.Port)
				return
			}
			if delay > 0 {
				time.Sleep(delay)
			}
		case <-ctx.Done():
			workerLogger.Info("Shutdown signal received. Exiting.")
			return
		}
	}
}
