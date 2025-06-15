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
	startTime := time.Now()
	address := fmt.Sprintf("%s:%d", target.IP, target.Port)

	s.Logger.Debug("Attempting to dial target",
		"scanner", "ConnectScanner",
		"target_ip", target.IP,
		"target_port", target.Port,
		"timeout", s.Timeout,
	)

	dialer := net.Dialer{
		Timeout: s.Timeout,
		// Let the OS choose the source IP and an unused source port.
		// Port 0 means the OS will choose an ephemeral port.
		// IP nil (or 0.0.0.0 / ::) means the OS will choose the source IP based on routing.
		LocalAddr: &net.TCPAddr{Port: 0},
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", address)
	latency := time.Since(startTime)

	result := models.ScanResult{
		Timestamp: startTime,
		Target:    target,
		Latency:   latency,
	}

	if err != nil {
		result.Error = err
		s.Logger.Debug("Failed to dial target",
			"scanner", "ConnectScanner",
			"target_ip", target.IP,
			"target_port", target.Port,
			"error", err,
			"latency_ms", latency.Seconds()*1000,
		)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.Status = models.StatusFiltered
			s.Logger.Debug("Target determined filtered (timeout)", "scanner", "ConnectScanner", "address", address)
		} else {
			result.Status = models.StatusClosed
			s.Logger.Debug("Target determined closed (connection error)", "scanner", "ConnectScanner", "address", address, "error", err)
		}
		return result
	}
	defer conn.Close() // Gracefully close the connection.

	localAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		// This is unlikely for a TCP connection but good to handle.
		s.Logger.Warn("Could not assert LocalAddr to *net.TCPAddr after successful dial",
			"scanner", "ConnectScanner",
			"local_addr_type", fmt.Sprintf("%T", conn.LocalAddr()),
			"local_addr_val", conn.LocalAddr().String(),
		)
		result.Status = models.StatusOpen // Still open, but source IP/port logging might be incomplete.
	} else {
		s.Logger.Debug("Successfully dialed target",
			"scanner", "ConnectScanner",
			"source_ip", localAddr.IP.String(),
			"source_port", localAddr.Port,
			"target_ip", target.IP,
			"target_port", target.Port,
			"latency_ms", latency.Seconds()*1000,
		)
		result.Status = models.StatusOpen
	}
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
				// Detailed logging of source/target IP/port is now within the Scan method.
				workerLogger.Debug("Scan result status", "ip", target.IP, "port", target.Port, "status", result.Status, "latency_ms", result.Latency.Seconds()*1000)
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
