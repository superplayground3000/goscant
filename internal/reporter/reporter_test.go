package reporter

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"port-scanner/internal/models"
	"strings"
	"sync"
	"testing"
	"time"
)

func setupTestLogger() (*slog.Logger, *bytes.Buffer) {
	var logBuf bytes.Buffer
	handler := slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)
	return logger, &logBuf
}

func TestReporter_Run(t *testing.T) {
	logger, logBuf := setupTestLogger()
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "results.csv")

	resultsChan := make(chan models.ScanResult, 3)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reporter := New(ctx, &wg, resultsChan, outputFile, logger)

	wg.Add(1)
	go reporter.Run()

	// Send some results
	now := time.Now()
	resultsToSend := []models.ScanResult{
		{Timestamp: now, Target: models.ScanTarget{IP: "192.168.1.1", Port: 80}, Status: models.StatusOpen, Latency: 10 * time.Millisecond},
		{Timestamp: now, Target: models.ScanTarget{IP: "192.168.1.1", Port: 443}, Status: models.StatusClosed, Latency: 5 * time.Millisecond, Error: nil},
		{Timestamp: now, Target: models.ScanTarget{IP: "192.168.1.2", Port: 22}, Status: models.StatusFiltered, Latency: 100 * time.Millisecond, Error: os.ErrDeadlineExceeded},
	}

	for _, res := range resultsToSend {
		resultsChan <- res
	}

	// Allow some time for processing before closing channel
	time.Sleep(100 * time.Millisecond)
	close(resultsChan)
	wg.Wait() // Wait for reporter to finish

	// Verify CSV content
	file, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to read CSV records: %v", err)
	}

	if len(records) != len(resultsToSend)+1 { // +1 for header
		t.Errorf("Expected %d records, got %d", len(resultsToSend)+1, len(records))
	}

	// Check header
	expectedHeader := models.CSVHeader()
	if !equalSlices(records[0], expectedHeader) {
		t.Errorf("Expected header %v, got %v", expectedHeader, records[0])
	}

	// Check data rows (simple check for IP and Port)
	for i, res := range resultsToSend {
		if records[i+1][1] != res.Target.IP || records[i+1][2] != fmt.Sprintf("%d", res.Target.Port) {
			t.Errorf("Record mismatch for result %d: expected %s:%d, got %s:%s", i, res.Target.IP, res.Target.Port, records[i+1][1], records[i+1][2])
		}
	}

	// Check logs (optional, basic check)
	if !strings.Contains(logBuf.String(), "Reporter started.") {
		t.Errorf("Expected log message 'Reporter started.' not found. Logs:\n%s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "Results channel closed. Shutting down.") {
		t.Errorf("Expected log message 'Results channel closed. Shutting down.' not found. Logs:\n%s", logBuf.String())
	}
}

func TestReporter_Run_ContextCancel(t *testing.T) {
	logger, _ := setupTestLogger()
	tempDir := t.TempDir()
	outputFile := filepath.Join(tempDir, "results.csv")

	resultsChan := make(chan models.ScanResult, 1)
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	reporter := New(ctx, &wg, resultsChan, outputFile, logger)

	wg.Add(1)
	go reporter.Run()

	resultsChan <- models.ScanResult{Target: models.ScanTarget{IP: "127.0.0.1", Port: 80}, Status: models.StatusOpen}
	time.Sleep(50 * time.Millisecond) // Give it time to write one record

	cancel() // Cancel the context

	// Try sending another result, it might be processed if context cancellation is slow
	// or might be dropped. The key is that the reporter exits.
	select {
	case resultsChan <- models.ScanResult{Target: models.ScanTarget{IP: "127.0.0.1", Port: 443}, Status: models.StatusOpen}:
	default:
	}

	wg.Wait() // Wait for reporter to finish

	// Check if file was created and has at least the header
	file, err := os.Open(outputFile)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil && err != io.EOF { // EOF is fine if only header was written
		t.Fatalf("Failed to read CSV records: %v", err)
	}
	if len(records) < 1 {
		t.Errorf("Expected at least a header record, got %d records", len(records))
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
