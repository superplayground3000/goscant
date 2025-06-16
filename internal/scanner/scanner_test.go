package scanner

import (
	"context"
	"net"
	"port-scanner/internal/models"
	"port-scanner/internal/testutils"
	"strings"
	"sync"
	"testing"
	"time"
)

// MockScanner is a test helper to simulate a Scanner implementation.
// MockScanner for worker tests
type MockScanner struct {
	ScanFunc func(target models.ScanTarget) models.ScanResult
	mu       sync.Mutex
	Calls    []models.ScanTarget
}

func (m *MockScanner) Scan(target models.ScanTarget) models.ScanResult {
	m.mu.Lock()
	m.Calls = append(m.Calls, target)
	m.mu.Unlock()
	if m.ScanFunc != nil {
		return m.ScanFunc(target)
	}
	return models.ScanResult{Target: target, Status: models.StatusOpen, Latency: 1 * time.Millisecond}
}

func TestConnectScanner_Scan_OpenPort(t *testing.T) {
	logger, logBuf := testutils.SetupTestLogger()
	listener, err := net.Listen("tcp", "127.0.0.1:0") // OS chooses a free port
	if err != nil {
		t.Fatalf("Failed to listen on a port: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	target := models.ScanTarget{IP: addr.IP.String(), Port: addr.Port}
	scanner := NewConnectScanner(100*time.Millisecond, logger)

	result := scanner.Scan(target) // Pass context

	if result.Status != models.StatusOpen {
		t.Errorf("Expected status Open, got %s. Logs: %s", result.Status, logBuf.String())
	}
	if result.Error != nil {
		t.Errorf("Expected no error, got %v", result.Error)
	}
	if !strings.Contains(logBuf.String(), "Successfully dialed target") {
		t.Errorf("Expected 'Successfully dialed target' in logs, got: %s", logBuf.String())
	}
}

func TestConnectScanner_Scan_ClosedPort(t *testing.T) {
	logger, logBuf := testutils.SetupTestLogger()
	// Find a port that is likely closed. This is a bit heuristic.
	// A more robust way would be to mock net.Dialer, but this is simpler for a direct test.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen to get a port: %v", err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close() // Ensure it's closed

	time.Sleep(50 * time.Millisecond) // Give OS time to release port

	target := models.ScanTarget{IP: "127.0.0.1", Port: closedPort}
	scanner := NewConnectScanner(100*time.Millisecond, logger)

	result := scanner.Scan(target) // Pass context

	if result.Status != models.StatusClosed {
		t.Errorf("Expected status Closed, got %s. Logs: %s", result.Status, logBuf.String())
	}
	if result.Error == nil {
		t.Errorf("Expected an error for a closed port, got nil")
	}
	if !strings.Contains(logBuf.String(), "Failed to dial target") {
		t.Errorf("Expected 'Failed to dial target' in logs, got: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "Target determined closed (connection error)") {
		t.Errorf("Expected 'Target determined closed (connection error)' in logs, got: %s", logBuf.String())
	}
}

func TestConnectScanner_Scan_FilteredPort(t *testing.T) {
	logger, logBuf := testutils.SetupTestLogger()
	// Use a non-routable IP address to simulate a timeout/filtered port
	// 192.0.2.1 is a TEST-NET-1 address, typically not routable.
	target := models.ScanTarget{IP: "192.0.2.1", Port: 12345}
	// Short timeout to make the test faster
	scanner := NewConnectScanner(50*time.Millisecond, logger)
	result := scanner.Scan(target) // Pass context

	if result.Status != models.StatusFiltered {
		t.Errorf("Expected status Filtered, got %s. Logs: %s", result.Status, logBuf.String())
	}
	if result.Error == nil {
		t.Errorf("Expected an error for a filtered port, got nil")
	}
	netErr, ok := result.Error.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Errorf("Expected a timeout error, got %T: %v", result.Error, result.Error)
	}
	if !strings.Contains(logBuf.String(), "Target determined filtered (timeout)") {
		t.Errorf("Expected 'Target determined filtered (timeout)' in logs, got: %s", logBuf.String())
	}
}

func TestWorker(t *testing.T) {
	logger, logBuf := testutils.SetupTestLogger()
	var wg sync.WaitGroup

	tasks := make(chan models.ScanTarget, 1)
	results := make(chan models.ScanResult, 1)

	mockScan := &MockScanner{
		ScanFunc: func(target models.ScanTarget) models.ScanResult {
			return models.ScanResult{Target: target, Status: models.StatusOpen, Latency: 5 * time.Millisecond} // Mock ScanFunc doesn't need context here
		},
	}

	wg.Add(1)
	go Worker(context.Background(), &wg, 1, logger, mockScan, tasks, results, 0, false)

	target := models.ScanTarget{IP: "127.0.0.1", Port: 80}
	tasks <- target

	select {
	case res := <-results:
		if res.Target.IP != target.IP || res.Target.Port != target.Port {
			t.Errorf("Worker processed wrong target: got %v, want %v", res.Target, target)
		}
		if res.Status != models.StatusOpen {
			t.Errorf("Worker returned wrong status: got %s, want Open", res.Status)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Worker timed out processing task")
	}

	if len(mockScan.Calls) != 1 || mockScan.Calls[0].IP != target.IP {
		t.Errorf("MockScanner.Scan was not called correctly. Calls: %v", mockScan.Calls)
	}

	// Test dry run
	mockScan.Calls = nil // Reset calls
	wg.Add(1)
	go Worker(context.Background(), &wg, 2, logger, mockScan, tasks, results, 0, true /* dryRun */)
	tasks <- target

	select {
	case res := <-results:
		if res.Status != models.StatusDryRun {
			t.Errorf("Worker in dry run mode returned wrong status: got %s, want DryRun", res.Status)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Worker (dry run) timed out processing task")
	}
	if len(mockScan.Calls) != 0 {
		t.Errorf("MockScanner.Scan should not be called in dry run mode. Calls: %v", mockScan.Calls)
	}

	// Test context cancellation
	wg.Wait() // Wait for all workers to finish (the first one should have finished, this waits for the second and any new ones if we didn't manage context correctly)

	if !strings.Contains(logBuf.String(), "Worker started.") {
		t.Errorf("Expected 'Worker started.' in logs, got: %s", logBuf.String())
	}
	// Note: "Task channel closed" or "Shutdown signal received" might appear depending on timing.
	// For a more precise check on cancellation, you might need more intricate signaling.
}

func TestWorker_ChannelClose(t *testing.T) {
	logger, _ := testutils.SetupTestLogger() // Use testutils logger
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tasks := make(chan models.ScanTarget) // Unbuffered
	results := make(chan models.ScanResult, 1)
	mockScan := &MockScanner{}

	wg.Add(1)
	go Worker(ctx, &wg, 1, logger, mockScan, tasks, results, 0, false)

	close(tasks) // Close tasks channel

	wg.Wait() // Worker should exit

	// Ensure no panic and graceful shutdown, log check is good here
	// (already done in setupTestLogger if we check logBuf)
}
