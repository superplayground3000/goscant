package pinger

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"port-scanner/internal/testutils" // Assuming this is your test utilities package
)

// TestPing tests the actual Ping function which relies on the system's ping command.
// This is more of an integration test for the Ping function itself.
func TestPing(t *testing.T) {
	t.Parallel() // This test can run in parallel as it doesn't modify global state.

	tests := []struct {
		name        string
		host        string
		timeout     time.Duration
		expect      bool
		description string
	}{
		{
			name:        "Reachable localhost",
			host:        "localhost", // Assumed to be reachable
			timeout:     2 * time.Second,
			expect:      true,
			description: "localhost should respond to ping.",
		},
		{
			name:        "Reachable 127.0.0.1",
			host:        "127.0.0.1", // Assumed to be reachable
			timeout:     2 * time.Second,
			expect:      true,
			description: "127.0.0.1 should respond to ping.",
		},
		{
			name:        "Unreachable IP",
			host:        "192.0.2.1", // TEST-NET-1, should be unreachable
			timeout:     100 * time.Millisecond,
			expect:      false,
			description: "A TEST-NET-1 IP (192.0.2.1) should be unreachable or timeout quickly.",
		},
		{
			name:        "Timeout on reachable host",
			host:        "localhost",
			timeout:     1 * time.Nanosecond, // Extremely short timeout
			expect:      false,
			description: "Ping to localhost should fail due to the 1ns timeout.",
		},
	}

	for _, tt := range tests {
		tt := tt // Capture range variable for parallel execution
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel() // Subtests can also run in parallel.
			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()
			// We are testing the original Ping function here, not the mockable pingHostFunc.
			got := Ping(ctx, tt.host)
			if got != tt.expect {
				t.Errorf("Ping(%q, timeout %v) = %v, want %v. Description: %s", tt.host, tt.timeout, got, tt.expect, tt.description)
			}
		})
	}
}

// TestFilterReachableHosts tests the FilterReachableHosts logic using a mocked Ping function.
// This makes the test deterministic and independent of actual network conditions.
func TestFilterReachableHosts(t *testing.T) {
	// This test modifies a global variable (pingHostFunc), so it cannot run in parallel
	// with other tests that might also modify it or rely on its original value.
	// Its sub-tests also cannot run in parallel for the same reason.

	logger, _ := testutils.SetupTestLogger() // Get a logger instance for testing

	// Setup mock for pingHostFunc
	originalPingFunc := pingHostFunc
	defer func() {
		pingHostFunc = originalPingFunc // Restore original function after test
	}()

	tests := []struct {
		name           string
		inputHosts     []string
		mockResponses  map[string]bool          // host -> shouldRespond (true/false for the mock)
		mockDelays     map[string]time.Duration // host -> artificial delay for the mock ping
		timeout        time.Duration            // Timeout for FilterReachableHosts's internal context per host
		workers        int
		expectedOutput []string
	}{
		{
			name:           "No input hosts",
			inputHosts:     []string{},
			mockResponses:  map[string]bool{},
			mockDelays:     map[string]time.Duration{},
			timeout:        1000 * time.Millisecond,
			workers:        1,
			expectedOutput: []string{},
		},
		{
			name:       "All hosts reachable",
			inputHosts: []string{"host1", "host2"},
			mockResponses: map[string]bool{
				"host1": true,
				"host2": true,
			},
			mockDelays:     map[string]time.Duration{},
			timeout:        1000 * time.Millisecond,
			workers:        2,
			expectedOutput: []string{"host1", "host2"},
		},
		{
			name:       "No hosts reachable",
			inputHosts: []string{"host1", "host2"},
			mockResponses: map[string]bool{
				"host1": false,
				"host2": false,
			},
			mockDelays:     map[string]time.Duration{},
			timeout:        1000 * time.Millisecond,
			workers:        2,
			expectedOutput: []string{},
		},
		{
			name:       "Mixed reachability",
			inputHosts: []string{"host1", "host2", "host3"},
			mockResponses: map[string]bool{
				"host1": true,
				"host2": false,
				"host3": true,
			},
			mockDelays:     map[string]time.Duration{},
			timeout:        1000 * time.Millisecond,
			workers:        3,
			expectedOutput: []string{"host1", "host3"},
		},
		{
			name:       "One worker, mixed reachability",
			inputHosts: []string{"host1", "host2", "host3"},
			mockResponses: map[string]bool{
				"host1": true,
				"host2": false,
				"host3": true,
			},
			mockDelays:     map[string]time.Duration{},
			timeout:        1000 * time.Millisecond,
			workers:        1,
			expectedOutput: []string{"host1", "host3"},
		},
		{
			name:       "Host ping times out due to FilterReachableHosts's context",
			inputHosts: []string{"host1", "slowhost", "host3"},
			mockResponses: map[string]bool{
				"host1":    true,
				"slowhost": true, // Mock would respond true if it weren't for the delay
				"host3":    true,
			},
			mockDelays: map[string]time.Duration{
				"slowhost": 150 * time.Millisecond, // This delay is longer than FilterReachableHosts's timeout
			},
			timeout:        500 * time.Millisecond, // FilterReachableHosts's timeout per host
			workers:        3,
			expectedOutput: []string{"host1", "host3"}, // slowhost should be filtered out
		},
		{
			name:       "Host ping completes within FilterReachableHosts's timeout",
			inputHosts: []string{"host1", "fastenoughhost"},
			mockResponses: map[string]bool{
				"host1":          true,
				"fastenoughhost": true,
			},
			mockDelays: map[string]time.Duration{
				"fastenoughhost": 20 * time.Millisecond, // Delay is less than FilterReachableHosts's timeout
			},
			timeout:        500 * time.Millisecond,
			workers:        2,
			expectedOutput: []string{"host1", "fastenoughhost"},
		},
	}

	for _, tt := range tests {
		tt := tt // Capture range variable
		t.Run(tt.name, func(t *testing.T) {
			// Define the mock behavior for this specific subtest
			currentMockPing := func(ctx context.Context, hostOrIP string) bool {
				if delay, ok := tt.mockDelays[hostOrIP]; ok {
					// Simulate the time it takes for the ping command to run or network latency
					select {
					case <-time.After(delay):
						// Delay completed, proceed to check mockResponses
					case <-ctx.Done():
						// Context provided to pingHostFunc was cancelled before delay completed
						// This simulates FilterReachableHosts's own timeout cutting short the ping.
						return false
					}
				}

				// After any artificial delay, check context again.
				// This is important if the delay was shorter than the context's deadline,
				// but the context might have been cancelled for other reasons or very close to its deadline.
				if ctx.Err() != nil {
					return false
				}

				responds, exists := tt.mockResponses[hostOrIP]
				if !exists {
					return false // Default to unreachable if not specified in mockResponses
				}
				return responds
			}
			pingHostFunc = currentMockPing // Set the global to our current mock

			actualOutput := FilterReachableHosts(tt.inputHosts, tt.timeout, tt.workers, logger)

			// Sort slices for consistent comparison, as the order of reachable hosts is not guaranteed.
			sort.Strings(actualOutput)
			sort.Strings(tt.expectedOutput)

			if !reflect.DeepEqual(actualOutput, tt.expectedOutput) {
				t.Errorf("FilterReachableHosts() with input %v, timeout %v, workers %d = %v, want %v",
					tt.inputHosts, tt.timeout, tt.workers, actualOutput, tt.expectedOutput)
			}
		})
	}
}
