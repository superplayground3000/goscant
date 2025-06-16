package pinger

import (
	"context"
	"log/slog"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

// pingHostFunc is a package-level variable that defaults to the actual Ping function.
var pingHostFunc = Ping

// FilterReachableHosts takes a slice of hosts, pings them concurrently,
// and returns a new slice containing only the hosts that responded.
func FilterReachableHosts(hosts []string, timeout time.Duration, workers int, parentLogger *slog.Logger) []string {
	var reachableHosts []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	hostJobChan := make(chan string, len(hosts))
	for _, host := range hosts {
		hostJobChan <- host
	}
	close(hostJobChan)

	pingerLogger := parentLogger.With(slog.String("component", "pinger"))
	pingerLogger.Info("Starting reachability check.", "host_count", len(hosts), "workers", workers, "timeout", timeout)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range hostJobChan {
				pingCtx, cancel := context.WithTimeout(context.Background(), timeout)

				if pingHostFunc(pingCtx, host) { // Use the mockable function variable
					mu.Lock()
					reachableHosts = append(reachableHosts, host)
					mu.Unlock()
					pingerLogger.Debug("Host is reachable.", "host", host)
				} else {
					pingerLogger.Debug("Host is unreachable or timed out, skipping.", "host", host)
				}
				cancel()
			}
		}()
	}

	wg.Wait()
	pingerLogger.Info("Reachability check complete.", "reachable_hosts", len(reachableHosts), "total_hosts", len(hosts))
	return reachableHosts
}

// Ping returns true if host responds to a single echo request within ctx deadline.
func Ping(ctx context.Context, hostOrIP string) bool {
	// Directly use systemPing. It can handle both hostnames and IP addresses.
	// The logger from FilterReachableHosts will indicate if a host is unreachable.
	return systemPing(ctx, hostOrIP)
}

func systemPing(ctx context.Context, ip string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// -n 1 (count). Rely on CommandContext for timeout.
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", ip)
	} else {
		// -c 1 (count). Rely on CommandContext for timeout.
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", ip)
	}
	return cmd.Run() == nil
}
