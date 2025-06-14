// pkg/utils/utils.go
package utils

import (
	"log/slog"
	"os"
	"port-scanner/config"
	"runtime"
	"syscall"
)

// CheckPrivileges warns if the process is not running with root/administrator rights.
func CheckPrivileges(logger *slog.Logger) {
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		logger.Error("Running as non-root. Raw socket mode (if implemented) will fail.", "os", runtime.GOOS, "uid", os.Geteuid())
		// slog doesn't have a Fatalf equivalent that exits. We need to explicitly exit.
		os.Exit(1)
	}
	logger.Debug("Privilege check passed or not required.", "os", runtime.GOOS)
}

// CheckFileDescriptorLimit warns if the worker count might exceed the open file limit on POSIX.
func CheckFileDescriptorLimit(logger *slog.Logger, cfg *config.Config) {
	if runtime.GOOS == "windows" {
		logger.Debug("File descriptor limit check skipped on Windows.")
		return
	}
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		logger.Debug("Current file descriptor limit.", "soft", rLimit.Cur, "hard", rLimit.Max)
		if uint64(cfg.Workers) >= rLimit.Cur-100 { // 100 is a safety margin
			logger.Warn("Worker count is close to the file descriptor limit.",
				"workers", cfg.Workers,
				"current_limit", rLimit.Cur)
		}
	} else {
		logger.Warn("Failed to get file descriptor limit.", "error", err)
	}
}
