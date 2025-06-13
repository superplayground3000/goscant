// pkg/utils/utils.go
package utils

import (
	"log"
	"os"
	"port-scanner/config"
	"runtime"
	"syscall"
)

// CheckPrivileges warns if the process is not running with root/administrator rights.
func CheckPrivileges(logger *log.Logger) {
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		logger.Fatalf("[Security] - FATAL: Running as non-root. Raw socket mode (if implemented) will fail.")
	}
}

// CheckFileDescriptorLimit warns if the worker count might exceed the open file limit on POSIX.
func CheckFileDescriptorLimit(logger *log.Logger, cfg *config.Config) {
	if runtime.GOOS == "windows" {
		return
	}
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		if uint64(cfg.Workers) >= rLimit.Cur-100 { // 100 is a safety margin
			logger.Printf(
				"[Resource] - WARNING: Worker count (%d) is close to the file descriptor limit (%d).",
				cfg.Workers, rLimit.Cur,
			)
		}
	}
}
