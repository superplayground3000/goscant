// internal/logger/logger.go
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
)

// New creates a logger that writes to both stdout and a log file.
func New(logFilePath string) (*log.Logger, func()) {
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file %s: %v", logFilePath, err)
	}
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger := log.New(multiWriter, "", log.LstdFlags)
	return logger, func() { _ = logFile.Close() }
}