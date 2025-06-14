// internal/logger/logger.go
package logger

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

// New creates a logger that writes to both stdout and a log file, supporting log levels.
func New(logFilePath string, logLevelStr string) (*slog.Logger, func()) {
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		// Use a basic logger for this critical failure, as our main logger isn't set up yet.
		// This will go to stderr by default.
		slog.Error("Failed to open log file, exiting.", "path", logFilePath, "error", err)
		os.Exit(1)
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)

	var level slog.Level
	switch strings.ToUpper(logLevelStr) {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo // Default to INFO
		slog.Warn("Invalid log level specified, defaulting to INFO.", "provided_level", logLevelStr, "default_level", "INFO")
	}

	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					a.Value = slog.StringValue(t.Format("2006/01/02 15:04:05")) // Matches log.LstdFlags format
				}
			}
			return a
		},
	}

	handler := slog.NewTextHandler(multiWriter, opts)
	logger := slog.New(handler)

	return logger, func() { _ = logFile.Close() }
}
