package testutils

import (
	"bytes"
	"io"
	"log/slog"
	"os"
)

// SetupTestLogger creates a new slog.Logger that writes to a bytes.Buffer and stdout,
// configured for DEBUG level. Returns the logger and the buffer.
func SetupTestLogger() (*slog.Logger, *bytes.Buffer) {
	var logBuf bytes.Buffer
	// Write to both buffer and stdout for easier debugging during test development
	handler := slog.NewTextHandler(io.MultiWriter(&logBuf, os.Stdout), &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)
	return logger, &logBuf
}

// Add other common test helpers or mock types here
