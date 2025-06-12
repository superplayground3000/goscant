// File: internal/config/config.go
package config

import "time"

// Config centralises all runtime parameters.
type Config struct {
    IPInput    string
    PortInput  string
    NumWorkers int
    Timeout    time.Duration
    Delay      time.Duration
    QueueSize  int
    DryRun     bool
    ResumeFile string
    OutputPath string
    LogPath    string
}