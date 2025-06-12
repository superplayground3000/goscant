// File: internal/logger/logger.go
package logger

import (
    "log"
    "os"
)

type Logger struct { *log.Logger }

func New(path string) *Logger {
    f, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    mw := io.MultiWriter(os.Stdout, f)
    return &Logger{log.New(mw, "", log.LstdFlags)}
}

func (l *Logger) Debugf(format string, v ...interface{}) { l.Printf("DEBUG "+format, v...) }
func (l *Logger) Info(msg string)                      { l.Println("INFO " + msg) }
func (l *Logger) Warn(msg string)                      { l.Println("WARN " + msg) }