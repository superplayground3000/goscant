// File: internal/writer/csvwriter.go
package writer

import (
    "encoding/csv"
    "os"
    "sync"
    "time"

    "goscant/internal/scanner"
)

type CSVWriter struct {
    mu     sync.Mutex
    f      *os.File
    w      *csv.Writer
    ch     chan scanner.Result
}

func New(path string) (*CSVWriter, error) {
    f, err := os.Create(path)
    if err != nil { return nil, err }
    w := csv.NewWriter(f)
    w.Write([]string{"timestamp", "dst_ip", "dst_port", "status", "latency_ms"})
    return &CSVWriter{f: f, w: w, ch: make(chan scanner.Result, 1024)}, nil
}

func (c *CSVWriter) Run() {
    for r := range c.ch {
        c.mu.Lock()
        c.w.Write([]string{time.Now().Format(time.RFC3339), r.IP, strconv.Itoa(r.Port), r.Status.String(), strconv.FormatInt(r.LatencyMS, 10)})
        c.w.Flush()
        c.mu.Unlock()
    }
}

func (c *CSVWriter) Submit(r scanner.Result) { c.ch <- r }

func (c *CSVWriter) Close() { close(c.ch); c.f.Close() }