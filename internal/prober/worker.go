// File: internal/prober/worker.go
package prober

import (
    "context"
    "time"

    "goscant/internal/config"
    "goscant/internal/input"
    "goscant/internal/logger"
    "goscant/internal/scanner"
    "goscant/internal/writer"
)

type Worker struct {
    id     int
    scan   scanner.Scanner
    writer *writer.CSVWriter
    cfg    *config.Config
    log    *logger.Logger
}

func New(id int, s scanner.Scanner, w *writer.CSVWriter, cfg *config.Config, log *logger.Logger) *Worker {
    return &Worker{id: id, scan: s, writer: w, cfg: cfg, log: log}
}

func (w *Worker) Run(ctx context.Context, tasks <-chan input.ProbeTarget) {
    for {
        select {
        case <-ctx.Done():
            return
        case t, ok := <-tasks:
            if !ok { return }
            res := w.scan.Scan(ctx, t.IP, t.Port)
            w.writer.Submit(res)
            w.log.Debugf("[WRK-%d] scanned %s:%d -> %v", w.id, t.IP, t.Port, res.Status)
            time.Sleep(w.cfg.Delay)
        }
    }
}