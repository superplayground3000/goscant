// File: internal/checkpoint/checkpoint.go
package checkpoint

import (
    "context"
    "encoding/json"
    "os"
    "time"

    "goscant/internal/input"
    "goscant/internal/logger"
)

type cpFile struct {
    Remaining [][]interface{} `json:"remaining"`
    Version   string          `json:"version"`
    Time      time.Time       `json:"time"`
}

func Handle(ctx context.Context, cfg *config.Config, taskCh <-chan input.ProbeTarget, log *logger.Logger) {
    <-ctx.Done()
    log.Info("interrupt received – dumping checkpoint")
    rem := [][]interface{}{}
    for t := range taskCh {
        rem = append(rem, []interface{}{t.IP, t.Port})
    }
    f := cpFile{Remaining: rem, Version: "1", Time: time.Now()}
    tmp := "checkpoint-" + f.Time.Format("2006-01-02T150405") + ".json.tmp"
    final := strings.TrimSuffix(tmp, ".tmp")
    os.WriteFile(tmp, mustJSON(f), 0644)
    os.Rename(tmp, final)
    log.Info("checkpoint saved to " + final)
    os.Exit(0)
}

func mustJSON(v interface{}) []byte { b, _ := json.MarshalIndent(v, "", "  "); return b }