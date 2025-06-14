package reporter

import (
	"context"
	"encoding/csv"
	"log/slog"
	"os"
	"port-scanner/internal/models"
	"sync"
)

// Reporter handles writing scan results to a CSV file in a separate goroutine.
type Reporter struct {
	ctx         context.Context
	wg          *sync.WaitGroup
	resultsChan <-chan models.ScanResult
	outputFile  string
	logger      *slog.Logger
}

// New creates a new Reporter instance.
func New(ctx context.Context, wg *sync.WaitGroup, resultsChan <-chan models.ScanResult, outputFile string, logger *slog.Logger) *Reporter {
	return &Reporter{ctx, wg, resultsChan, outputFile, logger}
}

// Run starts the reporter. It listens for results and writes them to the CSV.
func (r *Reporter) Run() {
	defer r.wg.Done()
	reporterLogger := r.logger.With(slog.String("component", "reporter"))
	file, err := os.Create(r.outputFile)
	if err != nil {
		reporterLogger.Error("Failed to create output file, exiting.", "file", r.outputFile, "error", err)
		// slog.Error doesn't exit, so if this is fatal, we should os.Exit or panic
		// For a library function, it's often better to return an error.
		// However, given the original Fatalf, we'll replicate the exit behavior.
		os.Exit(1) // Or handle error more gracefully depending on application design
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write(models.CSVHeader()); err != nil {
		reporterLogger.Error("Failed to write CSV header.", "error", err)
		return
	}
	reporterLogger.Info("Started.", "file", r.outputFile)

	for {
		select {
		case result, ok := <-r.resultsChan:
			if !ok {
				reporterLogger.Info("Results channel closed. Shutting down.")
				return
			}
			if err := writer.Write(result.ToCSVRow()); err != nil {
				reporterLogger.Error("Failed to write record.", "error", err)
			}
		case <-r.ctx.Done():
			reporterLogger.Info("Shutdown signal received. Draining remaining results...")
			for result := range r.resultsChan { // Drain the channel
				_ = writer.Write(result.ToCSVRow())
			}
			return
		}
	}
}
