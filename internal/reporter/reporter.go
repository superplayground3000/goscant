package reporter

import (
	"context"
	"encoding/csv"
	"log"
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
	logger      *log.Logger
}

// New creates a new Reporter instance.
func New(ctx context.Context, wg *sync.WaitGroup, resultsChan <-chan models.ScanResult, outputFile string, logger *log.Logger) *Reporter {
	return &Reporter{ctx, wg, resultsChan, outputFile, logger}
}

// Run starts the reporter. It listens for results and writes them to the CSV.
func (r *Reporter) Run() {
	defer r.wg.Done()
	file, err := os.Create(r.outputFile)
	if err != nil {
		r.logger.Fatalf("[Reporter] - Failed to create output file %s: %v", r.outputFile, err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write(models.CSVHeader()); err != nil {
		r.logger.Printf("[Reporter] - ERROR: Failed to write CSV header: %v", err)
		return
	}
	r.logger.Printf("[Reporter] - Started. Writing results to %s", r.outputFile)

	for {
		select {
		case result, ok := <-r.resultsChan:
			if !ok {
				r.logger.Printf("[Reporter] - Results channel closed. Shutting down.")
				return
			}
			if err := writer.Write(result.ToCSVRow()); err != nil {
				r.logger.Printf("[Reporter] - ERROR: Failed to write record: %v", err)
			}
		case <-r.ctx.Done():
			r.logger.Printf("[Reporter] - Shutdown signal received. Draining remaining results...")
			for result := range r.resultsChan { // Drain the channel
				_ = writer.Write(result.ToCSVRow())
			}
			return
		}
	}
}
