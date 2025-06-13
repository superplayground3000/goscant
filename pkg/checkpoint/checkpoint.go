// pkg/checkpoint/checkpoint.go
package checkpoint

import (
	"encoding/json"
	"os"
	"port-scanner/internal/models"
)

// SaveState marshals remaining scan targets to a JSON file.
func SaveState(targets []models.ScanTarget, filePath string) error {
	data, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

// LoadState unmarshals scan targets from a JSON file.
func LoadState(filePath string) ([]models.ScanTarget, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var targets []models.ScanTarget
	return targets, json.Unmarshal(data, &targets)
}