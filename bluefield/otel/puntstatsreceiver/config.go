package puntstatsreceiver

import (
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
)

// Config defines the configuration of the punt_stats receiver.
type Config struct {
	// Path to the file containing the punt stats to read.
	FilePath string `mapstructure:"file_path"`

	// Optional name of a container with the punt stats file.
	// An empty string means read from the DPU filesystem directly.
	ContainerName string `mapstructure:"container_name"`

	// Scrape interval, e.g. "2s".
	ScrapeInterval time.Duration `mapstructure:"scrape_interval"`
}

// ensure that Config implements the component.Config interface
var _ component.Config = (*Config)(nil)

// Validate implements the component.Config interface by checking whether the
// configuration is valid.
func (cfg *Config) Validate() error {
	if cfg.FilePath == "" {
		return errors.New("file_path must be set")
	}
	if cfg.ScrapeInterval <= 0 {
		return errors.New("scrape_interval must be positive")
	}
	return nil
}

func createDefaultConfig() component.Config {
	return &Config {
		FilePath:         "/cumulus/nl2docad/run/stats/punt",
		ContainerName:    "",
		ScrapeInterval:   5 * time.Second,
	}
}
