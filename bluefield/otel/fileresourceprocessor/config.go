package fileresourceprocessor

import (
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
)

type Config struct {
	// FilePaths configured files from which to read resource attributes
	FilePaths []string `mapstructure:"file_paths"`

	// PollInterval how often to try reading the configured file until successful
	PollInterval time.Duration `mapstructure:"poll_interval"`
}

var _ component.Config = (*Config)(nil)

func (c *Config) Validate() error {
	if len(c.FilePaths) == 0 {
		return errors.New("at least one file must be configured")
	}
	for _, path := range c.FilePaths {
		if path == "" {
			return errors.New("file path cannot be empty")
		}
	}
	if c.PollInterval <= 0 {
		return errors.New("poll_interval must be positive")
	}
	return nil
}

func createDefaultConfig() component.Config {
	return &Config{
		FilePaths:    []string{},
		PollInterval: 1 * time.Minute,
	}
}
