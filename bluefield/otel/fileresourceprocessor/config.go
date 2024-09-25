package fileresourceprocessor

import (
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
)

type Config struct {
	// FilePath the configured file from which to read a resource attribute
	FilePath string `mapstructure:"file_path"`

	// PollInterval how often to try reading the configured file until successful
	PollInterval time.Duration `mapstructure:"poll_interval"`
}

var _ component.Config = (*Config)(nil)

func (c *Config) Validate() error {
	if c.FilePath == "" {
		return errors.New("file_path cannot be empty")
	}
	if c.PollInterval <= 0 {
		return errors.New("poll_interval must be positive")
	}
	return nil
}
