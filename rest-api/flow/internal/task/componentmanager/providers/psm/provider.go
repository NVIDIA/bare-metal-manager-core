// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package psm

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/psmapi"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providerapi"
)

const (
	// ProviderName is the unique identifier for the PSM provider.
	ProviderName = "psm"

	// DefaultTimeout is the default timeout for PSM gRPC calls.
	DefaultTimeout = 30 * time.Second
)

// Config holds configuration for the PSM provider.
type Config struct {
	// Timeout is the gRPC call timeout for PSM operations.
	Timeout time.Duration
}

type rawConfig struct {
	Timeout string `yaml:"timeout"`
}

// Name returns the provider name for this config.
func (*Config) Name() string {
	return ProviderName
}

// NewProvider creates a PSM provider from this config.
func (c *Config) NewProvider(ctx context.Context) (providerapi.Provider, error) {
	// TODO: Thread ctx into psmapi client creation if provider construction
	// starts performing cancellable work.
	_ = ctx
	return New(*c)
}

// ConfigDecoder owns PSM provider config defaults and YAML decoding.
type ConfigDecoder struct{}

// Name returns the provider name handled by this decoder.
func (ConfigDecoder) Name() string {
	return ProviderName
}

// DefaultConfig returns the default PSM provider config.
func (ConfigDecoder) DefaultConfig() providerapi.ProviderConfig {
	return &Config{
		Timeout: DefaultTimeout,
	}
}

// DecodeYAML decodes PSM provider YAML into a typed config.
func (d ConfigDecoder) DecodeYAML(raw yaml.Node) (providerapi.ProviderConfig, error) {
	config := d.DefaultConfig().(*Config)

	var parsed rawConfig
	if err := providerapi.DecodeYAMLStrict(raw, &parsed); err != nil {
		return nil, providerapi.InvalidProviderConfigError{
			Provider: ProviderName,
			Err:      err,
		}
	}

	if parsed.Timeout != "" {
		timeout, err := time.ParseDuration(parsed.Timeout)
		if err != nil {
			return nil, providerapi.InvalidProviderConfigFieldError{
				Provider: ProviderName,
				Field:    "timeout",
				Err:      err,
			}
		}
		config.Timeout = timeout
	}

	return config, nil
}

// Provider wraps a psmapi.Client and provides it to component manager implementations.
type Provider struct {
	client psmapi.Client
}

// New creates a new Provider using the provided configuration.
func New(config Config) (*Provider, error) {
	client, err := psmapi.NewClient(config.Timeout)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create PSM client")
		return nil, err
	}
	log.Info().Msg("Successfully created PSM client")
	return &Provider{client: client}, nil
}

// NewWithDefault creates a new Provider with the default configuration.
func NewWithDefault() (*Provider, error) {
	cfg := ConfigDecoder{}.DefaultConfig().(*Config)
	return New(*cfg)
}

// NewFromClient creates a Provider from an existing client.
// This is primarily useful for testing with mock clients.
func NewFromClient(client psmapi.Client) *Provider {
	return &Provider{client: client}
}

// Name returns the unique identifier for this provider type.
func (p *Provider) Name() string {
	return ProviderName
}

// Client returns the underlying psmapi.Client.
func (p *Provider) Client() psmapi.Client {
	return p.client
}

// Close closes the underlying PSM client connection.
func (p *Provider) Close() error {
	if p.client != nil {
		return p.client.Close()
	}
	return nil
}
