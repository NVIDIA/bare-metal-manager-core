// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type logContainsWriter struct {
	needle string
	seen   chan struct{}
}

func (w logContainsWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.needle) {
		select {
		case w.seen <- struct{}{}:
		default:
		}
	}
	return len(p), nil
}

func writeConfigForTest(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestNewConfig(t *testing.T) {
	tests := []struct {
		name string
		want *Config
	}{
		{
			name: "initialize config",
			want: &Config{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewConfig()

			defaultPath := ProjectRoot + "/config.yaml"

			assert.Equal(t, defaultPath, got.GetPathToConfig())
		})
	}
}

func TestGetIssuersConfigClaimMappingAudiences(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(`
issuers:
  - name: custom-issuer
    issuer: https://auth.example.com
    jwks: https://auth.example.com/.well-known/jwks.json
    origin: custom
    audiences: [issuer-audience]
    claimMappings:
      - orgName: acme
        roles: [TENANT_ADMIN]
        audiences: [org-audience]
`)))

	c := &Config{v: v}
	issuers := c.GetIssuersConfig()
	require.Len(t, issuers, 1)
	require.Len(t, issuers[0].ClaimMappings, 1)
	assert.Equal(t, []string{"issuer-audience"}, issuers[0].Audiences)
	assert.Equal(t, []string{"org-audience"}, issuers[0].ClaimMappings[0].Audiences)
}

func TestConfig_ValidatePowerProvisioningConfig(t *testing.T) {
	tests := []struct {
		name      string
		values    map[string]any
		wantError string
	}{
		{
			name: "accepts disabled DPS without connection settings",
		},
		{
			name: "rejects non-boolean DPS enablement",
			values: map[string]any{
				ConfigDPSEnabled: "external",
			},
			wantError: "enabled must be a boolean",
		},
		{
			name: "requires endpoint when DPS is enabled",
			values: map[string]any{
				ConfigDPSEnabled:        true,
				ConfigDPSRequestTimeout: "15s",
			},
			wantError: "endpoint is required",
		},
		{
			name: "rejects whitespace endpoint when DPS is enabled",
			values: map[string]any{
				ConfigDPSEnabled:        true,
				ConfigDPSEndpoint:       "   ",
				ConfigDPSRequestTimeout: "15s",
			},
			wantError: "endpoint is required",
		},
		{
			name: "requires positive timeout when DPS is enabled",
			values: map[string]any{
				ConfigDPSEnabled:        true,
				ConfigDPSEndpoint:       "dps.example.com:443",
				ConfigDPSRequestTimeout: "0s",
				ConfigDPSTokenPath:      "/var/run/secrets/dps/token",
				ConfigDPSCAPath:         "/var/run/secrets/dps/ca.crt",
			},
			wantError: "must be greater than zero",
		},
		{
			name: "accepts complete enabled DPS configuration",
			values: map[string]any{
				ConfigDPSEnabled:        true,
				ConfigDPSEndpoint:       "dps.example.com:443",
				ConfigDPSRequestTimeout: "15s",
				ConfigDPSTokenPath:      "/var/run/secrets/dps/token",
				ConfigDPSCAPath:         "/var/run/secrets/dps/ca.crt",
				ConfigDPSServerName:     "dps.example.com",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v := viper.New()
			for key, value := range test.values {
				v.Set(key, value)
			}
			c := &Config{v: v}

			err := c.ValidatePowerProvisioningConfig()
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestConfig_WatchConfigFile(t *testing.T) {
	const initialSitePhoneHomeURL = "http://initial.example/phone_home"

	tests := []struct {
		name string // description of this test case
		run  func(t *testing.T, c *Config, configPath string)
	}{
		{
			name: "keeps current site phone home URL when changed config cannot be read",
			run: func(t *testing.T, c *Config, configPath string) {
				seenConfigChange := make(chan struct{}, 1)
				previousLogger := log.Logger
				log.Logger = zerolog.New(logContainsWriter{
					needle: "config file changed",
					seen:   seenConfigChange,
				})
				t.Cleanup(func() {
					log.Logger = previousLogger
				})

				require.NoError(t, os.WriteFile(configPath, []byte("site:\n  phoneHomeUrl: [\n"), 0o600))

				require.Eventually(t, func() bool {
					select {
					case <-seenConfigChange:
						return true
					default:
						return false
					}
				}, 3*time.Second, 100*time.Millisecond)
				assert.Equal(t, initialSitePhoneHomeURL, c.GetSitePhoneHomeUrl())
			},
		},
		{
			name: "reloads site phone home URL from changed config",
			run: func(t *testing.T, c *Config, configPath string) {
				const updatedSitePhoneHomeURL = "http://updated.example/phone_home"

				require.NoError(t, os.WriteFile(configPath, []byte(`
log:
  level: debug
site:
  phoneHomeUrl: http://updated.example/phone_home
`), 0o600))

				require.Eventually(t, func() bool {
					return c.GetSitePhoneHomeUrl() == updatedSitePhoneHomeURL
				}, 3*time.Second, 100*time.Millisecond)
				assert.Equal(t, "info", c.v.GetString(ConfigLogLevel))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfigForTest(t, `
site:
  phoneHomeUrl: http://initial.example/phone_home
`)
			c := &Config{v: viper.New()}
			c.v.SetDefault(ConfigFilePath, configPath)
			c.v.SetConfigFile(configPath)
			c.v.SetDefault(ConfigLogLevel, "info")
			c.SetSitePhoneHomeUrl(initialSitePhoneHomeURL)
			c.WatchConfigFile()
			tt.run(t, c, configPath)
		})
	}
}
