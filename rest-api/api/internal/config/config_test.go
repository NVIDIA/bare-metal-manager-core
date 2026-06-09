// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestReloadSitePhoneHomeUrl(t *testing.T) {
	configPath := writeConfigForTest(t, `
site:
  phoneHomeUrl: http://initial.example/phone_home
`)
	cfg := &Config{}
	cfg.SetSitePhoneHomeUrl(defaultSitePhoneHomeUrl)

	require.NoError(t, cfg.reloadSitePhoneHomeUrl(configPath))
	assert.Equal(t, "http://initial.example/phone_home", cfg.GetSitePhoneHomeUrl())

	require.NoError(t, os.WriteFile(configPath, []byte(`
site:
  phoneHomeUrl: http://updated.example/phone_home
`), 0o600))

	require.NoError(t, cfg.reloadSitePhoneHomeUrl(configPath))
	assert.Equal(t, "http://updated.example/phone_home", cfg.GetSitePhoneHomeUrl())
}

func TestWatchConfigFileReloadsSitePhoneHomeUrl(t *testing.T) {
	configPath := writeConfigForTest(t, `
site:
  phoneHomeUrl: http://initial.example/phone_home
`)
	cfg := &Config{v: viper.New()}
	cfg.v.SetDefault(ConfigFilePath, configPath)
	cfg.SetSitePhoneHomeUrl("http://initial.example/phone_home")
	cfg.WatchConfigFile()

	require.NoError(t, os.WriteFile(configPath, []byte(`
site:
  phoneHomeUrl: http://watched.example/phone_home
`), 0o600))

	require.Eventually(t, func() bool {
		return cfg.GetSitePhoneHomeUrl() == "http://watched.example/phone_home"
	}, 3*time.Second, 100*time.Millisecond)
}

func TestReloadSitePhoneHomeUrlKeepsPreviousValueOnInvalidReload(t *testing.T) {
	configPath := writeConfigForTest(t, `
site:
  phoneHomeUrl: ""
`)
	cfg := &Config{}
	cfg.SetSitePhoneHomeUrl("http://previous.example/phone_home")

	require.Error(t, cfg.reloadSitePhoneHomeUrl(configPath))
	assert.Equal(t, "http://previous.example/phone_home", cfg.GetSitePhoneHomeUrl())
}

func writeConfigForTest(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}
