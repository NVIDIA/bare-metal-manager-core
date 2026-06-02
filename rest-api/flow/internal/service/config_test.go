// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgcerts "github.com/NVIDIA/infra-controller-rest/flow/pkg/certs"
)

// tlsConfig creates stub certificate files in t.TempDir() and returns a
// CertConfig with their paths. Using real files ensures the tests remain valid
// if IsTLSAvailable is strengthened to verify file existence.
func tlsConfig(t *testing.T) pkgcerts.Config {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	cert := filepath.Join(dir, "tls.crt")
	key := filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(ca, []byte("stub"), 0600))
	require.NoError(t, os.WriteFile(cert, []byte("stub"), 0600))
	require.NoError(t, os.WriteFile(key, []byte("stub"), 0600))
	return pkgcerts.Config{CACert: ca, TLSCert: cert, TLSKey: key}
}

// noTLSConfig returns an empty CertConfig. Tests that use it must also call
// t.Setenv("CERTDIR", t.TempDir()) to prevent IsTLSAvailable from resolving
// certs from the k8s SPIFFE default path.
func noTLSConfig() pkgcerts.Config {
	return pkgcerts.Config{}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		flowEnv     string // value passed to t.Setenv; empty string sets the var to ""
		devMode     bool
		certConf    pkgcerts.Config
		wantErr     bool
		errContains string
	}{
		// ── FLOW_ENV empty — always an error; no implicit default ──────────────
		// t.Setenv(EnvVarName, "") and os.Unsetenv both cause os.Getenv to
		// return "", so GetDeploymentEnv treats them identically.
		{
			name:        "empty env, dev-mode off, no TLS",
			devMode:     false,
			certConf:    noTLSConfig(),
			wantErr:     true,
			errContains: EnvVarName,
		},
		{
			name:        "empty env, dev-mode off, TLS present",
			devMode:     false,
			certConf:    tlsConfig(t),
			wantErr:     true,
			errContains: EnvVarName,
		},
		{
			name:        "empty env, dev-mode on, no TLS",
			devMode:     true,
			certConf:    noTLSConfig(),
			wantErr:     true,
			errContains: EnvVarName,
		},
		{
			name:        "empty env, dev-mode on, TLS present",
			devMode:     true,
			certConf:    tlsConfig(t),
			wantErr:     true,
			errContains: EnvVarName,
		},
		// ── FLOW_ENV=development ───────────────────────────────────────────────
		{
			name:     "development, dev-mode off, no TLS",
			flowEnv:  "development",
			devMode:  false,
			certConf: noTLSConfig(),
			wantErr:  false,
		},
		{
			name:     "development, dev-mode off, TLS present",
			flowEnv:  "development",
			devMode:  false,
			certConf: tlsConfig(t),
			wantErr:  false,
		},
		{
			name:     "development, dev-mode on, no TLS",
			flowEnv:  "development",
			devMode:  true,
			certConf: noTLSConfig(),
			wantErr:  false,
		},
		{
			name:     "development, dev-mode on, TLS present",
			flowEnv:  "development",
			devMode:  true,
			certConf: tlsConfig(t),
			wantErr:  false,
		},
		// ── FLOW_ENV=staging ───────────────────────────────────────────────────
		{
			name:        "staging, dev-mode off, no TLS",
			flowEnv:     "staging",
			devMode:     false,
			certConf:    noTLSConfig(),
			wantErr:     true,
			errContains: "TLS",
		},
		{
			name:     "staging, dev-mode off, TLS present",
			flowEnv:  "staging",
			devMode:  false,
			certConf: tlsConfig(t),
			wantErr:  false,
		},
		{
			// Rule 1 (dev-mode blocked) fires before Rule 2 (TLS required).
			name:        "staging, dev-mode on, no TLS",
			flowEnv:     "staging",
			devMode:     true,
			certConf:    noTLSConfig(),
			wantErr:     true,
			errContains: "--dev-mode",
		},
		{
			name:        "staging, dev-mode on, TLS present",
			flowEnv:     "staging",
			devMode:     true,
			certConf:    tlsConfig(t),
			wantErr:     true,
			errContains: "--dev-mode",
		},
		// ── FLOW_ENV=production ────────────────────────────────────────────────
		{
			name:        "production, dev-mode off, no TLS",
			flowEnv:     "production",
			devMode:     false,
			certConf:    noTLSConfig(),
			wantErr:     true,
			errContains: "TLS",
		},
		{
			name:     "production, dev-mode off, TLS present",
			flowEnv:  "production",
			devMode:  false,
			certConf: tlsConfig(t),
			wantErr:  false,
		},
		{
			// Rule 1 (dev-mode blocked) fires before Rule 2 (TLS required).
			name:        "production, dev-mode on, no TLS",
			flowEnv:     "production",
			devMode:     true,
			certConf:    noTLSConfig(),
			wantErr:     true,
			errContains: "--dev-mode",
		},
		{
			name:        "production, dev-mode on, TLS present",
			flowEnv:     "production",
			devMode:     true,
			certConf:    tlsConfig(t),
			wantErr:     true,
			errContains: "--dev-mode",
		},
		// ── Partial CertConfig — env-independent, fires before TLS check ────────
		{
			// One path set: rejected in any environment before reaching IsTLSAvailable.
			name:        "development, one cert path set",
			flowEnv:     "development",
			devMode:     false,
			certConf:    pkgcerts.Config{CACert: "ca.crt"},
			wantErr:     true,
			errContains: "must all be provided",
		},
		{
			// Two paths set: CERTDIR/SPIFFE fallback must not mask the misconfiguration.
			name:        "staging, two cert paths set",
			flowEnv:     "staging",
			devMode:     false,
			certConf:    pkgcerts.Config{CACert: "ca.crt", TLSCert: "tls.crt"},
			wantErr:     true,
			errContains: "must all be provided",
		},
		// ── Invalid FLOW_ENV value ─────────────────────────────────────────────
		{
			// Unknown value is rejected regardless of other settings.
			name:        "invalid env, dev-mode off, no TLS",
			flowEnv:     "prod",
			devMode:     false,
			certConf:    noTLSConfig(),
			wantErr:     true,
			errContains: "unknown",
		},
		{
			// Unknown value is rejected regardless of other settings.
			name:        "invalid env, dev-mode on, TLS present",
			flowEnv:     "prod",
			devMode:     true,
			certConf:    tlsConfig(t),
			wantErr:     true,
			errContains: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Isolate CERTDIR so IsTLSAvailable cannot resolve certs from the
			// k8s SPIFFE default path when CertConfig is empty.
			t.Setenv("CERTDIR", t.TempDir())
			t.Setenv(EnvVarName, tt.flowEnv)

			c := Config{DevMode: tt.devMode, CertConfig: tt.certConf}
			err := c.Validate()

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
