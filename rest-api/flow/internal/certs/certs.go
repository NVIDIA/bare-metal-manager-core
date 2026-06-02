// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package certs provides TLS configuration resolution using deployment-specific
// defaults: the CERTDIR environment variable and the Kubernetes SPIFFE secret
// path. For explicit path-based loading, use pkg/certs.
package certs

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	pkgcerts "github.com/NVIDIA/infra-controller-rest/flow/pkg/certs"
)

// Default certificate directory and file names for the Kubernetes SPIFFE
// workload identity secret mount.
const (
	defaultCertDir  = "/var/run/secrets/spiffe.io"
	defaultCACert   = "ca.crt"
	defaultCertFile = "tls.crt"
	defaultKeyFile  = "tls.key"
)

// ErrNotPresent is returned when no certificate files are found at the
// resolved directory. Callers may use errors.Is(err, ErrNotPresent) to
// detect this case and fall back to non-mTLS.
var ErrNotPresent = errors.New("certificates are not present")

// IsTLSAvailable reports whether TLS certificates can be resolved. It checks,
// in order: explicit paths in c, the CERTDIR env var, and the k8s SPIFFE
// default directory. This mirrors the resolution order used by ResolveServer
// without loading any files.
func IsTLSAvailable(c pkgcerts.Config) bool {
	if c.IsSet() {
		for _, path := range []string{c.CACert, c.TLSCert, c.TLSKey} {
			if _, err := os.Stat(path); err != nil {
				return false
			}
		}
		return true
	}

	certDir := os.Getenv("CERTDIR")
	if certDir == "" {
		certDir = defaultCertDir
	}

	for _, name := range []string{defaultCACert, defaultCertFile, defaultKeyFile} {
		if _, err := os.Stat(filepath.Join(certDir, name)); err != nil {
			return false
		}
	}

	return true
}

// ResolveServer returns a server-side TLS config and source description. If c
// has explicit paths set, uses them via pkg/certs.ServerTLSConfig; otherwise
// falls back to the CERTDIR env var / k8s default via ServerTLSConfig.
func ResolveServer(c pkgcerts.Config) (*tls.Config, string, error) {
	if err := c.Validate(); err != nil {
		return nil, "", err
	}

	if c.IsSet() {
		tlsConfig, err := c.ServerTLSConfig()
		return tlsConfig, c.CACert, err
	}

	return ServerTLSConfig()
}

// TLSConfig resolves cert paths from the CERTDIR environment variable, falling
// back to the k8s default /var/run/secrets/spiffe.io, and returns a client-side
// tls.Config. Returns ErrNotPresent if no cert files are found.
func TLSConfig() (*tls.Config, string, error) {
	return tlsConfigFromDir(
		func(c pkgcerts.Config) (*tls.Config, error) {
			// Pass empty server name: gRPC derives it from the dial URL's hostname.
			return c.TLSConfig("")
		},
	)
}

// ServerTLSConfig resolves cert paths from the CERTDIR environment variable,
// falling back to the k8s default /var/run/secrets/spiffe.io, and returns a
// server-side tls.Config. Returns ErrNotPresent if no cert files are found.
func ServerTLSConfig() (*tls.Config, string, error) {
	return tlsConfigFromDir(
		func(c pkgcerts.Config) (*tls.Config, error) {
			return c.ServerTLSConfig()
		},
	)
}

// tlsConfigFromDir resolves the cert directory from CERTDIR (falling back to
// defaultCertDir), builds a pkgcerts.Config with the standard file names, and
// calls build to produce the tls.Config. Returns ErrNotPresent if any cert
// file is missing, or a wrapped error for other load failures.
func tlsConfigFromDir(
	build func(pkgcerts.Config) (*tls.Config, error),
) (*tls.Config, string, error) {
	certDir := os.Getenv("CERTDIR")
	if certDir == "" {
		certDir = defaultCertDir
	}

	tlsConfig, err := build(
		pkgcerts.Config{
			CACert:  filepath.Join(certDir, defaultCACert),
			TLSCert: filepath.Join(certDir, defaultCertFile),
			TLSKey:  filepath.Join(certDir, defaultKeyFile),
		},
	)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, certDir, ErrNotPresent
		}
		return nil, certDir, fmt.Errorf("loading certs from %q: %w", certDir, err)
	}

	return tlsConfig, certDir, nil
}
