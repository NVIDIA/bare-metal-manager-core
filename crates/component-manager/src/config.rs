// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ComponentManagerConfig {
    #[serde(default = "default_nsm_backend")]
    pub nv_switch_backend: String,
    #[serde(default = "default_psm_backend")]
    pub power_shelf_backend: String,
    #[serde(default)]
    pub nsm: Option<BackendEndpointConfig>,
    #[serde(default)]
    pub psm: Option<BackendEndpointConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackendEndpointConfig {
    pub url: String,
    #[serde(default)]
    pub tls: Option<BackendTlsConfig>,
}

/// TLS configuration for a backend gRPC connection.
///
/// Follows the same SPIFFE cert convention used by RLA: a directory
/// containing `ca.crt`, `tls.crt`, and `tls.key`. Alternatively, each
/// path can be set individually.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackendTlsConfig {
    /// Directory containing `ca.crt`, `tls.crt`, `tls.key`.
    /// Individual path fields override files from this directory.
    #[serde(default)]
    pub cert_dir: Option<String>,

    /// Path to the CA certificate PEM file.
    #[serde(default)]
    pub ca_cert_path: Option<String>,

    /// Path to the client certificate PEM file.
    #[serde(default)]
    pub client_cert_path: Option<String>,

    /// Path to the client private key PEM file.
    #[serde(default)]
    pub client_key_path: Option<String>,

    /// TLS domain name for server certificate verification.
    /// If unset, tonic derives it from the endpoint URL.
    #[serde(default)]
    pub domain: Option<String>,
}

impl BackendTlsConfig {
    pub fn resolve_ca_cert_path(&self) -> Option<String> {
        self.ca_cert_path
            .clone()
            .or_else(|| self.cert_dir.as_ref().map(|d| format!("{d}/ca.crt")))
    }

    pub fn resolve_client_cert_path(&self) -> Option<String> {
        self.client_cert_path
            .clone()
            .or_else(|| self.cert_dir.as_ref().map(|d| format!("{d}/tls.crt")))
    }

    pub fn resolve_client_key_path(&self) -> Option<String> {
        self.client_key_path
            .clone()
            .or_else(|| self.cert_dir.as_ref().map(|d| format!("{d}/tls.key")))
    }
}

fn default_nsm_backend() -> String {
    "nsm".into()
}

fn default_psm_backend() -> String {
    "psm".into()
}

impl Default for ComponentManagerConfig {
    fn default() -> Self {
        Self {
            nv_switch_backend: default_nsm_backend(),
            power_shelf_backend: default_psm_backend(),
            nsm: None,
            psm: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls_config(
        cert_dir: Option<&str>,
        ca: Option<&str>,
        cert: Option<&str>,
        key: Option<&str>,
    ) -> BackendTlsConfig {
        BackendTlsConfig {
            cert_dir: cert_dir.map(String::from),
            ca_cert_path: ca.map(String::from),
            client_cert_path: cert.map(String::from),
            client_key_path: key.map(String::from),
            domain: None,
        }
    }

    #[test]
    fn resolve_ca_cert_explicit_path_wins() {
        let cfg = tls_config(Some("/dir"), Some("/explicit/ca.pem"), None, None);
        assert_eq!(cfg.resolve_ca_cert_path().unwrap(), "/explicit/ca.pem");
    }

    #[test]
    fn resolve_ca_cert_falls_back_to_dir() {
        let cfg = tls_config(Some("/certs"), None, None, None);
        assert_eq!(cfg.resolve_ca_cert_path().unwrap(), "/certs/ca.crt");
    }

    #[test]
    fn resolve_ca_cert_none_when_nothing_set() {
        let cfg = tls_config(None, None, None, None);
        assert!(cfg.resolve_ca_cert_path().is_none());
    }

    #[test]
    fn resolve_client_cert_explicit_path_wins() {
        let cfg = tls_config(Some("/dir"), None, Some("/explicit/client.pem"), None);
        assert_eq!(
            cfg.resolve_client_cert_path().unwrap(),
            "/explicit/client.pem"
        );
    }

    #[test]
    fn resolve_client_cert_falls_back_to_dir() {
        let cfg = tls_config(Some("/certs"), None, None, None);
        assert_eq!(cfg.resolve_client_cert_path().unwrap(), "/certs/tls.crt");
    }

    #[test]
    fn resolve_client_cert_none_when_nothing_set() {
        let cfg = tls_config(None, None, None, None);
        assert!(cfg.resolve_client_cert_path().is_none());
    }

    #[test]
    fn resolve_client_key_explicit_path_wins() {
        let cfg = tls_config(Some("/dir"), None, None, Some("/explicit/key.pem"));
        assert_eq!(cfg.resolve_client_key_path().unwrap(), "/explicit/key.pem");
    }

    #[test]
    fn resolve_client_key_falls_back_to_dir() {
        let cfg = tls_config(Some("/certs"), None, None, None);
        assert_eq!(cfg.resolve_client_key_path().unwrap(), "/certs/tls.key");
    }

    #[test]
    fn resolve_client_key_none_when_nothing_set() {
        let cfg = tls_config(None, None, None, None);
        assert!(cfg.resolve_client_key_path().is_none());
    }
}
