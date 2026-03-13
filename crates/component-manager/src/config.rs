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
