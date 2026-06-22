// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::compute_tray_manager::Backend as ComputeBackend;
use crate::nv_switch_manager::Backend as NvSwitchBackend;
use crate::power_shelf_manager::Backend as PowerShelfBackend;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ComponentManagerConfig {
    #[serde(default)]
    pub nv_switch_backend: NvSwitchBackend,
    #[serde(default)]
    pub power_shelf_backend: PowerShelfBackend,
    #[serde(default)]
    pub compute_tray_backend: ComputeBackend,

    #[serde(default)]
    pub nsm: Option<BackendEndpointConfig>,
    #[serde(default)]
    pub psm: Option<BackendEndpointConfig>,

    /// When `true`, Switch power control and firmware update calls go
    /// through the switch state controller, instead of being dispatched
    /// directly to the device.
    ///
    /// Status reads and firmware-catalog reads still pass through to
    /// the "direct" backend.
    ///
    /// Defaults to `false` (existing direct-dispatch behaviour).
    #[serde(default)]
    pub nv_switch_use_state_controller: bool,

    /// When `true`, power shelf power control and firmware update calls
    /// go through the power shelf state controller instead of being dispatched
    /// directly.
    ///
    /// Defaults to `false`.
    #[serde(default)]
    pub power_shelf_use_state_controller: bool,

    /// When `true`, compute power control and firmware update calls
    /// go through the state controller instead of being dispatched
    /// directly.
    ///
    /// Defaults to `false`.
    #[serde(default)]
    pub compute_tray_use_state_controller: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackendEndpointConfig {
    pub url: String,
    #[serde(default)]
    pub tls: Option<BackendTlsConfig>,
}

/// TLS configuration for a backend gRPC connection.
///
/// Follows the same SPIFFE cert convention used by NICo Flow: a directory
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

#[cfg(test)]
mod tests {
    use carbide_test_support::{Check, check_values};

    use super::*;

    #[test]
    fn default_backends_are_rms() {
        let cfg = ComponentManagerConfig::default();
        assert_eq!(cfg.nv_switch_backend, NvSwitchBackend::Rms);
        assert_eq!(cfg.power_shelf_backend, PowerShelfBackend::Rms);
        assert_eq!(cfg.compute_tray_backend, ComputeBackend::Rms);
    }

    /// One `BackendTlsConfig` worth of path inputs for a resolver table.
    struct Row {
        cert_dir: Option<&'static str>,
        ca: Option<&'static str>,
        cert: Option<&'static str>,
        key: Option<&'static str>,
    }

    fn tls_config(row: Row) -> BackendTlsConfig {
        BackendTlsConfig {
            cert_dir: row.cert_dir.map(String::from),
            ca_cert_path: row.ca.map(String::from),
            client_cert_path: row.cert.map(String::from),
            client_key_path: row.key.map(String::from),
            domain: None,
        }
    }

    #[test]
    fn resolve_ca_cert_path_explicit_wins_then_dir_then_none() {
        check_values(
            [
                Check {
                    scenario: "explicit path wins",
                    input: Row {
                        cert_dir: Some("/dir"),
                        ca: Some("/explicit/ca.pem"),
                        cert: None,
                        key: None,
                    },
                    expect: Some("/explicit/ca.pem".to_string()),
                },
                Check {
                    scenario: "falls back to dir",
                    input: Row {
                        cert_dir: Some("/certs"),
                        ca: None,
                        cert: None,
                        key: None,
                    },
                    expect: Some("/certs/ca.crt".to_string()),
                },
                Check {
                    scenario: "none when nothing set",
                    input: Row {
                        cert_dir: None,
                        ca: None,
                        cert: None,
                        key: None,
                    },
                    expect: None,
                },
            ],
            |row| tls_config(row).resolve_ca_cert_path(),
        );
    }

    #[test]
    fn resolve_client_cert_path_explicit_wins_then_dir_then_none() {
        check_values(
            [
                Check {
                    scenario: "explicit path wins",
                    input: Row {
                        cert_dir: Some("/dir"),
                        ca: None,
                        cert: Some("/explicit/client.pem"),
                        key: None,
                    },
                    expect: Some("/explicit/client.pem".to_string()),
                },
                Check {
                    scenario: "falls back to dir",
                    input: Row {
                        cert_dir: Some("/certs"),
                        ca: None,
                        cert: None,
                        key: None,
                    },
                    expect: Some("/certs/tls.crt".to_string()),
                },
                Check {
                    scenario: "none when nothing set",
                    input: Row {
                        cert_dir: None,
                        ca: None,
                        cert: None,
                        key: None,
                    },
                    expect: None,
                },
            ],
            |row| tls_config(row).resolve_client_cert_path(),
        );
    }

    #[test]
    fn resolve_client_key_path_explicit_wins_then_dir_then_none() {
        check_values(
            [
                Check {
                    scenario: "explicit path wins",
                    input: Row {
                        cert_dir: Some("/dir"),
                        ca: None,
                        cert: None,
                        key: Some("/explicit/key.pem"),
                    },
                    expect: Some("/explicit/key.pem".to_string()),
                },
                Check {
                    scenario: "falls back to dir",
                    input: Row {
                        cert_dir: Some("/certs"),
                        ca: None,
                        cert: None,
                        key: None,
                    },
                    expect: Some("/certs/tls.key".to_string()),
                },
                Check {
                    scenario: "none when nothing set",
                    input: Row {
                        cert_dir: None,
                        ca: None,
                        cert: None,
                        key: None,
                    },
                    expect: None,
                },
            ],
            |row| tls_config(row).resolve_client_key_path(),
        );
    }
}
