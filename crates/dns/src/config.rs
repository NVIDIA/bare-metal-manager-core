/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::path::{Path, PathBuf};

use forge_tls::client_config::ClientCert;
use local_ip_address::local_ip;
use rpc::forge_tls_client::ForgeClientConfig;
use serde::{Deserialize, Serialize};
use tonic::codegen::http;

const SOCKET_PERMISSIONS: u32 = 660;
const DEFAULT_SOCKET_PATH: &str = "/tmp/pdns.sock";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default = "Defaults::socket_permissions")]
    pub socket_permissions: u32,
    #[serde(default = "Defaults::socket_path")]
    pub socket_path: PathBuf,
    #[serde(
        default = "Defaults::carbide_uri",
        serialize_with = "serialize_uri",
        deserialize_with = "deserialize_uri"
    )]
    pub carbide_uri: http::Uri,
    #[serde(default = "Defaults::forge_root_ca")]
    pub forge_root_ca: PathBuf,
    #[serde(default = "Defaults::client_cert")]
    pub client_cert_path: PathBuf,
    #[serde(default = "Defaults::client_key")]
    pub client_key_path: PathBuf,
    /// Legacy mode configuration: if set, run as a DNS server on this address
    #[serde(default)]
    pub legacy_listen: Option<std::net::SocketAddr>,
    #[serde(
        default = "Defaults::otlp_endpoint",
        serialize_with = "serialize_uri",
        deserialize_with = "deserialize_uri"
    )]
    pub otlp_endpoint: http::Uri,
}

pub struct Defaults;

impl Defaults {
    pub fn carbide_uri() -> http::Uri {
        "https://carbide-api.forge-system.svc.cluster.local:1079"
            .try_into()
            .expect("BUG: default carbide URI is invalid")
    }

    pub fn otlp_endpoint() -> http::Uri {
        "http://opentelemetry-collector.otel.svc.cluster.local:4317"
            .try_into()
            .expect("BUG: default OTLP endpoint URI is invalid")
    }
    pub fn socket_path() -> PathBuf {
        DEFAULT_SOCKET_PATH.into()
    }
    pub fn socket_permissions() -> u32 {
        SOCKET_PERMISSIONS
    }
    pub fn forge_root_ca() -> PathBuf {
        "/var/run/secrets/spiffe.io/ca.crt".into()
    }
    pub fn client_cert() -> PathBuf {
        "/var/run/secrets/spiffe.io/tls.crt".into()
    }
    pub fn client_key() -> PathBuf {
        "/var/run/secrets/spiffe.io/tls.key".into()
    }
    pub fn ns_ip_address() -> String {
        let address = local_ip().expect("Failed to get local IP address");
        tracing::debug!(
            "ns1_ip_address not specified in config file, defaulting to local interface: {}",
            address
        );
        address.to_string()
    }
}
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("Could not read config file: {path}: {error}")]
    CouldNotRead { path: String, error: std::io::Error },
    #[error("Invalid TOML in config file: {path}: {error}")]
    InvalidToml {
        path: String,
        error: toml::de::Error,
    },
}

impl Default for Config {
    fn default() -> Self {
        Self {
            socket_permissions: Defaults::socket_permissions(),
            socket_path: Defaults::socket_path(),
            carbide_uri: Defaults::carbide_uri(),
            forge_root_ca: Defaults::forge_root_ca(),
            client_cert_path: Defaults::client_cert(),
            client_key_path: Defaults::client_key(),
            otlp_endpoint: Defaults::otlp_endpoint(),
            legacy_listen: None,
        }
    }
}
fn serialize_uri<S>(uri: &http::Uri, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("{uri}"))
}

fn deserialize_uri<'de, D>(deserializer: D) -> Result<http::Uri, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let uri_str: String = Deserialize::deserialize(deserializer)?;
    uri_str.parse().map_err(serde::de::Error::custom)
}
impl Config {
    pub fn forge_client_config(&self) -> ForgeClientConfig {
        let forge_root_ca = self
            .forge_root_ca
            .to_str()
            .expect("forge root CA path is not valid UTF-8")
            .to_string();
        let client_cert = ClientCert {
            cert_path: self
                .client_cert_path
                .to_str()
                .expect("client cert path is not valid UTF-8")
                .to_string(),
            key_path: self
                .client_key_path
                .to_str()
                .expect("client key path is not valid UTF-8")
                .to_string(),
        };
        ForgeClientConfig::new(forge_root_ca, Some(client_cert))
    }
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let cfg = std::fs::read_to_string(path).map_err(|error| ConfigError::CouldNotRead {
            path: path.to_string_lossy().to_string(),
            error,
        })?;
        toml::from_str::<Self>(&cfg).map_err(|error| ConfigError::InvalidToml {
            path: path.to_string_lossy().to_string(),
            error,
        })
    }
}
