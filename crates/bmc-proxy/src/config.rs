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

use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;

use carbide_authn::config::{AllowedCertCriteria, TrustConfig};
use carbide_utils::HostPortPair;
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::acl::AclConfig;

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("{0}")]
    Read(String),
    #[error(transparent)]
    Figment(Box<figment::Error>),
}

impl From<figment::Error> for ConfigError {
    fn from(e: figment::Error) -> Self {
        Self::Figment(Box::new(e))
    }
}

#[derive(Deserialize)]
pub struct Config {
    #[serde(default = "Defaults::listen")]
    pub listen: SocketAddr,
    #[serde(default = "Defaults::metrics_endpoint")]
    pub metrics_endpoint: SocketAddr,
    #[serde(default)]
    pub allowed_principals: HashSet<String>,
    pub tls: TlsConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub carbide_api: CarbideApiConfig,
    pub bmc_proxy: Option<HostPortPair>,
}

struct Defaults;

impl Defaults {
    fn listen() -> SocketAddr {
        SocketAddr::from_str("[::]:1079").expect("BUG: default listen endpoint doesn't parse")
    }

    fn metrics_endpoint() -> SocketAddr {
        SocketAddr::from_str("[::]:1080").expect("BUG: default metrics endpoint doesn't parse")
    }

    fn trust_config() -> TrustConfig {
        TrustConfig {
            spiffe_trust_domain: "forge.local".to_string(),
            spiffe_service_base_paths: vec![
                "/forge-system/sa/".to_string(),
                "/default/sa/".to_string(),
            ],
            spiffe_machine_base_path: "/forge-system/machine/".to_string(),
            additional_issuer_cns: vec![],
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub identity_pemfile_path: String,
    pub identity_keyfile_path: String,
    pub root_cafile_path: String,
    pub admin_root_cafile_path: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            identity_pemfile_path: "/var/run/secrets/spiffe.io/tls.crt".to_string(),
            identity_keyfile_path: "/var/run/secrets/spiffe.io/tls.key".to_string(),
            root_cafile_path: "/var/run/secrets/spiffe.io/ca.crt".to_string(),
            admin_root_cafile_path: "/etc/forge/carbide-bmc-proxy/site/admin_root_cert_pem"
                .to_string(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CarbideApiConfig {
    pub root_ca: String,
    pub client_cert: String,
    pub client_key: String,
    pub api_url: Url,
}

impl Default for CarbideApiConfig {
    fn default() -> Self {
        Self {
            root_ca: "/var/run/secrets/spiffe.io/ca.crt".to_string(),
            client_cert: "/var/run/secrets/spiffe.io/tls.crt".to_string(),
            client_key: "/var/run/secrets/spiffe.io/tls.key".to_string(),
            api_url: Url::parse("https://carbide-api.forge-system.svc.cluster.local:1079").unwrap(),
        }
    }
}

/// Authentication related configuration
#[derive(Clone, Deserialize)]
pub struct AuthConfig {
    /// Additional nico-admin-cli certs allowed.  This does not include actually allowing the cert to connect, just that certs that can be verified which match these criteria can do GRPC requests.
    #[serde(default)]
    pub cli_certs: Option<AllowedCertCriteria>,

    /// Configuration for the root of trust for client cert auth
    #[serde(default = "Defaults::trust_config")]
    pub trust: TrustConfig,

    #[serde(default)]
    pub acls: AclConfig,
}

impl Config {
    pub fn parse(s: &str) -> Result<Config, ConfigError> {
        Figment::new()
            .merge(Toml::string(s))
            .merge(Env::prefixed("CARBIDE_BMC_PROXY_"))
            .extract()
            .map_err(Into::into)
    }
}
