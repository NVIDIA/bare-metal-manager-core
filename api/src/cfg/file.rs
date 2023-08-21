/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};

use crate::resource_pool::ResourcePoolDef;

/// carbide-api configuration file content
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CarbideConfig {
    /// The socket address that is used for the gRPC API server
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// The socket address that is used for the HTTP server which serves
    /// prometheus metrics under /metrics
    pub metrics_endpoint: Option<SocketAddr>,

    /// The DNS name and port of the opentelemetry collector
    pub otlp_endpoint: Option<String>,

    /// A connection string for the utilized postgres database
    pub database_url: String,

    /// A connection string for the utilized IBFabricManager
    /// TODO: Might become a fabrics section
    pub ib_fabric_manager: Option<String>,

    /// The token for IBFabricManager authentication.
    /// TODO: Might become a fabrics section
    /// TODO: Should be read from vault
    pub ib_fabric_manager_token: Option<String>,

    /// Set shorter timeouts and run background jobs more often. Appropriate
    /// for local development.
    /// See ServiceConfig type.
    #[serde(default)]
    pub rapid_iterations: bool,

    /// ASN: Autonomous System Number
    /// Fixed per environment. Used by forge-dpu-agent to write frr.conf (routing).
    pub asn: u32,

    /// List of DHCP servers that should be announced
    #[serde(default)]
    pub dhcp_servers: Vec<String>,

    /// Comma-separated list of route server IP addresses. Optional, only for L2VPN (Eth Virt).
    #[serde(default)]
    pub route_servers: Vec<String>,

    /// List of IPv4 prefixes (in CIDR notation) that tenant instances are not allowed to talk to.
    #[serde(default)]
    pub deny_prefixes: Vec<Ipv4Network>,

    /// TLS related configuration
    pub tls: Option<TlsConfig>,

    /// Authentication related configuration
    pub auth: Option<AuthConfig>,

    // Resource pools to allocate IPs, VNIs, etc.
    // Required.
    // Option so that we can de-serialize partial configs (and then merge them).
    pub pools: Option<HashMap<String, ResourcePoolDef>>,

    // The ipmi command (and args) to use to reboot a dpu
    pub dpu_ipmi_reboot_args: Option<String>,

    // The type of ipmitool to user (prod or fake)
    pub dpu_impi_tool_impl: Option<String>,

    // The number of retries to perform if ipmi returns an error
    pub dpu_ipmi_reboot_attempts: Option<u32>,
}

/// TLS related configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub root_cafile_path: String,

    #[serde(default)]
    pub identity_pemfile_path: String,

    #[serde(default)]
    pub identity_keyfile_path: String,

    #[serde(default)]
    pub admin_root_cafile_path: String,
}

/// Autentication related configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthConfig {
    /// Enable permissive mode in the authorization enforcer (for development).
    pub permissive_mode: bool,

    /// The Casbin policy file (in CSV format).
    pub casbin_policy_file: PathBuf,
}

fn default_listen() -> SocketAddr {
    "[::]:1079".parse().unwrap()
}

#[cfg(test)]
mod tests {
    use figment::{
        providers::{Env, Format, Toml},
        Figment,
    };

    use crate::resource_pool;

    use super::*;

    const TEST_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cfg/test_data");

    #[test]
    fn deserialize_min_config() {
        let config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{}/min_config.toml", TEST_DATA_DIR)))
            .extract()
            .unwrap();
        assert_eq!(config.listen, "[::]:1081".parse().unwrap());
        assert_eq!(config.metrics_endpoint, None);
        assert_eq!(config.asn, 123);
        assert_eq!(config.database_url, "postgres://a:b@postgresql".to_string());
        assert!(!config.rapid_iterations);
        assert!(config.dhcp_servers.is_empty());
        assert!(config.route_servers.is_empty());
        assert!(config.tls.is_none());
        assert!(config.auth.is_none());
        assert!(config.pools.is_none());
    }

    #[test]
    fn deserialize_patched_min_config() {
        let config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{}/min_config.toml", TEST_DATA_DIR)))
            .merge(Toml::file(format!("{}/site_config.toml", TEST_DATA_DIR)))
            .extract()
            .unwrap();
        assert_eq!(config.listen, "[::]:1081".parse().unwrap());
        assert_eq!(config.metrics_endpoint, None);
        assert_eq!(config.database_url, "postgres://a:b@postgresql".to_string());
        assert!(config.rapid_iterations);
        assert_eq!(config.asn, 777);
        assert_eq!(config.dhcp_servers, vec!["99.101.102.103".to_string()]);
        assert!(config.route_servers.is_empty());
        assert_eq!(
            config.tls.as_ref().unwrap().identity_pemfile_path,
            "/patched/path/to/cert"
        );
        assert_eq!(
            config.tls.as_ref().unwrap().identity_keyfile_path,
            "/patched/path/to/key"
        );
        assert_eq!(
            config.tls.as_ref().unwrap().root_cafile_path,
            "/patched/path/to/ca"
        );
        assert!(config.auth.as_ref().unwrap().permissive_mode);
        assert_eq!(
            config.auth.as_ref().unwrap().casbin_policy_file.as_os_str(),
            "/patched/path/to/policy"
        );
        let pools = config.pools.as_ref().unwrap();
        assert_eq!(
            pools.get("lo-ip").unwrap(),
            &ResourcePoolDef {
                ranges: Vec::new(),
                prefix: Some("10.180.63.0/26".to_string()),
                pool_type: resource_pool::ResourcePoolType::Ipv4
            }
        );
        assert!(pools.get("pkey").is_none());
    }

    #[test]
    fn deserialize_full_config() {
        let config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{}/full_config.toml", TEST_DATA_DIR)))
            .extract()
            .unwrap();
        assert_eq!(config.listen, "[::]:1081".parse().unwrap());
        assert_eq!(config.metrics_endpoint, Some("[::]:1080".parse().unwrap()));
        assert_eq!(config.database_url, "postgres://a:b@postgresql".to_string());
        assert!(!config.rapid_iterations);
        assert_eq!(config.asn, 123);
        assert_eq!(
            config.dhcp_servers,
            vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()]
        );
        assert_eq!(config.route_servers, vec!["9.10.11.12".to_string()]);
        assert_eq!(
            config.otlp_endpoint,
            Some("https://localhost:4317".to_string())
        );
        assert_eq!(
            config.tls.as_ref().unwrap().identity_pemfile_path,
            "/path/to/cert"
        );
        assert_eq!(
            config.tls.as_ref().unwrap().identity_keyfile_path,
            "/path/to/key"
        );
        assert_eq!(config.tls.as_ref().unwrap().root_cafile_path, "/path/to/ca");
        assert!(!config.auth.as_ref().unwrap().permissive_mode);
        assert_eq!(
            config.auth.as_ref().unwrap().casbin_policy_file.as_os_str(),
            "/path/to/policy"
        );
        let pools = config.pools.as_ref().unwrap();
        assert_eq!(
            pools.get("lo-ip").unwrap(),
            &ResourcePoolDef {
                ranges: Vec::new(),
                prefix: Some("10.180.62.1/26".to_string()),
                pool_type: resource_pool::ResourcePoolType::Ipv4
            }
        );
        assert_eq!(
            pools.get("vlan-id").unwrap(),
            &ResourcePoolDef {
                ranges: vec![resource_pool::Range {
                    start: "100".to_string(),
                    end: "501".to_string()
                }],
                prefix: None,
                pool_type: resource_pool::ResourcePoolType::Integer
            }
        );
        assert_eq!(
            pools.get("pkey").unwrap(),
            &ResourcePoolDef {
                ranges: vec![resource_pool::Range {
                    start: "1".to_string(),
                    end: "10".to_string()
                }],
                prefix: None,
                pool_type: resource_pool::ResourcePoolType::Integer
            }
        );
    }

    #[test]
    fn deserialize_patched_full_config() {
        let config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{}/full_config.toml", TEST_DATA_DIR)))
            .merge(Toml::file(format!("{}/site_config.toml", TEST_DATA_DIR)))
            .extract()
            .unwrap();
        assert_eq!(config.listen, "[::]:1081".parse().unwrap());
        assert_eq!(config.metrics_endpoint, Some("[::]:1080".parse().unwrap()));
        assert_eq!(config.database_url, "postgres://a:b@postgresql".to_string());
        assert_eq!(
            config.otlp_endpoint,
            Some("https://localhost:4399".to_string())
        );
        assert!(config.rapid_iterations);
        assert_eq!(config.asn, 777);
        assert_eq!(config.dhcp_servers, vec!["99.101.102.103".to_string()]);
        assert_eq!(config.route_servers, vec!["9.10.11.12".to_string()]);
        assert_eq!(
            config.tls.as_ref().unwrap().identity_pemfile_path,
            "/patched/path/to/cert"
        );
        assert_eq!(
            config.tls.as_ref().unwrap().identity_keyfile_path,
            "/patched/path/to/key"
        );
        assert_eq!(
            config.tls.as_ref().unwrap().root_cafile_path,
            "/patched/path/to/ca"
        );
        assert!(config.auth.as_ref().unwrap().permissive_mode);
        assert_eq!(
            config.auth.as_ref().unwrap().casbin_policy_file.as_os_str(),
            "/patched/path/to/policy"
        );
        let pools = config.pools.as_ref().unwrap();
        assert_eq!(
            pools.get("lo-ip").unwrap(),
            &ResourcePoolDef {
                ranges: Vec::new(),
                prefix: Some("10.180.63.0/26".to_string()),
                pool_type: resource_pool::ResourcePoolType::Ipv4
            }
        );
        assert_eq!(
            pools.get("vlan-id").unwrap(),
            &ResourcePoolDef {
                ranges: vec![resource_pool::Range {
                    start: "100".to_string(),
                    end: "501".to_string()
                }],
                prefix: None,
                pool_type: resource_pool::ResourcePoolType::Integer
            }
        );
        assert_eq!(
            pools.get("pkey").unwrap(),
            &ResourcePoolDef {
                ranges: vec![resource_pool::Range {
                    start: "1".to_string(),
                    end: "10".to_string()
                }],
                prefix: None,
                pool_type: resource_pool::ResourcePoolType::Integer
            }
        );
    }

    #[test]
    fn deserialize_env_patched_full_config() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("CARBIDE_API_DATABASE_URL", "postgres://othersql");
            jail.set_env("CARBIDE_API_ASN", 777);
            jail.set_env("CARBIDE_API_AUTH", "{permissive_mode=true}");
            jail.set_env(
                "CARBIDE_API_TLS",
                "{identity_pemfile_path=/patched/path/to/cert}",
            );

            let config: CarbideConfig = Figment::new()
                .merge(Toml::file(format!("{}/full_config.toml", TEST_DATA_DIR)))
                .merge(Env::prefixed("CARBIDE_API_"))
                .extract()
                .unwrap();
            assert_eq!(config.listen, "[::]:1081".parse().unwrap());
            assert_eq!(config.metrics_endpoint, Some("[::]:1080".parse().unwrap()));
            assert_eq!(
                config.otlp_endpoint,
                Some("https://localhost:4317".to_string())
            );
            assert_eq!(config.database_url, "postgres://othersql".to_string());
            assert!(!config.rapid_iterations);
            assert_eq!(config.asn, 777);
            assert_eq!(
                config.dhcp_servers,
                vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()]
            );
            assert_eq!(config.route_servers, vec!["9.10.11.12".to_string()]);
            assert_eq!(
                config.tls.as_ref().unwrap().identity_pemfile_path,
                "/patched/path/to/cert"
            );
            assert_eq!(
                config.tls.as_ref().unwrap().identity_keyfile_path,
                "/path/to/key"
            );
            assert_eq!(config.tls.as_ref().unwrap().root_cafile_path, "/path/to/ca");
            assert!(config.auth.as_ref().unwrap().permissive_mode);
            assert_eq!(
                config.auth.as_ref().unwrap().casbin_policy_file.as_os_str(),
                "/path/to/policy"
            );

            Ok(())
        })
    }
}
