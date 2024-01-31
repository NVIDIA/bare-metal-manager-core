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

use std::net::SocketAddr;
use std::path::PathBuf;
use std::{collections::HashMap, fmt::Display};

use ipnetwork::Ipv4Network;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{model::network_segment::NetworkDefinition, resource_pool::ResourcePoolDef};

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

    /// Enable IB fabric manager
    pub enable_ib_fabric: Option<bool>,

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

    #[serde(default)]
    pub enable_route_servers: bool,

    /// List of IPv4 prefixes (in CIDR notation) that tenant instances are not allowed to talk to.
    #[serde(default)]
    pub deny_prefixes: Vec<Ipv4Network>,

    /// List of IPv4 prefixes (in CIDR notation) that are assigned for tenant
    /// use within this site.
    #[serde(default)]
    pub site_fabric_prefixes: Vec<Ipv4Network>,

    /// TLS related configuration
    pub tls: Option<TlsConfig>,

    /// Authentication related configuration
    pub auth: Option<AuthConfig>,

    // Resource pools to allocate IPs, VNIs, etc.
    // Required.
    // Option so that we can de-serialize partial configs (and then merge them).
    pub pools: Option<HashMap<String, ResourcePoolDef>>,

    // Networks to create. Otherwise use grpcurl CreateNetworkSegment to create them later.
    pub networks: Option<HashMap<String, NetworkDefinition>>,

    // The type of ipmitool to user (prod or fake)
    pub dpu_impi_tool_impl: Option<String>,

    // The number of retries to perform if ipmi returns an error
    pub dpu_ipmi_reboot_attempts: Option<u32>,

    /// Domain to create if there are no domains.
    ///
    /// Most sites use a single domain for their lifetime. This is that domain.
    /// The alternative is to create it via `CreateDomain` grpc endpoint.
    pub initial_domain_name: Option<String>,

    /// The policy we use to decide whether a specific forge-dpu-agent should be upgraded
    /// Also settable via a `forge-admin-cli` command.
    pub initial_dpu_agent_upgrade_policy: Option<AgentUpgradePolicyChoice>,

    /// The version of DPU NIC firmware that is expected on the DPU.  If the actual DPU NIC firmware
    /// does not match, the DPU will be updated during reprovisioning.  It is the operators responsibilty
    /// to make sure this value matches the version shipped with carbide.  If "None" updates
    /// during reprovisioning will be disabled
    pub dpu_nic_firmware_update_version: Option<HashMap<String, String>>,

    /// Enable dpu firmware updates on initial discovery
    #[serde(default)]
    pub dpu_nic_firmware_initial_update_enabled: bool,

    /// Enable dpu firmware updates on known machines
    #[serde(default)]
    pub dpu_nic_firmware_reprovision_update_enabled: bool,

    /// The maximum number of machines that have in-progress updates running.  This prevents
    /// too many machines from being put into maintenance at any given time.
    pub max_concurrent_machine_updates: Option<i32>,

    /// The interval at which the machine update manager checks for machine updates in seconds.
    pub machine_update_run_interval: Option<u64>,

    /// SiteExplorer related configuration
    pub site_explorer: Option<SiteExplorerConfig>,

    /// Enable DHCP server on DPU to serve host.
    #[serde(default)]
    pub dpu_dhcp_server_enabled: bool,
}

/// SiteExplorer related configuration
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct SiteExplorerConfig {
    #[serde(default)]
    /// Whether SiteExplorer is enabled
    pub enabled: bool,
    /// The interval at which site explorer runs in seconds.
    /// Defaults to 5 Minutes if not specified.
    #[serde(default = "SiteExplorerConfig::default_run_interval_s")]
    pub run_interval: u64,
    /// The maximum amount of nodes that are explored concurrently.
    /// Default is 5.
    #[serde(default = "SiteExplorerConfig::default_concurrent_explorations")]
    pub concurrent_explorations: u64,
    /// How many nodes should be explored in a single run.
    /// Default is 10.
    /// This number deviced by `concurrent_explorations` will determine how many
    /// exploration batches are needed inside a run.
    /// If the value is set too high the site exploration will take a lot of time
    /// and the exploration report will be updated less frequent. Therefore it
    /// is recommended to reduce `run_interval` instead of increasing
    /// `explorations_per_run`.
    #[serde(default = "SiteExplorerConfig::default_explorations_per_run")]
    pub explorations_per_run: u64,
}

impl SiteExplorerConfig {
    const fn default_run_interval_s() -> u64 {
        300
    }

    const fn default_concurrent_explorations() -> u64 {
        5
    }

    const fn default_explorations_per_run() -> u64 {
        10
    }
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

// Should match api/src/model/machine/upgrade_policy.rs DpuAgentUpgradePolicy
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentUpgradePolicyChoice {
    Off,
    UpOnly,
    UpDown,
}

impl Display for AgentUpgradePolicyChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

fn default_listen() -> SocketAddr {
    "[::]:1079".parse().unwrap()
}

impl From<CarbideConfig> for rpc::forge::RuntimeConfig {
    fn from(value: CarbideConfig) -> Self {
        Self {
            listen: value.listen.to_string(),
            metrics_endpoint: value
                .metrics_endpoint
                .map(|x| x.to_string())
                .unwrap_or("NA".to_string()),
            otlp_endpoint: value
                .otlp_endpoint
                .map(|x| x.to_string())
                .unwrap_or("NA".to_string()),
            database_url: value.database_url,
            enable_ip_fabric: value.enable_ib_fabric.unwrap_or_default(),
            rapid_iterations: value.rapid_iterations,
            asn: value.asn,
            dhcp_servers: value.dhcp_servers,
            route_servers: value.route_servers,
            enable_route_servers: value.enable_route_servers,
            deny_prefixes: value
                .deny_prefixes
                .into_iter()
                .map(|x| x.to_string())
                .collect(),
            site_fabric_prefixes: value
                .site_fabric_prefixes
                .into_iter()
                .map(|x| x.to_string())
                .collect(),
            networks: value
                .networks
                .unwrap_or_default()
                .keys()
                .cloned()
                .collect_vec(),
            dpu_ipmi_tool_impl: value.dpu_impi_tool_impl.unwrap_or("Not Set".to_string()),
            dpu_ipmi_reboot_attempt: value.dpu_ipmi_reboot_attempts.unwrap_or_default(),
            initial_domain_name: value.initial_domain_name,
            initial_dpu_agent_upgrade_policy: value
                .initial_dpu_agent_upgrade_policy
                .unwrap_or(AgentUpgradePolicyChoice::Off)
                .to_string(),
            dpu_nic_firmware_update_version: value
                .dpu_nic_firmware_update_version
                .unwrap_or_default(),
            dpu_nic_firmware_initial_update_enabled: value.dpu_nic_firmware_initial_update_enabled,
            dpu_nic_firmware_reprovision_update_enabled: value
                .dpu_nic_firmware_reprovision_update_enabled,
            max_concurrent_machine_updates: value
                .max_concurrent_machine_updates
                .unwrap_or_default(),
            machine_update_runtime_interval: value.machine_update_run_interval.unwrap_or_default(),
            dpu_dhcp_server_enabled: value.dpu_dhcp_server_enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use figment::{
        providers::{Env, Format, Toml},
        Figment,
    };

    use super::*;
    use crate::resource_pool;

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
        assert!(config.site_explorer.is_none());
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
        assert_eq!(
            config.site_explorer.as_ref().unwrap(),
            &SiteExplorerConfig {
                enabled: true,
                run_interval: 300,
                concurrent_explorations: 10,
                explorations_per_run: 12,
            }
        );
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
        assert_eq!(
            config.site_explorer.as_ref().unwrap(),
            &SiteExplorerConfig {
                enabled: false,
                run_interval: 100,
                concurrent_explorations: 5,
                explorations_per_run: 11,
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
        assert_eq!(
            config.site_explorer.as_ref().unwrap(),
            &SiteExplorerConfig {
                enabled: true,
                run_interval: 100,
                concurrent_explorations: 10,
                explorations_per_run: 12,
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
