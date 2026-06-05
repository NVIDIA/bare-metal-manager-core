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
use std::string::ToString;

use forge_dpu_agent_utils::machine_identity::defaults::{
    BURST, REQUESTS_PER_SECOND, SIGN_TIMEOUT_SECS, WAIT_TIMEOUT_SECS,
};
use forge_tls::default as tls_default;
use serde::{Deserialize, Serialize};

/// HBN container root
const HBN_DEFAULT_ROOT: &str = "/var/lib/hbn";

/// Where DPU agent will try to connect to carbide-api
/// Unbound should define this in all environments
const DEFAULT_API_SERVER: &str = "https://carbide-api.forge";

// TODO(ianderson) we need to figure out the addresses on which those services should run
const INSTANCE_METADATA_SERVICE_ADDRESS: &str = "0.0.0.0:7777";
const TELEMETRY_METRICS_SERVICE_ADDRESS: &str = "0.0.0.0:8888";

/// The sub-part of the agent config that PXE server sets
///
/// This is what we WRITE to /etc/forge/config.toml
#[derive(Debug, Clone, Serialize)]
pub struct AgentConfigFromPxe {
    // This is primarily used in the case of "external" overrides. If a host is
    // being provisioned from an external location, this will ensure we correctly
    // populate the carbide-api endpoint with CARBIDE_EXTERNAL_API_URL, and
    // not [defaulting] to carbide-api.forge, to allow scout to work.
    #[serde(rename = "forge-system", skip_serializing_if = "Option::is_none")]
    pub forge_system: Option<ForgeSystemConfigFromPxe>,
    pub machine: MachineConfigFromPxe,
}

/// Optional forge-system overrides written by PXE for external hosts
/// whose DPU agents can't resolve the default internal hostname.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ForgeSystemConfigFromPxe {
    pub api_server: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MachineConfigFromPxe {
    pub interface_id: carbide_uuid::machine::MachineInterfaceId,
}

/// Describes the format of the configuration files that is used by Forge agents
/// that run on the DPU and host
///
/// This is what we READ from /etc/forge/config.toml. In prod most of the fields will default.
/// We only implement Serialize for unit tests.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default, rename = "forge-system")]
    pub forge_system: ForgeSystemConfig,
    pub machine: MachineConfig,
    #[serde(default, rename = "metadata-service")]
    pub metadata_service: MetadataServiceConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub hbn: HBNConfig,
    #[serde(default)]
    pub period: IterationTime,
    #[serde(default)]
    pub updates: UpdateConfig,
    #[serde(default, rename = "fmds-armos-networking")]
    pub fmds_armos_networking: FmdsDpuNetworkingConfig,
    #[serde(
        default,
        rename = "machine-identity",
        skip_serializing_if = "MachineIdentityConfig::is_default"
    )]
    pub machine_identity: MachineIdentityConfig,
}

impl AgentConfig {
    /// Loads the agent configuration file in toml format from the given path
    pub fn load_from(path: &Path) -> Result<Self, std::io::Error> {
        let data = std::fs::read_to_string(path)?;

        toml::from_str(&data).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid AgentConfig toml data: {e}"),
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ForgeSystemConfig {
    #[serde(default = "default_api_server")]
    pub api_server: String,
    #[serde(default = "default_root_ca")]
    pub root_ca: String,
    #[serde(default = "default_client_cert")]
    pub client_cert: String,
    #[serde(default = "default_client_key")]
    pub client_key: String,
}

// Called if no `[forge-system]` is provided at all.
// The serde defaults above are called if one or more fields are missing.
impl Default for ForgeSystemConfig {
    fn default() -> Self {
        Self {
            api_server: default_api_server(),
            root_ca: default_root_ca(),
            client_cert: default_client_cert(),
            client_key: default_client_key(),
        }
    }
}

pub fn default_api_server() -> String {
    DEFAULT_API_SERVER.to_string()
}

pub fn default_root_ca() -> String {
    tls_default::default_root_ca().to_string()
}

pub fn default_client_cert() -> String {
    tls_default::default_client_cert().to_string()
}

pub fn default_client_key() -> String {
    tls_default::default_client_key().to_string()
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MachineConfig {
    pub interface_id: Option<uuid::Uuid>,
    /// Local dev only. Pretend to be a DPU for discovery.
    /// If it's set to false, don't even serialize it out
    /// to config.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_fake_dpu: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataServiceConfig {
    pub address: String,
}

impl Default for MetadataServiceConfig {
    fn default() -> Self {
        Self {
            address: INSTANCE_METADATA_SERVICE_ADDRESS.to_string(),
        }
    }
}

/// Rate limit and timeout for `GET …/meta-data/identity` on the embedded metadata service
/// (paths such as `/latest/meta-data/identity` and `/2009-04-04/meta-data/identity`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MachineIdentityConfig {
    /// Sustained admission rate (Generic Cell Rate Algorithm refill), in requests per second.
    /// Valid range: 1–20.
    #[serde(default = "default_machine_identity_requests_per_second")]
    pub requests_per_second: u8,
    /// Maximum burst (cells) allowed by the rate limiter. Valid range: 1–40.
    #[serde(default = "default_machine_identity_burst")]
    pub burst: u8,
    /// Max time to wait for a rate-limit permit before failing the request (seconds).
    /// Applies to governor wait (`until_ready`), not to the Forge signing call.
    /// Valid range: 1–10.
    #[serde(default = "default_machine_identity_wait_timeout_secs")]
    pub wait_timeout_secs: u8,
    /// Wall-clock limit for the full Forge signing path on `GET …/meta-data/identity`
    /// (client build including connect retries, plus `SignMachineIdentity` RPC).
    /// Valid range: 1–60 seconds. Applies to the Forge gRPC signing path and to the optional
    /// HTTP sign proxy origin (`sign-proxy-url`).
    #[serde(default = "default_machine_identity_sign_timeout_secs")]
    pub sign_timeout_secs: u8,
    /// When set, `GET …/meta-data/identity` is forwarded over HTTP to `{url}/latest/meta-data/identity`
    /// with the same query string; the upstream response (status, body, `Content-Type`) is returned
    /// verbatim. When unset, the agent uses `SignMachineIdentity` gRPC to Forge.
    #[serde(default, rename = "sign-proxy-url")]
    pub sign_proxy_url: Option<String>,
    /// PEM file (one or more concatenated certificates) trusted as additional TLS roots when
    /// connecting to `sign-proxy-url` over HTTPS. Ignored for `http:` sign-proxy URLs.
    /// Requires `sign-proxy-url` to be set.
    #[serde(default, rename = "sign-proxy-tls-root-ca")]
    pub sign_proxy_tls_root_ca: Option<String>,
}

fn default_machine_identity_requests_per_second() -> u8 {
    REQUESTS_PER_SECOND
}

fn default_machine_identity_burst() -> u8 {
    BURST
}

fn default_machine_identity_wait_timeout_secs() -> u8 {
    WAIT_TIMEOUT_SECS
}

fn default_machine_identity_sign_timeout_secs() -> u8 {
    SIGN_TIMEOUT_SECS
}

impl Default for MachineIdentityConfig {
    fn default() -> Self {
        Self {
            requests_per_second: default_machine_identity_requests_per_second(),
            burst: default_machine_identity_burst(),
            wait_timeout_secs: default_machine_identity_wait_timeout_secs(),
            sign_timeout_secs: default_machine_identity_sign_timeout_secs(),
            sign_proxy_url: None,
            sign_proxy_tls_root_ca: None,
        }
    }
}

impl MachineIdentityConfig {
    pub fn validate(&self) -> Result<(), String> {
        use forge_dpu_agent_utils::machine_identity::limits::{
            BURST_MAX, BURST_MIN, REQUESTS_PER_SECOND_MAX, REQUESTS_PER_SECOND_MIN,
            SIGN_TIMEOUT_SECS_MAX, SIGN_TIMEOUT_SECS_MIN, WAIT_TIMEOUT_SECS_MAX,
            WAIT_TIMEOUT_SECS_MIN,
        };

        if !(REQUESTS_PER_SECOND_MIN..=REQUESTS_PER_SECOND_MAX).contains(&self.requests_per_second)
        {
            return Err(format!(
                "machine-identity.requests-per-second: must be between {REQUESTS_PER_SECOND_MIN} and {REQUESTS_PER_SECOND_MAX} (inclusive)"
            ));
        }
        if !(BURST_MIN..=BURST_MAX).contains(&self.burst) {
            return Err(format!(
                "machine-identity.burst: must be between {BURST_MIN} and {BURST_MAX} (inclusive)"
            ));
        }
        if !(WAIT_TIMEOUT_SECS_MIN..=WAIT_TIMEOUT_SECS_MAX).contains(&self.wait_timeout_secs) {
            return Err(format!(
                "machine-identity.wait-timeout-secs: must be between {WAIT_TIMEOUT_SECS_MIN} and {WAIT_TIMEOUT_SECS_MAX} (inclusive)"
            ));
        }
        if !(SIGN_TIMEOUT_SECS_MIN..=SIGN_TIMEOUT_SECS_MAX).contains(&self.sign_timeout_secs) {
            return Err(format!(
                "machine-identity.sign-timeout-secs: must be between {SIGN_TIMEOUT_SECS_MIN} and {SIGN_TIMEOUT_SECS_MAX} (inclusive)"
            ));
        }
        if let Some(ref raw) = self.sign_proxy_url {
            let s = raw.trim();
            if s.is_empty() {
                return Err(
                    "machine-identity.sign-proxy-url: must not be empty or whitespace-only"
                        .to_string(),
                );
            }
            let u = url::Url::parse(s)
                .map_err(|e| format!("machine-identity.sign-proxy-url: invalid URL ({e})"))?;
            match u.scheme() {
                "http" | "https" => {}
                other => {
                    return Err(format!(
                        "machine-identity.sign-proxy-url: scheme must be http or https, got {other}"
                    ));
                }
            }
        }
        if let Some(ref raw_ca) = self.sign_proxy_tls_root_ca {
            let path = raw_ca.trim();
            if path.is_empty() {
                return Err(
                    "machine-identity.sign-proxy-tls-root-ca: must not be empty or whitespace-only"
                        .to_string(),
                );
            }
            let url_ok = self
                .sign_proxy_url
                .as_ref()
                .is_some_and(|u| !u.trim().is_empty());
            if !url_ok {
                return Err(
                    "machine-identity.sign-proxy-tls-root-ca: requires machine-identity.sign-proxy-url"
                        .to_string(),
                );
            }
            let pem = std::fs::read(path).map_err(|e| {
                format!("machine-identity.sign-proxy-tls-root-ca: failed to read {path}: {e}")
            })?;
            if pem.is_empty() {
                return Err(format!(
                    "machine-identity.sign-proxy-tls-root-ca: file is empty: {path}"
                ));
            }
            let mut cursor = std::io::Cursor::new(&pem[..]);
            let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    format!("machine-identity.sign-proxy-tls-root-ca: invalid PEM in {path}: {e}")
                })?;
            if certs.is_empty() {
                return Err(format!(
                    "machine-identity.sign-proxy-tls-root-ca: no certificates found in {path}"
                ));
            }
        }
        Ok(())
    }

    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TelemetryConfig {
    pub metrics_address: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            metrics_address: TELEMETRY_METRICS_SERVICE_ADDRESS.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HBNConfig {
    /// Where to write the network config files
    pub root_dir: PathBuf,
    /// Do not run the config reload commands. Local dev only.
    pub skip_reload: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpuNetworkingInterface {
    pub addresses: Vec<ipnetwork::IpNetwork>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FmdsDpuNetworkingConfig {
    pub config: DpuNetworkingInterface,
}

impl Default for FmdsDpuNetworkingConfig {
    fn default() -> Self {
        Self {
            config: DpuNetworkingInterface {
                addresses: vec!["169.254.169.254/30".to_string().parse().unwrap()],
            },
        }
    }
}

impl Default for HBNConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from(HBN_DEFAULT_ROOT),
            skip_reload: false,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct UpdateConfig {
    /// Override normal upgrade command. For automated testing only.
    #[serde(default)]
    pub override_upgrade_cmd: Option<String>,
}

impl UpdateConfig {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct IterationTime {
    /// How often to report network health and poll for new configs when in stable state.
    /// Eventually we will need an event system. Block storage requires very fast DPU responses.
    pub main_loop_idle_secs: u64,

    /// How often to report network health and poll for new configs when things are in flux.
    /// This should be slightly bigger than bgpTimerHoldTimeMsecs as displayed in HBN
    /// container by 'show bgp neighbors json' - which is currently 9s.
    pub main_loop_active_secs: u64,

    /// How often we fetch the desired network configuration for a host
    pub network_config_fetch_secs: u64,

    /// How often to check if we have latest forge-dpu-agent version
    pub version_check_secs: u64,

    /// How often to update inventory
    #[serde(default = "default_inventory_update_secs")]
    pub inventory_update_secs: u64,

    /// How often to retry discover_machine registration
    /// calls in the event that retries are necessary.
    /// Default is every 60 seconds.
    #[serde(default = "default_discovery_retry_secs")]
    pub discovery_retry_secs: u64,

    /// How many times to retry discover_machine registration
    /// calls until giving up. Default is 10080, which,
    /// combine with the default discovery_retry_secs of 60,
    /// equals retrying for 1 week.
    #[serde(default = "default_discovery_retries_max")]
    pub discovery_retries_max: u32,
}

fn default_inventory_update_secs() -> u64 {
    3600u64
}

fn default_discovery_retry_secs() -> u64 {
    60u64
}

fn default_discovery_retries_max() -> u32 {
    10080u32
}

impl Default for IterationTime {
    fn default() -> Self {
        Self {
            main_loop_idle_secs: 30,
            main_loop_active_secs: 10,
            network_config_fetch_secs: 30,
            version_check_secs: 600, // 10 minutes
            inventory_update_secs: default_inventory_update_secs(),
            discovery_retry_secs: default_discovery_retry_secs(),
            discovery_retries_max: default_discovery_retries_max(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const TEST_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test");

    #[test]
    fn machine_identity_config_validate_accepts_defaults() {
        assert!(MachineIdentityConfig::default().validate().is_ok());
    }

    #[test]
    fn machine_identity_config_validate_rejects_rps_out_of_range() {
        let c = MachineIdentityConfig {
            requests_per_second: 0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
        let c = MachineIdentityConfig {
            requests_per_second: 21,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn machine_identity_config_validate_rejects_burst_out_of_range() {
        let c = MachineIdentityConfig {
            burst: 0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
        let c = MachineIdentityConfig {
            burst: 41,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn machine_identity_config_validate_accepts_boundary_values() {
        let c = MachineIdentityConfig {
            requests_per_second: 20,
            burst: 40,
            wait_timeout_secs: 10,
            sign_timeout_secs: 1,
            ..Default::default()
        };
        assert!(c.validate().is_ok());
        let c = MachineIdentityConfig {
            sign_timeout_secs: 60,
            ..c
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn machine_identity_config_validate_rejects_sign_timeout_out_of_range() {
        let c = MachineIdentityConfig {
            sign_timeout_secs: 0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
        let c = MachineIdentityConfig {
            sign_timeout_secs: 61,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn machine_identity_config_validate_accepts_sign_proxy_url() {
        let c = MachineIdentityConfig {
            sign_proxy_url: Some("https://idp.example.com/prefix".to_string()),
            ..Default::default()
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn machine_identity_config_validate_rejects_sign_proxy_url_whitespace_only() {
        let c = MachineIdentityConfig {
            sign_proxy_url: Some("   ".to_string()),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn machine_identity_config_validate_rejects_sign_proxy_url_scheme() {
        let c = MachineIdentityConfig {
            sign_proxy_url: Some("ftp://x".to_string()),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn machine_identity_config_validate_rejects_sign_proxy_tls_root_ca_without_url() {
        let c = MachineIdentityConfig {
            sign_proxy_tls_root_ca: Some("/etc/forge/sign_proxy_ca.pem".to_string()),
            ..Default::default()
        };
        let err = c.validate().unwrap_err();
        assert!(err.contains("sign-proxy-url"));
    }

    #[test]
    fn machine_identity_config_validate_rejects_sign_proxy_tls_root_ca_whitespace_only() {
        let c = MachineIdentityConfig {
            sign_proxy_url: Some("https://x.example".to_string()),
            sign_proxy_tls_root_ca: Some("  \t  ".to_string()),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn machine_identity_config_validate_accepts_sign_proxy_tls_root_ca_with_pem_file() {
        let pem_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../dev/certs/forge_root.pem"
        );
        let c = MachineIdentityConfig {
            sign_proxy_url: Some("https://sign-proxy.example".to_string()),
            sign_proxy_tls_root_ca: Some(pem_path.to_string()),
            ..Default::default()
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn machine_identity_config_validate_rejects_sign_proxy_tls_root_ca_invalid_pem() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        f.write_all(b"not a certificate").unwrap();
        let c = MachineIdentityConfig {
            sign_proxy_url: Some("https://x".to_string()),
            sign_proxy_tls_root_ca: Some(f.path().to_string_lossy().into_owned()),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn machine_identity_config_validate_rejects_wait_timeout_out_of_range() {
        let c = MachineIdentityConfig {
            wait_timeout_secs: 0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
        let c = MachineIdentityConfig {
            wait_timeout_secs: 11,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    // Load up the input, which is a minimum barebones
    // config, and then dump it back out to a string,
    // which should then have defaults set (and match
    // the expected output config).
    fn test_load_forge_agent_config_defaults() {
        let input_config: AgentConfig = toml::from_str(
            fs::read_to_string(format!("{TEST_DATA_DIR}/min_agent_config/input.toml"))
                .unwrap()
                .as_str(),
        )
        .unwrap();
        let observed_output = toml::to_string(&input_config).unwrap();
        let expected_output =
            fs::read_to_string(format!("{TEST_DATA_DIR}/min_agent_config/output.toml")).unwrap();
        assert_eq!(observed_output, expected_output);
    }

    #[test]
    fn test_load_forge_agent_config_full() {
        let config = r#"[forge-system]
api-server = "https://127.0.0.1:1234"
root-ca = "/opt/forge/forge_root.pem"

[machine]
is-fake-dpu = true
interface-id = "91609f10-c91d-470d-a260-6293ea0c1200"

[metadata-service]
address = "0.0.0.0:7777"

[telemetry]
metrics-address = "0.0.0.0:8888"

[hbn]
root-dir = "/tmp/hbn-root"
skip-reload = true

[period]
main-loop-active-secs = 10
main-loop-idle-secs = 30
network-config-fetch-secs = 20
version-check-secs = 600
inventory-update-secs = 3600
discovery-retry-secs = 1
discovery-retries-max = 1000

[updates]
override-upgrade-cmd = "update"

[fmds-armos-networking.config]
addresses = ["168.254.169.254/30"]
"#;

        let config: AgentConfig = toml::from_str(config).unwrap();

        assert_eq!(config.forge_system.api_server, "https://127.0.0.1:1234");
        assert_eq!(
            config.machine.interface_id,
            Some(uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200"))
        );
        assert!(config.machine.is_fake_dpu);

        assert_eq!(config.metadata_service.address, "0.0.0.0:7777");
        assert_eq!(config.telemetry.metrics_address, "0.0.0.0:8888");

        assert_eq!(config.hbn.root_dir, PathBuf::from("/tmp/hbn-root"));
        assert!(config.hbn.skip_reload);

        assert_eq!(
            config.updates.override_upgrade_cmd,
            Some("update".to_string())
        );
    }

    #[test]
    fn test_load_forge_agent_config_machine_identity_section() {
        let raw = r#"[forge-system]
api-server = "https://127.0.0.1:1234"
root-ca = "/opt/forge/forge_root.pem"

[machine]
interface-id = "91609f10-c91d-470d-a260-6293ea0c1200"

[machine-identity]
requests-per-second = 7
burst = 12
wait-timeout-secs = 4
sign-timeout-secs = 9
"#;

        let config: AgentConfig = toml::from_str(raw).unwrap();

        assert_eq!(config.machine_identity.requests_per_second, 7);
        assert_eq!(config.machine_identity.burst, 12);
        assert_eq!(config.machine_identity.wait_timeout_secs, 4);
        assert_eq!(config.machine_identity.sign_timeout_secs, 9);
        assert!(config.machine_identity.sign_proxy_url.is_none());
        assert!(config.machine_identity.sign_proxy_tls_root_ca.is_none());

        config.machine_identity.validate().unwrap();
    }

    #[test]
    fn test_load_forge_agent_config_without_services() {
        let config = "[forge-system]
api-server = \"https://127.0.0.1:1234\"
root-ca = \"/opt/forge/forge_root.pem\"

[machine]
interface-id = \"91609f10-c91d-470d-a260-6293ea0c1200\"
";

        let config: AgentConfig = toml::from_str(config).unwrap();

        assert_eq!(config.forge_system.api_server, "https://127.0.0.1:1234");
        assert_eq!(
            config.machine.interface_id,
            Some(uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200"))
        );
        assert!(!config.machine.is_fake_dpu);

        assert_eq!(config.metadata_service, MetadataServiceConfig::default());
        assert_eq!(config.telemetry, TelemetryConfig::default());
        assert_eq!(config.machine_identity, MachineIdentityConfig::default());

        assert_eq!(config.hbn.root_dir, PathBuf::from(HBN_DEFAULT_ROOT));
        assert!(!config.hbn.skip_reload);

        assert!(config.updates.override_upgrade_cmd.is_none());
    }
}
