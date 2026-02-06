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
    pub machine: MachineConfigFromPxe,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MachineConfigFromPxe {
    pub interface_id: uuid::Uuid,
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

        assert_eq!(config.hbn.root_dir, PathBuf::from(HBN_DEFAULT_ROOT));
        assert!(!config.hbn.skip_reload);

        assert!(config.updates.override_upgrade_cmd.is_none());
    }
}
