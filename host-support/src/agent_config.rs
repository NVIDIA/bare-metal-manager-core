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

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// HBN container root
const HBN_DEFAULT_ROOT: &str = "/var/lib/hbn";

/// Describes the format of the configuration files that is used by Forge agents
/// that run on the DPU and host
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(rename = "forge-system")]
    pub forge_system: ForgeSystemConfig,
    pub machine: MachineConfig,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "metadata-service"
    )]
    pub metadata_service: Option<MetadataServiceConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<TelemetryConfig>,
    #[serde(default)]
    pub hbn: HBNConfig,
}

impl AgentConfig {
    /// Loads the agent configuration file in toml format from the given path
    pub fn load_from(path: &Path) -> Result<Self, std::io::Error> {
        let data = std::fs::read(path)?;

        toml::from_slice(&data).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid AgentConfig toml data: {}", e),
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ForgeSystemConfig {
    pub api_server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pxe_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ntp_server: Option<String>,
    #[serde(default = "default_root_ca")]
    pub root_ca: String,
    #[serde(default = "default_client_cert")]
    pub client_cert: String,
    #[serde(default = "default_client_key")]
    pub client_key: String,
}

fn default_root_ca() -> String {
    rpc::forge_tls_client::default_root_ca().to_string()
}

fn default_client_cert() -> String {
    rpc::forge_tls_client::default_client_cert().to_string()
}

fn default_client_key() -> String {
    rpc::forge_tls_client::default_client_key().to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MachineConfig {
    pub interface_id: uuid::Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mac_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(default)]
    /// Local dev only. Pretend to be a DPU for discovery.
    pub is_fake_dpu: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataServiceConfig {
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TelemetryConfig {
    pub metrics_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HBNConfig {
    /// Where to write the network config files
    pub root_dir: PathBuf,
    /// Do not run the config reload commands. Local dev only.
    pub skip_reload: bool,
}

impl Default for HBNConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from(HBN_DEFAULT_ROOT),
            skip_reload: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_forge_agent_config_full() {
        let config = r#"[forge-system]
api-server = "https://127.0.0.1:1234"
pxe-server = "http://127.0.0.1:8080"
root-ca = "/opt/forge/forge_root.pem"

[machine]
is-fake-dpu = true
interface-id = "91609f10-c91d-470d-a260-6293ea0c1200"
mac-address = "11:22:33:44:55:66"
hostname = "abc.forge.com"

[metadata-service]
address = "0.0.0.0:7777"

[telemetry]
metrics-address = "0.0.0.0:8888"

[hbn]
root-dir = "/tmp/hbn-root"
skip-reload = true
"#;

        let config: AgentConfig = toml::from_str(config).unwrap();

        assert_eq!(config.forge_system.api_server, "https://127.0.0.1:1234");
        assert_eq!(
            config.forge_system.pxe_server.as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(config.forge_system.ntp_server, None);
        assert_eq!(
            config.machine.interface_id,
            uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200")
        );
        assert_eq!(
            config.machine.mac_address.as_deref(),
            Some("11:22:33:44:55:66")
        );
        assert_eq!(config.machine.hostname.as_deref(), Some("abc.forge.com"));
        assert!(config.machine.is_fake_dpu);

        assert_eq!(config.metadata_service.unwrap().address, "0.0.0.0:7777");
        assert_eq!(config.telemetry.unwrap().metrics_address, "0.0.0.0:8888");

        assert_eq!(config.hbn.root_dir, PathBuf::from("/tmp/hbn-root"));
        assert!(config.hbn.skip_reload);
    }

    #[test]
    fn test_load_forge_agent_config_without_services() {
        let config = "[forge-system]
api-server = \"https://127.0.0.1:1234\"
pxe-server = \"http://127.0.0.1:8080\"
root-ca = \"/opt/forge/forge_root.pem\"

[machine]
interface-id = \"91609f10-c91d-470d-a260-6293ea0c1200\"
mac-address = \"11:22:33:44:55:66\"
hostname = \"abc.forge.com\"
";

        let config: AgentConfig = toml::from_str(config).unwrap();

        assert_eq!(config.forge_system.api_server, "https://127.0.0.1:1234");
        assert_eq!(
            config.forge_system.pxe_server.as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(config.forge_system.ntp_server, None);
        assert_eq!(
            config.machine.interface_id,
            uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200")
        );
        assert_eq!(
            config.machine.mac_address.as_deref(),
            Some("11:22:33:44:55:66")
        );
        assert_eq!(config.machine.hostname.as_deref(), Some("abc.forge.com"));
        assert!(!config.machine.is_fake_dpu);

        assert_eq!(config.metadata_service, None);
        assert_eq!(config.telemetry, None);

        assert_eq!(config.hbn.root_dir, PathBuf::from(HBN_DEFAULT_ROOT));
        assert!(!config.hbn.skip_reload);
    }
}
