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

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Describes the format of the configuration files that is used by Forge agents
/// that run on the DPU and host
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(rename = "forge-system")]
    pub forge_system: ForgeSystemConfig,
    pub machine: MachineConfig,
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
pub struct ForgeSystemConfig {
    #[serde(rename = "api-server")]
    pub api_server: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "pxe-server"
    )]
    pxe_server: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "ntp-server"
    )]
    ntp_server: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineConfig {
    #[serde(rename = "interface-id")]
    pub interface_id: uuid::Uuid,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "mac-address"
    )]
    mac_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_forge_agent_config() {
        let config = "[forge-system]
api-server = \"https://127.0.0.1:1234\"
pxe-server = \"http://127.0.0.1:8080\"

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
    }
}
