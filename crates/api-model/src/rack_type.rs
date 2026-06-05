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

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// RackHardwareType identifies the hardware type of a rack.
/// This is a flexible string-based type to allow new hardware types
/// without code changes. The special value "any" indicates firmware
/// that is compatible with any rack hardware type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
#[serde(transparent)]
pub struct RackHardwareType(pub String);

impl RackHardwareType {
    /// Returns a RackHardwareType that matches any rack hardware.
    pub fn any() -> Self {
        Self("any".to_string())
    }

    /// Returns true if this is the wildcard "any" type.
    pub fn is_any(&self) -> bool {
        self.0 == "any"
    }
}

impl Default for RackHardwareType {
    fn default() -> Self {
        Self::any()
    }
}

impl fmt::Display for RackHardwareType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for RackHardwareType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for RackHardwareType {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// RackHardwareTopology describes the hardware topology of a rack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)] // Topology suffix is part of the canonical config names
pub enum RackHardwareTopology {
    Gb200Nvl36r1C2g4Topology,
    Gb300Nvl36r1C2g4Topology,
    Gb200Nvl72r1C2g4Topology,
    Gb300Nvl72r1C2g4Topology,
    VrNvl8r1C2g4RtfTopology,
    VrNvl72r1C2g4Topology,
}

impl fmt::Display for RackHardwareTopology {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RackHardwareTopology::Gb200Nvl36r1C2g4Topology => {
                write!(f, "gb200_nvl36r1_c2g4_topology")
            }
            RackHardwareTopology::Gb300Nvl36r1C2g4Topology => {
                write!(f, "gb300_nvl36r1_c2g4_topology")
            }
            RackHardwareTopology::Gb200Nvl72r1C2g4Topology => {
                write!(f, "gb200_nvl72r1_c2g4_topology")
            }
            RackHardwareTopology::Gb300Nvl72r1C2g4Topology => {
                write!(f, "gb300_nvl72r1_c2g4_topology")
            }
            RackHardwareTopology::VrNvl8r1C2g4RtfTopology => {
                write!(f, "vr_nvl8r1_c2g4_rtf_topology")
            }
            RackHardwareTopology::VrNvl72r1C2g4Topology => {
                write!(f, "vr_nvl72r1_c2g4_topology")
            }
        }
    }
}

/// RackHardwareClass indicates whether a rack is a dev or production rack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RackHardwareClass {
    Dev,
    Prod,
}

impl fmt::Display for RackHardwareClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RackHardwareClass::Dev => write!(f, "dev"),
            RackHardwareClass::Prod => write!(f, "prod"),
        }
    }
}

/* ********************************** */
/*        RackCapabilityType          */
/* ********************************** */

/// RackCapabilityType represents a category of rack component capability.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum RackCapabilityType {
    Compute,
    Switch,
    PowerShelf,
}

impl fmt::Display for RackCapabilityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RackCapabilityType::Compute => write!(f, "Compute"),
            RackCapabilityType::Switch => write!(f, "Switch"),
            RackCapabilityType::PowerShelf => write!(f, "PowerShelf"),
        }
    }
}

/* ********************************** */
/*       RackCapabilityCompute        */
/* ********************************** */

/// RackCapabilityCompute describes the expected compute tray capability
/// for a rack type.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RackCapabilityCompute {
    /// Model name of the compute tray (e.g. "GB200").
    #[serde(default)]
    pub name: Option<String>,

    /// Number of compute trays expected in the rack.
    pub count: u32,

    /// Vendor name (e.g. "NVIDIA").
    #[serde(default)]
    pub vendor: Option<String>,

    /// Slot IDs that compute trays are expected to occupy.
    #[serde(default)]
    pub slot_ids: Option<Vec<u32>>,
}

/* ********************************** */
/*        RackCapabilitySwitch        */
/* ********************************** */

/// RackCapabilitySwitch describes the expected switch capability
/// for a rack type.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RackCapabilitySwitch {
    /// Model name of the switch.
    #[serde(default)]
    pub name: Option<String>,

    /// Number of switches expected in the rack.
    pub count: u32,

    /// Vendor name.
    #[serde(default)]
    pub vendor: Option<String>,

    /// Slot IDs that switches are expected to occupy.
    #[serde(default)]
    pub slot_ids: Option<Vec<u32>>,
}

/* ********************************** */
/*      RackCapabilityPowerShelf      */
/* ********************************** */

/// RackCapabilityPowerShelf describes the expected power shelf capability
/// for a rack type.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RackCapabilityPowerShelf {
    /// Model name of the power shelf.
    #[serde(default)]
    pub name: Option<String>,

    /// Number of power shelves expected in the rack.
    pub count: u32,

    /// Vendor name.
    #[serde(default)]
    pub vendor: Option<String>,

    /// Slot IDs that power shelves are expected to occupy.
    #[serde(default)]
    pub slot_ids: Option<Vec<u32>>,
}

/* ********************************** */
/*       RackCapabilitiesSet          */
/* ********************************** */

/// RackCapabilitiesSet is the combined set of all expected rack component
/// capabilities. It describes what a rack should contain in terms of
/// compute trays, switches, and power shelves.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RackCapabilitiesSet {
    pub compute: RackCapabilityCompute,
    pub switch: RackCapabilitySwitch,
    pub power_shelf: RackCapabilityPowerShelf,
}

/* ********************************** */
/*           RackProfile              */
/* ********************************** */

/// RackProfile describes the hardware identity and expected device
/// capabilities for a class of rack. The profile is referenced by name
/// (the map key in the config file) from expected racks and rack configs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RackProfile {
    #[serde(default)]
    pub rack_hardware_type: Option<RackHardwareType>,

    #[serde(default)]
    pub rack_hardware_topology: Option<RackHardwareTopology>,

    #[serde(default)]
    pub rack_hardware_class: Option<RackHardwareClass>,

    pub rack_capabilities: RackCapabilitiesSet,
}

/* ********************************** */
/*        RackProfileConfig           */
/* ********************************** */

/// RackProfileConfig contains all known rack profiles, keyed by profile id.
/// Loaded from the Carbide configuration file and used to validate that
/// the correct number of expected devices have been registered for a rack.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RackProfileConfig {
    /// Map of rack profile id to its profile.
    #[serde(default, flatten)]
    pub rack_profiles: HashMap<String, RackProfile>,
}

impl RackProfileConfig {
    /// get looks up a rack profile by the profile ID.
    pub fn get(&self, name: &str) -> Option<&RackProfile> {
        self.rack_profiles.get(name)
    }

    /// keys returns all known rack profile IDs.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.rack_profiles.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rack_profile_config_lookup() {
        let mut config = RackProfileConfig::default();
        config.rack_profiles.insert(
            "NVL72".to_string(),
            RackProfile {
                rack_capabilities: RackCapabilitiesSet {
                    compute: RackCapabilityCompute {
                        name: Some("GB200".to_string()),
                        count: 18,
                        vendor: Some("NVIDIA".to_string()),
                        slot_ids: None,
                    },
                    switch: RackCapabilitySwitch {
                        name: None,
                        count: 9,
                        vendor: None,
                        slot_ids: None,
                    },
                    power_shelf: RackCapabilityPowerShelf {
                        name: None,
                        count: 8,
                        vendor: None,
                        slot_ids: None,
                    },
                },
                ..Default::default()
            },
        );

        let profile = config.get("NVL72").unwrap();
        assert_eq!(profile.rack_capabilities.compute.count, 18);
        assert_eq!(profile.rack_capabilities.switch.count, 9);
        assert_eq!(profile.rack_capabilities.power_shelf.count, 8);

        assert!(config.get("nonexistent").is_none());
    }

    #[test]
    fn test_rack_profile_config_toml_deserialization() {
        let toml_str = r#"
[NVL72.rack_capabilities.compute]
name = "GB200"
count = 18
vendor = "NVIDIA"

[NVL72.rack_capabilities.switch]
count = 9

[NVL72.rack_capabilities.power_shelf]
count = 8

[NVL36.rack_capabilities.compute]
count = 9

[NVL36.rack_capabilities.switch]
count = 9

[NVL36.rack_capabilities.power_shelf]
count = 2
"#;
        let config: RackProfileConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.rack_profiles.len(), 2);

        let nvl72 = config.get("NVL72").unwrap();
        assert_eq!(nvl72.rack_capabilities.compute.count, 18);
        assert_eq!(
            nvl72.rack_capabilities.compute.name.as_deref(),
            Some("GB200")
        );

        let nvl36 = config.get("NVL36").unwrap();
        assert_eq!(nvl36.rack_capabilities.compute.count, 9);
        assert_eq!(nvl36.rack_capabilities.switch.count, 9);
        assert_eq!(nvl36.rack_capabilities.power_shelf.count, 2);
    }

    #[test]
    fn test_rack_profile_config_toml_with_hardware_fields() {
        let toml_str = r#"
[NVL72]
rack_hardware_type = "dsx_gb200nvl_72x1"
rack_hardware_topology = "gb200_nvl72r1_c2g4_topology"
rack_hardware_class = "prod"

[NVL72.rack_capabilities.compute]
name = "GB200"
count = 18
vendor = "NVIDIA"

[NVL72.rack_capabilities.switch]
count = 9

[NVL72.rack_capabilities.power_shelf]
count = 8
"#;
        let config: RackProfileConfig = toml::from_str(toml_str).unwrap();
        let nvl72 = config.get("NVL72").unwrap();

        assert_eq!(
            nvl72.rack_hardware_type,
            Some(RackHardwareType::from("dsx_gb200nvl_72x1"))
        );
        assert_eq!(
            nvl72.rack_hardware_topology,
            Some(RackHardwareTopology::Gb200Nvl72r1C2g4Topology)
        );
        assert_eq!(nvl72.rack_hardware_class, Some(RackHardwareClass::Prod));
        assert_eq!(nvl72.rack_capabilities.compute.count, 18);
    }

    #[test]
    fn test_rack_profile_config_toml_without_hardware_fields_defaults_to_none() {
        let toml_str = r#"
[NVL36.rack_capabilities.compute]
count = 9
[NVL36.rack_capabilities.switch]
count = 9
[NVL36.rack_capabilities.power_shelf]
count = 2
"#;
        let config: RackProfileConfig = toml::from_str(toml_str).unwrap();
        let nvl36 = config.get("NVL36").unwrap();

        assert_eq!(nvl36.rack_hardware_type, None);
        assert_eq!(nvl36.rack_hardware_topology, None);
        assert_eq!(nvl36.rack_hardware_class, None);
    }

    // RackHardwareType tests.

    #[test]
    fn test_rack_hardware_type_serde_round_trip() {
        let hw_type = RackHardwareType::from("dsx_gb200nvl_72x1");
        let json = serde_json::to_string(&hw_type).unwrap();
        assert_eq!(json, "\"dsx_gb200nvl_72x1\"");
        let deserialized: RackHardwareType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, hw_type);
    }

    #[test]
    fn test_rack_hardware_type_display() {
        assert_eq!(RackHardwareType::any().to_string(), "any");
        assert_eq!(
            RackHardwareType::from("dsx_gb200nvl_72x1").to_string(),
            "dsx_gb200nvl_72x1"
        );
    }

    #[test]
    fn test_rack_hardware_type_is_any() {
        assert!(RackHardwareType::any().is_any());
        assert!(!RackHardwareType::from("dsx_gb200nvl_72x1").is_any());
    }

    #[test]
    fn test_rack_hardware_type_default_is_any() {
        assert_eq!(RackHardwareType::default(), RackHardwareType::any());
    }

    // RackHardwareTopology serde.

    #[test]
    fn test_rack_hardware_topology_serde_round_trip() {
        let cases = [
            (
                RackHardwareTopology::Gb200Nvl36r1C2g4Topology,
                "\"gb200_nvl36r1_c2g4_topology\"",
            ),
            (
                RackHardwareTopology::Gb300Nvl36r1C2g4Topology,
                "\"gb300_nvl36r1_c2g4_topology\"",
            ),
            (
                RackHardwareTopology::Gb200Nvl72r1C2g4Topology,
                "\"gb200_nvl72r1_c2g4_topology\"",
            ),
            (
                RackHardwareTopology::Gb300Nvl72r1C2g4Topology,
                "\"gb300_nvl72r1_c2g4_topology\"",
            ),
            (
                RackHardwareTopology::VrNvl8r1C2g4RtfTopology,
                "\"vr_nvl8r1_c2g4_rtf_topology\"",
            ),
            (
                RackHardwareTopology::VrNvl72r1C2g4Topology,
                "\"vr_nvl72r1_c2g4_topology\"",
            ),
        ];
        for (variant, expected_json) in cases {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected_json, "serialize {:?}", variant);
            let deserialized: RackHardwareTopology = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, variant, "deserialize {:?}", variant);
        }
    }

    #[test]
    fn test_rack_hardware_topology_display() {
        assert_eq!(
            RackHardwareTopology::Gb200Nvl36r1C2g4Topology.to_string(),
            "gb200_nvl36r1_c2g4_topology"
        );
        assert_eq!(
            RackHardwareTopology::VrNvl8r1C2g4RtfTopology.to_string(),
            "vr_nvl8r1_c2g4_rtf_topology"
        );
        assert_eq!(
            RackHardwareTopology::VrNvl72r1C2g4Topology.to_string(),
            "vr_nvl72r1_c2g4_topology"
        );
    }

    // RackHardwareClass serde.

    #[test]
    fn test_rack_hardware_class_serde_round_trip() {
        let cases = [
            (RackHardwareClass::Dev, "\"dev\""),
            (RackHardwareClass::Prod, "\"prod\""),
        ];
        for (variant, expected_json) in cases {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected_json, "serialize {:?}", variant);
            let deserialized: RackHardwareClass = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, variant, "deserialize {:?}", variant);
        }
    }

    #[test]
    fn test_rack_hardware_class_display() {
        assert_eq!(RackHardwareClass::Dev.to_string(), "dev");
        assert_eq!(RackHardwareClass::Prod.to_string(), "prod");
    }
}
