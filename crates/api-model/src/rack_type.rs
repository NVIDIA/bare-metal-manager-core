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

/// RackProductFamily identifies the product family shared by rack components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RackProductFamily {
    /// GB200 rack hardware.
    Gb200,
    /// GB300 rack hardware.
    Gb300,
}

impl fmt::Display for RackProductFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RackProductFamily::Gb200 => write!(f, "gb200"),
            RackProductFamily::Gb300 => write!(f, "gb300"),
        }
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
    /// Product family used for product-level component behavior.
    #[serde(default)]
    pub product_family: Option<RackProductFamily>,

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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{scenarios, value_scenarios};

    use super::*;

    #[test]
    fn test_rack_profile_config_lookup() {
        let mut config = RackProfileConfig::default();
        config.rack_profiles.insert(
            "NVL72".to_string(),
            RackProfile {
                product_family: Some(RackProductFamily::Gb200),
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
[NVL72]
product_family = "gb200"

[NVL72.rack_capabilities.compute]
name = "GB200"
count = 18
vendor = "NVIDIA"

[NVL72.rack_capabilities.switch]
count = 9

[NVL72.rack_capabilities.power_shelf]
count = 8

[NVL36]
product_family = "gb200"

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
        assert_eq!(nvl72.product_family, Some(RackProductFamily::Gb200));
        assert_eq!(nvl72.rack_capabilities.compute.count, 18);
        assert_eq!(
            nvl72.rack_capabilities.compute.name.as_deref(),
            Some("GB200")
        );

        let nvl36 = config.get("NVL36").unwrap();
        assert_eq!(nvl36.product_family, Some(RackProductFamily::Gb200));
        assert_eq!(nvl36.rack_capabilities.compute.count, 9);
        assert_eq!(nvl36.rack_capabilities.switch.count, 9);
        assert_eq!(nvl36.rack_capabilities.power_shelf.count, 2);
    }

    #[test]
    fn test_rack_profile_config_toml_with_hardware_fields() {
        let toml_str = r#"
[NVL72]
product_family = "gb200"
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

        assert_eq!(nvl72.product_family, Some(RackProductFamily::Gb200));
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
[NVL36]
product_family = "gb300"

[NVL36.rack_capabilities.compute]
count = 9
[NVL36.rack_capabilities.switch]
count = 9
[NVL36.rack_capabilities.power_shelf]
count = 2
"#;
        let config: RackProfileConfig = toml::from_str(toml_str).unwrap();
        let nvl36 = config.get("NVL36").unwrap();

        assert_eq!(nvl36.product_family, Some(RackProductFamily::Gb300));
        assert_eq!(nvl36.rack_hardware_type, None);
        assert_eq!(nvl36.rack_hardware_topology, None);
        assert_eq!(nvl36.rack_hardware_class, None);
    }

    #[test]
    fn test_rack_profile_config_without_product_family_defaults_to_none() {
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

        assert_eq!(nvl36.product_family, None);
    }

    // RackHardwareType tests.

    // JSON round-trip: each variant serializes to its expected string and
    // deserializes back to itself. Projected to (json, value_back); the closure
    // discards the (non-PartialEq) serde_json error since every row succeeds.
    #[test]
    fn test_rack_hardware_type_serde_round_trip() {
        scenarios!(
            run = |hw_type| {
                let json = serde_json::to_string(&hw_type).map_err(drop)?;
                let back: RackHardwareType = serde_json::from_str(&json).map_err(drop)?;
                Ok::<_, ()>((json, back))
            };
            "dsx hardware type round-trips through json" {
                RackHardwareType::from("dsx_gb200nvl_72x1") => Yields((
                    "\"dsx_gb200nvl_72x1\"".to_string(),
                    RackHardwareType::from("dsx_gb200nvl_72x1"),
                )),
            }
        );
    }

    // Display forwards the inner string verbatim, including for the wildcard
    // and for empty/odd inputs.
    #[test]
    fn test_rack_hardware_type_display() {
        value_scenarios!(
            run = |hw_type| hw_type.to_string();
            "wildcard any" {
                RackHardwareType::any() => "any".to_string(),
            }

            "dsx hardware type" {
                RackHardwareType::from("dsx_gb200nvl_72x1") => "dsx_gb200nvl_72x1".to_string(),
            }

            "empty string" {
                RackHardwareType::from("") => String::new(),
            }

            "uppercase verbatim" {
                RackHardwareType::from("ANY") => "ANY".to_string(),
            }

            "whitespace preserved" {
                RackHardwareType::from("  spaced  ") => "  spaced  ".to_string(),
            }

            "default renders as any" {
                RackHardwareType::default() => "any".to_string(),
            }
        );
    }

    // is_any is an exact, case-sensitive match against the literal "any".
    #[test]
    fn test_rack_hardware_type_is_any() {
        value_scenarios!(
            run = |hw_type| hw_type.is_any();
            "constructed via any()" {
                RackHardwareType::any() => true,
            }

            "default is any" {
                RackHardwareType::default() => true,
            }

            "literal any from str" {
                RackHardwareType::from("any") => true,
            }

            "concrete hardware type" {
                RackHardwareType::from("dsx_gb200nvl_72x1") => false,
            }

            "empty is not any" {
                RackHardwareType::from("") => false,
            }

            "uppercase is not any" {
                RackHardwareType::from("ANY") => false,
            }

            "any with trailing space is not any" {
                RackHardwareType::from("any ") => false,
            }

            "substring is not any" {
                RackHardwareType::from("anything") => false,
            }
        );
    }

    #[test]
    fn test_rack_hardware_type_default_is_any() {
        assert_eq!(RackHardwareType::default(), RackHardwareType::any());
    }

    // Both From conversions wrap the input verbatim and agree with each other.
    #[test]
    fn test_rack_hardware_type_from_conversions() {
        value_scenarios!(
            run = |hw_type| hw_type;
            "from owned string" {
                RackHardwareType::from("dsx".to_string()) => RackHardwareType("dsx".to_string()),
            }

            "from str slice" {
                RackHardwareType::from("dsx") => RackHardwareType("dsx".to_string()),
            }

            "from empty str" {
                RackHardwareType::from("") => RackHardwareType(String::new()),
            }

            "owned and borrowed agree" {
                RackHardwareType::from("any".to_string()) => RackHardwareType::from("any"),
            }
        );
    }

    // RackProductFamily serde.

    #[test]
    fn test_rack_product_family_serde_round_trip() {
        scenarios!(
            run = |variant| {
                let json = serde_json::to_string(&variant).map_err(drop)?;
                let back: RackProductFamily = serde_json::from_str(&json).map_err(drop)?;
                Ok::<_, ()>((json, back))
            };
            "gb200 round-trips" {
                RackProductFamily::Gb200 => Yields(("\"gb200\"".to_string(), RackProductFamily::Gb200)),
            }

            "gb300 round-trips" {
                RackProductFamily::Gb300 => Yields(("\"gb300\"".to_string(), RackProductFamily::Gb300)),
            }
        );
    }

    #[test]
    fn test_rack_product_family_display() {
        value_scenarios!(
            run = |variant| variant.to_string();
            "gb200" {
                RackProductFamily::Gb200 => "gb200".to_string(),
            }

            "gb300" {
                RackProductFamily::Gb300 => "gb300".to_string(),
            }
        );
    }

    #[test]
    fn test_rack_product_family_deserialize() {
        scenarios!(
            run = |json| serde_json::from_str::<RackProductFamily>(json).map_err(drop);
            "valid gb200" {
                "\"gb200\"" => Yields(RackProductFamily::Gb200),
            }

            "valid gb300" {
                "\"gb300\"" => Yields(RackProductFamily::Gb300),
            }

            "unknown product family" {
                "\"gb400\"" => Fails,
            }

            "wrong case" {
                "\"GB200\"" => Fails,
            }
        );
    }

    // RackHardwareTopology serde.

    // JSON round-trip: each topology variant serializes to its expected
    // snake_case string and deserializes back to itself. Projected to
    // (json, value_back); the (non-PartialEq) serde_json error is discarded.
    #[test]
    fn test_rack_hardware_topology_serde_round_trip() {
        scenarios!(
            run = |variant| {
                let json = serde_json::to_string(&variant).map_err(drop)?;
                let back: RackHardwareTopology = serde_json::from_str(&json).map_err(drop)?;
                Ok::<_, ()>((json, back))
            };
            "gb200 nvl36 round-trips" {
                RackHardwareTopology::Gb200Nvl36r1C2g4Topology => Yields((
                    "\"gb200_nvl36r1_c2g4_topology\"".to_string(),
                    RackHardwareTopology::Gb200Nvl36r1C2g4Topology,
                )),
            }

            "gb300 nvl36 round-trips" {
                RackHardwareTopology::Gb300Nvl36r1C2g4Topology => Yields((
                    "\"gb300_nvl36r1_c2g4_topology\"".to_string(),
                    RackHardwareTopology::Gb300Nvl36r1C2g4Topology,
                )),
            }

            "gb200 nvl72 round-trips" {
                RackHardwareTopology::Gb200Nvl72r1C2g4Topology => Yields((
                    "\"gb200_nvl72r1_c2g4_topology\"".to_string(),
                    RackHardwareTopology::Gb200Nvl72r1C2g4Topology,
                )),
            }

            "gb300 nvl72 round-trips" {
                RackHardwareTopology::Gb300Nvl72r1C2g4Topology => Yields((
                    "\"gb300_nvl72r1_c2g4_topology\"".to_string(),
                    RackHardwareTopology::Gb300Nvl72r1C2g4Topology,
                )),
            }

            "vr nvl8 rtf round-trips" {
                RackHardwareTopology::VrNvl8r1C2g4RtfTopology => Yields((
                    "\"vr_nvl8r1_c2g4_rtf_topology\"".to_string(),
                    RackHardwareTopology::VrNvl8r1C2g4RtfTopology,
                )),
            }

            "vr nvl72 round-trips" {
                RackHardwareTopology::VrNvl72r1C2g4Topology => Yields((
                    "\"vr_nvl72r1_c2g4_topology\"".to_string(),
                    RackHardwareTopology::VrNvl72r1C2g4Topology,
                )),
            }
        );
    }

    // Display covers every topology variant; the rendered string matches the
    // snake_case serde form.
    #[test]
    fn test_rack_hardware_topology_display() {
        value_scenarios!(
            run = |variant| variant.to_string();
            "gb200 nvl36" {
                RackHardwareTopology::Gb200Nvl36r1C2g4Topology => "gb200_nvl36r1_c2g4_topology".to_string(),
            }

            "gb300 nvl36" {
                RackHardwareTopology::Gb300Nvl36r1C2g4Topology => "gb300_nvl36r1_c2g4_topology".to_string(),
            }

            "gb200 nvl72" {
                RackHardwareTopology::Gb200Nvl72r1C2g4Topology => "gb200_nvl72r1_c2g4_topology".to_string(),
            }

            "gb300 nvl72" {
                RackHardwareTopology::Gb300Nvl72r1C2g4Topology => "gb300_nvl72r1_c2g4_topology".to_string(),
            }

            "vr nvl8 rtf" {
                RackHardwareTopology::VrNvl8r1C2g4RtfTopology => "vr_nvl8r1_c2g4_rtf_topology".to_string(),
            }

            "vr nvl72" {
                RackHardwareTopology::VrNvl72r1C2g4Topology => "vr_nvl72r1_c2g4_topology".to_string(),
            }
        );
    }

    // Deserialization accepts exactly the snake_case names and rejects anything
    // else (unknown names, the Display-only variant casing, empty). The
    // (non-PartialEq) serde error is discarded with map_err(drop).
    #[test]
    fn test_rack_hardware_topology_deserialize() {
        scenarios!(
            run = |json| serde_json::from_str::<RackHardwareTopology>(json).map_err(drop);
            "valid gb200 nvl36" {
                "\"gb200_nvl36r1_c2g4_topology\"" => Yields(RackHardwareTopology::Gb200Nvl36r1C2g4Topology),
            }

            "valid vr nvl72" {
                "\"vr_nvl72r1_c2g4_topology\"" => Yields(RackHardwareTopology::VrNvl72r1C2g4Topology),
            }

            "unknown topology name" {
                "\"gb500_nvl99_topology\"" => Fails,
            }

            "empty string" {
                "\"\"" => Fails,
            }

            "wrong json type" {
                "42" => Fails,
            }
        );
    }

    // RackHardwareClass serde.

    // JSON round-trip: each class variant serializes to its expected snake_case
    // string and deserializes back to itself. Projected to (json, value_back);
    // the (non-PartialEq) serde_json error is discarded.
    #[test]
    fn test_rack_hardware_class_serde_round_trip() {
        scenarios!(
            run = |variant| {
                let json = serde_json::to_string(&variant).map_err(drop)?;
                let back: RackHardwareClass = serde_json::from_str(&json).map_err(drop)?;
                Ok::<_, ()>((json, back))
            };
            "dev round-trips" {
                RackHardwareClass::Dev => Yields(("\"dev\"".to_string(), RackHardwareClass::Dev)),
            }

            "prod round-trips" {
                RackHardwareClass::Prod => Yields(("\"prod\"".to_string(), RackHardwareClass::Prod)),
            }
        );
    }

    #[test]
    fn test_rack_hardware_class_display() {
        value_scenarios!(
            run = |variant| variant.to_string();
            "dev" {
                RackHardwareClass::Dev => "dev".to_string(),
            }

            "prod" {
                RackHardwareClass::Prod => "prod".to_string(),
            }
        );
    }

    // Deserialization accepts the two snake_case names and rejects others.
    // The (non-PartialEq) serde error is discarded with map_err(drop).
    #[test]
    fn test_rack_hardware_class_deserialize() {
        scenarios!(
            run = |json| serde_json::from_str::<RackHardwareClass>(json).map_err(drop);
            "valid dev" {
                "\"dev\"" => Yields(RackHardwareClass::Dev),
            }

            "valid prod" {
                "\"prod\"" => Yields(RackHardwareClass::Prod),
            }

            "uppercase rejected" {
                "\"Dev\"" => Fails,
            }

            "unknown class" {
                "\"staging\"" => Fails,
            }

            "empty string" {
                "\"\"" => Fails,
            }
        );
    }

    // RackCapabilityType Display renders each variant with its canonical
    // PascalCase label.
    #[test]
    fn test_rack_capability_type_display() {
        value_scenarios!(
            run = |variant| variant.to_string();
            "compute" {
                RackCapabilityType::Compute => "Compute".to_string(),
            }

            "switch" {
                RackCapabilityType::Switch => "Switch".to_string(),
            }

            "power shelf" {
                RackCapabilityType::PowerShelf => "PowerShelf".to_string(),
            }
        );
    }
}
