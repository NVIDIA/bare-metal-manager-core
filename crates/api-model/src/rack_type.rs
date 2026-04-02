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
/*         RackTypeConfig             */
/* ********************************** */

/// RackTypeConfig contains all known rack types, keyed by rack type name.
/// Loaded from the Carbide configuration file and used to validate that
/// the correct number of expected devices have been registered for a rack.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RackTypeConfig {
    /// Map of rack type name to its capabilities set.
    #[serde(default, flatten)]
    pub rack_types: HashMap<String, RackCapabilitiesSet>,
}

impl RackTypeConfig {
    /// get looks up a rack capabilities set by name.
    pub fn get(&self, name: &str) -> Option<&RackCapabilitiesSet> {
        self.rack_types.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rack_type_config_lookup() {
        let mut config = RackTypeConfig::default();
        config.rack_types.insert(
            "NVL72".to_string(),
            RackCapabilitiesSet {
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
        );

        let def = config.get("NVL72").unwrap();
        assert_eq!(def.compute.count, 18);
        assert_eq!(def.switch.count, 9);
        assert_eq!(def.power_shelf.count, 8);

        assert!(config.get("nonexistent").is_none());
    }

    #[test]
    fn test_rack_type_config_toml_deserialization() {
        let toml_str = r#"
[NVL72]
[NVL72.compute]
name = "GB200"
count = 18
vendor = "NVIDIA"

[NVL72.switch]
count = 9

[NVL72.power_shelf]
count = 8

[NVL36]
[NVL36.compute]
count = 9

[NVL36.switch]
count = 9

[NVL36.power_shelf]
count = 2
"#;
        let config: RackTypeConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.rack_types.len(), 2);

        let nvl72 = config.get("NVL72").unwrap();
        assert_eq!(nvl72.compute.count, 18);
        assert_eq!(nvl72.compute.name.as_deref(), Some("GB200"));

        let nvl36 = config.get("NVL36").unwrap();
        assert_eq!(nvl36.compute.count, 9);
        assert_eq!(nvl36.switch.count, 9);
        assert_eq!(nvl36.power_shelf.count, 2);
    }
}
