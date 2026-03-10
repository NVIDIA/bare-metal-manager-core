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

use serde::{Deserialize, Serialize};

/// Defines a rack type with expected counts for each node type. Rack types are
/// loaded from the Carbide configuration file and used to validate that the
/// correct number of expected devices have been registered for a rack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RackTypeDefinition {
    /// Short name for this rack type (e.g. "NVL72").
    #[serde(default)]
    pub name: String,

    /// Human-readable description of this rack type.
    pub description: String,

    /// Number of compute trays (machines) expected in this rack type.
    pub expected_compute_trays: u32,

    /// Number of NVLink switches expected in this rack type.
    pub expected_switches: u32,

    /// Number of power shelves expected in this rack type.
    pub expected_power_shelves: u32,
}

/// Configuration for all known rack types, keyed by rack type name.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RackTypeConfig {
    /// Map of rack type name to its definition.
    #[serde(default)]
    pub rack_types: HashMap<String, RackTypeDefinition>,
}

impl RackTypeConfig {
    /// Look up a rack type definition by name.
    pub fn get(&self, name: &str) -> Option<&RackTypeDefinition> {
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
            RackTypeDefinition {
                name: "NVL72".to_string(),
                description: "72x1 GB200 NVL72 rack".to_string(),
                expected_compute_trays: 18,
                expected_switches: 9,
                expected_power_shelves: 4,
            },
        );

        let def = config.get("NVL72").unwrap();
        assert_eq!(def.expected_compute_trays, 18);
        assert_eq!(def.expected_switches, 9);
        assert_eq!(def.expected_power_shelves, 4);

        assert!(config.get("nonexistent").is_none());
    }

    #[test]
    fn test_rack_type_config_toml_deserialization() {
        let toml_str = r#"
[rack_types.NVL72]
description = "72x1 GB200 NVL72 rack"
expected_compute_trays = 18
expected_switches = 9
expected_power_shelves = 4

[rack_types.NVL36x2]
description = "36x2 GB200 rack"
expected_compute_trays = 9
expected_switches = 9
expected_power_shelves = 4
"#;
        let config: RackTypeConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.rack_types.len(), 2);

        let nvl72 = config.get("NVL72").unwrap();
        assert_eq!(nvl72.expected_compute_trays, 18);
        assert_eq!(nvl72.description, "72x1 GB200 NVL72 rack");

        let nvl36x2 = config.get("NVL36x2").unwrap();
        assert_eq!(nvl36x2.expected_compute_trays, 9);
    }
}
