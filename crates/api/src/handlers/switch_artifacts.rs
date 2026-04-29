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

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SwitchSystemImageArtifact {
    pub(crate) device_type: String,
    pub(crate) component: String,
    pub(crate) version: String,
    pub(crate) firmware_type: String,
    pub(crate) package_name: String,
    pub(crate) location: String,
    pub(crate) location_type: String,
    pub(crate) required: bool,
    pub(crate) image_filename: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RawSwitchArtifactsConfig {
    #[serde(rename = "SwitchSystemImages", default)]
    switch_system_images: Vec<RawSwitchSystemImageArtifact>,
    #[serde(rename = "BoardSKUs", default)]
    board_skus: Vec<RawBoardSku>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSwitchSystemImageArtifact {
    #[serde(rename = "DeviceType")]
    device_type: String,
    #[serde(rename = "Component")]
    component: String,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Type")]
    firmware_type: String,
    #[serde(rename = "PackageName")]
    package_name: String,
    #[serde(rename = "Location")]
    location: String,
    #[serde(rename = "LocationType")]
    location_type: String,
    #[serde(rename = "Required", default = "default_true")]
    required: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RawBoardSku {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Type", default)]
    sku_type: String,
    #[serde(rename = "Components", default)]
    components: RawBoardSkuComponents,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RawBoardSkuComponents {
    #[serde(rename = "Software", default)]
    software: Vec<RawSoftwareComponent>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RawSoftwareComponent {
    #[serde(rename = "Component", default)]
    component: String,
    #[serde(rename = "Version", default)]
    version: String,
    #[serde(rename = "Type", default)]
    firmware_type: String,
    #[serde(rename = "Locations", default)]
    locations: Vec<RawSoftwareLocation>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RawSoftwareLocation {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Location", default)]
    location: String,
    #[serde(rename = "LocationType", default)]
    location_type: String,
    #[serde(rename = "PackageName", default)]
    package_name: String,
    #[serde(rename = "Required", default = "default_true")]
    required: bool,
}

pub(crate) fn collect_switch_system_images(
    config: &Value,
) -> Result<Vec<SwitchSystemImageArtifact>, String> {
    let raw: RawSwitchArtifactsConfig = serde_json::from_value(config.clone())
        .map_err(format_switch_artifacts_deserialize_error)?;

    let mut parsed = Vec::new();
    let mut seen_keys = HashSet::new();

    for (idx, entry) in raw.switch_system_images.iter().enumerate() {
        let device_type = entry.device_type.trim();
        if device_type != "Switch Tray" {
            return Err(format!(
                "SwitchSystemImages[{idx}].DeviceType must be 'Switch Tray'"
            ));
        }

        let component = entry.component.trim();
        if component != "NVOS" {
            return Err(format!(
                "SwitchSystemImages[{idx}].Component must be 'NVOS'"
            ));
        }

        let version = entry.version.trim();
        if version.is_empty() {
            return Err(format!("SwitchSystemImages[{idx}].Version is required"));
        }

        let firmware_type = entry.firmware_type.trim();
        if firmware_type.is_empty() {
            return Err(format!("SwitchSystemImages[{idx}].Type is required"));
        }
        let firmware_type = firmware_type.to_lowercase();

        let package_name = entry.package_name.trim();
        if package_name.is_empty() {
            return Err(format!("SwitchSystemImages[{idx}].PackageName is required"));
        }

        let location = entry.location.trim();
        if location.is_empty() {
            return Err(format!("SwitchSystemImages[{idx}].Location is required"));
        }

        let location_type = entry.location_type.trim();
        if location_type.is_empty() {
            return Err(format!(
                "SwitchSystemImages[{idx}].LocationType is required"
            ));
        }

        let key = (
            device_type.to_string(),
            component.to_string(),
            firmware_type.clone(),
        );
        if seen_keys.insert(key) {
            parsed.push(SwitchSystemImageArtifact {
                device_type: device_type.to_string(),
                component: component.to_string(),
                version: version.to_string(),
                firmware_type,
                package_name: package_name.to_string(),
                location: location.to_string(),
                location_type: location_type.to_string(),
                required: entry.required,
                image_filename: filename_from_location(location)?,
            });
        }
    }

    for (board_idx, board_sku) in raw.board_skus.iter().enumerate() {
        if board_sku.sku_type.trim() != "Switch Tray" {
            continue;
        }

        let board_context = if board_sku.name.trim().is_empty() {
            format!("BoardSKUs[{board_idx}]")
        } else {
            format!("BoardSKUs[{board_idx}] ({})", board_sku.name.trim())
        };

        let board_nvos_package_name = board_sku
            .components
            .software
            .iter()
            .filter(|software| software.component.trim() == "NVOS")
            .flat_map(|software| software.locations.iter())
            .map(|location| location.package_name.trim())
            .find(|package_name| !package_name.is_empty());

        for (software_idx, software) in board_sku.components.software.iter().enumerate() {
            if software.component.trim() != "NVOS" {
                continue;
            }

            let context = format!("{board_context}.Components.Software[{software_idx}]");
            let version = software.version.trim();
            if version.is_empty() {
                return Err(format!("{context}.Version is required"));
            }

            let firmware_type = software.firmware_type.trim();
            if firmware_type.is_empty() {
                return Err(format!("{context}.Type is required"));
            }
            let firmware_type = firmware_type.to_lowercase();

            let software_package_name = software
                .locations
                .iter()
                .map(|location| location.package_name.trim())
                .find(|package_name| !package_name.is_empty());

            let mut candidates = Vec::new();
            for (location_idx, location) in software.locations.iter().enumerate() {
                let location_value = location.location.trim();
                if location_value.is_empty() {
                    continue;
                }

                let image_filename = filename_from_location(location_value)?;
                if !image_filename.to_ascii_lowercase().ends_with(".bin") {
                    continue;
                }

                let name_upper = location.name.to_ascii_uppercase();
                let filename_upper = image_filename.to_ascii_uppercase();
                let location_upper = location_value.to_ascii_uppercase();
                let mut score = 0;
                if name_upper.contains("NVOS") || filename_upper.contains("NVOS") {
                    score += 2;
                }
                if name_upper.contains("AMD64")
                    || filename_upper.contains("AMD64")
                    || location_upper.contains("/AMD64/")
                {
                    score += 1;
                }

                candidates.push((location_idx, score, image_filename));
            }

            if candidates.is_empty() {
                return Err(format!(
                    "{context}.Locations must include an NVOS .bin image location"
                ));
            }

            let best_score = candidates
                .iter()
                .map(|(_, score, _)| *score)
                .max()
                .expect("candidates is not empty");
            let best_candidates: Vec<_> = candidates
                .iter()
                .filter(|(_, score, _)| *score == best_score)
                .collect();
            if best_candidates.len() != 1 {
                return Err(format!(
                    "{context}.Locations contains multiple NVOS .bin image candidates"
                ));
            }

            let (location_idx, _, image_filename) = best_candidates[0];
            let selected_location = &software.locations[*location_idx];
            let location = selected_location.location.trim();
            let location_type = selected_location.location_type.trim();
            if location_type.is_empty() {
                return Err(format!(
                    "{context}.Locations[{location_idx}].LocationType is required"
                ));
            }

            let selected_package_name = selected_location.package_name.trim();
            let package_name = if selected_package_name.is_empty() {
                software_package_name.or(board_nvos_package_name)
            } else {
                Some(selected_package_name)
            }
            .ok_or_else(|| {
                format!("{context}.Locations[{location_idx}].PackageName is required")
            })?;

            let key = (
                "Switch Tray".to_string(),
                "NVOS".to_string(),
                firmware_type.clone(),
            );
            if seen_keys.insert(key) {
                parsed.push(SwitchSystemImageArtifact {
                    device_type: "Switch Tray".to_string(),
                    component: "NVOS".to_string(),
                    version: version.to_string(),
                    firmware_type,
                    package_name: package_name.to_string(),
                    location: location.to_string(),
                    location_type: location_type.to_string(),
                    required: selected_location.required,
                    image_filename: image_filename.to_string(),
                });
            }
        }
    }

    Ok(parsed)
}

fn filename_from_location(location: &str) -> Result<String, String> {
    location
        .split('/')
        .next_back()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("Location must end with a filename: {location}"))
}

fn default_true() -> bool {
    true
}

fn format_switch_artifacts_deserialize_error(error: serde_json::Error) -> String {
    let message = error.to_string();

    if let Some(field) = message
        .strip_prefix("missing field `")
        .and_then(|s| s.strip_suffix('`'))
    {
        return format!("Invalid SwitchSystemImages: {field} is required");
    }

    format!("Invalid switch artifacts: {message}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_nvos_from_board_sku_software() {
        let config = serde_json::json!({
            "BoardSKUs": [
                {
                    "Name": "P4978-Juliet_Switch",
                    "Type": "Switch Tray",
                    "Components": {
                        "Software": [
                            {
                                "Component": "NVOS",
                                "Version": "25.02.2553",
                                "Type": "Prod",
                                "Locations": [
                                    {
                                        "Name": "NVOS_Prod_AMD64",
                                        "Location": "https://example.invalid/release/25.02.2553/amd64/prod/nvos-amd64-25.02.2553.bin",
                                        "LocationType": "HTTPS",
                                        "PackageName": "GB300_NVOS",
                                        "Required": true
                                    },
                                    {
                                        "Name": "NVOS_OpenAPI_Spec",
                                        "Location": "https://example.invalid/release/25.02.2553/openapi.json",
                                        "LocationType": "HTTPS",
                                        "PackageName": "GB300_NVOS",
                                        "Required": true
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        });

        let artifacts = collect_switch_system_images(&config).unwrap();

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].device_type, "Switch Tray");
        assert_eq!(artifacts[0].component, "NVOS");
        assert_eq!(artifacts[0].version, "25.02.2553");
        assert_eq!(artifacts[0].firmware_type, "prod");
        assert_eq!(artifacts[0].package_name, "GB300_NVOS");
        assert_eq!(artifacts[0].image_filename, "nvos-amd64-25.02.2553.bin");
    }

    #[test]
    fn uses_board_sku_nvos_package_name_fallback() {
        let config = serde_json::json!({
            "BoardSKUs": [
                {
                    "Name": "P4978-Juliet_Switch",
                    "Type": "Switch Tray",
                    "Components": {
                        "Software": [
                            {
                                "Component": "NVOS",
                                "Version": "25.02.2553",
                                "Type": "Prod",
                                "Locations": [
                                    {
                                        "Name": "NVOS_Prod_AMD64",
                                        "Location": "https://example.invalid/prod/nvos-amd64-25.02.2553.bin",
                                        "LocationType": "HTTPS",
                                        "PackageName": "GB300_NVOS"
                                    }
                                ]
                            },
                            {
                                "Component": "NVOS",
                                "Version": "25.02.2553",
                                "Type": "Dev",
                                "Locations": [
                                    {
                                        "Name": "NVOS_Dev_AMD64",
                                        "Location": "https://example.invalid/dev/nvos-amd64-25.02.2553.bin",
                                        "LocationType": "HTTPS",
                                        "PackageName": ""
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        });

        let artifacts = collect_switch_system_images(&config).unwrap();

        let dev = artifacts
            .iter()
            .find(|artifact| artifact.firmware_type == "dev")
            .expect("expected dev NVOS artifact");
        assert_eq!(dev.package_name, "GB300_NVOS");
    }

    #[test]
    fn explicit_switch_system_image_wins_over_derived() {
        let config = serde_json::json!({
            "SwitchSystemImages": [
                {
                    "DeviceType": "Switch Tray",
                    "Component": "NVOS",
                    "Version": "explicit",
                    "Type": "Prod",
                    "PackageName": "EXPLICIT_NVOS",
                    "Location": "https://example.invalid/explicit.bin",
                    "LocationType": "HTTPS"
                }
            ],
            "BoardSKUs": [
                {
                    "Type": "Switch Tray",
                    "Components": {
                        "Software": [
                            {
                                "Component": "NVOS",
                                "Version": "derived",
                                "Type": "Prod",
                                "Locations": [
                                    {
                                        "Name": "NVOS_Prod_AMD64",
                                        "Location": "https://example.invalid/derived.bin",
                                        "LocationType": "HTTPS",
                                        "PackageName": "DERIVED_NVOS"
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        });

        let artifacts = collect_switch_system_images(&config).unwrap();

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].version, "explicit");
        assert_eq!(artifacts[0].package_name, "EXPLICIT_NVOS");
    }

    #[test]
    fn rejects_nvos_software_without_bin_location() {
        let config = serde_json::json!({
            "BoardSKUs": [
                {
                    "Type": "Switch Tray",
                    "Components": {
                        "Software": [
                            {
                                "Component": "NVOS",
                                "Version": "25.02.2553",
                                "Type": "Prod",
                                "Locations": [
                                    {
                                        "Name": "NVOS_OpenAPI_Spec",
                                        "Location": "https://example.invalid/openapi.json",
                                        "LocationType": "HTTPS",
                                        "PackageName": "GB300_NVOS"
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        });

        let error = collect_switch_system_images(&config).unwrap_err();

        assert!(error.contains("must include an NVOS .bin image location"));
    }
}
