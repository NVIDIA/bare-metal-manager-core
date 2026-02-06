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
use std::fmt::{Debug, Display};
use std::path::PathBuf;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::site_explorer::EndpointExplorationReport;

/// Firmware versions this carbide instance wants to install onto hosts
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DesiredFirmwareVersions {
    /// Parsed versions, serializtion override means it will always be sorted
    #[serde(default, serialize_with = "utils::ordered_map")]
    pub versions: HashMap<FirmwareComponentType, String>,
}

impl From<Firmware> for DesiredFirmwareVersions {
    fn from(value: Firmware) -> Self {
        // Using a BTreeMap instead of a hash means that this will be sorted by the key
        let mut versions: DesiredFirmwareVersions = Default::default();
        for (component_type, component) in value.components {
            for firmware in component.known_firmware {
                if firmware.default {
                    versions.versions.insert(component_type, firmware.version);
                    break;
                }
            }
        }
        versions
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct Firmware {
    pub vendor: bmc_vendor::BMCVendor,
    pub model: String,

    pub components: HashMap<FirmwareComponentType, FirmwareComponent>,

    #[serde(default)]
    pub explicit_start_needed: bool,

    #[serde(default)]
    pub ordering: Vec<FirmwareComponentType>,
}

impl Firmware {
    pub fn matching_version_id(
        &self,
        redfish_id: &str,
        firmware_type: FirmwareComponentType,
    ) -> bool {
        // This searches for the regex we've recorded for what this vendor + model + firmware_type gets reported as in the list of firmware versions
        self.components
            .get(&firmware_type)
            .unwrap_or(&FirmwareComponent::default()) // Will trigger the unwrap_or below
            .current_version_reported_as
            .as_ref()
            .map(|regex| regex.captures(redfish_id).is_some())
            .unwrap_or(false)
    }
    pub fn ordering(&self) -> Vec<FirmwareComponentType> {
        let mut ordering = self.ordering.clone();
        if ordering.is_empty() {
            const ORDERING: [FirmwareComponentType; 2] =
                [FirmwareComponentType::Bmc, FirmwareComponentType::Uefi];
            ordering = ORDERING.to_vec();
        }
        ordering
    }

    /// find_version will locate a version number within an EndpointExplorationReport
    pub fn find_version(
        &self,
        report: &EndpointExplorationReport,
        firmware_type: FirmwareComponentType,
    ) -> Option<String> {
        for service in report.service.iter() {
            if let Some(matching_inventory) = service
                .inventories
                .iter()
                .find(|&x| self.matching_version_id(&x.id, firmware_type))
            {
                tracing::debug!(
                    "find_version {:?}: For {firmware_type:?} found {:?}",
                    report.machine_id,
                    matching_inventory.version
                );
                return matching_inventory.version.clone();
            };
        }
        None
    }
}

#[derive(
    Debug, Default, Deserialize, Serialize, Eq, PartialEq, Hash, Copy, Clone, Ord, PartialOrd,
)]
#[serde(rename_all = "lowercase")]
pub enum FirmwareComponentType {
    Bmc,
    Cec,
    Uefi,
    Nic,
    CpldMb,
    CpldPdb,
    HGXBmc,
    CombinedBmcUefi,
    Gpu,
    #[serde(other)]
    #[default]
    Unknown,
}

impl From<FirmwareComponentType> for libredfish::model::update_service::ComponentType {
    fn from(fct: FirmwareComponentType) -> libredfish::model::update_service::ComponentType {
        use libredfish::model::update_service::ComponentType;
        match fct {
            FirmwareComponentType::Bmc => ComponentType::BMC,
            FirmwareComponentType::Uefi => ComponentType::UEFI,
            FirmwareComponentType::Cec => ComponentType::Unknown,
            FirmwareComponentType::Nic => ComponentType::Unknown,
            FirmwareComponentType::CpldMb => ComponentType::CPLDMB,
            FirmwareComponentType::CpldPdb => ComponentType::CPLDPDB,
            FirmwareComponentType::HGXBmc => ComponentType::HGXBMC,
            FirmwareComponentType::CombinedBmcUefi => ComponentType::Unknown,
            FirmwareComponentType::Gpu => ComponentType::Unknown,
            FirmwareComponentType::Unknown => ComponentType::Unknown,
        }
    }
}

impl fmt::Display for FirmwareComponentType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FirmwareComponentType::Bmc => write!(f, "BMC"),
            FirmwareComponentType::Uefi => write!(f, "UEFI"),
            FirmwareComponentType::CombinedBmcUefi => write!(f, "BMC+UEFI"),
            FirmwareComponentType::Nic => write!(f, "NIC"),
            FirmwareComponentType::CpldMb => write!(f, "CPLD MB"),
            FirmwareComponentType::CpldPdb => write!(f, "CPLD PDB"),
            FirmwareComponentType::Cec => write!(f, "CEC"),
            FirmwareComponentType::Gpu => write!(f, "GPU"),
            FirmwareComponentType::HGXBmc => write!(f, "HGX BMC"),
            FirmwareComponentType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl FirmwareComponentType {
    pub fn is_bmc(&self) -> bool {
        matches!(
            self,
            FirmwareComponentType::Bmc | FirmwareComponentType::CombinedBmcUefi
        )
    }
    pub fn is_uefi(&self) -> bool {
        matches!(
            self,
            FirmwareComponentType::Uefi | FirmwareComponentType::CombinedBmcUefi
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct FirmwareComponent {
    #[serde(with = "serde_regex")]
    pub current_version_reported_as: Option<Regex>,
    pub preingest_upgrade_when_below: Option<String>,
    #[serde(default)]
    pub known_firmware: Vec<FirmwareEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct FirmwareEntry {
    pub version: String,
    pub mandatory_upgrade_from_priority: Option<MandatoryUpgradeFromPriority>,
    #[serde(default)]
    pub default: bool,
    pub filename: Option<String>,
    #[serde(default)]
    pub filenames: Vec<String>,
    pub url: Option<String>,
    pub checksum: Option<String>,
    #[serde(default)]
    // If set, we will pass the firmware type to libredfish which for some platforms will install only one part of a multi-firmware package.
    pub install_only_specified: bool,
    pub power_drains_needed: Option<u32>,
    #[serde(default)]
    // this firmware entry is only applicable in preingestion.
    // BF3s are the only machine with multiple firmware entries for a given firmware compoanent type (BMC FWs).
    // This flag is used to mark the firmware entry for BMC preingestion on BF3s.
    pub preingestion_exclusive_config: bool,
    /// If true, we will need a series of resets before even trying to upgrade
    #[serde(default)]
    pub pre_update_resets: bool,
    #[serde(default)]
    pub script: Option<PathBuf>,
}

impl FirmwareEntry {
    /// Creates a FirmwareEntry with default parameters for tests
    pub fn standard(version: &str) -> Self {
        Self {
            version: version.to_string(),
            default: true,
            filename: Some("/dev/null".to_string()),
            filenames: vec![],
            url: Some("file://dev/null".to_string()),
            checksum: None,
            mandatory_upgrade_from_priority: None,
            install_only_specified: false,
            power_drains_needed: None,
            preingestion_exclusive_config: false,
            pre_update_resets: false,
            script: None,
        }
    }
    pub fn standard_multiple_filenames(version: &str) -> Self {
        let mut ret = FirmwareEntry::standard(version);
        ret.filename = None;
        ret.filenames = vec!["/dev/null".to_string(), "/dev/null".to_string()];
        ret
    }
    pub fn standard_notdefault(version: &str) -> Self {
        let mut ret = FirmwareEntry::standard(version);
        ret.default = false;
        ret
    }
    pub fn standard_filename(version: &str, filename: &str) -> Self {
        let mut ret = FirmwareEntry::standard(version);
        ret.filename = Some(filename.to_string());
        ret.url = None;
        ret
    }
    pub fn standard_filename_notdefault(version: &str, filename: &str) -> Self {
        let mut ret = FirmwareEntry::standard_notdefault(version);
        ret.filename = Some(filename.to_string());
        ret.url = None;
        ret
    }
    pub fn standard_powerdrains(version: &str, powerdrains: u32) -> Self {
        let mut ret = FirmwareEntry::standard(version);
        ret.power_drains_needed = Some(powerdrains);
        ret.pre_update_resets = true;
        ret
    }
    pub fn standard_script(version: &str, script: &str) -> Self {
        let mut ret = FirmwareEntry::standard(version);
        ret.script = Some(script.into());
        ret
    }

    pub fn get_filename(&self, pos: u32) -> PathBuf {
        let pos = pos.try_into().unwrap_or(usize::MAX);
        let filename = if self.filenames.is_empty() {
            &self.filename
        } else if pos < self.filenames.len() {
            let filename_clone = self.filenames[pos].clone();
            &Some(filename_clone)
        } else {
            &None
        };
        match filename {
            None => PathBuf::from("/dev/null"),
            Some(file_key) => PathBuf::from(file_key),
        }
    }
    pub fn get_url(&self) -> String {
        match &self.url {
            None => "file://dev/null".to_string(),
            Some(url) => url.to_owned(),
        }
    }
    pub fn get_checksum(&self) -> String {
        match &self.checksum {
            None => "".to_string(),
            Some(checksum) => checksum.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MandatoryUpgradeFromPriority {
    None,
    Security,
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
