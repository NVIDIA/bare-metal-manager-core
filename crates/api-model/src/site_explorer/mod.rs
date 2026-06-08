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
use std::fmt::Display;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use carbide_network::BaseMac;
use carbide_utils::arch::CpuArchitecture;
use carbide_uuid::machine::{MachineId, MachineType};
use carbide_uuid::power_shelf::{PowerShelfId, PowerShelfIdSource, PowerShelfType};
use carbide_uuid::switch::{SwitchId, SwitchIdSource, SwitchType};
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use itertools::Itertools;
use lazy_static::lazy_static;
use mac_address::MacAddress;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};

use super::DpuModel;
use super::bmc_info::BmcInfo;
use super::hardware_info::DpuData;
use crate::errors::{ModelError, ModelResult};
use crate::firmware::{Firmware, FirmwareComponentType};
use crate::hardware_info::{DmiData, HardwareInfo, HardwareInfoError};
use crate::machine::machine_id::{MissingHardwareInfo, from_hardware_info_with_type};
use crate::machine_boot_interface::MachineBootInterface;
use crate::power_shelf::power_shelf_id;
use crate::switch::switch_id;

#[derive(Clone, Debug, Default)]
pub struct ExploredEndpointSearchFilter {}

#[derive(Clone, Debug, Default)]
pub struct ExploredManagedHostSearchFilter {}

/// Data that we gathered about a particular endpoint during site exploration
/// This data is stored as JSON in the Database. Therefore the format can
/// only be adjusted in a backward compatible fashion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct EndpointExplorationReport {
    /// The type of the endpoint
    pub endpoint_type: EndpointType,
    /// If the endpoint could not be explored, this contains the last error
    pub last_exploration_error: Option<EndpointExplorationError>,
    /// The time it took to explore the endpoint in the last site explorer run
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_exploration_latency: Option<std::time::Duration>,
    /// Vendor as reported by Redfish
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<bmc_vendor::BMCVendor>,
    /// `Managers` reported by Redfish
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managers: Vec<Manager>,
    /// `Systems` reported by Redfish
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub systems: Vec<ComputerSystem>,
    /// `Chassis` reported by Redfish
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chassis: Vec<Chassis>,
    /// `Service` reported by Redfish
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Service>,
    /// If the endpoint is a BMC that belongs to a Machine and enough data is
    /// available to calculate the `MachineId`, this field contains the `MachineId`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<MachineId>,
    /// Parsed versions, serializtion override means it will always be sorted
    #[serde(
        default,
        serialize_with = "carbide_utils::ordered_map",
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub versions: HashMap<FirmwareComponentType, String>,
    /// Model, parsed out of chassis and service
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "ForgeSetupStatus"
    )]
    pub machine_setup_status: Option<MachineSetupStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_boot_status: Option<SecureBootStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockdown_status: Option<LockdownStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_shelf_id: Option<PowerShelfId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch_id: Option<SwitchId>,
    // Merged from multiple chassis entries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_slot_number: Option<i32>,
    // Merged from multiple chassis entries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_tray_index: Option<i32>,
    // Merged from multiple chassis entries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology_id: Option<i32>,
    // Merged from multiple chassis entries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<i32>,
    /// Transient remediation error detected during an otherwise successful exploration.
    /// Not persisted; used to trigger Site Explorer auto-remediation in the same run.
    #[serde(skip, default)]
    pub remediation_error: Option<EndpointExplorationError>,
}

impl EndpointExplorationReport {
    /// model does a best effort to find a model name within the report
    pub fn model(&self) -> Option<String> {
        // Prefer Systems, not Chassis; at least for Lenovo, Chassis has what is more of a SKU instead of the actual model name.
        let system_with_model = self.systems.iter().find(|&x| x.model.is_some());
        Some(match system_with_model {
            Some(system) => match &system.model {
                Some(model) => model.to_owned(),
                None => {
                    return None;
                }
            },
            None if self.is_dpu() => self
                .identify_dpu()
                .map(|d| d.to_string())
                .unwrap_or("unknown model".to_string()),
            None => match self.chassis.iter().find(|&x| x.model.is_some()) {
                Some(chassis) => chassis.model.as_ref().unwrap().to_string(),
                None => {
                    return None;
                }
            },
        })
    }

    pub fn all_mac_addresses(&self) -> Vec<MacAddress> {
        self.systems
            .iter()
            .flat_map(|s| s.ethernet_interfaces.as_slice())
            .filter_map(|e| e.mac_address)
            .dedup()
            .collect()
    }

    /// Finds the Redfish interface id of the host ethernet interface whose MAC
    /// matches `mac`, if any.
    ///
    /// Used to capture the boot interface's [stable] Redfish interface id
    /// alongside its MAC, giving setup calls a second, [stable] handle to target
    /// in addition to the MAC.
    pub fn find_interface_id_for_mac(&self, mac: MacAddress) -> Option<&str> {
        self.systems
            .iter()
            .flat_map(|s| s.ethernet_interfaces.iter())
            .find(|e| e.mac_address == Some(mac))
            .and_then(|e| e.id.as_deref())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExploredEndpoint {
    /// The IP address of the endpoint we explored
    pub address: std::net::IpAddr,
    /// The data we gathered about the endpoint
    pub report: EndpointExplorationReport,
    /// The version of `report`.
    /// Will increase every time the report gets updated.
    pub report_version: ConfigVersion,
    /// State within preingestion state machine
    pub preingestion_state: PreingestionState,
    /// Indicates that preingestion is waiting for site explorer to refresh the state
    pub waiting_for_explorer_refresh: bool,
    /// Whether the endpoint will be explored in the next site-explorer run
    pub exploration_requested: bool,
    /// Last BMC Reset issued through redfish
    pub last_redfish_bmc_reset: Option<chrono::DateTime<chrono::Utc>>,
    /// Last BMC Reset issued through ipmitool
    pub last_ipmitool_bmc_reset: Option<chrono::DateTime<chrono::Utc>>,
    /// Last Reboot issued through redfish
    pub last_redfish_reboot: Option<chrono::DateTime<chrono::Utc>>,
    /// Last Powercycle issued through redfish
    pub last_redfish_powercycle: Option<chrono::DateTime<chrono::Utc>>,
    /// whether this host is allowed to power on
    pub pause_ingestion_and_poweron: bool,
    /// Flag to prevent site explorer from taking remediation actions on redfish errors
    pub pause_remediation: bool,
    /// The MAC address of the boot interface (primary interface) for this host endpoint
    pub boot_interface_mac: Option<MacAddress>,
    /// The vendor-native Redfish interface id of the boot interface, captured
    /// alongside `boot_interface_mac`. Combined with the MAC via
    /// [`ExploredEndpoint::boot_interface`] to form a [`MachineBootInterface`].
    pub boot_interface_id: Option<String>,
}

impl Display for ExploredEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} / {}", self.address, self.report_version)
    }
}

impl ExploredEndpoint {
    /// Returns the fully-populated boot interface (MAC + Redfish interface id)
    /// for this endpoint, or `None` if either part is missing.
    ///
    /// `None` means we have no complete pair yet -- e.g. the endpoint predates
    /// interface-id capture, or has only ever been reported without a resolvable
    /// interface id.
    pub fn boot_interface(&self) -> Option<MachineBootInterface> {
        MachineBootInterface::from_parts(self.boot_interface_mac, self.boot_interface_id.clone())
    }

    /// find_version will locate a version number within an ExploredEndpoint
    pub fn find_version(
        &self,
        fw_info: &Firmware,
        firmware_type: FirmwareComponentType,
    ) -> Option<&String> {
        for service in self.report.service.iter() {
            if let Some(matching_inventory) = service
                .inventories
                .iter()
                .find(|&x| fw_info.matching_version_id(&x.id, firmware_type))
            {
                tracing::debug!(
                    "find_version {}: For {firmware_type:?} found {:?}",
                    self.address,
                    matching_inventory.version
                );
                return matching_inventory.version.as_ref();
            };
        }
        None
    }

    pub fn find_all_versions(
        &self,
        fw_info: &Firmware,
        firmware_type: FirmwareComponentType,
    ) -> Vec<&String> {
        let mut versions = Vec::new();

        // find all matching versions
        for service in self.report.service.iter() {
            for inventory in service.inventories.iter() {
                if fw_info.matching_version_id(&inventory.id, firmware_type)
                    && let Some(ref version) = inventory.version
                {
                    versions.push(version);
                };
            }
        }

        tracing::debug!(
            "find_all_versions {}: Found {} versions for {firmware_type:?}: {:?}",
            self.address,
            versions.len(),
            versions
        );

        versions
    }

    pub fn is_bluefield_model(&self) -> bool {
        self.report.chassis.iter().any(|chassis| {
            chassis
                .part_number
                .as_ref()
                .is_some_and(|p| is_bluefield_model(p.trim()))
                || chassis.network_adapters.iter().any(|n| {
                    n.part_number
                        .as_ref()
                        .is_some_and(|p| is_bluefield_model(p.trim()))
                })
        })
    }
}

impl EndpointExplorationReport {
    pub fn fetch_host_primary_interface_mac(
        &self,
        explored_dpus: &[ExploredDpu],
    ) -> Option<MacAddress> {
        let system = self.systems.first()?;

        // Gather explored DPUs mac.
        let explored_dpus_macs = explored_dpus
            .iter()
            .filter_map(|x| x.host_pf_mac_address)
            .collect::<Vec<MacAddress>>();

        // Filter PCI device names only for the interfaces which are mapped to DPU.
        // Host might have some integrated or embedded interfaces, which are not used by forge.
        // Need to ignore them.
        let interfaces = system
            .ethernet_interfaces
            .iter()
            .filter(|x| {
                if let Some(mac) = x.mac_address {
                    explored_dpus_macs.contains(&mac)
                } else {
                    false
                }
            })
            .collect::<Vec<&EthernetInterface>>();

        // If any of the interface does not contain pci path, return None.
        if interfaces.iter().any(|x| x.uefi_device_path.is_none()) {
            return None;
        }

        let Some(first) = interfaces.first() else {
            // PCI path is missing from all interfaces, can't sort based on pci path.
            return None;
        };

        let interface_with_min_pci = interfaces.iter().fold(first, |acc, x| {
            // It can never be none as verified above.
            if let (Some(pci_path), Some(existing_path)) =
                (&x.uefi_device_path, &acc.uefi_device_path)
            {
                let path = &pci_path.0;
                let existing_path = &existing_path.0;

                if let Ok(res) =
                    version_compare::compare_to(path, existing_path, version_compare::Cmp::Lt)
                    && res
                {
                    return x;
                }

                return acc;
            }

            acc
        });

        // If we know the bootable interface name, find the MAC address associated with it.
        interface_with_min_pci.mac_address
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum PreingestionState {
    Initial,
    RecheckVersions,
    ScriptRunning,
    BfbRecoveryNeeded {
        reason: String,
        host_bmc_ip: IpAddr,
        #[serde(default)]
        pre_copy_powercycle: bool,
    },
    BfbPlatformPowercycle {
        host_bmc_ip: IpAddr,
        phase: BfbPlatformPowercyclePhase,
        #[serde(default)]
        post_install: bool,
    },
    BfbCopyInProgress {
        started_at: DateTime<Utc>,
        host_bmc_ip: IpAddr,
    },
    BfbInstallationWait {
        started_at: DateTime<Utc>,
        host_bmc_ip: IpAddr,
    },
    InitialReset {
        phase: InitialResetPhase,
        last_time: DateTime<Utc>,
    },
    /// One-shot BMC reset run immediately after `Initial` for every endpoint,
    /// so a freshly-booted BMC report is what pairing/ingestion reads. Notably
    /// refreshes GB200 host BMCs that intermittently drop a DPU from their
    /// PCIe inventory.
    InitialBMCReset {
        phase: InitialBmcResetPhase,
    },
    TimeSyncReset {
        phase: TimeSyncResetPhase,
        last_time: DateTime<Utc>,
    },
    UpgradeFirmwareWait {
        task_id: String,
        final_version: String,
        upgrade_type: FirmwareComponentType,
        power_drains_needed: Option<u32>,
        firmware_number: Option<u32>,
    },
    ResetForNewFirmware {
        final_version: String,
        upgrade_type: FirmwareComponentType,
        power_drains_needed: Option<u32>,
        delay_until: Option<i64>,
        last_power_drain_operation: Option<PowerDrainState>,
    },
    NewFirmwareReportedWait {
        final_version: String,
        upgrade_type: FirmwareComponentType,
        previous_reset_time: Option<i64>,
    },
    RecheckVersionsAfterFailure {
        reason: String,
    },
    Failed {
        reason: String,
    },
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BfbPlatformPowercyclePhase {
    PowerOff,
    PowerOn,
    WaitingForDpuBmc,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InitialResetPhase {
    Start,
    BMCWasReset,
    WaitHostBoot,
}

/// Phases of the one-shot `InitialBMCReset` state. `Start { attempts }` issues
/// the BMC reset; if the BMC is reachable but the reset errors, it retries up
/// to a bound and then proceeds without the reset rather than blocking
/// ingestion. `WaitForBmc` polls until the BMC comes back; an unreachable BMC
/// keeps waiting (it is never a reason to move on). Once it returns, a fresh
/// exploration report is requested and `WaitForExplorerRefresh` waits for it so
/// the relocated checks (and downstream pairing) read the post-reset inventory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InitialBmcResetPhase {
    Start { attempts: u32 },
    WaitForBmc,
    WaitForExplorerRefresh,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TimeSyncResetPhase {
    Start,
    BMCWasReset,
    WaitHostBoot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PowerDrainState {
    Off,
    Powercycle,
    On,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct PCIeDevice {
    pub description: Option<String>,
    pub firmware_version: Option<String>,
    pub gpu_vendor: Option<String>,
    pub id: Option<String>,
    pub manufacturer: Option<String>,
    pub name: Option<String>,
    pub part_number: Option<String>,
    pub serial_number: Option<String>,
    pub status: Option<SystemStatus>,
}

impl PCIeDevice {
    // is_bluefield returns whether the device is a Bluefield
    pub fn is_bluefield(&self) -> bool {
        let Some(model) = &self.part_number else {
            // TODO: maybe model this as an enum that has "Indeterminable" if there's no model
            // but for now it's 'technically' true
            return false;
        };

        is_bluefield_model(model)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SystemStatus {
    pub health: Option<String>,
    pub health_rollup: Option<String>,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExploredDpu {
    /// The DPUs BMC IP
    pub bmc_ip: IpAddr,
    /// The MAC address that is visible to the host (provided by the DPU)
    #[serde(with = "serialize_option_display", default)]
    pub host_pf_mac_address: Option<MacAddress>,

    #[serde(skip)]
    pub report: Arc<EndpointExplorationReport>,
}

impl ExploredDpu {
    pub fn machine_id_if_valid_report(&self) -> ModelResult<&MachineId> {
        let Some(machine_id) = self.report.machine_id.as_ref() else {
            return Err(ModelError::MissingArgument("Missing Machine ID"));
        };

        if self.report.systems.is_empty() {
            return Err(ModelError::MissingArgument("Missing Systems Info"));
        }

        if self.report.chassis.is_empty() {
            return Err(ModelError::MissingArgument("Missing Chassis Info"));
        }

        if self.report.service.is_empty() {
            return Err(ModelError::MissingArgument("Missing Service Info"));
        }

        Ok(machine_id)
    }

    pub fn bmc_firmware_version(&self) -> Option<String> {
        self.report
            .dpu_component_version(FirmwareComponentType::Bmc)
    }

    pub fn bmc_info(&self) -> BmcInfo {
        BmcInfo {
            ip: Some(self.bmc_ip.to_string()),
            mac: self
                .report
                .managers
                .first()
                .and_then(|m| m.ethernet_interfaces.first().and_then(|e| e.mac_address)),
            firmware_version: self.bmc_firmware_version(),
            ..Default::default()
        }
    }

    pub fn hardware_info(&self) -> ModelResult<HardwareInfo> {
        let serial_number = self
            .report
            .systems
            .first()
            .and_then(|system| system.serial_number.as_ref())
            .unwrap();
        let vendor = self
            .report
            .systems
            .first()
            .and_then(|system| system.manufacturer.as_ref());
        let model = self
            .report
            .systems
            .first()
            .and_then(|system| system.model.as_ref());
        let dmi_data = self
            .report
            .create_temporary_dmi_data(serial_number.as_str(), vendor, model);

        let chassis_map = self
            .report
            .chassis
            .iter()
            .map(|x| (x.id.as_str(), x))
            .collect::<HashMap<_, _>>();
        let inventory_map = self.report.get_inventory_map();

        let dpu_data = DpuData {
            factory_mac_address: self
                .host_pf_mac_address
                .ok_or(ModelError::MissingArgument("Missing base mac"))?
                .to_string(),
            part_number: chassis_map
                .get("Card1")
                .and_then(|value| value.part_number.as_ref())
                .unwrap_or(&"".to_string())
                .to_string(),
            part_description: chassis_map
                .get("Card1")
                .and_then(|value| value.model.as_ref())
                .unwrap_or(&"".to_string())
                .to_string(),
            firmware_version: inventory_map
                .get("DPU_NIC")
                .and_then(|value| value.version.as_ref())
                .unwrap_or(&"".to_string())
                .to_string(),
            firmware_date: inventory_map
                .get("DPU_NIC")
                .and_then(|value| value.release_date.as_ref())
                .unwrap_or(&"".to_string())
                .to_string(),
            ..Default::default()
        };

        Ok(HardwareInfo {
            dmi_data: Some(dmi_data),
            dpu_info: Some(dpu_data),
            machine_type: CpuArchitecture::Aarch64,
            ..Default::default()
        })
    }
}

/// A combination of DPU and host that was discovered via Site Exploration
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExploredManagedHost {
    /// The Hosts BMC IP
    pub host_bmc_ip: IpAddr,
    /// Attached DPUs
    pub dpus: Vec<ExploredDpu>,
}

impl ExploredManagedHost {
    pub fn bmc_info(&self) -> BmcInfo {
        BmcInfo {
            ip: Some(self.host_bmc_ip.to_string()),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExploredManagedSwitch {
    /// The Switch's BMC IP
    pub bmc_ip: IpAddr,
    // Host mac address
    pub nv_os_mac_addresses: Vec<MacAddress>,
    /// Exploration report for this switch endpoint
    pub report: EndpointExplorationReport,
}

impl ExploredManagedSwitch {
    pub fn bmc_info(&self) -> BmcInfo {
        BmcInfo {
            ip: Some(self.bmc_ip.to_string()),
            ..Default::default()
        }
    }
}

/// Serialization methods for types which support FromStr/Display
mod serialize_option_display {
    use std::fmt::Display;
    use std::str::FromStr;

    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<T, S>(value: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Display,
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_str(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        T: FromStr,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        let value: Option<String> = Option::deserialize(deserializer)?;
        match value {
            None => Ok(None),
            Some(value) => Ok(Some(T::from_str(&value).map_err(de::Error::custom)?)),
        }
    }
}

/// That that we gathered from exploring a site
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SiteExplorationReport {
    /// The endpoints that had been explored
    pub endpoints: Vec<ExploredEndpoint>,
    /// The managed-hosts which have been explored
    pub managed_hosts: Vec<ExploredManagedHost>,
}

impl EndpointExplorationReport {
    /// Returns a report for an endpoint that is not reachable and could therefore
    /// not be explored
    pub fn new_with_error(e: EndpointExplorationError) -> Self {
        Self {
            endpoint_type: EndpointType::Unknown,
            last_exploration_error: Some(e),
            last_exploration_latency: None,
            managers: Vec::new(),
            systems: Vec::new(),
            chassis: Vec::new(),
            service: Vec::new(),
            vendor: None,
            machine_id: None,
            versions: HashMap::default(),
            model: None,
            machine_setup_status: None,
            secure_boot_status: None,
            lockdown_status: None,
            power_shelf_id: None,
            switch_id: None,
            physical_slot_number: None,
            compute_tray_index: None,
            topology_id: None,
            revision_id: None,
            remediation_error: None,
        }
    }

    pub fn nic_mode(&self) -> Option<NicMode> {
        if self.is_dpu() && !self.systems.is_empty() {
            self.systems[0].attributes.nic_mode
        } else {
            None
        }
    }

    /// Return `true` if the explored endpoint is a DPU
    pub fn is_dpu(&self) -> bool {
        self.identify_dpu().is_some()
    }

    /// Return `true` if the explored endpoint is a PowerShelf.
    /// This checks if the chassis ID is /Chassis/powershelf, or,
    /// if that fails, checks to see if /Chassis/chassis has
    /// a manufacturer containing "lite-on".
    ///
    /// TODO(chet): These are obviously workarounds for now while
    /// we work with vendors to update their BMC firmware.
    pub fn is_power_shelf(&self) -> bool {
        self.chassis.iter().any(|c| {
            c.id.to_lowercase().contains("powershelf")
                || (c.id == "chassis"
                    && c.manufacturer
                        .as_ref()
                        .is_some_and(|m| m.to_lowercase().contains("lite-on")))
        })
    }

    /// Return `true` if the explored endpoint is a Switch
    pub fn is_switch(&self) -> bool {
        self.chassis
            .iter()
            .any(|c| c.id.to_lowercase().contains("mgx_nvswitch_0"))
    }

    /// Return `DpuModel` if the explored endpoint is a DPU
    pub fn identify_dpu(&self) -> Option<DpuModel> {
        if !self
            .systems
            .first()
            .map(|system| system.id == "Bluefield")
            .unwrap_or(false)
        {
            return None;
        }

        let chassis_map = self
            .chassis
            .iter()
            .map(|x| (x.id.as_str(), x))
            .collect::<HashMap<_, _>>();
        let model = chassis_map
            .get("Card1")
            .and_then(|value| value.model.as_ref())
            .unwrap_or(&"".to_string())
            .to_string();
        match model.to_lowercase() {
            value if value.contains("bluefield 2") => Some(DpuModel::BlueField2),
            value if value.contains("bluefield 3") => Some(DpuModel::BlueField3),
            _ => Some(DpuModel::Unknown),
        }
    }

    pub fn create_temporary_dmi_data(
        &self,
        serial_number: &str,
        vendor: Option<&String>,
        model: Option<&String>,
    ) -> DmiData {
        let sys_vendor = if let Some(x) = vendor {
            x.to_string()
        } else {
            carbide_utils::DEFAULT_DMI_SYSTEM_MANUFACTURER.to_string()
        };
        let product_name = if let Some(x) = model {
            x.to_string()
        } else {
            carbide_utils::DEFAULT_DMI_SYSTEM_MODEL.to_string()
        };
        // For DPUs the discovered data contains enough information to
        // calculate a MachineId
        // The "Unspecified" strings are delivered as serial numbers when doing
        // inband discovery via libudev. For compatibility we have to use
        // the same values here.
        DmiData {
            product_serial: serial_number.trim().to_string(),
            chassis_serial: carbide_utils::DEFAULT_DPU_DMI_CHASSIS_SERIAL_NUMBER.to_string(),
            board_serial: carbide_utils::DEFAULT_DPU_DMI_BOARD_SERIAL_NUMBER.to_string(),
            bios_version: "".to_string(),
            sys_vendor,
            board_name: "BlueField SoC".to_string(),
            bios_date: "".to_string(),
            board_version: "".to_string(),
            product_name,
        }
    }

    /// Tries to generate and store a MachineId for the discovered endpoint if
    /// enough data for generation is available
    pub fn generate_machine_id(
        &mut self,
        force_predicted_host: bool,
    ) -> ModelResult<Option<&MachineId>> {
        if let Some(serial_number) = self
            .systems
            .first()
            .and_then(|system| system.serial_number.as_ref())
        {
            let vendor = self
                .systems
                .first()
                .and_then(|system| system.manufacturer.as_ref());
            let model = self
                .systems
                .first()
                .and_then(|system| system.model.as_ref());

            let dmi_data = self.create_temporary_dmi_data(serial_number, vendor, model);

            // Construct a HardwareInfo object specifically so that we can mint a MachineId.
            let hardware_info = HardwareInfo {
                dmi_data: Some(dmi_data),
                // This field should not be read, machine_id::from_hardware_info_with_type should not
                // need this, only the dmi_data.
                machine_type: CpuArchitecture::Unknown,
                ..Default::default()
            };

            let machine_type = if self.is_dpu() {
                MachineType::Dpu
            } else if force_predicted_host {
                MachineType::PredictedHost
            } else {
                return Ok(None);
            };

            let machine_id = from_hardware_info_with_type(&hardware_info, machine_type)
                .map_err(|e| ModelError::HardwareInfo(HardwareInfoError::MissingHardwareInfo(e)))?;

            Ok(Some(self.machine_id.insert(machine_id)))
        } else {
            Err(ModelError::HardwareInfo(
                HardwareInfoError::MissingHardwareInfo(MissingHardwareInfo::Serial),
            ))
        }
    }

    /// Tries to generate and store a MachineId for the discovered endpoint if
    /// enough data for generation is available
    pub fn generate_power_shelf_id(&mut self) -> ModelResult<Option<&PowerShelfId>> {
        let chassis = self.chassis.first().unwrap();
        let serial_number = chassis.serial_number.clone().unwrap_or("".to_string());
        let manufacturer = chassis.manufacturer.clone().unwrap_or("".to_string());
        let model = chassis.model.clone().unwrap_or("".to_string());

        let power_shelf_type = PowerShelfType::Rack; //TODO Check later if we need to support other types
        let power_shelf_source = PowerShelfIdSource::ProductBoardChassisSerial;

        let power_shelf_id = power_shelf_id::from_hardware_info_with_type(
            serial_number.as_str(),
            manufacturer.as_str(),
            model.as_str(),
            power_shelf_source,
            power_shelf_type,
        )
        .map_err(|_e| {
            ModelError::HardwareInfo(HardwareInfoError::MissingHardwareInfo(
                MissingHardwareInfo::Serial,
            ))
        })?;

        Ok(Some(self.power_shelf_id.insert(power_shelf_id)))
    }

    //TODO: refactor for common code with generate_power_shelf_id
    /// Tries to generate and store a MachineId for the discovered endpoint if
    /// enough data for generation is available
    pub fn generate_switch_id(&mut self) -> ModelResult<Option<SwitchId>> {
        let chassis = self
            .chassis
            .iter()
            .find(|c| c.id.to_string().to_lowercase() == "mgx_nvswitch_0")
            .unwrap();
        let serial_number = chassis.serial_number.clone();
        let manufacturer = chassis.manufacturer.clone().unwrap_or("NVIDIA".to_string());
        let model = "Switch".to_string();

        if let Some(serial_number) = serial_number.as_ref() {
            let switch_type = SwitchType::NvLink;
            let switch_source = SwitchIdSource::ProductBoardChassisSerial;

            let switch_id = switch_id::from_hardware_info_with_type(
                serial_number.as_str(),
                manufacturer.as_str(),
                model.as_str(),
                switch_source,
                switch_type,
            )
            .map_err(|_e| {
                ModelError::HardwareInfo(HardwareInfoError::MissingHardwareInfo(
                    MissingHardwareInfo::Serial,
                ))
            })?;
            self.switch_id = Some(switch_id);
            Ok(self.switch_id)
        } else {
            Err(ModelError::HardwareInfo(
                HardwareInfoError::MissingHardwareInfo(MissingHardwareInfo::Serial),
            ))
        }
    }

    pub fn get_inventory_map(&self) -> HashMap<&str, &Inventory> {
        self.service
            .iter()
            .find(|s| s.id == *"FirmwareInventory")
            .map(|s| {
                s.inventories
                    .iter()
                    .map(|i| (i.id.as_str(), i))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default()
    }

    pub fn dpu_component_version(&self, component: FirmwareComponentType) -> Option<String> {
        match component {
            FirmwareComponentType::Bmc => self.dpu_bmc_version(),
            FirmwareComponentType::Uefi => self.dpu_uefi_version(),
            _ => None,
        }
    }

    pub fn dpu_bmc_version(&self) -> Option<String> {
        Some(
            self.get_inventory_map()
                .iter()
                .find(|s| s.0.contains("BMC_Firmware"))
                .and_then(|value| value.1.version.as_ref())
                .unwrap_or(&"0".to_string())
                .to_lowercase()
                .replace("bf-", ""),
        )
    }

    pub fn dpu_uefi_version(&self) -> Option<String> {
        self.get_inventory_map()
            .get("DPU_UEFI")
            .and_then(|value| value.version.clone())
    }

    pub fn parse_versions(&mut self, fw_info: &Firmware) -> Vec<FirmwareComponentType> {
        let mut not_found = Vec::new();
        for fwtype in fw_info.components.keys() {
            if let Some(current) = fw_info.find_version(self, *fwtype) {
                self.versions.insert(*fwtype, current);
            } else {
                not_found.push(*fwtype)
            }
        }
        not_found
    }

    /// Extract position info from chassis entries into the report-level fields.
    ///
    /// Uses "first wins" strategy: takes the first non-None value found across
    /// all chassis entries. This is consistent with how `model()` extracts data
    /// from the chassis array.
    pub fn parse_position_info(&mut self) {
        for chassis in &self.chassis {
            self.physical_slot_number = self.physical_slot_number.or(chassis.physical_slot_number);
            self.compute_tray_index = self.compute_tray_index.or(chassis.compute_tray_index);
            self.topology_id = self.topology_id.or(chassis.topology_id);
            self.revision_id = self.revision_id.or(chassis.revision_id);
        }
    }
}

/// Describes errors that might have been encountered during exploring an endpoint
#[derive(thiserror::Error, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "Type", rename_all = "PascalCase")]
pub enum EndpointExplorationError {
    /// site-explorer timed out sending a request (or getting a response) from
    /// this endpoint, either due to connectivity issues to the destination IP,
    /// or the destination port [being up but] not responding in a timely
    /// matter. This is ultimately tripped by a reqwest is_timeout error in
    /// the current implementation. For cases where the destination IP *is*
    /// reachable, but the  port is not listening, see ConnectionRefused.
    #[error("site-explorer timed out communicating with the endpoint: {details:?}")]
    #[serde(rename_all = "PascalCase")]
    ConnectionTimeout { details: String },
    /// The connection to the configured endpoint was refused. This indicates
    /// that site-explorer probably has connectivity to the target IP (unless
    /// a network device in the path is sending an RST), and is able to positively
    /// confirm the endpoint is not listening on the target port (which probably
    /// means no Redfish API is being exposed), OR, can ALSO mean there was a TLS
    /// handshake failure (since reqwest is_connect errors capture TLS handshake
    /// errors as well). A more common example here is if site-explorer is
    /// [unknowingly] exploring a yet-unpaired DPU, and the IP it is attempting
    /// to explore happens to be the DPU admin IP. Since the admin/host side of
    /// a DPU doesn't expose a Redfish API, you will see ConnectionRefused. This
    /// is ultimately tripped by a reqwest is_connect error in the current
    /// implementation.
    #[error("The connection to the endpoint was refused: {details:?}")]
    #[serde(rename_all = "PascalCase")]
    ConnectionRefused { details: String },
    /// Some other generic error happened while attempting to connect
    /// and make a request (or receive a response) from the endpoint
    /// which was not otherwise handled by connection timeout or
    /// connection refused handlers.
    #[error("The endpoint was not reachable due to a generic network issue: {details:?}")]
    #[serde(rename_all = "PascalCase")]
    Unreachable { details: Option<String> },
    /// A Redfish variant we don't support, typically a new vendor
    #[error("Redfish vendor '{vendor}' not supported")]
    UnsupportedVendor { vendor: String },
    /// A generic redfish error. No additional details are available
    #[error(
        "Error while performing Redfish request: {details}: {response_body:?} (response code: {response_code:?})"
    )]
    #[serde(rename_all = "PascalCase")]
    RedfishError {
        details: String,
        response_body: Option<String>,
        response_code: Option<u16>,
    },
    /// The endpoint returned a 401 Unauthorized or 403 Forbidden Status
    #[error("Unauthorized: {details}")]
    #[serde(rename_all = "PascalCase")]
    Unauthorized {
        details: String,
        response_body: Option<String>,
        response_code: Option<u16>,
    },
    #[error("Missing credential {key}")]
    MissingCredentials {
        #[serde(default)]
        key: String,
        cause: String,
    },
    #[error("Secrets engine error occurred: {cause}")]
    SecretsEngineError {
        #[serde(default)]
        cause: String,
    },
    #[error("Failed setting credential {key}: {cause}")]
    SetCredentials { key: String, cause: String },
    /// Deprecated. Replaced by `RedfishError`.
    /// This field just exists here until site-explorer updates existing records
    #[error("Endpoint is not a BMC with Redfish support at the specified URI")]
    MissingRedfish { uri: Option<String> },
    #[error("BMC vendor field is not populated. Unsupported BMC.")]
    MissingVendor,
    #[error(
        "Site explorer will not explore this endpoint to avoid lockout: it could not login previously"
    )]
    AvoidLockout,
    /// An error which is not further detailed
    #[error("Error: {details}")]
    #[serde(rename_all = "PascalCase")]
    Other { details: String },

    #[error("VikingFWInventoryForbiddenError: {details}")]
    #[serde(rename_all = "PascalCase")]
    VikingFWInventoryForbiddenError {
        details: String,
        response_body: Option<String>,
        response_code: Option<u16>,
    },

    #[error("Invalid Redfish response for DPU BIOS: {details}")]
    #[serde(rename_all = "PascalCase")]
    InvalidDpuRedfishBiosResponse {
        details: String,
        response_body: Option<String>,
        response_code: Option<u16>,
    },

    /// An intermittent unauthorized error that occurred even when site-wide
    /// credentials are already set. This is a transient error that should be
    /// retried rather than triggering AvoidLockout behavior.
    /// After `consecutive_count` reaches the threshold, escalates to regular Unauthorized.
    #[error("Intermittent unauthorized error (attempt {consecutive_count}): {details}")]
    #[serde(rename_all = "PascalCase")]
    IntermittentUnauthorized {
        details: String,
        response_body: Option<String>,
        response_code: Option<u16>,
        #[serde(default)]
        consecutive_count: u32,
    },
}

impl EndpointExplorationError {
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, EndpointExplorationError::Unauthorized { .. })
            || matches!(self, EndpointExplorationError::AvoidLockout)
    }

    pub fn is_unreachable(&self) -> bool {
        matches!(
            self,
            EndpointExplorationError::ConnectionTimeout { .. }
                | EndpointExplorationError::ConnectionRefused { .. }
                | EndpointExplorationError::Unreachable { .. }
        )
    }

    pub fn is_redfish(&self) -> bool {
        matches!(self, EndpointExplorationError::RedfishError { .. })
            || matches!(
                self,
                EndpointExplorationError::InvalidDpuRedfishBiosResponse { .. }
            )
    }

    pub fn is_dpu_redfish_bios_response_invalid(&self) -> bool {
        matches!(
            self,
            EndpointExplorationError::InvalidDpuRedfishBiosResponse { .. }
        )
    }

    /// Returns the consecutive count if this is an IntermittentUnauthorized error.
    pub fn intermittent_unauthorized_count(&self) -> Option<u32> {
        match self {
            EndpointExplorationError::IntermittentUnauthorized {
                consecutive_count, ..
            } => Some(*consecutive_count),
            _ => None,
        }
    }
}

/// The type of the endpoint
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum EndpointType {
    Bmc,
    #[default]
    Unknown,
}

#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ComputerSystemAttributes {
    pub nic_mode: Option<NicMode>,
    pub is_infinite_boot_enabled: Option<bool>,
}

/// `ComputerSystem` definition. Matches redfish definition
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ComputerSystem {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ethernet_interfaces: Vec<EthernetInterface>,
    pub id: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    #[serde(default)]
    pub attributes: ComputerSystemAttributes,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pcie_devices: Vec<PCIeDevice>,
    #[serde(default, deserialize_with = "base_mac_deserialize")]
    pub base_mac: Option<BaseMac>,
    #[serde(default)]
    pub power_state: PowerState,
    pub sku: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_order: Option<BootOrder>,
}

pub fn base_mac_deserialize<'a, D>(deserializer: D) -> Result<Option<BaseMac>, D::Error>
where
    D: Deserializer<'a>,
{
    let optional_value: Option<String> = Option::deserialize(deserializer)?;
    Ok(optional_value.and_then(|v| v.parse().ok()))
}

impl ComputerSystem {
    pub fn check_serial_number(&self, expected_serial_number: &String) -> bool {
        match self.serial_number {
            Some(ref serial_number) => serial_number == expected_serial_number,
            None => false,
        }
    }

    pub fn check_sku(&self, expected_sku: &String) -> bool {
        match self.sku {
            Some(ref sku) => sku == expected_sku,
            None => false,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    Off,
    #[default]
    On,
    PoweringOff,
    PoweringOn,
    Paused,
    Unknown,
}

/// `Manager` definition. Matches redfish definition
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Manager {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ethernet_interfaces: Vec<EthernetInterface>,
    pub id: String,
}

/// `EthernetInterface` definition. Matches redfish definition
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct EthernetInterface {
    pub description: Option<String>,
    pub id: Option<String>,
    pub interface_enabled: Option<bool>,
    // We want to store as MACAddress in topology data (tbh I don't actually
    // know why, maybe it's fine if we store it as MacAddress), but there are
    // cases where the input data is MacAddress, so we'll allow MacAddress
    // as or MACAddress as inputs, but always serialize out to MACAddress.
    #[serde(
        rename = "MACAddress",
        alias = "MacAddress",
        deserialize_with = "carbide_network::deserialize_optional_mlx_mac"
    )]
    pub mac_address: Option<MacAddress>,

    /// Redfish `LinkStatus` as reported by the BMC (e.g. LinkUp, LinkDown, NoLink).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_status: Option<String>,

    pub uefi_device_path: Option<UefiDevicePath>,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct UefiDevicePath(String);

lazy_static! {
    static ref PCI_ROOT_REGEX: Regex =
        Regex::new(r"^PciRoot\(([^)]*)\)").expect("must always compile");
    static ref PCI_NODE_REGEX: Regex = Regex::new(r"/Pci\(([^)]*)\)").expect("must always compile");
}

impl FromStr for UefiDevicePath {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // UEFI 2.10 §10.3.4: PciRoot followed by one or more Pci nodes,
        // e.g. PciRoot(0x8)/Pci(0x2,0xa)/Pci(0x0,0x0) (NIC behind a bridge) or
        //      PciRoot(0x7)/Pci(0x0,0x0)            (NIC on a root port).
        // Trailing /MAC(...) is optional and discarded.

        let st = s.rsplit_once("/MAC").map(|x| x.0).unwrap_or(s);

        let mut pci = vec![];
        let mut push_group = |group: &str| -> Result<(), String> {
            for hex in group.split(',') {
                let hex_int = u32::from_str_radix(&hex.to_lowercase().replace("0x", ""), 16)
                    .map_err(|e| {
                        format!("Can't convert pci address to int {hex}, error: {e} for pci: {s}")
                    })?;
                pci.push(hex_int.to_string());
            }
            Ok(())
        };

        let root = PCI_ROOT_REGEX
            .captures(st)
            .and_then(|c| c.get(1))
            .ok_or_else(|| format!("Could not match regex in PCI Device Path {s}."))?;
        push_group(root.as_str())?;

        let mut had_pci = false;
        for cap in PCI_NODE_REGEX.captures_iter(st) {
            if let Some(g) = cap.get(1) {
                had_pci = true;
                push_group(g.as_str())?;
            }
        }
        if !had_pci {
            return Err(format!("Could not match regex in PCI Device Path {s}."));
        }

        Ok(UefiDevicePath(pci.join(".")))
    }
}

/// `Chassis` definition. Matches redfish definition
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Chassis {
    pub id: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub part_number: Option<String>,
    pub serial_number: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_adapters: Vec<NetworkAdapter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_slot_number: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_tray_index: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology_id: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<i32>,
}

/// `NetworkAdapter` definition. Matches redfish definition
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkAdapter {
    pub id: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    #[serde(rename = "PartNumber")]
    pub part_number: Option<String>,
    #[serde(rename = "SerialNumber")]
    pub serial_number: Option<String>,
}

/// `SecureBootStatus` definition.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SecureBootStatus {
    pub is_enabled: bool,
}

/// `LockdownStatus` definition. Matches redfish definition
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct LockdownStatus {
    pub status: InternalLockdownStatus,
    pub message: String,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum InternalLockdownStatus {
    Enabled,
    Partial,
    #[default]
    Disabled,
}

/// `Service` definition. Matches redfish definition
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Service {
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inventories: Vec<Inventory>,
}

/// `Inventory` definition. Matches redfish definition
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Inventory {
    pub id: String,
    pub description: Option<String>,
    pub version: Option<String>,
    pub release_date: Option<String>,
}

/// `MachineSetupStatus` definition. Matches redfish definition
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MachineSetupStatus {
    pub is_done: bool,
    pub diffs: Vec<MachineSetupDiff>,
}

/// `BootOrder` definition.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct BootOrder {
    pub boot_order: Vec<BootOption>,
}

/// `MachineSetupDiff` definition. Matches redfish definition
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MachineSetupDiff {
    pub key: String,
    pub expected: String,
    pub actual: String,
}

/// `BootOption` definition.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct BootOption {
    pub display_name: String,
    pub id: String,
    pub boot_option_enabled: Option<bool>,
    pub uefi_device_path: Option<String>,
}

/// Whether a found/explored machine is in the set of expected machines,
/// currently defined by the expected_machines table in the database.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum MachineExpectation {
    #[default]
    NotApplicable,
    Unexpected,
    Expected,
}

impl Display for MachineExpectation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApplicable => write!(f, "na"),
            Self::Unexpected => write!(f, "unexpected"),
            Self::Expected => write!(f, "expected"),
        }
    }
}

impl From<bool> for MachineExpectation {
    fn from(b: bool) -> Self {
        match b {
            true => MachineExpectation::Expected,
            false => MachineExpectation::Unexpected,
        }
    }
}

impl From<Option<bool>> for MachineExpectation {
    fn from(b: Option<bool>) -> Self {
        match b {
            None => MachineExpectation::NotApplicable,
            Some(true) => MachineExpectation::Expected,
            _ => MachineExpectation::Unexpected,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum NicMode {
    #[serde(rename = "DpuMode", alias = "Dpu")]
    Dpu,
    #[serde(rename = "NicMode", alias = "Nic")]
    Nic,
}

impl Display for NicMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

// returns true if the model is for a Bluefield-3 DPU
pub fn is_bf3_dpu(model: &str) -> bool {
    let normalized_model = model.to_lowercase();
    // prefix matching for BlueField-3 DPUs (https://docs.nvidia.com/networking/display/bf3dpu)
    normalized_model.starts_with("900-9d3b6")
    // looks like Lenovo ThinkSystem SR675 V3s will report the part number of NVIDIA BlueField-3 VPI QSFP112 2P 200G PCIe Gen5 x16 as SN37B36732
    // https://windows-server.lenovo.com/repo/2024_05/html/SR675V3_7D9Q_7D9R-Windows_Server_2019.html
    ||  normalized_model.starts_with("sn37b36732")
}

// returns true if the model is for a Bluefield-3 SuperNIC
pub fn is_bf3_supernic(model: &str) -> bool {
    let normalized_model = model.to_lowercase();
    // prefix matching for BlueField-3 SuperNICs (https://docs.nvidia.com/networking/display/bf3dpu)
    normalized_model.starts_with("900-9d3b4") || normalized_model.starts_with("900-9d3d4")
}

// returns true if the model is for a Bluefield-2
pub fn is_bf2_dpu(model: &str) -> bool {
    let normalized_model = model.to_lowercase();
    // prefix matching for BlueField-2 DPU (https://docs.nvidia.com/nvidia-bluefield-2-ethernet-dpu-user-guide.pdf)
    normalized_model.starts_with("mbf2")
}
// is_bluefield_model returns true if the passed in string is a bluefield model
pub fn is_bluefield_model(model: &str) -> bool {
    let normalized_model = model.to_lowercase();

    normalized_model.contains("bluefield")
        || is_bf3_dpu(&normalized_model)
        // prefix matching for BlueField-3 SuperNICs (https://docs.nvidia.com/networking/display/bf3dpu)
        || is_bf3_supernic(&normalized_model)
        // prefix matching for BlueField-2 DPU (https://docs.nvidia.com/nvidia-bluefield-2-ethernet-dpu-user-guide.pdf)
        // TODO (sp): should we be matching on all the individual models listed ("MBF2M516C-CECOT", .. etc)
        || is_bf2_dpu(&normalized_model)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firmware::FirmwareComponent;
    use crate::machine::machine_id::from_hardware_info;

    fn create_test_firmware(firmware_type: FirmwareComponentType, regex_pattern: &str) -> Firmware {
        let mut components = HashMap::new();
        components.insert(
            firmware_type,
            FirmwareComponent {
                current_version_reported_as: Some(Regex::new(regex_pattern).unwrap()),
                preingest_upgrade_when_below: None,
                known_firmware: vec![],
            },
        );

        Firmware {
            vendor: bmc_vendor::BMCVendor::Nvidia,
            model: "Test Model".to_string(),
            components,
            explicit_start_needed: false,
            ordering: vec![],
        }
    }

    fn create_test_endpoint(inventories: Vec<(&str, Option<&str>)>) -> ExploredEndpoint {
        let inventory_objects: Vec<Inventory> = inventories
            .into_iter()
            .map(|(id, version)| Inventory {
                id: id.to_string(),
                description: None,
                version: version.map(|v| v.to_string()),
                release_date: None,
            })
            .collect();

        ExploredEndpoint {
            address: "192.168.1.1".parse::<IpAddr>().unwrap(),
            report: EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                service: vec![Service {
                    id: "FirmwareInventory".to_string(),
                    inventories: inventory_objects,
                }],
                ..Default::default()
            },
            report_version: ConfigVersion::new(1),
            preingestion_state: PreingestionState::Initial,
            waiting_for_explorer_refresh: false,
            exploration_requested: false,
            last_redfish_bmc_reset: None,
            last_ipmitool_bmc_reset: None,
            last_redfish_reboot: None,
            last_redfish_powercycle: None,
            pause_remediation: false,
            boot_interface_mac: None,
            boot_interface_id: None,
            pause_ingestion_and_poweron: false,
        }
    }

    #[test]
    fn test_find_version_single_match() {
        let fw_info = create_test_firmware(FirmwareComponentType::Bmc, r"^BMC_Firmware$");
        let endpoint = create_test_endpoint(vec![
            ("BMC_Firmware", Some("1.2.3")),
            ("DPU_UEFI", Some("4.5.6")),
        ]);

        let result = endpoint.find_version(&fw_info, FirmwareComponentType::Bmc);
        assert_eq!(result, Some(&"1.2.3".to_string()));
    }

    #[test]
    fn test_find_version_no_match() {
        let fw_info = create_test_firmware(FirmwareComponentType::Bmc, r"^BMC_Firmware$");
        let endpoint = create_test_endpoint(vec![
            ("DPU_UEFI", Some("4.5.6")),
            ("Other_Component", Some("7.8.9")),
        ]);

        let result = endpoint.find_version(&fw_info, FirmwareComponentType::Bmc);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_all_versions_single_match() {
        let fw_info = create_test_firmware(FirmwareComponentType::Bmc, r"^BMC_Firmware$");
        let endpoint = create_test_endpoint(vec![
            ("BMC_Firmware", Some("1.2.3")),
            ("DPU_UEFI", Some("4.5.6")),
        ]);

        let results = endpoint.find_all_versions(&fw_info, FirmwareComponentType::Bmc);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], &"1.2.3".to_string());
    }

    #[test]
    fn test_find_all_versions_multiple_matches() {
        let fw_info = create_test_firmware(FirmwareComponentType::Bmc, r"BMC_Firmware");
        let endpoint = create_test_endpoint(vec![
            ("BMC_Firmware_1", Some("1.2.3")),
            ("BMC_Firmware_2", Some("2.3.4")),
            ("BMC_Firmware_3", Some("3.4.5")),
            ("DPU_UEFI", Some("4.5.6")),
        ]);

        let results = endpoint.find_all_versions(&fw_info, FirmwareComponentType::Bmc);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], &"1.2.3".to_string());
        assert_eq!(results[1], &"2.3.4".to_string());
        assert_eq!(results[2], &"3.4.5".to_string());
    }

    #[test]
    fn test_find_all_versions_no_matches() {
        let fw_info = create_test_firmware(FirmwareComponentType::Bmc, r"^BMC_Firmware$");
        let endpoint =
            create_test_endpoint(vec![("DPU_UEFI", Some("4.5.6")), ("Other", Some("7.8.9"))]);

        let results = endpoint.find_all_versions(&fw_info, FirmwareComponentType::Bmc);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_find_all_versions_skips_none() {
        let fw_info = create_test_firmware(FirmwareComponentType::Bmc, r"BMC_Firmware");
        let endpoint = create_test_endpoint(vec![
            ("BMC_Firmware_1", Some("1.2.3")),
            ("BMC_Firmware_2", None),
            ("BMC_Firmware_3", Some("3.4.5")),
        ]);

        let results = endpoint.find_all_versions(&fw_info, FirmwareComponentType::Bmc);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], &"1.2.3".to_string());
        assert_eq!(results[1], &"3.4.5".to_string());
    }

    #[test]
    fn serialize_endpoint_exploration_error() {
        // test handling legacy format for the Unreachable error
        let report =
            EndpointExplorationReport::new_with_error(EndpointExplorationError::Unreachable {
                details: None,
            });

        let serialized = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serialized,
            r#"{"EndpointType":"Unknown","LastExplorationError":{"Type":"Unreachable","Details":null}}"#
        );
        assert_eq!(
            serde_json::from_str::<EndpointExplorationReport>(&serialized).unwrap(),
            report
        );

        let report =
            EndpointExplorationReport::new_with_error(EndpointExplorationError::Unreachable {
                details: Some("test_details".to_string()),
            });

        let serialized = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serialized,
            r#"{"EndpointType":"Unknown","LastExplorationError":{"Type":"Unreachable","Details":"test_details"}}"#
        );
        assert_eq!(
            serde_json::from_str::<EndpointExplorationReport>(&serialized).unwrap(),
            report
        );

        let mut report =
            EndpointExplorationReport::new_with_error(EndpointExplorationError::RedfishError {
                details: "test".to_string(),
                response_body: None,
                response_code: None,
            });

        let serialized = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serialized,
            r#"{"EndpointType":"Unknown","LastExplorationError":{"Type":"RedfishError","Details":"test","ResponseBody":null,"ResponseCode":null}}"#
        );
        assert_eq!(
            serde_json::from_str::<EndpointExplorationReport>(&serialized).unwrap(),
            report
        );

        let serialized_nobody = r#"{"EndpointType":"Unknown","LastExplorationError":{"Type":"RedfishError","Details":"test"}}"#;
        assert_eq!(
            serde_json::from_str::<EndpointExplorationReport>(serialized_nobody).unwrap(),
            report
        );

        report.last_exploration_latency = Some(std::time::Duration::from_millis(1111));
        let serialized = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serialized,
            r#"{"EndpointType":"Unknown","LastExplorationError":{"Type":"RedfishError","Details":"test","ResponseBody":null,"ResponseCode":null},"LastExplorationLatency":{"secs":1,"nanos":111000000}}"#
        );
        assert_eq!(
            serde_json::from_str::<EndpointExplorationReport>(&serialized).unwrap(),
            report
        );
    }

    #[test]
    fn serialize_explored_managed_host() {
        let host = ExploredManagedHost {
            host_bmc_ip: "1.2.3.4".parse().unwrap(),
            dpus: vec![ExploredDpu {
                bmc_ip: "1.2.3.5".parse().unwrap(),
                host_pf_mac_address: Some("11:22:33:44:55:66".parse().unwrap()),
                report: Default::default(),
            }],
        };
        let serialized = serde_json::to_string(&host).unwrap();
        assert_eq!(
            serialized,
            r#"{"HostBmcIp":"1.2.3.4","Dpus":[{"BmcIp":"1.2.3.5","HostPfMacAddress":"11:22:33:44:55:66"}]}"#
        );
        assert_eq!(
            serde_json::from_str::<ExploredManagedHost>(&serialized).unwrap(),
            host
        );

        let host = ExploredManagedHost {
            host_bmc_ip: "1.2.3.4".parse().unwrap(),
            dpus: vec![ExploredDpu {
                bmc_ip: "1.2.3.5".parse().unwrap(),
                host_pf_mac_address: None,
                report: Default::default(),
            }],
        };
        let serialized = serde_json::to_string(&host).unwrap();
        assert_eq!(
            serialized,
            r#"{"HostBmcIp":"1.2.3.4","Dpus":[{"BmcIp":"1.2.3.5","HostPfMacAddress":null}]}"#
        );
        assert_eq!(
            serde_json::from_str::<ExploredManagedHost>(&serialized).unwrap(),
            host
        );
    }

    #[test]
    fn test_firmware_inventory() {
        let uefi_version = Some("4.5.0-46-gf57517d".to_string());
        let uefi_inventory = Inventory {
            id: "DPU_UEFI".to_string(),
            description: Some("Host image".to_string()),
            version: uefi_version.clone(),
            release_date: None,
        };
        let report = EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            last_exploration_latency: None,
            vendor: Some(bmc_vendor::BMCVendor::Nvidia),
            managers: vec![Manager {
                ethernet_interfaces: vec![],
                id: "bmc".to_string(),
            }],
            systems: vec![ComputerSystem {
                ethernet_interfaces: vec![],
                id: "Bluefield".to_string(),
                manufacturer: None,
                model: None,
                serial_number: Some("MT2242XZ00NX".to_string()),
                attributes: ComputerSystemAttributes {
                    nic_mode: Some(NicMode::Dpu),
                    is_infinite_boot_enabled: None,
                },
                pcie_devices: vec![],
                base_mac: Some("A088C208804C".parse().unwrap()),
                power_state: PowerState::On,
                sku: None,
                boot_order: None,
            }],
            chassis: vec![Chassis {
                id: "NIC.Slot.1".to_string(),
                manufacturer: None,
                model: None,
                serial_number: Some("MT2242XZ00NX".to_string()),
                part_number: None,
                network_adapters: vec![],
                physical_slot_number: None,
                compute_tray_index: None,
                topology_id: None,
                revision_id: None,
            }],
            service: vec![
                Service {
                    id: "FirmwareInventory".to_string(),
                    inventories: vec![uefi_inventory],
                },
                Service {
                    id: "SoftwareInventory".to_string(),
                    inventories: vec![],
                },
            ],
            machine_id: None,
            versions: HashMap::default(),
            model: None,
            machine_setup_status: None,
            secure_boot_status: None,
            lockdown_status: None,
            power_shelf_id: None,
            switch_id: None,

            physical_slot_number: None,
            compute_tray_index: None,
            revision_id: None,
            topology_id: None,
            remediation_error: None,
        };

        let inventory_map = report.get_inventory_map();
        // SoftwareInventory doesn't have inventories in it. So map should have only FW inventory.
        assert_eq!(inventory_map.len(), 1);
        assert_eq!(report.dpu_uefi_version(), uefi_version);
    }

    #[test]
    fn generate_machine_id_for_dpu() {
        let mut report = EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            last_exploration_latency: None,
            vendor: Some(bmc_vendor::BMCVendor::Nvidia),
            managers: vec![Manager {
                ethernet_interfaces: vec![],
                id: "bmc".to_string(),
            }],
            systems: vec![ComputerSystem {
                ethernet_interfaces: vec![],
                id: "Bluefield".to_string(),
                manufacturer: None,
                model: None,
                serial_number: Some("MT2242XZ00NX".to_string()),
                attributes: ComputerSystemAttributes {
                    nic_mode: Some(NicMode::Dpu),
                    is_infinite_boot_enabled: None,
                },
                pcie_devices: vec![],
                base_mac: Some("A088C208804C".parse().unwrap()),
                power_state: PowerState::On,
                sku: None,
                boot_order: None,
            }],
            chassis: vec![Chassis {
                id: "NIC.Slot.1".to_string(),
                manufacturer: None,
                model: None,
                serial_number: Some("MT2242XZ00NX".to_string()),
                part_number: None,
                network_adapters: vec![],
                physical_slot_number: None,
                compute_tray_index: None,
                topology_id: None,
                revision_id: None,
            }],
            service: vec![
                Service {
                    id: "FirmwareInventory".to_string(),
                    inventories: vec![],
                },
                Service {
                    id: "SoftwareInventory".to_string(),
                    inventories: vec![],
                },
            ],
            machine_id: None,
            versions: HashMap::default(),
            model: None,
            machine_setup_status: None,
            secure_boot_status: None,
            lockdown_status: None,
            power_shelf_id: None,
            switch_id: None,
            physical_slot_number: None,
            compute_tray_index: None,
            revision_id: None,
            topology_id: None,
            remediation_error: None,
        };
        report
            .generate_machine_id(false)
            .expect("Error generating machine ID");

        let machine_id = report.machine_id.unwrap();

        assert_eq!(
            machine_id.to_string(),
            "fm100dsbiu5ckus880v8407u0mkcensa39cule26im5gnpvmuufckacguc0"
        );

        // Check whether the MachineId is equal to what we generate inband
        let data = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/hardware_info/test_data/dpu_info.json"
        ));
        let info = serde_json::from_slice::<HardwareInfo>(data).unwrap();
        let hardware_info_machine_id = from_hardware_info(&info).unwrap();
        assert_eq!(hardware_info_machine_id.to_string(), machine_id.to_string());

        // Check the MachineId serialization and deserialization
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(serialized.contains(
            r#""MachineId":"fm100dsbiu5ckus880v8407u0mkcensa39cule26im5gnpvmuufckacguc0""#
        ));
        let deserialized = serde_json::from_str::<EndpointExplorationReport>(&serialized).unwrap();
        assert_eq!(deserialized.machine_id.unwrap(), machine_id);
    }

    #[test]
    fn test_uefi_device_path() {
        let path = "PciRoot(0x2)/Pci(0x1,0x0)/Pci(0x0,0x1)";
        let converted: UefiDevicePath = UefiDevicePath::from_str(path).unwrap();
        assert_eq!(converted.0, "2.1.0.0.1");

        let path = "PciRoot(0x11)/Pci(0x1,0x0)/Pci(0x0,0xa)/MAC(A088C20C87C6,0x1)";
        let converted: UefiDevicePath = UefiDevicePath::from_str(path).unwrap();
        assert_eq!(converted.0, "17.1.0.0.10");

        // NIC attached directly to a root port (no PCI-PCI bridge upstream).
        let path = "PciRoot(0x7)/Pci(0x0,0x0)/MAC(525400A8282F,0x1)";
        let converted: UefiDevicePath = UefiDevicePath::from_str(path).unwrap();
        assert_eq!(converted.0, "7.0.0");

        // Three Pci nodes (NIC behind two upstream bridges/switches).
        let path = "PciRoot(0x0)/Pci(0x1,0x0)/Pci(0x0,0x0)/Pci(0x0,0x0)";
        let converted: UefiDevicePath = UefiDevicePath::from_str(path).unwrap();
        assert_eq!(converted.0, "0.1.0.0.0.0.0");

        // PciRoot without any Pci node should fail.
        assert!(UefiDevicePath::from_str("PciRoot(0x7)/MAC(525400A8282F,0x1)").is_err());
    }

    #[test]
    fn test_parse_position_info_first_wins() {
        // Test that parse_position_info uses "first wins" strategy
        let mut report = EndpointExplorationReport {
            chassis: vec![
                Chassis {
                    id: "chassis_0".to_string(),
                    physical_slot_number: Some(1),
                    compute_tray_index: None,
                    topology_id: Some(10),
                    revision_id: None,
                    ..Default::default()
                },
                Chassis {
                    id: "chassis_1".to_string(),
                    physical_slot_number: Some(2), // should be ignored (first wins)
                    compute_tray_index: Some(5),
                    topology_id: Some(20), // should be ignored (first wins)
                    revision_id: Some(3),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        report.parse_position_info();

        // First chassis has physical_slot_number=1, so we get 1 (not 2)
        assert_eq!(report.physical_slot_number, Some(1));
        // First chassis has no compute_tray_index, second has 5, so we get 5
        assert_eq!(report.compute_tray_index, Some(5));
        // First chassis has topology_id=10, so we get 10 (not 20)
        assert_eq!(report.topology_id, Some(10));
        // First chassis has no revision_id, second has 3, so we get 3
        assert_eq!(report.revision_id, Some(3));
    }

    #[test]
    fn test_parse_position_info_all_none() {
        // Test when no chassis has position info
        let mut report = EndpointExplorationReport {
            chassis: vec![Chassis {
                id: "chassis_0".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };

        report.parse_position_info();

        assert_eq!(report.physical_slot_number, None);
        assert_eq!(report.compute_tray_index, None);
        assert_eq!(report.topology_id, None);
        assert_eq!(report.revision_id, None);
    }

    #[test]
    fn test_parse_position_info_empty_chassis() {
        // Test when there are no chassis entries
        let mut report = EndpointExplorationReport {
            chassis: vec![],
            ..Default::default()
        };

        report.parse_position_info();

        assert_eq!(report.physical_slot_number, None);
        assert_eq!(report.compute_tray_index, None);
        assert_eq!(report.topology_id, None);
        assert_eq!(report.revision_id, None);
    }

    #[test]
    fn is_power_shelf_with_powershelf_chassis_id() {
        let report = EndpointExplorationReport {
            chassis: vec![Chassis {
                id: "powershelf".to_string(),
                manufacturer: Some("doesnt-matter-in-this-case".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(report.is_power_shelf());
    }

    #[test]
    fn find_interface_id_for_mac_matches_host_ethernet_interface() {
        let mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
        let other = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let report = EndpointExplorationReport {
            systems: vec![ComputerSystem {
                ethernet_interfaces: vec![
                    EthernetInterface {
                        id: Some("NIC.Embedded.1".to_string()),
                        mac_address: Some(other),
                        ..Default::default()
                    },
                    EthernetInterface {
                        id: Some("NIC.Slot.7-1-1".to_string()),
                        mac_address: Some(mac),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            report.find_interface_id_for_mac(mac),
            Some("NIC.Slot.7-1-1")
        );
        // Unknown MAC -> None (so the capture keeps the last-known-good record).
        assert_eq!(
            report.find_interface_id_for_mac(MacAddress::new([0, 0, 0, 0, 0, 0])),
            None
        );
    }

    #[test]
    fn find_interface_id_for_mac_none_when_id_missing() {
        let mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
        let report = EndpointExplorationReport {
            systems: vec![ComputerSystem {
                ethernet_interfaces: vec![EthernetInterface {
                    id: None,
                    mac_address: Some(mac),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        // MAC present but no interface id -> can't form a fully-populated pair.
        assert_eq!(report.find_interface_id_for_mac(mac), None);
    }

    #[test]
    fn is_power_shelf_with_chassis_id_and_liteon_manufacturer() {
        let report = EndpointExplorationReport {
            chassis: vec![Chassis {
                id: "chassis".to_string(),
                manufacturer: Some("LITE-ON TECHNOLOGY CORP.".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(report.is_power_shelf());
    }

    #[test]
    fn is_power_shelf_with_generic_chassis_id_not_liteon() {
        let report = EndpointExplorationReport {
            chassis: vec![Chassis {
                id: "chassis".to_string(),
                manufacturer: Some("Dell Inc.".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(!report.is_power_shelf());
    }

    #[test]
    fn is_power_shelf_with_no_manufacturer() {
        let report = EndpointExplorationReport {
            chassis: vec![Chassis {
                id: "chassis".to_string(),
                manufacturer: None,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(!report.is_power_shelf());
    }

    #[test]
    fn test_computer_system_with_invalid_base_mac_deserializes_as_none() {
        let json = serde_json::json!({
            "EthernetInterfaces": [],
            "Id": "Bluefield",
            "Manufacturer": "Nvidia",
            "Model": "Bluefield-3 DPU",
            "SerialNumber": "ABC1234",
            "Attributes": {},
            "PcieDevices": [],
            "BaseMac": "pe:",
            "PowerState": "On"
        });

        let system: ComputerSystem =
            serde_json::from_value(json).expect("should deserialize despite invalid BaseMac");
        assert_eq!(system.base_mac, None);
    }

    #[test]
    fn test_computer_system_with_valid_base_mac_deserializes_correctly() {
        let json = serde_json::json!({
            "EthernetInterfaces": [],
            "Id": "Bluefield",
            "Manufacturer": "Nvidia",
            "Model": "Bluefield-3 DPU",
            "SerialNumber": "ABC1234",
            "Attributes": {},
            "PcieDevices": [],
            "BaseMac": "A088C208804C",
            "PowerState": "On"
        });

        let system: ComputerSystem =
            serde_json::from_value(json).expect("should deserialize valid BaseMac");
        assert_eq!(system.base_mac, Some("A088C208804C".parse().unwrap()));
    }

    #[test]
    fn test_computer_system_with_null_base_mac_deserializes_as_none() {
        let json = serde_json::json!({
            "EthernetInterfaces": [],
            "Id": "Bluefield",
            "Manufacturer": "Nvidia",
            "Model": "Bluefield-3 DPU",
            "SerialNumber": "ABC1234",
            "Attributes": {},
            "PcieDevices": [],
            "BaseMac": null,
            "PowerState": "On"
        });

        let system: ComputerSystem =
            serde_json::from_value(json).expect("should deserialize null BaseMac");
        assert_eq!(system.base_mac, None);
    }

    #[test]
    fn test_computer_system_with_missing_base_mac_deserializes_as_none() {
        let json = serde_json::json!({
            "EthernetInterfaces": [],
            "Id": "Bluefield",
            "Manufacturer": "Nvidia",
            "Model": "Bluefield-3 DPU",
            "SerialNumber": "ABC1234",
            "Attributes": {},
            "PcieDevices": [],
            "PowerState": "On"
        });

        let system: ComputerSystem =
            serde_json::from_value(json).expect("should deserialize missing BaseMac");
        assert_eq!(system.base_mac, None);
    }
}
