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
use std::collections::HashMap;
use std::fmt::Display;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use carbide_uuid::machine::{MachineId, MachineType};
use carbide_uuid::power_shelf::{PowerShelfId, PowerShelfIdSource, PowerShelfType};
use carbide_uuid::switch::{SwitchId, SwitchIdSource, SwitchType};
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use itertools::Itertools;
use lazy_static::lazy_static;
use libredfish::RedfishError;
use libredfish::model::oem::nvidia_dpu::NicMode;
use mac_address::MacAddress;
use regex::Regex;
use serde::{Deserialize, Serialize};
use utils::models::arch::CpuArchitecture;

use super::DpuModel;
use super::bmc_info::BmcInfo;
use super::hardware_info::DpuData;
use crate::errors::{ModelError, ModelResult};
use crate::firmware::{Firmware, FirmwareComponentType};
use crate::hardware_info::{DmiData, HardwareInfo, HardwareInfoError};
use crate::machine::machine_id::{MissingHardwareInfo, from_hardware_info_with_type};
use crate::power_shelf::power_shelf_id;
use crate::switch::switch_id;

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
        serialize_with = "utils::ordered_map",
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
}

impl EndpointExplorationReport {
    pub fn cannot_login(&self) -> bool {
        if let Some(ref e) = self.last_exploration_error {
            return e.is_unauthorized();
        }

        false
    }

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
}

impl From<EndpointExplorationReport> for rpc::site_explorer::EndpointExplorationReport {
    fn from(report: EndpointExplorationReport) -> Self {
        rpc::site_explorer::EndpointExplorationReport {
            endpoint_type: format!("{:?}", report.endpoint_type),
            last_exploration_error: report.last_exploration_error.map(|error| {
                serde_json::to_string(&error).unwrap_or_else(|_| "Unserializable error".to_string())
            }),
            last_exploration_latency: report.last_exploration_latency.map(Into::into),
            machine_id: report.machine_id.map(|id| id.to_string()),
            vendor: report.vendor.map(|v| v.to_string()),
            managers: report.managers.into_iter().map(Into::into).collect(),
            systems: report.systems.into_iter().map(Into::into).collect(),
            chassis: report.chassis.into_iter().map(Into::into).collect(),
            service: report.service.into_iter().map(Into::into).collect(),
            machine_setup_status: report.machine_setup_status.map(Into::into),
            secure_boot_status: report.secure_boot_status.map(Into::into),
            lockdown_status: report.lockdown_status.map(Into::into),
        }
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
}

impl Display for ExploredEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} / {}", self.address, self.report_version)
    }
}

impl ExploredEndpoint {
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
    InitialReset {
        phase: InitialResetPhase,
        last_time: DateTime<Utc>,
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
pub enum InitialResetPhase {
    Start,
    BMCWasReset,
    WaitHostBoot,
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

impl From<SystemStatus> for rpc::site_explorer::SystemStatus {
    fn from(status: SystemStatus) -> Self {
        rpc::site_explorer::SystemStatus {
            health: status.health,
            health_rollup: status.health_rollup,
            state: status.state,
        }
    }
}

impl From<PCIeDevice> for rpc::site_explorer::PcIeDevice {
    fn from(device: PCIeDevice) -> Self {
        rpc::site_explorer::PcIeDevice {
            description: device.description,
            firmware_version: device.firmware_version,
            gpu_vendor: device.gpu_vendor,
            id: device.id,
            manufacturer: device.manufacturer,
            name: device.name,
            part_number: device.part_number,
            serial_number: device.serial_number,
            status: device.status.map(Into::into),
        }
    }
}

impl From<ExploredEndpoint> for rpc::site_explorer::ExploredEndpoint {
    fn from(endpoint: ExploredEndpoint) -> Self {
        rpc::site_explorer::ExploredEndpoint {
            address: endpoint.address.to_string(),
            report: Some(endpoint.report.into()),
            report_version: endpoint.report_version.to_string(),
            exploration_requested: endpoint.exploration_requested,
            preingestion_state: format!("{:?}", endpoint.preingestion_state),
            last_redfish_bmc_reset: endpoint
                .last_redfish_bmc_reset
                .map(|time| time.to_string())
                .unwrap_or_else(|| "no timestamp available".to_string()),
            last_ipmitool_bmc_reset: endpoint
                .last_ipmitool_bmc_reset
                .map(|time| time.to_string())
                .unwrap_or_else(|| "no timestamp available".to_string()),
            last_redfish_reboot: endpoint
                .last_redfish_reboot
                .map(|time| time.to_string())
                .unwrap_or_else(|| "no timestamp available".to_string()),
            last_redfish_powercycle: endpoint
                .last_redfish_powercycle
                .map(|time| time.to_string())
                .unwrap_or_else(|| "no timestamp available".to_string()),
            pause_remediation: endpoint.pause_remediation,
        }
    }
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

impl From<&ExploredDpu> for rpc::site_explorer::ExploredDpu {
    fn from(dpu: &ExploredDpu) -> Self {
        rpc::site_explorer::ExploredDpu {
            bmc_ip: dpu.bmc_ip.to_string(),
            host_pf_mac_address: dpu.host_pf_mac_address.map(|m| m.to_string()),
        }
    }
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

impl From<ExploredManagedHost> for rpc::site_explorer::ExploredManagedHost {
    fn from(host: ExploredManagedHost) -> Self {
        rpc::site_explorer::ExploredManagedHost {
            host_bmc_ip: host.host_bmc_ip.to_string(),
            dpus: host
                .dpus
                .iter()
                .map(rpc::site_explorer::ExploredDpu::from)
                .collect(),
            dpu_bmc_ip: host
                .dpus
                .first()
                .map_or("".to_string(), |d| d.bmc_ip.to_string()),
            host_pf_mac_address: host
                .dpus
                .first()
                .and_then(|d| d.host_pf_mac_address.map(|m| m.to_string())),
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

    /// Return `true` if the explored endpoint is a PowerShelf
    pub fn is_power_shelf(&self) -> bool {
        self.chassis
            .iter()
            .any(|c| c.id.to_lowercase().contains("powershelf"))
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
            utils::DEFAULT_DMI_SYSTEM_MANUFACTURER.to_string()
        };
        let product_name = if let Some(x) = model {
            x.to_string()
        } else {
            utils::DEFAULT_DMI_SYSTEM_MODEL.to_string()
        };
        // For DPUs the discovered data contains enough information to
        // calculate a MachineId
        // The "Unspecified" strings are delivered as serial numbers when doing
        // inband discovery via libudev. For compatibility we have to use
        // the same values here.
        DmiData {
            product_serial: serial_number.trim().to_string(),
            chassis_serial: utils::DEFAULT_DPU_DMI_CHASSIS_SERIAL_NUMBER.to_string(),
            board_serial: utils::DEFAULT_DPU_DMI_BOARD_SERIAL_NUMBER.to_string(),
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
    pub fn generate_switch_id(&mut self) -> ModelResult<Option<&SwitchId>> {
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
            let _hardware_info = HardwareInfo {
                dmi_data: Some(dmi_data),
                // This field should not be read, machine_id::from_hardware_info_with_type should not
                // need this, only the dmi_data.
                machine_type: CpuArchitecture::Unknown,
                ..Default::default()
            };

            let switch_type = SwitchType::NvLink;
            let switch_source = SwitchIdSource::ProductBoardChassisSerial;

            let switch_id = switch_id::from_hardware_info_with_type(
                serial_number,
                vendor.unwrap(),
                model.unwrap(),
                switch_source,
                switch_type,
            )
            .map_err(|_e| {
                ModelError::HardwareInfo(HardwareInfoError::MissingHardwareInfo(
                    MissingHardwareInfo::Serial,
                ))
            })?;

            Ok(Some(self.switch_id.insert(switch_id)))
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

impl From<SiteExplorationReport> for rpc::site_explorer::SiteExplorationReport {
    fn from(report: SiteExplorationReport) -> Self {
        rpc::site_explorer::SiteExplorationReport {
            endpoints: report.endpoints.into_iter().map(Into::into).collect(),
            managed_hosts: report.managed_hosts.into_iter().map(Into::into).collect(),
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

impl From<ComputerSystemAttributes> for rpc::site_explorer::ComputerSystemAttributes {
    fn from(attributes: ComputerSystemAttributes) -> Self {
        rpc::site_explorer::ComputerSystemAttributes {
            nic_mode: attributes.nic_mode.map(|a| match a {
                NicMode::Nic => rpc::site_explorer::NicMode::Nic.into(),
                NicMode::Dpu => rpc::site_explorer::NicMode::Dpu.into(),
            }),
        }
    }
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
    pub base_mac: Option<String>,
    #[serde(default)]
    pub power_state: PowerState,
    pub sku: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_order: Option<BootOrder>,
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

impl From<ComputerSystem> for rpc::site_explorer::ComputerSystem {
    fn from(system: ComputerSystem) -> Self {
        rpc::site_explorer::ComputerSystem {
            id: system.id,
            manufacturer: system.manufacturer,
            model: system.model,
            serial_number: system.serial_number,
            ethernet_interfaces: system
                .ethernet_interfaces
                .into_iter()
                .map(Into::into)
                .collect(),
            attributes: Some(rpc::site_explorer::ComputerSystemAttributes::from(
                system.attributes,
            )),
            pcie_devices: system.pcie_devices.into_iter().map(Into::into).collect(),
            power_state: rpc::site_explorer::PowerState::from(system.power_state) as _,
            boot_order: system.boot_order.map(|order| order.into()),
        }
    }
}

impl From<PowerState> for rpc::site_explorer::PowerState {
    fn from(state: PowerState) -> Self {
        match state {
            PowerState::Off => rpc::site_explorer::PowerState::Off,
            PowerState::On => rpc::site_explorer::PowerState::On,
            PowerState::PoweringOff => rpc::site_explorer::PowerState::PoweringOff,
            PowerState::PoweringOn => rpc::site_explorer::PowerState::PoweringOn,
            PowerState::Paused => rpc::site_explorer::PowerState::Paused,
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
}

/// `Manager` definition. Matches redfish definition
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Manager {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ethernet_interfaces: Vec<EthernetInterface>,
    pub id: String,
}

impl From<Manager> for rpc::site_explorer::Manager {
    fn from(manager: Manager) -> Self {
        rpc::site_explorer::Manager {
            id: manager.id,
            ethernet_interfaces: manager
                .ethernet_interfaces
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
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
        deserialize_with = "forge_network::deserialize_optional_mlx_mac"
    )]
    pub mac_address: Option<MacAddress>,

    pub uefi_device_path: Option<UefiDevicePath>,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct UefiDevicePath(String);

lazy_static! {
    static ref UEFI_DEVICE_PATH_REGEX: Regex =
        Regex::new(r"PciRoot\((.*?)\)\/Pci\((.*?)\)\/Pci\((.*?)\)").expect("must always compile");
}

impl FromStr for UefiDevicePath {
    type Err = RedfishError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Uefi string is received as PciRoot(0x8)/Pci(0x2,0xa)/Pci(0x0,0x0)/MAC(A088C208545C,0x1)
        // Need to convert it as 8.2.10.0.0
        // Some output does not contain MAC part. Also it is useless for us.

        let st = s.rsplit_once("/MAC").map(|x| x.0).unwrap_or(s);

        let captures =
            UEFI_DEVICE_PATH_REGEX
                .captures(st)
                .ok_or_else(|| RedfishError::GenericError {
                    error: format!("Could not match regex in PCI Device Path {s}."),
                })?;

        let mut pci = vec![];

        for (i, capture) in captures.iter().enumerate() {
            if i == 0 {
                continue;
            }

            if let Some(capture) = capture {
                for hex in capture.as_str().split(',') {
                    let hex_int = u32::from_str_radix(&hex.to_lowercase().replace("0x", ""), 16)
                        .map_err(|e| RedfishError::GenericError {
                            error: format!(
                                "Can't convert pci address to int {hex}, error: {e} for pci: {s}"
                            ),
                        })?;
                    pci.push(hex_int.to_string());
                }
            }
            // Should we return error if capture is not proper??
        }

        Ok(UefiDevicePath(pci.join(".")))
    }
}

impl From<EthernetInterface> for rpc::site_explorer::EthernetInterface {
    fn from(interface: EthernetInterface) -> Self {
        rpc::site_explorer::EthernetInterface {
            id: interface.id,
            description: interface.description,
            interface_enabled: interface.interface_enabled,
            mac_address: interface.mac_address.map(|mac| mac.to_string()),
        }
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

impl From<Chassis> for rpc::site_explorer::Chassis {
    fn from(chassis: Chassis) -> Self {
        rpc::site_explorer::Chassis {
            id: chassis.id,
            manufacturer: chassis.manufacturer,
            model: chassis.model,
            part_number: chassis.part_number,
            serial_number: chassis.serial_number,
            network_adapters: chassis
                .network_adapters
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
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

impl From<NetworkAdapter> for rpc::site_explorer::NetworkAdapter {
    fn from(adapter: NetworkAdapter) -> Self {
        rpc::site_explorer::NetworkAdapter {
            id: adapter.id,
            manufacturer: adapter.manufacturer,
            model: adapter.model,
            part_number: adapter.part_number,
            serial_number: adapter.serial_number,
        }
    }
}

/// `SecureBootStatus` definition.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SecureBootStatus {
    pub is_enabled: bool,
}

impl From<SecureBootStatus> for rpc::site_explorer::SecureBootStatus {
    fn from(secure_boot_status: SecureBootStatus) -> Self {
        rpc::site_explorer::SecureBootStatus {
            is_enabled: secure_boot_status.is_enabled,
        }
    }
}

/// `LockdownStatus` definition. Matches redfish definition
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct LockdownStatus {
    pub status: InternalLockdownStatus,
    pub message: String,
}

impl From<LockdownStatus> for rpc::site_explorer::LockdownStatus {
    fn from(lockdown_status: LockdownStatus) -> Self {
        rpc::site_explorer::LockdownStatus {
            status: rpc::site_explorer::InternalLockdownStatus::from(lockdown_status.status) as _,
            message: lockdown_status.message,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum InternalLockdownStatus {
    Enabled,
    Partial,
    #[default]
    Disabled,
}

impl From<InternalLockdownStatus> for rpc::site_explorer::InternalLockdownStatus {
    fn from(state: InternalLockdownStatus) -> Self {
        match state {
            InternalLockdownStatus::Enabled => rpc::site_explorer::InternalLockdownStatus::Enabled,
            InternalLockdownStatus::Partial => rpc::site_explorer::InternalLockdownStatus::Partial,
            InternalLockdownStatus::Disabled => {
                rpc::site_explorer::InternalLockdownStatus::Disabled
            }
        }
    }
}

/// `Service` definition. Matches redfish definition
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Service {
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inventories: Vec<Inventory>,
}

impl From<Service> for rpc::site_explorer::Service {
    fn from(service: Service) -> Self {
        rpc::site_explorer::Service {
            id: service.id,
            inventories: service.inventories.into_iter().map(Into::into).collect(),
        }
    }
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

impl From<Inventory> for rpc::site_explorer::Inventory {
    fn from(inventory: Inventory) -> Self {
        rpc::site_explorer::Inventory {
            id: inventory.id,
            description: inventory.description,
            version: inventory.version,
            release_date: inventory.release_date,
        }
    }
}

/// `MachineSetupStatus` definition. Matches redfish definition
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MachineSetupStatus {
    pub is_done: bool,
    pub diffs: Vec<MachineSetupDiff>,
}

impl From<MachineSetupStatus> for rpc::site_explorer::MachineSetupStatus {
    fn from(machine_setup_status: MachineSetupStatus) -> Self {
        rpc::site_explorer::MachineSetupStatus {
            is_done: machine_setup_status.is_done,
            diffs: machine_setup_status
                .diffs
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

/// `BootOrder` definition.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct BootOrder {
    pub boot_order: Vec<BootOption>,
}

impl From<BootOrder> for rpc::site_explorer::BootOrder {
    fn from(order: BootOrder) -> Self {
        rpc::site_explorer::BootOrder {
            boot_order: order.boot_order.into_iter().map(Into::into).collect(),
        }
    }
}

/// `MachineSetupDiff` definition. Matches redfish definition
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MachineSetupDiff {
    pub key: String,
    pub expected: String,
    pub actual: String,
}

impl From<MachineSetupDiff> for rpc::site_explorer::MachineSetupDiff {
    fn from(machine_setup_diff: MachineSetupDiff) -> Self {
        rpc::site_explorer::MachineSetupDiff {
            key: machine_setup_diff.key,
            expected: machine_setup_diff.expected,
            actual: machine_setup_diff.actual,
        }
    }
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

impl From<BootOption> for rpc::site_explorer::BootOption {
    fn from(boot_option: BootOption) -> Self {
        rpc::site_explorer::BootOption {
            display_name: boot_option.display_name,
            id: boot_option.id,
            boot_option_enabled: boot_option.boot_option_enabled,
            uefi_device_path: boot_option.uefi_device_path,
        }
    }
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

impl From<libredfish::PowerState> for PowerState {
    fn from(state: libredfish::PowerState) -> Self {
        match state {
            libredfish::PowerState::Off => PowerState::Off,
            libredfish::PowerState::On => PowerState::On,
            libredfish::PowerState::PoweringOff => PowerState::PoweringOff,
            libredfish::PowerState::PoweringOn => PowerState::PoweringOn,
            libredfish::PowerState::Paused => PowerState::Paused,
            libredfish::PowerState::Reset => PowerState::PoweringOn,
        }
    }
}

impl From<libredfish::PCIeDevice> for PCIeDevice {
    fn from(device: libredfish::PCIeDevice) -> Self {
        PCIeDevice {
            description: device.description,
            firmware_version: device.firmware_version,
            id: device.id,
            manufacturer: device.manufacturer,
            name: device.name,
            part_number: device.part_number,
            serial_number: device.serial_number,
            status: device.status.map(|s| s.into()),
            gpu_vendor: device.gpu_vendor,
        }
    }
}
impl From<PCIeDevice> for libredfish::PCIeDevice {
    fn from(device: PCIeDevice) -> Self {
        libredfish::PCIeDevice {
            description: device.description,
            firmware_version: device.firmware_version,
            id: device.id,
            manufacturer: device.manufacturer,
            name: device.name,
            part_number: device.part_number,
            serial_number: device.serial_number,
            status: device.status.map(|s| s.into()),
            gpu_vendor: device.gpu_vendor,
            odata: libredfish::OData {
                odata_id: "odata_id".to_owned(),
                odata_type: "odata_type".to_owned(),
                odata_etag: None,
                odata_context: None,
            },
            pcie_functions: None,
            slot: None,
        }
    }
}

impl From<SystemStatus> for libredfish::model::SystemStatus {
    fn from(status: SystemStatus) -> Self {
        libredfish::model::SystemStatus {
            health: status.health,
            health_rollup: status.health_rollup,
            state: Some(status.state),
        }
    }
}
impl From<libredfish::model::SystemStatus> for SystemStatus {
    fn from(status: libredfish::model::SystemStatus) -> Self {
        SystemStatus {
            health: status.health,
            health_rollup: status.health_rollup,
            state: status.state.unwrap_or("".to_string()),
        }
    }
}

impl From<libredfish::model::BootOption> for BootOption {
    fn from(boot_option: libredfish::model::BootOption) -> Self {
        BootOption {
            display_name: boot_option.display_name,
            id: boot_option.id,
            boot_option_enabled: boot_option.boot_option_enabled,
            uefi_device_path: boot_option.uefi_device_path,
        }
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
fn is_bf2_dpu(model: &str) -> bool {
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
                base_mac: Some("A088C208804C".to_string()),
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
                base_mac: Some("A088C208804C".to_string()),
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
}
