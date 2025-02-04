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
use std::{collections::HashMap, fmt::Display, net::IpAddr, str::FromStr};

use config_version::ConfigVersion;
use forge_uuid::machine::{MachineId, MachineType};
use itertools::Itertools;
use libredfish::RedfishError;
use mac_address::MacAddress;
use regex::Regex;
use serde::{Deserialize, Serialize};
use utils::models::arch::CpuArchitecture;

use super::{bmc_info::BmcInfo, hardware_info::DpuData};
use crate::model::hardware_info::HardwareInfoError;
use crate::model::machine::machine_id::MissingHardwareInfo;
use crate::{
    cfg::file::{DpuModel, Firmware, FirmwareComponentType},
    model::{
        hardware_info::{DmiData, HardwareInfo},
        machine::machine_id::from_hardware_info_with_type,
    },
    CarbideError, CarbideResult,
};

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
            Some(chassis) => match &chassis.model {
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
    ) -> Option<String> {
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
                return matching_inventory.version.clone();
            };
        }
        None
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
                let path = pci_path.0.clone();
                let existing_path = existing_path.0.clone();

                if let Ok(res) =
                    version_compare::compare_to(path, existing_path, version_compare::Cmp::Lt)
                {
                    if res {
                        return x;
                    }
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
    UpgradeFirmwareWait {
        task_id: String,
        final_version: String,
        upgrade_type: FirmwareComponentType,
    },
    ResetForNewFirmware {
        final_version: String,
        upgrade_type: FirmwareComponentType,
    },
    NewFirmwareReportedWait {
        final_version: String,
        upgrade_type: FirmwareComponentType,
    },
    RecheckVersionsAfterFailure {
        reason: String,
    },
    Complete,
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
    pub report: EndpointExplorationReport,
}

impl From<ExploredDpu> for rpc::site_explorer::ExploredDpu {
    fn from(dpu: ExploredDpu) -> Self {
        rpc::site_explorer::ExploredDpu {
            bmc_ip: dpu.bmc_ip.to_string(),
            host_pf_mac_address: dpu.host_pf_mac_address.map(|m| m.to_string()),
        }
    }
}

impl ExploredDpu {
    pub fn machine_id_if_valid_report(&self) -> CarbideResult<&MachineId> {
        let Some(machine_id) = self.report.machine_id.as_ref() else {
            return Err(CarbideError::MissingArgument("Missing Machine ID"));
        };

        if self.report.systems.is_empty() {
            return Err(CarbideError::MissingArgument("Missing Systems Info"));
        }

        if self.report.chassis.is_empty() {
            return Err(CarbideError::MissingArgument("Missing Chassis Info"));
        }

        if self.report.service.is_empty() {
            return Err(CarbideError::MissingArgument("Missing Service Info"));
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

    pub fn hardware_info(&self) -> CarbideResult<HardwareInfo> {
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
            .clone()
            .into_iter()
            .map(|x| (x.id.clone(), x))
            .collect::<HashMap<_, _>>();
        let inventory_map = self.report.get_inventory_map();

        let dpu_data = DpuData {
            factory_mac_address: self
                .host_pf_mac_address
                .ok_or(CarbideError::MissingArgument("Missing base mac"))?
                .to_string(),
            part_number: chassis_map
                .get("Card1")
                .and_then(|value: &Chassis| value.part_number.as_ref())
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

    use serde::{de, Deserialize, Deserializer, Serializer};

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
                .map(|d| rpc::site_explorer::ExploredDpu::from(d.clone()))
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        }
    }

    pub fn nic_mode(&self) -> Option<NicMode> {
        if self.is_dpu()
            && self
                .systems
                .first()
                .is_some_and(|s| s.attributes.nic_mode.is_some())
        {
            Some(self.systems[0].attributes.nic_mode.unwrap())
        } else {
            None
        }
    }

    /// Return `true` if the explored endpoint is a DPU
    pub fn is_dpu(&self) -> bool {
        self.identify_dpu().is_some()
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
            .clone()
            .into_iter()
            .map(|x| (x.id.clone(), x))
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
    ) -> CarbideResult<Option<&MachineId>> {
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

            let machine_id =
                from_hardware_info_with_type(&hardware_info, machine_type).map_err(|e| {
                    CarbideError::HardwareInfoError(HardwareInfoError::MissingHardwareInfo(e))
                })?;

            Ok(Some(self.machine_id.insert(machine_id)))
        } else {
            Err(CarbideError::HardwareInfoError(
                HardwareInfoError::MissingHardwareInfo(MissingHardwareInfo::Serial),
            ))
        }
    }

    pub fn get_inventory_map(&self) -> HashMap<String, Inventory> {
        self.service
            .iter()
            .find(|s| s.id == *"FirmwareInventory")
            .map(|s| {
                s.inventories
                    .iter()
                    .map(|i| (i.id.clone(), i.clone()))
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

    pub fn parse_versions(&mut self, fw_info: &Firmware) {
        for fwtype in fw_info.components.keys() {
            if let Some(current) = fw_info.find_version(self, *fwtype) {
                self.versions.insert(*fwtype, current);
            }
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
    /// It was not possible to establish a connection to the endpoint
    #[error("The endpoint was not reachable: {details:?}")]
    #[serde(rename_all = "PascalCase")]
    Unreachable { details: Option<String> },
    /// A Redfish variant we don't support, typically a new vendor
    #[error("Redfish vendor '{0}' not supported")]
    UnsupportedVendor(String),
    /// A generic redfish error. No additional details are available
    #[error("Error while performing Redfish request: {details}")]
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
    #[error("Missing credential {key}: {cause}")]
    MissingCredentials {
        #[serde(default)]
        key: String,
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
    #[error("Site explorer will not explore this endpoint to avoid lockout: it could not login previously")]
    AvoidLockout,
    /// An error which is not further detailed
    #[error("Error: {details}")]
    #[serde(rename_all = "PascalCase")]
    Other { details: String },

    #[error("Invalid Redfish response for DPU BIOS: {details}")]
    #[serde(rename_all = "PascalCase")]
    InvalidDpuRedfishBiosResponse {
        details: String,
        response_body: Option<String>,
        response_code: Option<u16>,
    },
}

pub const DPU_BIOS_ATTRIBUTES_MISSING: &str = "DPU has an empty BIOS attributes";

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
}

/// The type of the endpoint
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum EndpointType {
    Bmc,
    #[default]
    Unknown,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum NicMode {
    Dpu,
    Nic,
}

impl FromStr for NicMode {
    type Err = ();

    fn from_str(input: &str) -> Result<NicMode, Self::Err> {
        match input {
            "NicMode" => Ok(NicMode::Nic),
            "DpuMode" => Ok(NicMode::Dpu),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ComputerSystemAttributes {
    pub nic_mode: Option<NicMode>,
    pub http_dev1_interface: Option<String>,
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

impl FromStr for UefiDevicePath {
    type Err = RedfishError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Uefi string is received as PciRoot(0x8)/Pci(0x2,0xa)/Pci(0x0,0x0)/MAC(A088C208545C,0x1)
        // Need to convert it as 8.2.10.0.0
        // Some output does not contain MAC part. Also it is useless for us.

        let st = s.rsplit_once("/MAC").map(|x| x.0).unwrap_or(s);

        let re = Regex::new(r"PciRoot\((.*?)\)\/Pci\((.*?)\)\/Pci\((.*?)\)").map_err(|x| {
            RedfishError::GenericError {
                error: x.to_string(),
            }
        })?;
        let captures = re.captures(st).ok_or_else(|| RedfishError::GenericError {
            error: format!("Could not match regex in PCI Device Path {}.", s),
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
                                "Can't convert pci address to int {}, error: {} for pci: {}",
                                hex, e, s
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

// is_bluefield_model returns true if the passed in string is a bluefield model
fn is_bluefield_model(model: &str) -> bool {
    let normalized_model = model.to_lowercase();

    normalized_model.contains("bluefield")
        // prefix matching for BlueField-3 DPUs (https://docs.nvidia.com/networking/display/bf3dpu)
        || normalized_model.starts_with("900-9d3b6")
        // prefix matching for BlueField-3 SuperNICs (https://docs.nvidia.com/networking/display/bf3dpu)
        || normalized_model.starts_with("900-9d3b4")
        // prefix matching for BlueField-2 DPU (https://docs.nvidia.com/nvidia-bluefield-2-ethernet-dpu-user-guide.pdf)
        // TODO (sp): should we be matching on all the individual models listed ("MBF2M516C-CECOT", .. etc)
        || normalized_model.starts_with("mbf2")
        // looks like Lenovo ThinkSystem SR675 V3s will report the part number of NVIDIA BlueField-3 VPI QSFP112 2P 200G PCIe Gen5 x16 as SN37B36732
        // https://windows-server.lenovo.com/repo/2024_05/html/SR675V3_7D9Q_7D9R-Windows_Server_2019.html
        || normalized_model.starts_with("sn37b36732")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::machine::machine_id::from_hardware_info;

    const TEST_DATA_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/model/hardware_info/test_data"
    );

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
                    http_dev1_interface: None,
                    is_infinite_boot_enabled: None,
                },
                pcie_devices: vec![],
                base_mac: Some("A088C208804C".to_string()),
                power_state: PowerState::On,
                sku: None,
            }],
            chassis: vec![Chassis {
                id: "NIC.Slot.1".to_string(),
                manufacturer: None,
                model: None,
                serial_number: Some("MT2242XZ00NX".to_string()),
                part_number: None,
                network_adapters: vec![],
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
                    http_dev1_interface: None,
                    is_infinite_boot_enabled: None,
                },
                pcie_devices: vec![],
                base_mac: Some("A088C208804C".to_string()),
                power_state: PowerState::On,
                sku: None,
            }],
            chassis: vec![Chassis {
                id: "NIC.Slot.1".to_string(),
                manufacturer: None,
                model: None,
                serial_number: Some("MT2242XZ00NX".to_string()),
                part_number: None,
                network_adapters: vec![],
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
        let path = format!("{}/dpu_info.json", TEST_DATA_DIR);
        let data = std::fs::read(path).unwrap();
        let info = serde_json::from_slice::<HardwareInfo>(&data).unwrap();
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
}
