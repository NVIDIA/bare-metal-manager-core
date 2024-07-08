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
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

use crate::{
    cfg::{DpuComponent, DpuDesc, DpuModel, FirmwareHostComponentType},
    model::{
        hardware_info::{DmiData, HardwareInfo},
        machine::machine_id::MachineId,
    },
    CarbideError, CarbideResult,
};

use super::hardware_info::DpuData;

/// Data that we gathered about a particular endpoint during site exploration
/// This data is stored as JSON in the Database. Therefore the format can
/// only be adjusted in a backward compatible fashion.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EndpointExplorationReport {
    /// The type of the endpoint
    pub endpoint_type: EndpointType,
    /// If the endpoint could not be explored, this contains the last error
    pub last_exploration_error: Option<EndpointExplorationError>,
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
}

impl EndpointExplorationReport {
    pub fn cannot_login(&self) -> bool {
        if let Some(e) = self.last_exploration_error.clone() {
            return e.is_unauthorized();
        }

        false
    }
}

impl From<EndpointExplorationReport> for rpc::site_explorer::EndpointExplorationReport {
    fn from(report: EndpointExplorationReport) -> Self {
        rpc::site_explorer::EndpointExplorationReport {
            endpoint_type: format!("{:?}", report.endpoint_type),
            last_exploration_error: report.last_exploration_error.map(|error| {
                serde_json::to_string(&error).unwrap_or_else(|_| "Unserializable error".to_string())
            }),
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
}

impl Display for ExploredEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} / {}", self.address, self.report_version)
    }
}

impl ExploredEndpoint {
    pub fn cannot_login(&self) -> bool {
        self.report.cannot_login()
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
        upgrade_type: FirmwareHostComponentType,
    },
    Complete,
}

impl From<ExploredEndpoint> for rpc::site_explorer::ExploredEndpoint {
    fn from(endpoint: ExploredEndpoint) -> Self {
        rpc::site_explorer::ExploredEndpoint {
            address: endpoint.address.to_string(),
            report: Some(endpoint.report.into()),
            report_version: endpoint.report_version.to_string(),
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
    pub fn has_valid_report(&self) -> CarbideResult<()> {
        if self.report.machine_id.is_none() {
            return Err(CarbideError::MissingArgument("Missing Machine ID"));
        }

        if self.report.systems.is_empty() {
            return Err(CarbideError::MissingArgument("Missing Systems Info"));
        }

        if self.report.chassis.is_empty() {
            return Err(CarbideError::MissingArgument("Missing Chassis Info"));
        }

        if self.report.service.is_empty() {
            return Err(CarbideError::MissingArgument("Missing Service Info"));
        }

        Ok(())
    }

    pub fn has_valid_firmware(&self, dpu_models: &HashMap<DpuModel, DpuDesc>) -> CarbideResult<()> {
        match self.report.identify_dpu() {
            Some(dpu_model) => match dpu_models.get(&dpu_model) {
                Some(dpu_desc) => {
                    for dpu_component in DpuComponent::iter() {
                        if let Some(min_version) =
                            dpu_desc.component_min_version.get(&dpu_component)
                        {
                            if let Some(cur_version) =
                                self.report.dpu_component_version(dpu_component)
                            {
                                match version_compare::compare_to(
                                    &cur_version,
                                    min_version,
                                    version_compare::Cmp::Lt,
                                ) {
                                    Ok(is_unsuppored_firmware_version) => {
                                        if is_unsuppored_firmware_version {
                                            return Err(CarbideError::UnsupportedFirmwareVersion(format!(
                                                    "{:?} firmware version {} is not supported. Please update to: {}",
                                                    dpu_component, cur_version, min_version
                                                )));
                                        }
                                    }
                                    Err(e) => {
                                        return Err(CarbideError::GenericError(format!(
                                                "Could not compare firmware versions (cur_version: {cur_version}, min_version: {min_version}) for DPU {:#?}: {e:#?}",
                                                self.report.machine_id
                                            )));
                                    }
                                }
                            }
                        }
                    }
                }
                None => {
                    return Err(CarbideError::GenericError(format!(
                        "Missing Forge model information for DPU model {:#?} out of {:#?}",
                        dpu_model.clone(),
                        dpu_models.clone()
                    )));
                }
            },
            None => {
                return Err(CarbideError::GenericError(format!(
                    "Cannot determine DPU model for {:#?}",
                    self
                )));
            }
        }

        Ok(())
    }

    pub fn bmc_firmware_version(&self) -> CarbideResult<Option<String>> {
        Ok(self.report.dpu_component_version(DpuComponent::Bmc))
    }

    pub fn hardware_info(&self) -> CarbideResult<HardwareInfo> {
        let serial_number = self
            .report
            .systems
            .first()
            .and_then(|system| system.serial_number.as_ref())
            .unwrap();
        let dmi_data = self
            .report
            .create_temporary_dmi_data(serial_number.as_str());

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
            machine_type: "aarch64".to_string(),
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
            managers: Vec::new(),
            systems: Vec::new(),
            chassis: Vec::new(),
            service: Vec::new(),
            vendor: None,
            machine_id: None,
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

    pub fn create_temporary_dmi_data(&self, serial_number: &str) -> DmiData {
        // For DPUs the discovered data contains enough information to
        // calculate a MachineId
        // The "Unspecified" strings are delivered as serial numbers when doing
        // inband discovery via libudev. For compatibility we have to use
        // the same values here.
        DmiData {
            product_serial: serial_number.trim().to_string(),
            chassis_serial: "Unspecified Chassis Board Serial Number".to_string(),
            board_serial: "Unspecified Base Board Serial Number".to_string(),
            bios_version: "".to_string(),
            sys_vendor: "".to_string(),
            board_name: "BlueField SoC".to_string(),
            bios_date: "".to_string(),
            board_version: "".to_string(),
            product_name: "".to_string(),
        }
    }

    /// Tries to generate and store a MachineId for the discovered endpoint if
    /// enough data for generation is available
    pub fn generate_machine_id(&mut self) {
        if let (true, Some(serial_number)) = (
            self.is_dpu(),
            self.systems
                .first()
                .and_then(|system| system.serial_number.as_ref()),
        ) {
            let dmi_data = self.create_temporary_dmi_data(serial_number.as_str());

            let hardware_info = HardwareInfo {
                dmi_data: Some(dmi_data),
                machine_type: "aarch64".to_string(),
                ..Default::default()
            };

            match MachineId::from_hardware_info(&hardware_info) {
                Ok(machine_id) => {
                    self.machine_id = Some(machine_id);
                }
                Err(error) => {
                    tracing::error!(%error, "Can not generate MachineId for explored endpoint");
                }
            }
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

    pub fn dpu_component_version(&self, component: DpuComponent) -> Option<String> {
        match component {
            DpuComponent::Bmc => self.dpu_bmc_version(),
            DpuComponent::Uefi => self.dpu_uefi_version(),
            DpuComponent::Cec => None,
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
    #[error("The endpoint was not reachable")]
    Unreachable,
    /// A Redfish variant we don't support, typically a new vendor
    #[error("Redfish vendor '{0}' not supported")]
    UnsupportedVendor(String),
    /// A generic redfish error. No additional details are available
    #[error("Error while performing Redfish request: {details}")]
    #[serde(rename_all = "PascalCase")]
    RedfishError { details: String },
    /// The endpoint returned a 401 Unauthorized Status
    #[error("Unauthorized: {details}")]
    #[serde(rename_all = "PascalCase")]
    Unauthorized { details: String },
    #[error("Missing credential {key}: {cause}")]
    MissingCredentials { key: String, cause: String },
    #[error("Failed setting credential {key}: {cause}")]
    SetCredentials { key: String, cause: String },
    #[error("Endpoint is not a BMC with Redfish support")]
    MissingRedfish,
    #[error("BMC vendor field is not populated. Unsupported BMC.")]
    MissingVendor,
    #[error("Site explorer will not explore this endpoint to avoid lockout: it could not login previously")]
    AvoidLockout,
    /// An error which is not further detailed
    #[error("Error: {details}")]
    #[serde(rename_all = "PascalCase")]
    Other { details: String },
}

impl EndpointExplorationError {
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, EndpointExplorationError::Unauthorized { details: _ })
            || matches!(self, EndpointExplorationError::AvoidLockout)
    }
}

/// The type of the endpoint
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
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
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
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
        }
    }
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
    #[serde(rename = "MACAddress")]
    pub mac_address: Option<String>,
}

impl From<EthernetInterface> for rpc::site_explorer::EthernetInterface {
    fn from(interface: EthernetInterface) -> Self {
        rpc::site_explorer::EthernetInterface {
            id: interface.id,
            description: interface.description,
            interface_enabled: interface.interface_enabled,
            mac_address: interface.mac_address,
        }
    }
}

/// `Chassis` definition. Matches redfish definition
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
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

impl NetworkAdapter {
    // is_bluefield returns whether the given network adapter attached to the chassis is a Bluefield
    pub fn is_bluefield(&self) -> bool {
        let Some(model) = &self.model else {
            // TODO: maybe model this as an enum that has "Indeterminable" if there's no model
            // but for now it's 'technically' true
            return false;
        };

        let normalized_model = model.to_lowercase();

        normalized_model.contains("bluefield")
            // prefix matching for BlueField-3 DPUs (https://docs.nvidia.com/networking/display/bf3dpu)
            || normalized_model.starts_with("900-9d3b6")
            // prefix matching for BlueField-3 SuperNICs (https://docs.nvidia.com/networking/display/bf3dpu)
            || normalized_model.starts_with("900-9d3b4")
            // prefix matching for BlueField-2 DPU (https://docs.nvidia.com/nvidia-bluefield-2-ethernet-dpu-user-guide.pdf)
            // TODO (sp): should we be matching on all the individual models listed ("MBF2M516C-CECOT", .. etc)
            || normalized_model.starts_with("mbf2")
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATA_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/model/hardware_info/test_data"
    );

    #[test]
    fn serialize_endpoint_exloration_error() {
        let report =
            EndpointExplorationReport::new_with_error(EndpointExplorationError::Unreachable);

        let serialized = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serialized,
            r#"{"EndpointType":"Unknown","LastExplorationError":{"Type":"Unreachable"}}"#
        );
        assert_eq!(
            serde_json::from_str::<EndpointExplorationReport>(&serialized).unwrap(),
            report
        );

        let report =
            EndpointExplorationReport::new_with_error(EndpointExplorationError::RedfishError {
                details: "test".to_string(),
            });

        let serialized = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serialized,
            r#"{"EndpointType":"Unknown","LastExplorationError":{"Type":"RedfishError","Details":"test"}}"#
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
                },
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
                },
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
        };
        report.generate_machine_id();

        let machine_id = report.machine_id.clone().unwrap();

        assert_eq!(
            machine_id.to_string(),
            "fm100dsbiu5ckus880v8407u0mkcensa39cule26im5gnpvmuufckacguc0"
        );

        // Check whether the MachineId is equal to what we generate inband
        let path = format!("{}/dpu_info.json", TEST_DATA_DIR);
        let data = std::fs::read(path).unwrap();
        let info = serde_json::from_slice::<HardwareInfo>(&data).unwrap();
        let hardware_info_machine_id = MachineId::from_hardware_info(&info).unwrap();
        assert_eq!(hardware_info_machine_id.to_string(), machine_id.to_string());

        // Check the MachineId serialization and deserialization
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(serialized.contains(
            r#""MachineId":"fm100dsbiu5ckus880v8407u0mkcensa39cule26im5gnpvmuufckacguc0""#
        ));
        let deserialized = serde_json::from_str::<EndpointExplorationReport>(&serialized).unwrap();
        assert_eq!(deserialized.machine_id.clone().unwrap(), machine_id);
    }
}
