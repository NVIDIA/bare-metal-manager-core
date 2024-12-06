/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use bmc_vendor::BMCVendor;
use forge_network::deserialize_input_mac_to_address;
use forge_secrets::credentials::Credentials;
use libredfish::model::service_root::RedfishVendor;
use libredfish::{EnabledDisabled, ForgeSetupStatus, Redfish, RedfishError, RoleId};
use regex::Regex;
use serde_json::Value;

use crate::model::site_explorer::{
    Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationError,
    EndpointExplorationReport, EndpointType, EthernetInterface, Inventory, Manager, NetworkAdapter,
    NicMode, PCIeDevice, PowerState, Service, SystemStatus, UefiDevicePath,
    DPU_BIOS_ATTRIBUTES_MISSING,
};
use crate::redfish::{RedfishAuth, RedfishClientCreationError, RedfishClientPool};

const NOT_FOUND: u16 = 404;

// RedfishClient is a wrapper around a redfish client pool and implements redfish utility functions that the site explorer utilizes.
// TODO: In the future, we should refactor a lot of this client's work to api/src/redfish.rs because other components in carbide can utilize this functionality.
// Eventually, this file should only have code related to generating the site exploration report.
pub struct RedfishClient {
    redfish_client_pool: Arc<dyn RedfishClientPool>,
}

impl RedfishClient {
    pub fn new(redfish_client_pool: Arc<dyn RedfishClientPool>) -> Self {
        Self {
            redfish_client_pool,
        }
    }

    async fn create_redfish_client(
        &self,
        bmc_ip_address: SocketAddr,
        auth: RedfishAuth,
        initialize: bool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.redfish_client_pool
            .create_client(
                &bmc_ip_address.ip().to_string(),
                Some(bmc_ip_address.port()),
                auth,
                initialize,
            )
            .await
    }

    async fn create_anon_redfish_client(
        &self,
        bmc_ip_address: SocketAddr,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.create_redfish_client(bmc_ip_address, RedfishAuth::Anonymous, false)
            .await
    }

    async fn create_direct_redfish_client(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
        initialize: bool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.create_redfish_client(
            bmc_ip_address,
            RedfishAuth::Direct(username, password),
            initialize,
        )
        .await
    }

    async fn create_authenticated_redfish_client(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.create_direct_redfish_client(bmc_ip_address, username.clone(), password.clone(), true)
            .await
    }

    pub async fn probe_redfish_endpoint(
        &self,
        bmc_ip_address: SocketAddr,
    ) -> Result<RedfishVendor, EndpointExplorationError> {
        let client = self
            .create_anon_redfish_client(bmc_ip_address)
            .await
            .map_err(map_redfish_client_creation_error)?;

        let service_root = client.get_service_root().await.map_err(map_redfish_error)?;

        let Some(vendor) = service_root.vendor() else {
            return Err(EndpointExplorationError::MissingVendor);
        };

        Ok(vendor)
    }

    pub async fn set_bmc_root_password(
        &self,
        bmc_ip_address: SocketAddr,
        vendor: RedfishVendor,
        current_bmc_root_credentials: Credentials,
        new_bmc_root_credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        let (curr_user, curr_pass) = match current_bmc_root_credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        let (new_user, new_pass) = match new_bmc_root_credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        let mut client = self
            .create_direct_redfish_client(
                bmc_ip_address,
                curr_user.clone(),
                curr_pass.clone(),
                false, // Since we're changing the password we don't need to load any
                       // default endpoints
            )
            .await
            .map_err(map_redfish_client_creation_error)?;

        match vendor {
            RedfishVendor::Lenovo => {
                // Change (factory_user, factory_pass) to (factory_user, site_pass)
                // We must do this first, BMC won't allow any other call until this is done
                client
                    .change_password_by_id("1", new_pass.as_str())
                    .await
                    .map_err(map_redfish_error)?;

                // Auth has changed
                let mid_client = self
                    .create_authenticated_redfish_client(
                        bmc_ip_address,
                        curr_user.clone(),
                        new_pass.clone(),
                    )
                    .await
                    .map_err(map_redfish_client_creation_error)?;

                // Change (factory_user, site_pass) to (site_user, site_pass)
                mid_client
                    .change_username(&curr_user, &new_user)
                    .await
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::NvidiaDpu | RedfishVendor::NvidiaGH200 => {
                // change_password does things that require a password and DPUs need a first
                // password use to be change, so just change it directly
                //
                // GH200 doesn't require change-on-first-use, but it's good practice. GB200
                // probably will.
                client
                    .change_password_by_id("root", new_pass.as_str())
                    .await
                    .map_err(map_redfish_error)?;
            }
            // Handle Vikings
            RedfishVendor::AMI => {
                // new user will always be "admin"
                client
                    .change_password(new_user.as_str(), new_pass.as_str())
                    .await
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::Supermicro => {
                // I think Supermicro does not allow renaming its original superuser ('ADMIN').
                // Check this.
                client
                    .create_user(&new_user, &new_pass, RoleId::Administrator)
                    .await
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::Dell => {
                client
                    .change_password(new_user.as_str(), new_pass.as_str())
                    .await
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::Hpe => {
                // We don't have an Ansible playbook for HPE. We only run one or two of them
                // in dev, no prod deploys.
                return Err(EndpointExplorationError::UnsupportedVendor(
                    vendor.to_string(),
                ));
            }
            RedfishVendor::Unknown => {
                return Err(EndpointExplorationError::UnsupportedVendor(
                    vendor.to_string(),
                ));
            }
        };

        // log in using the new credentials
        client = self
            .create_authenticated_redfish_client(bmc_ip_address, new_user, new_pass)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .set_forge_password_policy()
            .await
            .map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn generate_exploration_report(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        let service_root = client.get_service_root().await.map_err(map_redfish_error)?;
        let vendor = service_root.vendor().map(|v| v.into());

        let manager = fetch_manager(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let system = fetch_system(client.as_ref(), vendor).await?;

        // TODO (spyda): once we test the BMC reset logic, we can enhance our logic here
        // to detect cases where the host's BMC is returning invalid (empty) chassis information, even though
        // an error is not returned.
        let chassis = fetch_chassis(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let service = fetch_service(client.as_ref())
            .await
            .map_err(map_redfish_error)?;

        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            last_exploration_latency: None,
            machine_id: None,
            managers: vec![manager],
            systems: vec![system],
            chassis,
            service,
            vendor,
            versions: HashMap::default(),
            model: None,
        })
    }

    pub async fn reset_bmc(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client.bmc_reset().await.map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn power(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
        action: libredfish::SystemPowerControl,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client.power(action).await.map_err(map_redfish_error)?;
        Ok(())
    }

    pub async fn forge_setup(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
        boot_interface_mac: Option<&str>,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .forge_setup(boot_interface_mac)
            .await
            .map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn forge_setup_status(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
    ) -> Result<ForgeSetupStatus, EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        let status = client
            .forge_setup_status()
            .await
            .map_err(map_redfish_error)?;

        Ok(status)
    }
}

async fn fetch_manager(client: &dyn Redfish) -> Result<Manager, RedfishError> {
    let manager = client.get_manager().await?;
    let ethernet_interfaces = fetch_ethernet_interfaces(client, false, false)
        .await
        .or_else(|err| match err {
            RedfishError::NotSupported(_) => Ok(vec![]),
            _ => Err(err),
        })?;

    Ok(Manager {
        ethernet_interfaces,
        id: manager.id,
    })
}

async fn fetch_system(
    client: &dyn Redfish,
    vendor: Option<BMCVendor>,
) -> Result<ComputerSystem, EndpointExplorationError> {
    let mut system = client.get_system().await.map_err(map_redfish_error)?;
    let is_dpu = system.id.to_lowercase().contains("bluefield");
    let ethernet_interfaces = fetch_ethernet_interfaces(client, true, is_dpu)
        .await
        .map_err(map_redfish_error)?;

    // This part processes dpu case and do two things such as
    // 1. update system serial_number in case it is empty using chassis serial_number
    // 2. format serial_number data using the same rules as in fetch_chassis()
    if is_dpu && system.serial_number.is_none() {
        let chassis = client
            .get_chassis("Card1")
            .await
            .map_err(map_redfish_error)?;
        system.serial_number = chassis.serial_number;
    }

    let base_mac = if is_dpu {
        match client.get_base_mac_address().await {
            Ok(base_mac) => base_mac,
            Err(error) => {
                tracing::info!("Could not use new method to retreive base mac address for DPU (serial number {:#?}): {error}", system.serial_number);
                None
            }
        }
    } else {
        None
    };

    system.serial_number = system.serial_number.map(|s| s.trim().to_string());

    let bios_attributes: Value;
    match client.bios().await {
        Ok(bios) => {
            match bios.get("Attributes") {
                Some(attributes) => bios_attributes = attributes.clone(),
                None => {
                    if is_dpu {
                        return Err(EndpointExplorationError::InvalidDpuRedfishBiosResponse {
                            details: DPU_BIOS_ATTRIBUTES_MISSING.to_owned(),
                            response_body: Some(
                                serde_json::to_string(&bios)
                                    .unwrap_or_else(|_| "Can not serialize map".to_string()),
                            ),
                            response_code: None,
                        });
                    }

                    bios_attributes = Value::default();
                }
            };
        }
        Err(e) => {
            if is_dpu {
                match e {
                    RedfishError::HTTPErrorCode {
                        url,
                        status_code,
                        response_body,
                    } if status_code.is_server_error() => {
                        let code_str = status_code.as_str();
                        return Err(EndpointExplorationError::InvalidDpuRedfishBiosResponse {
                            details: format!("Failed to retrieve bios attributes: HTTP {status_code} {code_str} at {url}"),
                            response_body: Some(response_body),
                            response_code: Some(status_code.as_u16()),
                        });
                    }
                    _ => {}
                }
            }

            return Err(map_redfish_error(e));
        }
    };

    let pcie_devices = fetch_pcie_devices(client)
        .await
        .map_err(map_redfish_error)?;

    let nic_mode: Option<NicMode> = if is_dpu {
        bios_attributes
            .get("NicMode")
            .and_then(|v| v.as_str().and_then(|v| NicMode::from_str(v).ok()))
    } else {
        None
    };

    let vendor = vendor.unwrap_or_default();

    let http_dev1_interface = if vendor.is_dell() {
        Some(
            bios_attributes
                .get("HttpDev1Interface")
                .and_then(|v| v.as_str())
                .ok_or_else(|| RedfishError::MissingKey {
                    key: "HttpDev1Interface".to_string(),
                    url: "Bios attributes".to_string(),
                })
                .map_err(map_redfish_error)?
                .to_string(),
        )
    } else {
        None
    };

    let is_infinite_boot_enabled = if vendor.is_dell() {
        let infinite_boot_status = bios_attributes
            .get("BootSeqRetry")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RedfishError::MissingKey {
                key: "BootSeqRetry".to_string(),
                url: "Bios attributes".to_string(),
            })
            .map_err(map_redfish_error)?;
        Some(infinite_boot_status == EnabledDisabled::Enabled.to_string())
    } else if vendor.is_lenovo() {
        let infinite_boot_status = bios_attributes
            .get("BootModes_InfiniteBootRetry")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RedfishError::MissingKey {
                key: "BootModes_InfiniteBootRetry".to_string(),
                url: "Bios attributes".to_string(),
            })
            .map_err(map_redfish_error)?;
        Some(infinite_boot_status == EnabledDisabled::Enabled.to_string())
    } else {
        None
    };

    Ok(ComputerSystem {
        ethernet_interfaces,
        id: system.id,
        manufacturer: system.manufacturer,
        model: system.model,
        serial_number: system.serial_number,
        attributes: ComputerSystemAttributes {
            nic_mode,
            http_dev1_interface,
            is_infinite_boot_enabled,
        },
        pcie_devices,
        base_mac,
        power_state: system.power_state.into(),
        sku: system.sku,
    })
}

async fn fetch_ethernet_interfaces(
    client: &dyn Redfish,
    fetch_system_interfaces: bool,
    fetch_bluefield_oob: bool,
) -> Result<Vec<EthernetInterface>, RedfishError> {
    let eth_if_ids: Vec<String> = match match fetch_system_interfaces {
        false => client.get_manager_ethernet_interfaces().await,
        true => client.get_system_ethernet_interfaces().await,
    } {
        Ok(ids) => ids,
        Err(e) => {
            match e {
                RedfishError::HTTPErrorCode { status_code, .. } if status_code == NOT_FOUND => {
                    // API to enumerate Ethernet interfaces is not supported
                    // This is the case for Bluefield NICs with some BMCs
                    // For this case we use a workaround to fetch the OOB interface
                    // information
                    if fetch_system_interfaces && fetch_bluefield_oob {
                        if let Some(oob_iface) = get_oob_interface(client).await? {
                            return Ok(vec![oob_iface]);
                        }
                    }
                    return Ok(Vec::new());
                }
                _ => return Err(e),
            }
        }
    };
    let mut eth_ifs: Vec<EthernetInterface> = Vec::new();

    for iface_id in eth_if_ids.iter() {
        let iface = match fetch_system_interfaces {
            false => client.get_manager_ethernet_interface(iface_id).await,
            true => client.get_system_ethernet_interface(iface_id).await,
        }?;

        let mac_address = if let Some(iface_mac_address) = iface.mac_address {
            let mac_addr = deserialize_input_mac_to_address(&iface_mac_address).map_err(|e| {
                RedfishError::GenericError {
                    error: format!("MAC address not valid: {} (err: {})", iface_mac_address, e),
                }
            })?;

            Some(mac_addr)
        } else {
            None
        };

        let uefi_device_path = if let Some(uefi_device_path) = iface.uefi_device_path {
            let path_as_version_string = UefiDevicePath::from_str(&uefi_device_path)?;
            Some(path_as_version_string)
        } else {
            None
        };

        let iface = EthernetInterface {
            description: iface.description,
            id: iface.id,
            interface_enabled: iface.interface_enabled,
            mac_address,
            uefi_device_path,
        };

        eth_ifs.push(iface);
    }

    if eth_ifs.is_empty() && fetch_bluefield_oob {
        // Temporary workaround untill get_system_ethernet_interface will return oob interface information
        // Usually the workaround for not even being able to enumerate the interfaces
        // would be used. But if a future Bluefield BMC revision returns interfaces
        // but still misses the OOB interface, we would use this path.
        if let Some(oob_iface) = get_oob_interface(client).await? {
            eth_ifs.push(oob_iface);
        }
    }

    Ok(eth_ifs)
}

async fn get_oob_interface(
    client: &dyn Redfish,
) -> Result<Option<EthernetInterface>, RedfishError> {
    // Temporary workaround until oob mac would be possible to get via Redfish
    let boot_options = client.get_boot_options().await?;
    let mac_pattern = Regex::new(r"MAC\((?<mac>[[:alnum:]]+)\,").unwrap();

    for option in boot_options.members.iter() {
        // odata_id: "/redfish/v1/Systems/Bluefield/BootOptions/Boot0001"
        let option_id = option.odata_id.split('/').last().unwrap();
        let boot_option = client.get_boot_option(option_id).await?;
        // display_name: "NET-OOB-IPV4"
        if boot_option.display_name.contains("OOB") {
            if boot_option.uefi_device_path.is_none() {
                // Try whether there might be other matching options
                continue;
            }
            // UefiDevicePath: "MAC(B83FD2909582,0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)/Uri()"
            if let Some(captures) =
                mac_pattern.captures(boot_option.uefi_device_path.unwrap().as_str())
            {
                let mac_addr_str = captures.name("mac").unwrap().as_str();
                let mut mac_addr_builder = String::new();

                // Transform B83FD2909582 -> B8:3F:D2:90:95:82
                for (i, c) in mac_addr_str.chars().enumerate() {
                    mac_addr_builder.push(c);
                    if ((i + 1) % 2 == 0) && ((i + 1) < mac_addr_str.len()) {
                        mac_addr_builder.push(':');
                    }
                }

                let mac_addr =
                    deserialize_input_mac_to_address(&mac_addr_builder).map_err(|e| {
                        RedfishError::GenericError {
                            error: format!(
                                "MAC address not valid: {} (err: {})",
                                mac_addr_builder, e
                            ),
                        }
                    })?;

                return Ok(Some(EthernetInterface {
                    description: Some("1G DPU OOB network interface".to_string()),
                    id: Some("oob_net0".to_string()),
                    interface_enabled: None,
                    mac_address: Some(mac_addr),
                    uefi_device_path: None,
                }));
            }
        }
    }

    // OOB Interface was not found
    Ok(None)
}

async fn fetch_chassis(client: &dyn Redfish) -> Result<Vec<Chassis>, RedfishError> {
    let mut chassis: Vec<Chassis> = Vec::new();

    let chassis_list = client.get_chassis_all().await?;
    for chassis_id in &chassis_list {
        let Ok(desc) = client.get_chassis(chassis_id).await else {
            continue;
        };

        let Ok(net_adapter_list) = client
            .get_chassis_network_adapters(chassis_id)
            .await
            .or_else(|err| match err {
                RedfishError::NotSupported(_) => Ok(vec![]),
                _ => Err(err),
            })
        else {
            continue;
        };

        let mut net_adapters: Vec<NetworkAdapter> = Vec::new();
        for net_adapter_id in &net_adapter_list {
            let value = client
                .get_chassis_network_adapter(chassis_id, net_adapter_id)
                .await?;

            let net_adapter = NetworkAdapter {
                id: value.id,
                manufacturer: value.manufacturer,
                model: value.model,
                part_number: value.part_number,
                serial_number: Some(
                    value
                        .serial_number
                        .as_ref()
                        .unwrap_or(&"".to_string())
                        .trim()
                        .to_string(),
                ),
            };

            net_adapters.push(net_adapter);
        }

        chassis.push(Chassis {
            id: chassis_id.to_string(),
            manufacturer: desc.manufacturer,
            model: desc.model,
            part_number: desc.part_number,
            serial_number: desc.serial_number,
            network_adapters: net_adapters,
        });
    }

    Ok(chassis)
}

impl From<libredfish::PowerState> for PowerState {
    fn from(state: libredfish::PowerState) -> Self {
        match state {
            libredfish::PowerState::Off => PowerState::Off,
            libredfish::PowerState::On => PowerState::On,
            libredfish::PowerState::PoweringOff => PowerState::PoweringOff,
            libredfish::PowerState::PoweringOn => PowerState::PoweringOn,
            libredfish::PowerState::Paused => PowerState::Paused,
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

async fn fetch_pcie_devices(client: &dyn Redfish) -> Result<Vec<PCIeDevice>, RedfishError> {
    let pci_device_list = client.pcie_devices().await?;
    let mut pci_devices: Vec<PCIeDevice> = Vec::new();

    for pci_device in pci_device_list {
        pci_devices.push(PCIeDevice {
            description: pci_device.description,
            firmware_version: pci_device.firmware_version,
            id: pci_device.id.clone(),
            manufacturer: pci_device.manufacturer,
            gpu_vendor: pci_device.gpu_vendor,
            name: pci_device.name,
            part_number: pci_device.part_number,
            serial_number: pci_device.serial_number,
            status: pci_device.status.map(|s| s.into()),
        });
    }
    Ok(pci_devices)
}

async fn fetch_service(client: &dyn Redfish) -> Result<Vec<Service>, RedfishError> {
    let mut service: Vec<Service> = Vec::new();

    let inventory_list = client.get_software_inventories().await?;
    let mut inventories: Vec<Inventory> = Vec::new();
    for inventory_id in &inventory_list {
        let Ok(value) = client.get_firmware(inventory_id).await else {
            continue;
        };

        let inventory = Inventory {
            id: value.id,
            description: value.description,
            version: value.version,
            release_date: value.release_date,
        };

        inventories.push(inventory);
    }

    service.push(Service {
        id: "FirmwareInventory".to_string(),
        inventories,
    });

    Ok(service)
}

pub(crate) fn map_redfish_client_creation_error(
    error: RedfishClientCreationError,
) -> EndpointExplorationError {
    match error {
        RedfishClientCreationError::MissingCredentials { key, cause } => {
            EndpointExplorationError::MissingCredentials {
                key,
                cause: format!("{cause:#}"),
            }
        }
        RedfishClientCreationError::SetCredentials { key, cause } => {
            EndpointExplorationError::SetCredentials {
                key,
                cause: format!("{cause:#}"),
            }
        }
        RedfishClientCreationError::RedfishError(e) => map_redfish_error(e),
        RedfishClientCreationError::SubtaskError(e) => EndpointExplorationError::Other {
            details: format!("Error joining tokio task: {e}"),
        },
        RedfishClientCreationError::NotImplemented => EndpointExplorationError::Other {
            details: "RedfishClientCreationError::NotImplemented".to_string(),
        },
        RedfishClientCreationError::InvalidHeader(original_error) => {
            EndpointExplorationError::Other {
                details: format!("RedfishClientError::InvalidHeader: {}", original_error),
            }
        }
        RedfishClientCreationError::MissingBmcEndpoint(argument)
        | RedfishClientCreationError::MissingArgument(argument) => {
            EndpointExplorationError::Other {
                details: format!("Missing argument to RedFish client: {0}", argument),
            }
        }
        RedfishClientCreationError::InvalidArgument(key, value) => {
            EndpointExplorationError::Other {
                details: format!("Invalid Argument to RedFish client: {}={}", key, value),
            }
        }
        RedfishClientCreationError::MachineInterfaceLoadError(db_error) => {
            EndpointExplorationError::Other {
                details: format!(
                    "Database error loading the machine interface for the redfish client: {0}",
                    db_error
                ),
            }
        }
    }
}

pub(crate) fn map_redfish_error(error: RedfishError) -> EndpointExplorationError {
    match &error {
        RedfishError::NetworkError { url, source }
            if source.is_connect() || source.is_timeout() =>
        {
            // TODO: It might actually also be TLS related
            EndpointExplorationError::Unreachable {
                details: Some(format!("url: {url};\nsource: {source};\nerror: {error}",)),
            }
        }
        RedfishError::HTTPErrorCode { status_code, .. } if *status_code == NOT_FOUND => {
            EndpointExplorationError::MissingRedfish
        }
        RedfishError::HTTPErrorCode {
            status_code,
            response_body,
            url,
        } if *status_code == http::StatusCode::UNAUTHORIZED
            || *status_code == http::StatusCode::FORBIDDEN =>
        {
            let code_str = status_code.as_str();
            EndpointExplorationError::Unauthorized {
                details: format!("HTTP {status_code} {code_str} at {url}"),
                response_body: Some(response_body.clone()),
                response_code: Some(status_code.as_u16()),
            }
        }
        RedfishError::HTTPErrorCode {
            status_code,
            response_body,
            url,
        } => EndpointExplorationError::RedfishError {
            details: format!("HTTP {status_code} at {url}"),
            response_body: Some(response_body.clone()),
            response_code: Some(status_code.as_u16()),
        },
        RedfishError::JsonDeserializeError { url, body, source } => {
            EndpointExplorationError::RedfishError {
                details: format!("Failed to deserialize data from {url}: {source}"),
                response_body: Some(body.clone()),
                response_code: None,
            }
        }
        _ => EndpointExplorationError::RedfishError {
            details: error.to_string(),
            response_body: None,
            response_code: None,
        },
    }
}
