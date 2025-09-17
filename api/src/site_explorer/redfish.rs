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

use forge_network::deserialize_input_mac_to_address;
use forge_secrets::credentials::Credentials;
use libredfish::model::oem::nvidia_dpu::NicMode;
use libredfish::model::service_root::RedfishVendor;
use libredfish::{Redfish, RedfishError};
use regex::Regex;

use crate::model::site_explorer::{
    BootOption, BootOrder, Chassis, ComputerSystem, ComputerSystemAttributes,
    EndpointExplorationError, EndpointExplorationReport, EndpointType, EthernetInterface,
    ForgeSetupDiff, ForgeSetupStatus, Inventory, Manager, NetworkAdapter, PCIeDevice, PowerState,
    SecureBootStatus, Service, SystemStatus, UefiDevicePath,
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
        new_password: String,
    ) -> Result<(), EndpointExplorationError> {
        let (curr_user, curr_pass) = match current_bmc_root_credentials.clone() {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        let mut client = self
            .create_direct_redfish_client(
                bmc_ip_address,
                curr_user.clone(),
                curr_pass.clone(),
                false,
            )
            .await
            .map_err(|e| {
                tracing::error!(
                    "Failed to create Redfish client while setting BMC password for vendor {:?} (bmc_ip = {}): {:?}",
                    vendor,
                    bmc_ip_address,
                    e
                );
                map_redfish_client_creation_error(e)
            })?;

        match vendor {
            RedfishVendor::Lenovo => {
                // Change (factory_user, factory_pass) to (factory_user, site_pass)
                client
                    .change_password_by_id("1", new_password.as_str())
                    .await
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::NvidiaDpu | RedfishVendor::NvidiaGH200 | RedfishVendor::NvidiaGBx00 => {
                // change_password does things that require a password and DPUs need a first
                // password use to be change, so just change it directly
                //
                // GH200 doesn't require change-on-first-use, but it's good practice. GB200
                // probably will.
                client
                    .change_password_by_id(curr_user.as_str(), new_password.as_str())
                    .await
                    .map_err(map_redfish_error)?;
            }
            // Handle Vikings
            RedfishVendor::AMI => {
                /*
                https://docs.nvidia.com/dgx/dgxh100-user-guide/redfish-api-supp.html

                You should set the password after the first boot. The following curl command changes the password for the admin user.
                curl -k -u <bmc-user>:<password> --request PATCH 'https://<bmc-ip-address>/redfish/v1/AccountService/Accounts/2' --header 'If-Match: *'  --header 'Content-Type: application/json' --data-raw '{ "Password" : "<password>" }'
                */
                client
                    .change_password_by_id("2", new_password.as_str())
                    .await
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::Supermicro => {
                client
                    .change_password(curr_user.as_str(), new_password.as_str())
                    .await
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::Dell => {
                client
                    .change_password(curr_user.as_str(), new_password.as_str())
                    .await
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::Hpe => {
                client
                    .change_password(curr_user.as_str(), new_password.as_str())
                    .await
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::Unknown => {
                return Err(EndpointExplorationError::UnsupportedVendor {
                    vendor: vendor.to_string(),
                });
            }
        };

        // log in using the new credentials
        client = self
            .create_authenticated_redfish_client(bmc_ip_address, curr_user, new_password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .set_machine_password_policy()
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
        let system = fetch_system(client.as_ref()).await?;

        // TODO (spyda): once we test the BMC reset logic, we can enhance our logic here
        // to detect cases where the host's BMC is returning invalid (empty) chassis information, even though
        // an error is not returned.
        let chassis = fetch_chassis(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let service = fetch_service(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let forge_setup_status = fetch_forge_setup_status(client.as_ref())
            .await
            .inspect_err(|error| tracing::warn!(%error, "Failed to fetch forge setup status."))
            .ok();

        let secure_boot_status = fetch_secure_boot_status(client.as_ref())
            .await
            .inspect_err(
                |error| tracing::warn!(%error, "Failed to fetch forge secure boot status."),
            )
            .ok();

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
            forge_setup_status,
            secure_boot_status,
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

    pub async fn disable_secure_boot(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .disable_secure_boot()
            .await
            .map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn enable_infinite_boot(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .enable_infinite_boot()
            .await
            .map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn is_infinite_boot_enabled(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
    ) -> Result<Option<bool>, EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .is_infinite_boot_enabled()
            .await
            .map_err(map_redfish_error)
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

        // We will be redoing machine_setup later and can worry about getting the profile right then.
        client
            .machine_setup(
                boot_interface_mac,
                &HashMap::default(),
                libredfish::BiosProfileType::Performance,
            )
            .await
            .map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn set_boot_order_dpu_first(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
        boot_interface_mac: &str,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .set_boot_order_dpu_first(boot_interface_mac)
            .await
            .map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn set_nic_mode(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
        mode: NicMode,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client.set_nic_mode(mode).await.map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn is_viking(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
    ) -> Result<bool, EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        let service_root = client.get_service_root().await.map_err(map_redfish_error)?;
        let system = client.get_system().await.map_err(map_redfish_error)?;
        let manager = client.get_manager().await.map_err(map_redfish_error)?;
        Ok(
            service_root.vendor().unwrap_or(RedfishVendor::Unknown) == RedfishVendor::AMI
                && system.id == "DGX"
                && manager.id == "BMC",
        )
    }

    pub async fn clear_nvram(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client.clear_nvram().await.map_err(map_redfish_error)?;
        Ok(())
    }

    pub async fn create_bmc_user(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
        new_username: &str,
        new_password: &str,
        new_user_role_id: libredfish::RoleId,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .create_user(new_username, new_password, new_user_role_id)
            .await
            .map_err(map_redfish_error)?;
        Ok(())
    }

    pub async fn delete_bmc_user(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
        delete_user: &str,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, username, password)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .delete_user(delete_user)
            .await
            .map_err(map_redfish_error)?;
        Ok(())
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

async fn fetch_system(client: &dyn Redfish) -> Result<ComputerSystem, EndpointExplorationError> {
    let mut system = client.get_system().await.map_err(map_redfish_error)?;
    let is_dpu = system.id.to_lowercase().contains("bluefield");
    let ethernet_interfaces = fetch_ethernet_interfaces(client, true, is_dpu)
        .await
        .map_err(map_redfish_error)?;
    let mut base_mac = None;
    let mut nic_mode = None;

    if is_dpu {
        if !ethernet_interfaces
            .iter()
            .any(|i| i.id == Some("oob_net0".to_owned()))
        {
            return Err(EndpointExplorationError::RedfishError {
                details: "oob interface missing for dpu".to_string(),
                response_body: None,
                response_code: None,
            });
        }
        // This part processes dpu case and do two things such as
        // 1. update system serial_number in case it is empty using chassis serial_number
        // 2. format serial_number data using the same rules as in fetch_chassis()
        if system.serial_number.is_none() {
            let chassis = client
                .get_chassis("Card1")
                .await
                .map_err(map_redfish_error)?;
            system.serial_number = chassis.serial_number;
        }

        base_mac = match client.get_base_mac_address().await {
            Ok(base_mac) => base_mac,
            Err(error) => {
                tracing::info!(
                    "Could not use new method to retreive base mac address for DPU (serial number {:#?}): {error}",
                    system.serial_number
                );
                None
            }
        };

        nic_mode = match client.get_nic_mode().await {
            Ok(nic_mode) => nic_mode,
            Err(e) => return Err(map_redfish_error(e)),
        };
    }

    system.serial_number = system.serial_number.map(|s| s.trim().to_string());

    let pcie_devices = fetch_pcie_devices(client)
        .await
        .map_err(map_redfish_error)?;

    let is_infinite_boot_enabled = client
        .is_infinite_boot_enabled()
        .await
        .map_err(map_redfish_error)?;

    let boot_order = fetch_boot_order(client, system.clone())
        .await
        .inspect_err(|error| tracing::warn!(%error, "Failed to fetch boot order."))
        .ok();

    Ok(ComputerSystem {
        ethernet_interfaces,
        id: system.id,
        manufacturer: system.manufacturer,
        model: system.model,
        serial_number: system.serial_number,
        attributes: ComputerSystemAttributes {
            nic_mode,
            is_infinite_boot_enabled,
        },
        pcie_devices,
        base_mac,
        power_state: system.power_state.into(),
        sku: system.sku,
        boot_order,
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
            match deserialize_input_mac_to_address(&iface_mac_address).map_err(|e| {
                RedfishError::GenericError {
                    error: format!("MAC address not valid: {iface_mac_address} (err: {e})"),
                }
            }) {
                Ok(mac) => Ok(Some(mac)),
                Err(e) => {
                    if iface
                        .interface_enabled
                        .is_some_and(|is_enabled| !is_enabled)
                    {
                        // disabled interfaces sometimes populate the MAC address with junk,
                        // ignore this error and create the interface with an empty mac address
                        // in the exploration report
                        tracing::debug!(
                            "could not parse MAC address for a disabled interface {iface_id} (link_status: {:#?}): {e}",
                            iface.link_status
                        );
                        Ok(None)
                    } else {
                        Err(e)
                    }
                }
            }
        } else {
            Ok(None)
        }?;

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
        let option_id = option.odata_id.split('/').next_back().unwrap();
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
                            error: format!("MAC address not valid: {mac_addr_builder} (err: {e})"),
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
                // Nautobot uses Chassis_0 as the source of truth for the GB200 chassis serial number.
                // Other chassis subsystems with network adapters may report different serial numbers.
                RedfishError::MissingKey { .. } if chassis_id == "Chassis_0" => Ok(vec![]),
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

        // For GB200s, use the Chassis_0 assembly serial number to match Nautobot.
        let serial_number = if chassis_id == "Chassis_0" {
            client
                .get_chassis_assembly("Chassis_0")
                .await
                .ok()
                .and_then(|assembly| {
                    assembly
                        .assemblies
                        .iter()
                        .find(|asm| asm.model.as_deref() == Some("GB200 NVL"))
                        .and_then(|asm| asm.serial_number.clone())
                })
                .or(desc.serial_number)
        } else {
            desc.serial_number
        };

        chassis.push(Chassis {
            id: chassis_id.to_string(),
            manufacturer: desc.manufacturer,
            model: desc.model,
            part_number: desc.part_number,
            serial_number,
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

async fn fetch_boot_order(
    client: &dyn Redfish,
    system: libredfish::model::ComputerSystem,
) -> Result<BootOrder, RedfishError> {
    let boot_options_id = system
        .boot
        .boot_options
        .ok_or_else(|| RedfishError::MissingKey {
            key: "boot.boot_options".to_string(),
            url: system.odata.odata_id.to_string(),
        })?;

    let all_boot_options: Vec<BootOption> = client
        .get_collection(boot_options_id)
        .await
        .and_then(|t1| t1.try_get::<libredfish::model::BootOption>())
        .into_iter()
        .flat_map(|x1| x1.members)
        .map(Into::into)
        .collect();

    let boot_order: Vec<BootOption> = system
        .boot
        .boot_order
        .into_iter()
        .filter_map(|id| all_boot_options.iter().find(|opt| opt.id == id).cloned())
        .collect();

    Ok(BootOrder { boot_order })
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

async fn fetch_forge_setup_status(client: &dyn Redfish) -> Result<ForgeSetupStatus, RedfishError> {
    let status = client.machine_setup_status(None).await?;
    let mut diffs: Vec<ForgeSetupDiff> = Vec::new();

    for diff in status.diffs {
        diffs.push(ForgeSetupDiff {
            key: diff.key,
            expected: diff.expected,
            actual: diff.actual,
        });
    }

    Ok(ForgeSetupStatus {
        is_done: status.is_done,
        diffs,
    })
}

async fn fetch_secure_boot_status(client: &dyn Redfish) -> Result<SecureBootStatus, RedfishError> {
    let status = client.get_secure_boot().await?;

    let secure_boot_enable =
        status
            .secure_boot_enable
            .ok_or_else(|| RedfishError::GenericError {
                error: "expected secure_boot_enable_field set in secure boot response".to_string(),
            })?;

    let secure_boot_current_boot =
        status
            .secure_boot_current_boot
            .ok_or_else(|| RedfishError::GenericError {
                error: "expected secure_boot_current_boot set in secure boot response".to_string(),
            })?;

    let is_enabled = secure_boot_enable && secure_boot_current_boot.is_enabled();

    Ok(SecureBootStatus { is_enabled })
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
        RedfishClientCreationError::RedfishError(e) => map_redfish_error(e),
        RedfishClientCreationError::InvalidHeader(original_error) => {
            EndpointExplorationError::Other {
                details: format!("RedfishClientError::InvalidHeader: {original_error}"),
            }
        }
        RedfishClientCreationError::MissingBmcEndpoint(argument)
        | RedfishClientCreationError::MissingArgument(argument) => {
            EndpointExplorationError::Other {
                details: format!("Missing argument to RedFish client: {argument}"),
            }
        }
        RedfishClientCreationError::MachineInterfaceLoadError(db_error) => {
            EndpointExplorationError::Other {
                details: format!(
                    "Database error loading the machine interface for the redfish client: {db_error}"
                ),
            }
        }
    }
}

pub(crate) fn map_redfish_error(error: RedfishError) -> EndpointExplorationError {
    match &error {
        RedfishError::NetworkError { url, source } => {
            let details = format!("url: {url};\nsource: {source};\nerror: {error}");
            if source.is_connect() {
                EndpointExplorationError::ConnectionRefused { details }
            } else if source.is_timeout() {
                EndpointExplorationError::ConnectionTimeout { details }
            } else {
                EndpointExplorationError::Unreachable {
                    details: Some(details),
                }
            }
        }
        RedfishError::HTTPErrorCode {
            status_code,
            response_body,
            url,
        } if *status_code == http::StatusCode::FORBIDDEN && url.contains("FirmwareInventory") => {
            EndpointExplorationError::VikingFWInventoryForbiddenError {
                details: format!(
                    "HTTP {status_code} at {url} - this is a known, intermittent issue for Vikings."
                ),
                response_body: Some(response_body.clone()),
                response_code: Some(status_code.as_u16()),
            }
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
