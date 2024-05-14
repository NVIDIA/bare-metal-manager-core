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

use std::net::SocketAddr;
use std::sync::Arc;

use forge_secrets::credentials::{CredentialKey, CredentialType};
use libredfish::{Redfish, RedfishError};
use regex::Regex;

use crate::{
    db::machine_interface::MachineInterface,
    model::{
        hardware_info::BMCVendor,
        site_explorer::{
            Chassis, ComputerSystem, EndpointExplorationError, EndpointExplorationReport,
            EndpointType, EthernetInterface, Inventory, Manager, NetworkAdapter, Service,
        },
    },
    redfish::{RedfishClientCreationError, RedfishClientPool},
    site_explorer::EndpointExplorer,
};

/// An `EndpointExplorer` which uses redfish APIs to query the endpoint
pub struct RedfishEndpointExplorer {
    redfish_client_pool: Arc<dyn RedfishClientPool>,
}

impl RedfishEndpointExplorer {
    pub fn new(redfish_client_pool: Arc<dyn RedfishClientPool>) -> Self {
        Self {
            redfish_client_pool,
        }
    }

    async fn try_get_client_with_hardware_cred(
        &self,
        address: SocketAddr,
        credential_key: CredentialKey,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let client = self
            .redfish_client_pool
            .create_client(
                &address.ip().to_string(),
                Some(address.port()),
                credential_key,
            )
            .await?;

        Ok(client)
    }

    async fn try_change_root_password_to_site_default(
        &self,
        address: SocketAddr,
        vendor: BMCVendor,
    ) -> Result<(), RedfishClientCreationError> {
        let credential_key = if vendor.is_dpu() {
            CredentialKey::DpuRedfish {
                credential_type: CredentialType::DpuHardwareDefault,
            }
        } else {
            CredentialKey::HostRedfish {
                credential_type: CredentialType::HostHardwareDefault {
                    vendor: vendor.to_string(),
                },
            }
        };
        let client = self
            .try_get_client_with_hardware_cred(address, credential_key)
            .await?;

        let systems = client
            .get_systems()
            .await
            .map_err(RedfishClientCreationError::RedfishError)?;

        let new_cred = if systems
            .first()
            .map(|x| x.to_lowercase().contains("bluefield"))
            .unwrap_or(false)
        {
            CredentialKey::DpuRedfish {
                credential_type: CredentialType::SiteDefault,
            }
        } else {
            CredentialKey::HostRedfish {
                credential_type: CredentialType::SiteDefault,
            }
        };

        self.redfish_client_pool
            .change_root_password_to_site_default(client, new_cred)
            .await?;

        Ok(())
    }

    async fn try_hardware_default_creds(
        &self,
        address: SocketAddr,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let (_org, vendor) = crate::site_explorer::identify_bmc(&address.to_string()).await?;
        self.try_change_root_password_to_site_default(address, vendor)
            .await?;

        tracing::info!(
            address = %address,
            "Changed password from factory default to site default"
        );
        let creds = if vendor.is_dpu() {
            forge_secrets::credentials::CredentialKey::DpuRedfish {
                credential_type: CredentialType::SiteDefault,
            }
        } else {
            CredentialKey::HostRedfish {
                credential_type: CredentialType::SiteDefault,
            }
        };
        self.redfish_client_pool
            .create_client(&address.ip().to_string(), Some(address.port()), creds)
            .await
    }
}

#[async_trait::async_trait]
impl EndpointExplorer for RedfishEndpointExplorer {
    async fn explore_endpoint(
        &self,
        address: SocketAddr,
        _interface: &MachineInterface,
        _last_report: Option<&EndpointExplorationReport>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        let client;
        // Try DpuRedfish and HostRedfish credentials.
        let client_result = self
            .redfish_client_pool
            .create_client(
                &address.ip().to_string(),
                Some(address.port()),
                forge_secrets::credentials::CredentialKey::DpuRedfish {
                    credential_type: CredentialType::SiteDefault,
                },
            )
            .await;

        match client_result {
            Ok(c) => client = c,
            Err(RedfishClientCreationError::RedfishError(e)) if e.is_unauthorized() => {
                match self
                    .redfish_client_pool
                    .create_client(
                        &address.ip().to_string(),
                        Some(address.port()),
                        forge_secrets::credentials::CredentialKey::HostRedfish {
                            credential_type: CredentialType::SiteDefault,
                        },
                    )
                    .await
                {
                    Ok(c) => client = c,
                    Err(RedfishClientCreationError::RedfishError(e)) if e.is_unauthorized() => {
                        client = self
                            .try_hardware_default_creds(address)
                            .await
                            .map_err(map_redfish_client_creation_error)?
                    }
                    Err(err) => return Err(map_redfish_client_creation_error(err)),
                }
            }
            Err(err) => return Err(map_redfish_client_creation_error(err)),
        };

        let service_root = client.get_service_root().await.map_err(map_redfish_error)?;
        let vendor = service_root.vendor_string();

        let manager = fetch_manager(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let system = fetch_system(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let chassis = fetch_chassis(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let service = fetch_service(client.as_ref())
            .await
            .map_err(map_redfish_error)?;

        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            machine_id: None,
            managers: vec![manager],
            systems: vec![system],
            chassis,
            service,
            vendor,
        })
    }
}

async fn fetch_manager(client: &dyn Redfish) -> Result<Manager, RedfishError> {
    let manager = client.get_manager().await?;
    let ethernet_interfaces = fetch_ethernet_interfaces(client, false, false).await?;

    Ok(Manager {
        ethernet_interfaces,
        id: manager.id,
    })
}

async fn fetch_system(client: &dyn Redfish) -> Result<ComputerSystem, RedfishError> {
    let mut system = client.get_system().await?;
    let fetch_bluefield_oob = system.id.to_lowercase().contains("bluefield");
    let ethernet_interfaces = fetch_ethernet_interfaces(client, true, fetch_bluefield_oob).await?;

    // This part processes dpu case and do two things such as
    // 1. update system serial_number in case it is empty using chassis serial_number
    // 2. format serial_number data using the same rules as in fetch_chassis()
    if system.id.to_lowercase().contains("bluefield") && system.serial_number.is_none() {
        let chassis = client.get_chassis("Card1").await?;
        system.serial_number = chassis.serial_number;
    }

    system.serial_number = system.serial_number.map(|s| s.trim().to_string());

    Ok(ComputerSystem {
        ethernet_interfaces,
        id: system.id,
        manufacturer: system.manufacturer,
        model: system.model,
        serial_number: system.serial_number,
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
                RedfishError::HTTPErrorCode { status_code, .. }
                    if status_code == http::StatusCode::NOT_FOUND =>
                {
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

        let iface = EthernetInterface {
            description: iface.description,
            id: iface.id,
            interface_enabled: iface.interface_enabled,
            mac_address: iface.mac_address.map(|m| m.to_lowercase()),
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
                let mut mac_addr = String::new();

                // Transform B83FD2909582 -> B8:3F:D2:90:95:82
                for (i, c) in mac_addr_str.chars().enumerate() {
                    mac_addr.push(c);
                    if ((i + 1) % 2 == 0) && ((i + 1) < mac_addr_str.len()) {
                        mac_addr.push(':');
                    }
                }

                return Ok(Some(EthernetInterface {
                    description: Some("1G DPU OOB network interface".to_string()),
                    id: Some("oob_net0".to_string()),
                    interface_enabled: None,
                    mac_address: Some(mac_addr),
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

        let Ok(net_adapter_list) = client.get_chassis_network_adapters(chassis_id).await else {
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

fn map_redfish_client_creation_error(
    error: RedfishClientCreationError,
) -> EndpointExplorationError {
    match error {
        RedfishClientCreationError::MissingCredentials(_) => {
            EndpointExplorationError::MissingCredentials
        }
        RedfishClientCreationError::RedfishError(e) => map_redfish_error(e),
        RedfishClientCreationError::SubtaskError(e) => EndpointExplorationError::Other {
            details: format!("Error joining tokio task: {e}"),
        },
        RedfishClientCreationError::NotImplemented => EndpointExplorationError::Other {
            details: "RedfishClientCreationError::NotImplemented".to_string(),
        },
        RedfishClientCreationError::IdentifyError(msg) => EndpointExplorationError::Other {
            details: msg.to_string(),
        },
    }
}

fn map_redfish_error(error: RedfishError) -> EndpointExplorationError {
    match &error {
        RedfishError::NetworkError { url: _, source }
            if source.is_connect() || source.is_timeout() =>
        {
            // TODO: It might actually also be TLS related
            EndpointExplorationError::Unreachable
        }
        error if error.is_unauthorized() => EndpointExplorationError::Unauthorized {
            details: error.to_string(),
        },
        _ => EndpointExplorationError::RedfishError {
            details: error.to_string(),
        },
    }
}
