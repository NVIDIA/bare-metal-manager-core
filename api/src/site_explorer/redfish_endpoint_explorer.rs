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

use std::{net::IpAddr, sync::Arc};

use libredfish::{Redfish, RedfishError};
use regex::Regex;

use crate::{
    db::machine_interface::MachineInterface,
    model::site_explorer::{
        Chassis, ComputerSystem, EndpointExplorationError, EndpointExplorationReport, EndpointType,
        EthernetInterface, Manager, NetworkAdapter,
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

    async fn try_hardware_default_creds(
        &self,
        address: &IpAddr,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let standard_client = self
            .redfish_client_pool
            .create_standard_client(&address.to_string(), None)
            .await?;
        self.redfish_client_pool
            .change_root_password_to_site_default(*standard_client.clone())
            .await?;
        self.redfish_client_pool
            .create_client(
                &address.to_string(),
                None,
                crate::redfish::RedfishCredentialType::SiteDefault,
            )
            .await
    }
}

#[async_trait::async_trait]
impl EndpointExplorer for RedfishEndpointExplorer {
    async fn explore_endpoint(
        &self,
        address: &IpAddr,
        _interface: &MachineInterface,
        _last_report: Option<&EndpointExplorationReport>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        let client;
        let client_result = self
            .redfish_client_pool
            .create_client(
                &address.to_string(),
                None,
                crate::redfish::RedfishCredentialType::SiteDefault,
            )
            .await;

        match client_result {
            Ok(c) => client = c,
            Err(RedfishClientCreationError::RedfishError(e)) if e.is_unauthorized() => {
                client = self
                    .try_hardware_default_creds(address)
                    .await
                    .map_err(map_redfish_client_creation_error)?
            }
            Err(err) => return Err(map_redfish_client_creation_error(err)),
        };

        let service_root = client.get_service_root().await.map_err(map_redfish_error)?;
        let vendor = service_root.vendor();

        let manager = fetch_manager(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let system = fetch_system(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let chassis = fetch_chassis(client.as_ref())
            .await
            .map_err(map_redfish_error)?;

        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            machine_id: None,
            managers: vec![manager],
            systems: vec![system],
            chassis,
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
    let fetch_oob = system.id.to_lowercase().contains("bluefield");
    let ethernet_interfaces = fetch_ethernet_interfaces(client, true, fetch_oob).await?;

    // This part processes dpu case and do two things such as
    // 1. update system serial_number in case it is empty using chassis serial_number
    // 2. format serial_number data using the same rules as in fetch_chassis()
    if system.id.to_lowercase().contains("bluefield") {
        if system.serial_number.is_none() {
            let chassis = client.get_chassis("Card1").await?;
            system.serial_number = chassis.serial_number;
        }
        system.serial_number = Some(
            system
                .serial_number
                .as_ref()
                .unwrap_or(&"".to_string())
                .trim()
                .to_string(),
        )
        .map(|m| m.to_uppercase());
    }

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
    fetch_oob: bool,
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

    if fetch_oob {
        // Temporary workaround untill get_system_ethernet_interface will return oob interface information
        let oob_iface = get_oob_interface(client).await?;
        eth_ifs.push(oob_iface);
    }

    Ok(eth_ifs)
}

async fn get_oob_interface(client: &dyn Redfish) -> Result<EthernetInterface, RedfishError> {
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
                return Err(RedfishError::NoContent);
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

                return Ok(EthernetInterface {
                    description: Some("1G DPU OOB network interface".to_string()),
                    id: Some("oob_net0".to_string()),
                    interface_enabled: None,
                    mac_address: Some(mac_addr),
                });
            }
        }
    }
    Err(RedfishError::NoContent)
}

async fn fetch_chassis(client: &dyn Redfish) -> Result<Vec<Chassis>, RedfishError> {
    let mut chassis: Vec<Chassis> = Vec::new();

    let chassis_list = client.get_chassis_all().await?;
    for chassis_id in &chassis_list {
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
                )
                .map(|m| m.to_uppercase()),
            };

            net_adapters.push(net_adapter);
        }

        chassis.push(Chassis {
            id: chassis_id.to_string(),
            network_adapters: net_adapters,
        });
    }

    Ok(chassis)
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
