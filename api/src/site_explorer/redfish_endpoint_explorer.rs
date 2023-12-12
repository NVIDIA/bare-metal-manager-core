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

use crate::{
    db::machine_interface::MachineInterface,
    model::site_explorer::{
        ComputerSystem, EndpointExplorationError, EndpointExplorationReport, EndpointType,
        EthernetInterface, Manager,
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
}

#[async_trait::async_trait]
impl EndpointExplorer for RedfishEndpointExplorer {
    async fn explore_endpoint(
        &self,
        address: &IpAddr,
        _interface: &MachineInterface,
        _last_report: Option<&EndpointExplorationReport>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        let client = &self
            .redfish_client_pool
            .create_client(
                &address.to_string(),
                None,
                crate::redfish::RedfishCredentialType::SiteDefault,
            )
            .await
            .map_err(map_redfish_client_creation_error)?;

        let service_root = client.get_service_root().await.map_err(map_redfish_error)?;
        let vendor = service_root.vendor();

        let manager = fetch_manager(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let system = fetch_system(client.as_ref())
            .await
            .map_err(map_redfish_error)?;

        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            machine_id: None,
            managers: vec![manager],
            systems: vec![system],
            vendor,
        })
    }
}

async fn fetch_manager(client: &dyn Redfish) -> Result<Manager, RedfishError> {
    let manager = client.get_manager().await?;
    let ethernet_interfaces = fetch_ethernet_interfaces(client, false).await?;

    Ok(Manager {
        ethernet_interfaces,
        id: manager.id,
    })
}

async fn fetch_system(client: &dyn Redfish) -> Result<ComputerSystem, RedfishError> {
    let system = client.get_system().await?;
    let ethernet_interfaces = fetch_ethernet_interfaces(client, true).await?;

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

    Ok(eth_ifs)
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
        RedfishError::HTTPErrorCode {
            url: _,
            status_code,
            response_body: _,
        } if *status_code == http::StatusCode::UNAUTHORIZED
            || *status_code == http::StatusCode::FORBIDDEN =>
        {
            EndpointExplorationError::Unauthorized {
                details: error.to_string(),
            }
        }
        _ => EndpointExplorationError::RedfishError {
            details: error.to_string(),
        },
    }
}
