/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::net::IpAddr;

use ::rpc::forge as rpc;
use tonic::{Request, Response, Status};

use crate::api::{log_request_data, Api};
use crate::db::domain::{Domain, DomainIdKeyedObjectFilter};
use crate::db::instance::Instance;
use crate::db::instance_address::InstanceAddress;
use crate::db::machine::{Machine, MachineSearchConfig};
use crate::db::machine_boot_override::MachineBootOverride;
use crate::db::machine_interface::{MachineInterface, MachineInterfaceId};
use crate::db::DatabaseError;
use crate::ipxe::PxeInstructions;
use crate::model::machine::ReprovisionState;
use crate::model::os::OperatingSystemVariant;
use crate::CarbideError;

// The carbide pxe server makes this RPC call
pub(crate) async fn get_pxe_instructions(
    api: &Api,
    request: Request<rpc::PxeInstructionRequest>,
) -> Result<Response<rpc::PxeInstructions>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_pxe_instructions",
            e,
        ))
    })?;

    let request = request.into_inner();

    let interface_id = match request.interface_id {
        None => {
            return Err(Status::invalid_argument("Interface ID is missing."));
        }
        Some(interface_id) => MachineInterfaceId::try_from(interface_id)
            .map_err(|e| Status::invalid_argument(format!("Interface ID is invalid: {}", e)))?,
    };

    let arch = rpc::MachineArchitecture::try_from(request.arch)
        .map_err(|_| Status::invalid_argument("Unknown arch received."))?;
    let pxe_script = PxeInstructions::get_pxe_instructions(&mut txn, interface_id, arch).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit get_pxe_instructions",
            e,
        ))
    })?;

    Ok(Response::new(rpc::PxeInstructions { pxe_script }))
}

pub(crate) async fn get_cloud_init_instructions(
    api: &Api,
    request: Request<rpc::CloudInitInstructionsRequest>,
) -> Result<Response<rpc::CloudInitInstructions>, Status> {
    log_request_data(&request);
    let cloud_name = "nvidia".to_string();
    let platform = "forge".to_string();

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_cloud_init_instructions",
            e,
        ))
    })?;

    let ip_str = &request.into_inner().ip;
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|e| Status::invalid_argument(format!("Failed parsing IP '{ip_str}': {e}")))?;
    if ip.is_ipv6() {
        return Err(CarbideError::GenericError("IPv6 not supported".to_string()).into());
    }

    let instructions = match InstanceAddress::find_by_address(&mut txn, ip)
        .await
        .map_err(CarbideError::from)?
    {
        None => {
            // assume there is no instance associated with this IP and check if there is an interface associated with it
            let machine_interface = MachineInterface::find_by_ip(&mut txn, ip)
                .await
                .map_err(CarbideError::from)?
                .ok_or_else(|| {
                    CarbideError::GenericError(format!(
                        "No machine interface with IP {ip} was found"
                    ))
                })?;

            let domain_id = machine_interface.domain_id.ok_or_else(|| {
                CarbideError::GenericError(format!(
                    "Machine Interface did not have an associated domain {}",
                    machine_interface.id
                ))
            })?;

            let domain = Domain::find(&mut txn, DomainIdKeyedObjectFilter::One(domain_id))
                .await
                .map_err(CarbideError::from)?
                .first()
                .ok_or_else(|| {
                    CarbideError::GenericError(format!("Could not find a domain for {}", domain_id))
                })?
                .to_owned();

            // This custom pxe is different from a customer instance of pxe. It is more for testing one off
            // changes until a real dev env is established and we can just override our existing code to test
            // It is possible for the user data to be null if we are only trying to test the pxe, and this will
            // follow the same code path and retrieve the non custom user data
            let custom_cloud_init =
                match MachineBootOverride::find_optional(&mut txn, machine_interface.id).await? {
                    Some(machine_boot_override) => machine_boot_override.custom_user_data,
                    None => None,
                };

            // we update DPU firmware on first boot every time (determined by a missing machine id) or during reprovisioning.
            let update_firmware = match &machine_interface.machine_id {
                None => api.runtime_config.dpu_nic_firmware_initial_update_enabled,
                Some(machine_id) => {
                    let machine =
                        Machine::find_one(&mut txn, machine_id, MachineSearchConfig::default())
                            .await
                            .map_err(CarbideError::from)?;

                    if let Some(machine) = machine {
                        if let Some(reprov_state) = machine.current_state().as_reprovision_state() {
                            matches!(reprov_state, ReprovisionState::FirmwareUpgrade,)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
            };

            let metadata: Option<rpc::CloudInitMetaData> = machine_interface
                .machine_id
                .as_ref()
                .map(|machine_id| rpc::CloudInitMetaData {
                    instance_id: machine_id.to_string(),
                    cloud_name,
                    platform,
                });

            rpc::CloudInitInstructions {
                custom_cloud_init,
                discovery_instructions: Some(rpc::CloudInitDiscoveryInstructions {
                    machine_interface: Some(machine_interface.into()),
                    domain: Some(domain.into()),
                    update_firmware,
                }),
                metadata,
            }
        }

        Some(instance_address) => {
            let instance = Instance::find_by_id(&mut txn, instance_address.instance_id)
                .await
                .map_err(CarbideError::from)?
                .ok_or_else(|| {
                    // Note that this isn't a NotFound error since it indicates an
                    // inconsistent data model
                    CarbideError::GenericError(format!(
                        "Could not find an instance for {}",
                        instance_address.instance_id
                    ))
                })?
                .to_owned();

            let user_data = match instance.config.os.variant {
                OperatingSystemVariant::Ipxe(ipxe) => ipxe.user_data,
            };

            rpc::CloudInitInstructions {
                custom_cloud_init: user_data,
                discovery_instructions: None,
                metadata: Some(rpc::CloudInitMetaData {
                    instance_id: instance.id.to_string(),
                    cloud_name,
                    platform,
                }),
            }
        }
    };

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit get_cloud_init_instructions",
            e,
        ))
    })?;

    Ok(Response::new(instructions))
}
