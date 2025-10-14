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
use db::{DatabaseError, ObjectColumnFilter, domain};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::ipxe::PxeInstructions;

// The carbide pxe server makes this RPC call
pub(crate) async fn get_pxe_instructions(
    api: &Api,
    request: Request<rpc::PxeInstructionRequest>,
) -> Result<Response<rpc::PxeInstructions>, Status> {
    log_request_data(&request);

    const DB_TXN_NAME: &str = "get_pxe_instructions";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let request = request.into_inner();

    let interface_id = request
        .interface_id
        .ok_or_else(|| Status::invalid_argument("Interface ID is missing."))?;

    let arch = rpc::MachineArchitecture::try_from(request.arch)
        .map_err(|_| Status::invalid_argument("Unknown arch received."))?;
    let pxe_script = PxeInstructions::get_pxe_instructions(&mut txn, interface_id, arch).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(Response::new(rpc::PxeInstructions { pxe_script }))
}

pub(crate) async fn get_cloud_init_instructions(
    api: &Api,
    request: Request<rpc::CloudInitInstructionsRequest>,
) -> Result<Response<rpc::CloudInitInstructions>, Status> {
    log_request_data(&request);
    let cloud_name = "nvidia".to_string();
    let platform = "forge".to_string();

    const DB_TXN_NAME: &str = "get_cloud_init_instructions";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let ip_str = &request.into_inner().ip;
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|e| Status::invalid_argument(format!("Failed parsing IP '{ip_str}': {e}")))?;
    if ip.is_ipv6() {
        return Err(CarbideError::internal("IPv6 not supported".to_string()).into());
    }

    let instructions = match db::instance_address::find_by_address(&mut txn, ip).await? {
        None => {
            // assume there is no instance associated with this IP and check if there is an interface associated with it
            let machine_interface = db::machine_interface::find_by_ip(&mut txn, ip)
                .await?
                .ok_or_else(|| {
                    CarbideError::internal(format!("No machine interface with IP {ip} was found"))
                })?;

            let domain_id = machine_interface.domain_id.ok_or_else(|| {
                CarbideError::internal(format!(
                    "Machine Interface did not have an associated domain {}",
                    machine_interface.id
                ))
            })?;

            let domain = domain::find_by(
                &mut txn,
                ObjectColumnFilter::One(domain::IdColumn, &domain_id),
            )
            .await?
            .first()
            .ok_or_else(|| {
                CarbideError::internal(format!("Could not find a domain for {domain_id}"))
            })?
            .to_owned();

            // This custom pxe is different from a customer instance of pxe. It is more for testing one off
            // changes until a real dev env is established and we can just override our existing code to test
            // It is possible for the user data to be null if we are only trying to test the pxe, and this will
            // follow the same code path and retrieve the non custom user data
            let custom_cloud_init =
                match db::machine_boot_override::find_optional(&mut txn, machine_interface.id)
                    .await?
                {
                    Some(machine_boot_override) => machine_boot_override.custom_user_data,
                    None => None,
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
                    hbn_reps: api
                        .runtime_config
                        .vmaas_config
                        .as_ref()
                        .and_then(|vc| vc.hbn_reps.clone()),
                }),
                metadata,
            }
        }

        Some(instance_address) => {
            let instance = db::instance::find_by_id(&mut txn, instance_address.instance_id)
                .await?
                .ok_or_else(|| {
                    // Note that this isn't a NotFound error since it indicates an
                    // inconsistent data model
                    CarbideError::internal(format!(
                        "Could not find an instance for {}",
                        instance_address.instance_id
                    ))
                })?;

            rpc::CloudInitInstructions {
                custom_cloud_init: instance.config.os.user_data,
                discovery_instructions: None,
                metadata: Some(rpc::CloudInitMetaData {
                    instance_id: instance.id.to_string(),
                    cloud_name,
                    platform,
                }),
            }
        }
    };

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(Response::new(instructions))
}
