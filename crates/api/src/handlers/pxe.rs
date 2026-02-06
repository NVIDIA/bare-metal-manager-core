/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::net::IpAddr;

use ::rpc::forge as rpc;
use db;
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

    let mut txn = api.txn_begin().await?;

    let request = request.into_inner().try_into()?;

    let pxe_script = PxeInstructions::get_pxe_instructions(&mut txn, request).await?;

    txn.commit().await?;

    Ok(Response::new(rpc::PxeInstructions { pxe_script }))
}

pub(crate) async fn get_cloud_init_instructions(
    api: &Api,
    request: Request<rpc::CloudInitInstructionsRequest>,
) -> Result<Response<rpc::CloudInitInstructions>, Status> {
    log_request_data(&request);
    let cloud_name = "nvidia".to_string();
    let platform = "forge".to_string();

    let mut txn = api.txn_begin().await?;

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

            let domain = db::dns::domain::find_by_uuid(&mut txn, domain_id)
                .await
                .map_err(CarbideError::from)?
                .ok_or_else(|| {
                    CarbideError::internal(format!("Could not find domain with id {domain_id}"))
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
                    domain: Some(rpc::PxeDomain {
                        domain: Some(rpc::pxe_domain::Domain::NewDomain(domain.into())),
                    }),
                    hbn_reps: api
                        .runtime_config
                        .vmaas_config
                        .as_ref()
                        .and_then(|vc| vc.hbn_reps.clone()),
                    hbn_sfs: api
                        .runtime_config
                        .vmaas_config
                        .as_ref()
                        .and_then(|vc| vc.hbn_sfs.clone()),
                    vf_intercept_bridge_name: api.runtime_config.vmaas_config.as_ref().and_then(
                        |vc| {
                            vc.bridging
                                .as_ref()
                                .map(|b| b.vf_intercept_bridge_name.clone())
                        },
                    ),
                    host_intercept_bridge_name: api.runtime_config.vmaas_config.as_ref().and_then(
                        |vc| {
                            vc.bridging
                                .as_ref()
                                .map(|b| b.host_intercept_bridge_name.clone())
                        },
                    ),
                    host_intercept_bridge_port: api.runtime_config.vmaas_config.as_ref().and_then(
                        |vc| {
                            vc.bridging
                                .as_ref()
                                .map(|b| b.host_intercept_bridge_port.clone())
                        },
                    ),
                    vf_intercept_bridge_port: api.runtime_config.vmaas_config.as_ref().and_then(
                        |vc| {
                            vc.bridging
                                .as_ref()
                                .map(|b| b.vf_intercept_bridge_port.clone())
                        },
                    ),
                    vf_intercept_bridge_sf: api.runtime_config.vmaas_config.as_ref().and_then(
                        |vc| {
                            vc.bridging
                                .as_ref()
                                .map(|b| b.vf_intercept_bridge_sf.clone())
                        },
                    ),
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

    txn.commit().await?;

    Ok(Response::new(instructions))
}
