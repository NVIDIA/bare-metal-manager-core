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

use std::collections::HashSet;
use std::net::IpAddr;

use ::rpc::forge as rpc;
use db;
use model::instance::snapshot::InstanceSnapshot;
use model::machine::MachineInterfaceSnapshot;
use sqlx::PgConnection;

use crate::CarbideError;
use crate::api::Api;

/// What `resolve_client_ip` returned. Either the IP belongs directly
/// to a `machine_interface` (admin / host case), or it belongs to a
/// tenant-allocated `instance_address` (instance case).
#[allow(clippy::large_enum_variant)]
enum ResolvedClient {
    Interface(MachineInterfaceSnapshot),
    Instance(InstanceSnapshot),
}

/// This is a shared two-table lookup that both cloud-init and pxe boot
/// flows use for resolving a client IP . Check `machine_interface_addresses`
/// first (the common admin path), then fall back to `instance_address`.
async fn resolve_client_ip(
    conn: &mut PgConnection,
    client_ip: IpAddr,
) -> Result<ResolvedClient, CarbideError> {
    if let Some(iface) = db::machine_interface::find_by_ip(&mut *conn, client_ip).await? {
        return Ok(ResolvedClient::Interface(iface));
    }

    let instance_address = db::instance_address::find_by_address(&mut *conn, client_ip)
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "Client",
            id: client_ip.to_string(),
        })?;

    let instance = db::instance::find_by_id(&mut *conn, instance_address.instance_id)
        .await?
        .ok_or_else(|| {
            CarbideError::internal(format!(
                "instance_address {client_ip} references missing instance {}",
                instance_address.instance_id,
            ))
        })?;

    Ok(ResolvedClient::Instance(instance))
}

/// Resolve a client IP to the host's `machine_interface` for PXE-script
/// generation. For direct-interface IPs this returns the matching
/// interface; for tenant-allocated IPs it resolves through the instance
/// to the host's machine_interfaces, and prefers an admin-segment one.
pub(crate) async fn resolve_machine_interface(
    conn: &mut PgConnection,
    client_ip: IpAddr,
) -> Result<MachineInterfaceSnapshot, CarbideError> {
    match resolve_client_ip(conn, client_ip).await? {
        ResolvedClient::Interface(iface) => Ok(iface),
        ResolvedClient::Instance(instance) => {
            let interfaces_by_machine =
                db::machine_interface::find_by_machine_ids(&mut *conn, &[instance.machine_id])
                    .await?;
            let host_interfaces =
                interfaces_by_machine
                    .get(&instance.machine_id)
                    .ok_or_else(|| {
                        CarbideError::internal(format!(
                            "no machine_interfaces for host {}",
                            instance.machine_id,
                        ))
                    })?;

            let admin_segment_ids: HashSet<_> = db::network_segment::admin(&mut *conn)
                .await?
                .into_iter()
                .map(|s| s.id)
                .collect();

            host_interfaces
                .iter()
                .find(|i| admin_segment_ids.contains(&i.segment_id))
                .or_else(|| host_interfaces.first())
                .cloned()
                .ok_or_else(|| {
                    CarbideError::internal(format!(
                        "host {} has no machine_interfaces",
                        instance.machine_id,
                    ))
                })
        }
    }
}

/// Resolve a client IP to its `CloudInitInstructions` response. The
/// interface arm produces a discovery-instructions response (for
/// unassigned hosts running scout, etc.); the instance arm produces an
/// instance-specific response with the tenant-provided user_data.
pub(crate) async fn resolve_cloud_init_instructions(
    api: &Api,
    conn: &mut PgConnection,
    client_ip: IpAddr,
) -> Result<rpc::CloudInitInstructions, CarbideError> {
    let cloud_name = "nvidia".to_string();
    let platform = "forge".to_string();

    match resolve_client_ip(conn, client_ip).await? {
        ResolvedClient::Instance(instance) => Ok(rpc::CloudInitInstructions {
            custom_cloud_init: instance.config.os.user_data,
            discovery_instructions: None,
            metadata: Some(rpc::CloudInitMetaData {
                instance_id: instance.id.to_string(),
                cloud_name,
                platform,
            }),
            api_url_override: None,
            pxe_url_override: None,
        }),
        ResolvedClient::Interface(machine_interface) => {
            let domain_id = machine_interface.domain_id.ok_or_else(|| {
                CarbideError::internal(format!(
                    "Machine Interface did not have an associated domain {}",
                    machine_interface.id
                ))
            })?;

            let domain = db::dns::domain::find_by_uuid(&mut *conn, domain_id)
                .await
                .map_err(CarbideError::from)?
                .ok_or_else(|| {
                    CarbideError::internal(format!("Could not find domain with id {domain_id}"))
                })?
                .to_owned();

            // This custom pxe is different from a customer instance of pxe. It is more for testing
            // one off changes until a real dev env is established and we can just override our
            // existing code to test. It is possible for the user data to be null if we are only
            // trying to test the pxe, and this will follow the same code path and retrieve the
            // non custom user data.
            let custom_cloud_init =
                match db::machine_boot_override::find_optional(&mut *conn, machine_interface.id)
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

            // For interfaces on the static-assignments segment, include
            // hostname or IP-based URL overrides so external hosts can
            // reach carbide-api and carbide-pxe services. Just to reiterate,
            // these can be either routable IPs, or externally resolvable
            // hostnames to routable IPs.
            let is_external = machine_interface.segment_id
                == db::network_segment::static_assignments(&mut *conn)
                    .await
                    .map(|s| s.id)
                    .unwrap_or_default();

            let (api_url_override, pxe_url_override) = if is_external {
                (
                    api.runtime_config.external_api_url.clone(),
                    api.runtime_config.external_pxe_url.clone(),
                )
            } else {
                (None, None)
            };

            Ok(rpc::CloudInitInstructions {
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
                    num_of_vfs: Some(api.runtime_config.dpu_config.num_of_vfs),
                }),
                metadata,
                api_url_override,
                pxe_url_override,
            })
        }
    }
}
