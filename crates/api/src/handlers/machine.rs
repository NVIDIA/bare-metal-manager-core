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

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use carbide_uuid::machine::MachineId;
use forge_secrets::credentials::{BmcCredentialType, CredentialKey};
use itertools::Itertools;
use libredfish::SystemPowerControl;
use model::hardware_info::MachineNvLinkInfo;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{LoadSnapshotOptions, Machine, ManagedHostState, ManagedHostStateSnapshot};
use model::metadata::Metadata;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;
use crate::redfish::RedfishAuth;

pub(crate) async fn find_machine_ids(
    api: &Api,
    request: Request<rpc::MachineSearchConfig>,
) -> Result<Response<::rpc::common::MachineIdList>, Status> {
    log_request_data(&request);

    let search_config = request.into_inner().try_into()?;

    let machine_ids =
        db::machine::find_machine_ids(&api.database_connection, search_config).await?;

    Ok(Response::new(::rpc::common::MachineIdList {
        machine_ids: machine_ids.into_iter().collect(),
    }))
}

pub(crate) async fn find_machine_ids_by_bmc_ips(
    api: &Api,
    request: Request<rpc::BmcIpList>,
) -> Result<Response<rpc::MachineIdBmcIpPairs>, Status> {
    log_request_data(&request);

    let pairs = db::machine_topology::find_machine_bmc_pairs(
        &api.database_connection,
        request.into_inner().bmc_ips,
    )
    .await?;
    let rpc_pairs = rpc::MachineIdBmcIpPairs {
        pairs: pairs
            .into_iter()
            .map(|(machine_id, bmc_ip)| rpc::MachineIdBmcIp {
                machine_id: Some(machine_id),
                bmc_ip,
            })
            .collect(),
    };

    Ok(Response::new(rpc_pairs))
}

pub(crate) async fn find_machines_by_ids(
    api: &Api,
    request: Request<::rpc::forge::MachinesByIdsRequest>,
) -> Result<Response<::rpc::MachineList>, Status> {
    log_request_data(&request);
    let request = request.into_inner();

    let mut txn = api.txn_begin().await?;

    let machine_ids = request.machine_ids;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if machine_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if machine_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let snapshots = db::managed_host::load_by_machine_ids(
        &mut txn,
        &machine_ids,
        LoadSnapshotOptions {
            include_history: request.include_history,
            include_instance_data: false,
            host_health_config: api.runtime_config.host_health,
        },
    )
    .await?;

    txn.commit().await?;

    Ok(Response::new(snapshot_map_to_rpc_machines(snapshots)))
}

pub(crate) async fn find_machine_state_histories(
    api: &Api,
    request: Request<rpc::MachineStateHistoriesRequest>,
) -> Result<Response<rpc::MachineStateHistories>, Status> {
    log_request_data(&request);
    let request = request.into_inner();

    let machine_ids = request.machine_ids;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if machine_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if machine_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let mut txn = api.txn_begin().await?;

    let results = db::machine_state_history::find_by_machine_ids(&mut txn, &machine_ids).await?;

    let mut response = rpc::MachineStateHistories::default();
    for (machine_id, records) in results {
        response.histories.insert(
            machine_id.to_string(),
            ::rpc::forge::MachineStateHistoryRecords {
                records: records.into_iter().map(Into::into).collect(),
            },
        );
    }

    txn.commit().await?;

    Ok(Response::new(response))
}

pub(crate) async fn find_machine_health_histories(
    api: &Api,
    request: Request<rpc::MachineHealthHistoriesRequest>,
) -> Result<Response<rpc::MachineHealthHistories>, Status> {
    log_request_data(&request);
    let request = request.into_inner();

    let machine_ids = request.machine_ids;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if machine_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if machine_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let mut txn = api.txn_begin().await?;

    let results = db::machine_health_history::find_by_machine_ids(&mut txn, &machine_ids).await?;

    let mut response = rpc::MachineHealthHistories::default();
    for (machine_id, records) in results {
        response.histories.insert(
            machine_id.to_string(),
            ::rpc::forge::MachineHealthHistoryRecords {
                records: records.into_iter().map(Into::into).collect(),
            },
        );
    }

    txn.commit().await?;

    Ok(Response::new(response))
}

pub(crate) async fn machine_set_auto_update(
    api: &Api,
    request: Request<rpc::MachineSetAutoUpdateRequest>,
) -> Result<Response<rpc::MachineSetAutoUpdateResponse>, Status> {
    log_request_data(&request);

    let request = request.into_inner();

    let mut txn = api.txn_begin().await?;

    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;
    let Some(_machine) =
        db::machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default()).await?
    else {
        return Err(Status::not_found("The machine ID was not found"));
    };

    let state = match request.action() {
        rpc::machine_set_auto_update_request::SetAutoupdateAction::Enable => Some(true),
        rpc::machine_set_auto_update_request::SetAutoupdateAction::Disable => Some(false),
        rpc::machine_set_auto_update_request::SetAutoupdateAction::Clear => None,
    };
    db::machine::set_firmware_autoupdate(&mut txn, &machine_id, state).await?;

    txn.commit().await?;

    Ok(Response::new(rpc::MachineSetAutoUpdateResponse {}))
}

pub(crate) async fn update_machine_metadata(
    api: &Api,
    request: Request<rpc::MachineMetadataUpdateRequest>,
) -> std::result::Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

    // Prepare the metadata
    let metadata = match request.metadata {
        Some(m) => Metadata::try_from(m).map_err(CarbideError::from)?,
        _ => {
            return Err(
                CarbideError::from(RpcDataConversionError::MissingArgument("metadata")).into(),
            );
        }
    };
    metadata.validate(true).map_err(CarbideError::from)?;

    let (machine, mut txn) = api
        .load_machine(
            &machine_id,
            MachineSearchConfig {
                include_dpus: true,
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?;

    let expected_version: config_version::ConfigVersion = match request.if_version_match {
        Some(version) => version.parse().map_err(CarbideError::from)?,
        None => machine.version,
    };

    db::machine::update_metadata(&mut txn, &machine_id, expected_version, metadata).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

pub(crate) async fn admin_force_delete_machine(
    api: &Api,
    request: Request<rpc::AdminForceDeleteMachineRequest>,
) -> Result<Response<rpc::AdminForceDeleteMachineResponse>, Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let query = request.host_query;

    let mut response = rpc::AdminForceDeleteMachineResponse {
        all_done: true,
        ..Default::default()
    };
    // This is the default
    // If we can't delete something in one go - we will reset it
    response.all_done = true;
    response.initial_lockdown_state = "".to_string();
    response.machine_unlocked = false;

    tracing::info!("admin_force_delete_machine query='{query}'");

    let mut txn = api.txn_begin().await?;

    let machine = match db::machine::find_by_query(&mut txn, &query).await? {
        Some(machine) => machine,
        None => {
            // If the machine was already deleted, then there is nothing to do
            // and this is a success
            return Ok(Response::new(response));
        }
    };
    log_machine_id(&machine.id);

    if machine.instance_type_id.is_some() {
        return Err(CarbideError::FailedPrecondition(format!(
            "association with instance type must be removed before deleting machine {}",
            &machine.id
        ))
        .into());
    }

    // TODO: This should maybe just use the snapshot loading functionality that the
    // state controller will use - which already contains the combined state
    let host_machine;
    let dpu_machines;
    if machine.is_dpu() {
        if let Some(host) = db::machine::find_host_by_dpu_machine_id(&mut txn, &machine.id).await? {
            tracing::info!("Found host Machine {:?}", machine.id.to_string());
            // Get all DPUs attached to this host, in case there are more than one.
            dpu_machines = db::machine::find_dpus_by_host_machine_id(&mut txn, &host.id).await?;
            host_machine = Some(host);
        } else {
            host_machine = None;
            dpu_machines = vec![machine];
        }
    } else {
        dpu_machines = db::machine::find_dpus_by_host_machine_id(&mut txn, &machine.id).await?;
        tracing::info!(
            "Found dpu Machines {:?}",
            dpu_machines.iter().map(|m| m.id.to_string()).join(", ")
        );
        host_machine = Some(machine);
    }

    let mut instance_id = None;
    if let Some(host_machine) = &host_machine {
        instance_id = db::instance::find_id_by_machine_id(&mut txn, &host_machine.id).await?;
    }

    if let Some(host_machine) = &host_machine {
        response.managed_host_machine_id = host_machine.id.to_string();
        if let Some(iface) = host_machine.interfaces.first() {
            response.managed_host_machine_interface_id = iface.id.to_string();
        }
        if let Some(ip) = host_machine.bmc_info.ip.as_ref() {
            response.managed_host_bmc_ip = ip.to_string();
        }
    }
    if let Some(dpu_machine) = dpu_machines.first() {
        response.dpu_machine_ids = dpu_machines.iter().map(|m| m.id.to_string()).collect();
        // deprecated field:
        response.dpu_machine_id = dpu_machine.id.to_string();

        let dpu_interfaces = dpu_machines
            .iter()
            .flat_map(|m| m.interfaces.clone())
            .collect::<Vec<_>>();
        if let Some(iface) = dpu_interfaces.first() {
            response.dpu_machine_interface_ids =
                dpu_interfaces.iter().map(|i| i.id.to_string()).collect();
            // deprecated field:
            response.dpu_machine_interface_id = iface.id.to_string();
        }
        if let Some(ip) = dpu_machine.bmc_info.ip.as_ref() {
            response.dpu_bmc_ip = ip.to_string();
        }
    }
    if let Some(instance_id) = &instance_id {
        response.instance_id = instance_id.to_string();
    }

    // So far we only inspected state - now we start the deletion process
    // TODO: In the new model we might just need to move one Machine to this state
    if let Some(host_machine) = &host_machine {
        db::machine::advance(
            host_machine,
            &mut txn,
            &ManagedHostState::ForceDeletion,
            None,
        )
        .await?;
    }
    for dpu_machine in dpu_machines.iter() {
        db::machine::advance(
            dpu_machine,
            &mut txn,
            &ManagedHostState::ForceDeletion,
            None,
        )
        .await?;
    }

    // Commit the transaction to make the the ForceDeletion state visible to other consumers, and to
    // avoid holding a long-running transaction while we issue redfish calls.
    txn.commit().await?;

    // Note: The following deletion steps are all ordered in an idempotent fashion
    if let Some(instance_id) = instance_id {
        crate::handlers::instance::force_delete_instance(instance_id, api, &mut response).await?;
    }

    if let Some(machine) = &host_machine {
        if let Some(ip) = machine.bmc_info.ip.as_deref() {
            if let Some(bmc_mac_address) = machine.bmc_info.mac {
                tracing::info!(
                    ip,
                    machine_id = %machine.id,
                    "BMC IP and MAC address for machine was found. Trying to perform Bios unlock",
                );

                match api
                    .redfish_pool
                    .create_client(
                        ip,
                        machine.bmc_info.port,
                        RedfishAuth::Key(CredentialKey::BmcCredentials {
                            credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
                        }),
                        true,
                    )
                    .await
                {
                    Ok(client) => {
                        let machine_id = machine.id;
                        let mut host_restart_needed = false;
                        match client.lockdown_status().await {
                            Ok(status) if status.is_fully_disabled() => {
                                tracing::info!(%machine_id, "Bios is not locked down");
                                response.initial_lockdown_state = status.to_string();
                                response.machine_unlocked = false;
                            }
                            Ok(status) => {
                                tracing::info!(%machine_id, ?status, "Unlocking BIOS");
                                if let Err(e) =
                                    client.lockdown(libredfish::EnabledDisabled::Disabled).await
                                {
                                    tracing::warn!(%machine_id, error = %e, "Failed to unlock");
                                    response.initial_lockdown_state = status.to_string();
                                    response.machine_unlocked = false;
                                } else {
                                    response.initial_lockdown_state = status.to_string();
                                    response.machine_unlocked = true;
                                }
                                // Dell, at least, needs a reboot after disabling lockdown.  Safest to just do this for everything.
                                host_restart_needed = true;
                            }
                            Err(e) => {
                                tracing::warn!(%machine_id, error = %e, "Failed to fetch lockdown status");
                                response.initial_lockdown_state = "".to_string();
                                response.machine_unlocked = false;
                            }
                        }

                        if machine.bios_password_set_time.is_some() {
                            if let Err(e) = crate::redfish::clear_host_uefi_password(
                                client.as_ref(),
                                api.redfish_pool.clone(),
                            )
                            .await
                            {
                                tracing::warn!(%machine_id, error = %e, "Failed to clear host UEFI password while force deleting machine");
                            }

                            // TODO (spyda): have libredfish return whether the client needs to reboot the host after clearing the host uefi password
                            if machine.bmc_vendor().is_lenovo() {
                                host_restart_needed = true;
                            }
                        }

                        if host_restart_needed
                            && let Err(e) = client.power(SystemPowerControl::ForceRestart).await
                        {
                            tracing::warn!(%machine_id, error = %e, "Failed to reboot host while force deleting machine");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            machine_id = %machine.id,
                            error = %e,
                            "Failed to create Redfish client. Skipping bios unlock",
                        );
                    }
                }
            } else {
                tracing::warn!(
                    "Failed to unlock this host because Forge could not retrieve the BMC MAC address for machine {}",
                    machine.id
                );
            }

            if machine.dpf.enabled || machine.dpf.used_for_ingestion {
                api.kube_client_provider
                    .force_delete_machine(ip, &response.dpu_machine_ids)
                    .await
                    .map_err(CarbideError::DpfError)?;
            }
        } else {
            tracing::warn!(
                "Failed to unlock this host because Forge could not retrieve the BMC IP address for machine {}",
                machine.id
            );
        }
    }

    let mut txn = api.txn_begin().await?;
    let mut machines_to_clear_credentials = Vec::new();

    if let Some(machine) = &host_machine {
        if request.delete_bmc_interfaces
            && let Some(bmc_ip) = &machine.bmc_info.ip
        {
            response.host_bmc_interface_associated = true;
            if let Ok(ip_addr) = IpAddr::from_str(bmc_ip)
                && db::machine_interface::delete_by_ip(&mut txn, ip_addr)
                    .await?
                    .is_some()
            {
                response.host_bmc_interface_deleted = true;
            }
        }
        db::machine::force_cleanup(&mut txn, &machine.id).await?;

        if request.delete_interfaces {
            for interface in &machine.interfaces {
                db::machine_interface::delete(&interface.id, &mut txn).await?;
            }
            response.host_interfaces_deleted = true;
        }

        if let Some(addr) = &machine.bmc_info.ip
            && let Ok(addr) = IpAddr::from_str(addr)
        {
            tracing::info!("Cleaning up explored endpoint at {addr} {}", machine.id);

            db::explored_endpoints::delete(&mut txn, addr).await?;

            db::explored_managed_host::delete_by_host_bmc_addr(&mut txn, addr).await?;
        }

        if request.delete_bmc_credentials {
            machines_to_clear_credentials.push(machine);
        }

        if let Err(e) =
            db::attestation::ek_cert_verification_status::delete_ca_verification_status_by_machine_id(
                &mut txn,
                &machine.id,
            )
            .await
        {
            // just log the error and carry on
            tracing::error!(
                "Could not remove EK cert status for machine with id {}: {}",
                machine.id,
                e
            );
        }
    }

    for dpu_machine in dpu_machines.iter() {
        // Free up all loopback IPs allocated for this DPU.
        db::vpc_dpu_loopback::delete_and_deallocate(
            &api.common_pools,
            &dpu_machine.id,
            &mut txn,
            true,
        )
        .await?;

        if let Some(loopback_ip) = dpu_machine.network_config.loopback_ip {
            db::resource_pool::release(
                &api.common_pools.ethernet.pool_loopback_ip,
                &mut txn,
                loopback_ip,
            )
            .await?
        }

        if let Some(secondary_overlay_vtep_ip) =
            dpu_machine.network_config.secondary_overlay_vtep_ip
        {
            db::resource_pool::release(
                &api.common_pools.ethernet.pool_secondary_vtep_ip,
                &mut txn,
                secondary_overlay_vtep_ip,
            )
            .await
            .map_err(CarbideError::from)?
        }

        db::network_devices::dpu_to_network_device_map::delete(&mut txn, &dpu_machine.id).await?;

        if request.delete_bmc_interfaces
            && let Some(bmc_ip) = &dpu_machine.bmc_info.ip
        {
            response.dpu_bmc_interface_associated = true;
            if let Ok(ip_addr) = IpAddr::from_str(bmc_ip)
                && db::machine_interface::delete_by_ip(&mut txn, ip_addr)
                    .await?
                    .is_some()
            {
                response.dpu_bmc_interface_deleted = true;
            }
        }
        if let Some(asn) = dpu_machine.asn {
            db::resource_pool::release(&api.common_pools.ethernet.pool_fnn_asn, &mut txn, asn)
                .await?;
        }
        db::machine::force_cleanup(&mut txn, &dpu_machine.id).await?;

        if request.delete_interfaces {
            for interface in &dpu_machine.interfaces {
                db::machine_interface::delete(&interface.id, &mut txn).await?;
            }
            response.dpu_interfaces_deleted = true;
        }

        if let Some(addr) = &dpu_machine.bmc_info.ip
            && let Ok(addr) = IpAddr::from_str(addr)
        {
            tracing::info!("Cleaning up explored endpoint at {addr} {}", dpu_machine.id);

            db::explored_endpoints::delete(&mut txn, addr).await?;
        }

        if request.delete_bmc_credentials {
            machines_to_clear_credentials.push(dpu_machine);
        }
    }

    txn.commit().await?;

    // Do BMC operations outside a transaction to avoid long-running transactions
    for machine in machines_to_clear_credentials {
        clear_bmc_credentials(api, machine).await?;
    }

    Ok(Response::new(response))
}

/// Retrieves all DPU information including id and loopback IP
pub(crate) async fn get_dpu_info_list(
    api: &Api,
    request: Request<rpc::GetDpuInfoListRequest>,
) -> Result<Response<rpc::GetDpuInfoListResponse>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let dpu_list = db::machine::find_dpu_ids_and_loopback_ips(&mut txn).await?;

    txn.commit().await?;

    let response = rpc::GetDpuInfoListResponse { dpu_list };
    Ok(Response::new(response))
}

fn snapshot_map_to_rpc_machines(
    snapshots: HashMap<MachineId, ManagedHostStateSnapshot>,
) -> rpc::MachineList {
    let mut result = rpc::MachineList {
        machines: Vec::with_capacity(snapshots.len()),
    };

    for (machine_id, snapshot) in snapshots.into_iter() {
        if let Some(rpc_machine) =
            snapshot.rpc_machine_state(match machine_id.machine_type().is_dpu() {
                true => Some(&machine_id),
                false => None,
            })
        {
            result.machines.push(rpc_machine);
        }
        // A log message for the None case is already emitted inside
        // managed_host::load_by_machine_ids
    }

    result
}

async fn clear_bmc_credentials(api: &Api, machine: &Machine) -> Result<(), CarbideError> {
    if let Some(mac_address) = machine.bmc_info.mac {
        tracing::info!(
            "Cleaning up BMC credentials in vault at {} for machine {}",
            mac_address,
            machine.id
        );
        crate::handlers::credential::delete_bmc_root_credentials_by_mac(api, mac_address).await?;
    }

    Ok(())
}

pub async fn get_machine_position_info(
    api: &Api,
    request: Request<rpc::MachinePositionQuery>,
) -> Result<Response<rpc::MachinePositionInfoList>, Status> {
    let request = request.into_inner();

    if request.machine_ids.is_empty() {
        return Err(CarbideError::InvalidArgument(
            "At least one machine ID must be specified".to_string(),
        )
        .into());
    }
    let mut txn = api.txn_begin().await?;

    // Translate the machine IDs to BMC IPs.
    // Note: Machines without topology records will be silently omitted from the result,
    // consistent with how find_machines_by_ids handles missing machines.
    let pairs =
        db::machine_topology::find_machine_bmc_pairs_by_machine_id(&mut txn, request.machine_ids)
            .await?;

    // Find the explored endpoints for those BMC IPs
    let explored_endpoints = db::explored_endpoints::find_by_ips(
        &mut txn,
        pairs
            .iter()
            .filter_map(|(machine_id, ip_opt)| match ip_opt {
                Some(ip_str) => ip_str.parse().ok().or_else(|| {
                    tracing::warn!(
                        "Failed to parse BMC IP '{}' for machine {}",
                        ip_str,
                        machine_id
                    );
                    None
                }),
                None => {
                    tracing::warn!(
                        "Machine {} has topology but no BMC IP configured",
                        machine_id
                    );
                    None
                }
            })
            .collect(),
    )
    .await?;
    txn.commit().await?;

    // Redo the explored endpoints into a hashmap based on the IP address
    let as_hashmap = explored_endpoints
        .into_iter()
        .map(|x| (x.address.to_string(), x))
        .collect::<HashMap<String, model::site_explorer::ExploredEndpoint>>();

    // Build the response, looking up explored endpoints by BMC IP
    let ret = rpc::MachinePositionInfoList {
        machine_position_info: pairs
            .iter()
            .map(|(machine_id, ip_opt)| {
                let endpoint = ip_opt.as_ref().and_then(|ip| as_hashmap.get(ip));
                rpc::MachinePositionInfo {
                    machine_id: Some(*machine_id),
                    physical_slot_number: endpoint.and_then(|ep| ep.report.physical_slot_number),
                    compute_tray_index: endpoint.and_then(|ep| ep.report.compute_tray_index),
                    topology_id: endpoint.and_then(|ep| ep.report.topology_id),
                    revision_id: endpoint.and_then(|ep| ep.report.revision_id),
                    switch_id: endpoint.and_then(|ep| ep.report.switch_id),
                    power_shelf_id: endpoint.and_then(|ep| ep.report.power_shelf_id),
                }
            })
            .collect(),
    };

    Ok(Response::new(ret))
}

pub(crate) async fn update_machine_nv_link_info(
    api: &Api,
    request: Request<rpc::UpdateMachineNvLinkInfoRequest>,
) -> std::result::Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

    let nvlink_info = request.nvlink_info.ok_or_else(|| {
        CarbideError::from(RpcDataConversionError::MissingArgument("nvlink_info"))
    })?;

    let nvlink_info = MachineNvLinkInfo::try_from(nvlink_info).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    db::machine::update_nvlink_info(&mut txn, &machine_id, nvlink_info).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}
