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

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use ::rpc::forge as rpc;
use model::machine::machine_search_config::MachineSearchConfig;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

// This is a work-around for FORGE-7085.  Due to an issue with interface reporting in the host BMC
// its possible that the primary DPU is not the lowest slot DPU.  Functionally this is not a problem
// but the host names interfaces by pci address so the behavior between machines of the same type
// is different.
//
// this function is broken into the following parts
// 1. collect interface and bmc information
// 2. set the boot device
// 3. update the primary interface and network config versions.
// 4. reboot the host if requested.
//
// No transaction should be held during 2 or 4 since they are requests to the host bmc.
//
pub(crate) async fn set_primary_dpu(
    api: &Api,
    request: Request<rpc::SetPrimaryDpuRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let host_machine_id = request
        .host_machine_id
        .ok_or_else(|| CarbideError::InvalidArgument("Host Machine ID is required".to_string()))?;
    let dpu_machine_id = request
        .dpu_machine_id
        .ok_or_else(|| CarbideError::InvalidArgument("DPU Machine ID is required".to_string()))?;

    log_machine_id(&host_machine_id);

    let mut txn = api.txn_begin().await?;

    let interface_map =
        db::machine_interface::find_by_machine_ids(&mut txn, &[host_machine_id]).await?;

    let interface_snapshots =
        interface_map
            .get(&host_machine_id)
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "Machine",
                id: host_machine_id.to_string(),
            })?;

    // Find the interface id for the old primary dpu and the interface for the new primary dpu.  they have to be found
    // before the db update since the "only one primary" constraint will cause a failure
    // if the new interface is found first.
    let mut current_primary_interface_id = None;
    let mut new_primary_interface = None;

    for interface_snapshot in interface_snapshots {
        if interface_snapshot.primary_interface {
            let Some(attached_dpu_machine_id) = interface_snapshot.attached_dpu_machine_id else {
                return Err(CarbideError::InvalidArgument(
                    "Primary interface is not associated with a DPU.  Operation not supported"
                        .to_string(),
                )
                .into());
            };

            if attached_dpu_machine_id == dpu_machine_id {
                return Err(CarbideError::InvalidArgument(
                    "Requested DPU is already primary".to_string(),
                )
                .into());
            }
            current_primary_interface_id = Some(interface_snapshot.id);
            tracing::info!("Removing primary from {}", attached_dpu_machine_id);
        } else if interface_snapshot.attached_dpu_machine_id == Some(dpu_machine_id) {
            new_primary_interface = Some(interface_snapshot);
            tracing::info!("Setting primary on {}", dpu_machine_id);
        }
    }

    // we need to set the boot device or the host will no longer be able to boot.  we need BMC info.
    // the same BMC info is used if a reboot was requested.
    let machine = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "Machine",
            id: host_machine_id.to_string(),
        })?;

    let bmc_addr_str = machine
        .bmc_info
        .ip
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "BMC IP",
            id: host_machine_id.to_string(),
        })?;

    let bmc_addr = IpAddr::from_str(&bmc_addr_str).map_err(CarbideError::AddressParseError)?;
    let bmc_socket_addr = SocketAddr::new(bmc_addr, 443);

    let bmc_interface = db::machine_interface::find_by_ip(&mut txn, bmc_addr)
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "BMC Interface",
            id: bmc_addr.to_string(),
        })?;

    let primary_interface_mac_address = new_primary_interface
        .ok_or_else(|| {
            CarbideError::internal("Primary interface disappeared during update".to_string())
        })?
        .mac_address
        .to_string();

    txn.rollback().await?;

    let Some(current_primary_interface_id) = current_primary_interface_id else {
        return Err(CarbideError::internal(
            "Could not determing old primary interface id".to_string(),
        )
        .into());
    };
    let Some(new_primary_interface) = new_primary_interface else {
        return Err(CarbideError::internal(
            "Could not determing new primary interface id".to_string(),
        )
        .into());
    };

    // set the boot device
    api.endpoint_explorer
        .set_boot_order_dpu_first(
            bmc_socket_addr,
            &bmc_interface,
            &primary_interface_mac_address,
        )
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    let mut txn = api.txn_begin().await?;

    // update the primary interface
    db::machine_interface::set_primary_interface(&current_primary_interface_id, false, &mut txn)
        .await?;
    db::machine_interface::set_primary_interface(&new_primary_interface.id, true, &mut txn).await?;

    // increment the network config version so that the DPUs pick up their new config
    let (network_config, network_config_version) =
        db::machine::get_network_config(&mut txn, &host_machine_id)
            .await?
            .take();
    db::machine::try_update_network_config(
        &mut txn,
        &host_machine_id,
        network_config_version,
        &network_config,
    )
    .await?;

    // if there is an instance, update the instances network config version so the DPUs pick up the new config
    if let Some(instance) = db::instance::find_by_machine_id(&mut txn, &host_machine_id).await? {
        db::instance::update_network_config(
            &mut txn,
            instance.id,
            instance.network_config_version,
            &instance.config.network,
            true,
        )
        .await?;
    }

    txn.commit().await?;

    // optionally reboot the host.  if there is an instance, this is probably a required step,
    // but an operator will need to make that call.  The scout image handles this pretty well,
    // albeit with a leftover IP on the unused interface
    if request.reboot {
        api.endpoint_explorer
            .redfish_power_control(
                bmc_socket_addr,
                &bmc_interface,
                libredfish::SystemPowerControl::ForceRestart,
            )
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?;
    }
    Ok(Response::new(()))
}

/// Maintenance mode: Put a machine into maintenance mode or take it out.
/// Switching a host into maintenance mode prevents an instance being assigned to it.
#[allow(txn_held_across_await)]
pub(crate) async fn set_maintenance(
    api: &Api,
    request: Request<rpc::MaintenanceRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let machine_id = convert_and_log_machine_id(req.host_id.as_ref())?;

    let (host_machine, mut txn) = api
        .load_machine(&machine_id, MachineSearchConfig::default())
        .await?;
    if host_machine.is_dpu() {
        return Err(Status::invalid_argument(
            "DPU ID provided. Need managed host.",
        ));
    }
    let dpu_machines = db::machine::find_dpus_by_host_machine_id(&mut txn, &machine_id).await?;

    // We set status on both host and dpu machine to make them easier to query from DB
    match req.operation() {
        rpc::MaintenanceOperation::Enable => {
            let Some(reference) = req.reference else {
                return Err(Status::invalid_argument(
                    "Missing reference url".to_string(),
                ));
            };

            let reference = reference.trim().to_string();
            if reference.len() < 5 {
                return Err(Status::invalid_argument(
                    "Provide some valid reference. Minimum expected length is 5.".to_string(),
                ));
            }

            // Maintenance mode is implemented as a host health override
            crate::handlers::health::insert_health_report_override(
                api,
                Request::new(rpc::InsertHealthReportOverrideRequest {
                    machine_id: req.host_id,
                    r#override: Some(::rpc::forge::HealthReportOverride {
                        report: Some(health_report::HealthReport {
                            source: "maintenance".to_string(),
                            observed_at: Some(chrono::Utc::now()),
                            successes: Vec::new(),
                            alerts: vec![health_report::HealthProbeAlert {
                                id: "Maintenance".parse().unwrap(),
                                target: None,
                                in_alert_since: Some(chrono::Utc::now()),
                                message: reference.clone(),
                                tenant_message: None,
                                classifications: vec![
                                    health_report::HealthAlertClassification::prevent_allocations(),
                                    health_report::HealthAlertClassification::suppress_external_alerting(),
                                ],
                            }],
                        }
                                     .into()),
                        mode: ::rpc::forge::OverrideMode::Merge.into(),
                    }),
                }),
            )
                .await?;
        }
        rpc::MaintenanceOperation::Disable => {
            for dpu_machine in dpu_machines.iter() {
                if dpu_machine.reprovision_requested.is_some() {
                    return Err(Status::invalid_argument(format!(
                        "Reprovisioning request is set on DPU: {}. Clear it first.",
                        &dpu_machine.id
                    )));
                }
            }

            match crate::handlers::health::remove_health_report_override(
                api,
                Request::new(rpc::RemoveHealthReportOverrideRequest {
                    machine_id: req.host_id,
                    source: "maintenance".to_string(),
                }),
            )
            .await
            {
                Ok(_) => (),
                Err(status) if status.code() == tonic::Code::NotFound => (),
                Err(status) => return Err(status),
            };
        }
    };

    txn.commit().await?;

    Ok(Response::new(()))
}
