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

use ::rpc::protos::mlx_device as mlx_device_pb;
use carbide_host_support::dpa_cmds::{DpaCommand, OpCode};
use carbide_uuid::machine::MachineId;
use db::dpa_interface;
use eyre::eyre;
use libmlx::device::report::MlxDeviceReport;
use model::dpa_interface::{
    CardState, DpaInterface, DpaInterfaceControllerState, DpaInterfaceNetworkStatusObservation,
    DpaLockMode, NewDpaInterface,
};
use rpc::forge_agent_control_response::forge_agent_control_extra_info::KeyValuePair;
use rpc::forge_agent_control_response::{Action, ForgeAgentControlExtraInfo};
use rpc::protos::mlx_device::MlxDeviceInfo;
use sqlx::PgConnection;
use tonic::{Request, Response, Status};

use crate::api::{Api, log_request_data};
use crate::{CarbideError, CarbideResult};

// This is called from the grpc interface and is mainly for debugging purposes.
pub(crate) async fn create(
    api: &Api,
    request: Request<::rpc::forge::DpaInterfaceCreationRequest>,
) -> Result<Response<::rpc::forge::DpaInterface>, Status> {
    if !api.runtime_config.is_dpa_enabled() {
        return Err(CarbideError::InvalidArgument(
            "CreateDpaInterface cannot be done as dpa_enabled is false".to_string(),
        )
        .into());
    }
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let new_dpa =
        db::dpa_interface::persist(NewDpaInterface::try_from(request.into_inner())?, &mut txn)
            .await?;

    let dpa_out: rpc::forge::DpaInterface = new_dpa.into();

    txn.commit().await?;

    Ok(Response::new(dpa_out))
}

// This is the normal code path. When scout reports a DPA NIC, we call this
// routine to create a dpa_interface object and associate it with the machine.
async fn create_internal(
    api: &Api,
    dpa_info: NewDpaInterface,
) -> CarbideResult<Response<::rpc::forge::DpaInterface>> {
    let mut txn = api.txn_begin().await?;

    let new_dpa = db::dpa_interface::persist(dpa_info, &mut txn).await?;

    let dpa_out: rpc::forge::DpaInterface = new_dpa.into();

    txn.commit().await?;

    tracing::info!("created dpa: {:#?}", dpa_out);

    Ok(Response::new(dpa_out))
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<::rpc::forge::DpaInterfaceDeletionRequest>,
) -> Result<Response<::rpc::forge::DpaInterfaceDeletionResult>, Status> {
    if !api.runtime_config.is_dpa_enabled() {
        return Err(CarbideError::InvalidArgument(
            "DeleteDpaInterface cannot be done as dpa_enabled is false".to_string(),
        )
        .into());
    }
    log_request_data(&request);

    let req = request.into_inner();

    let id = req.id.ok_or(CarbideError::InvalidArgument(
        "at least one ID must be provided to delete dpa interface".to_string(),
    ))?;

    // Prepare our txn to grab the NetworkSecurityGroups from the DB
    let mut txn = api.txn_begin().await?;

    let dpa_ifs_int = db::dpa_interface::find_by_ids(&mut txn, &[id], false).await?;

    let dpa_if_int = match dpa_ifs_int.len() {
        1 => dpa_ifs_int[0].clone(),
        _ => {
            return Err(CarbideError::InvalidArgument(
                "ID could not be used to locate interface".to_string(),
            )
            .into());
        }
    };

    db::dpa_interface::delete(dpa_if_int, &mut txn).await?;

    txn.commit().await?;

    Ok(Response::new(::rpc::forge::DpaInterfaceDeletionResult {}))
}

pub(crate) async fn get_all_ids(
    api: &Api,
    request: Request<()>,
) -> Result<Response<::rpc::forge::DpaInterfaceIdList>, Status> {
    log_request_data(&request);

    let ids = db::dpa_interface::find_ids(&api.database_connection).await?;

    Ok(Response::new(::rpc::forge::DpaInterfaceIdList { ids }))
}

pub(crate) async fn find_dpa_interfaces_by_ids(
    api: &Api,
    request: Request<::rpc::forge::DpaInterfacesByIdsRequest>,
) -> Result<Response<::rpc::forge::DpaInterfaceList>, Status> {
    log_request_data(&request);

    let req = request.into_inner();

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if req.ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be submitted to find_dpa_interfaces_by_ids"
        ))
        .into());
    }

    if req.ids.is_empty() {
        return Err(CarbideError::InvalidArgument(
            "at least one ID must be provided to find_dpa_interfaces_by_ids".to_string(),
        )
        .into());
    }

    // Prepare our txn to grab the NetworkSecurityGroups from the DB
    let mut txn = api.txn_begin().await?;

    let dpa_ifs_int =
        db::dpa_interface::find_by_ids(&mut txn, &req.ids, req.include_history).await?;

    let rpc_dpa_ifs = dpa_ifs_int
        .into_iter()
        .map(|i| i.into())
        .collect::<Vec<rpc::forge::DpaInterface>>();

    // Commit if nothing has gone wrong up to now
    txn.commit().await?;

    Ok(Response::new(rpc::forge::DpaInterfaceList {
        interfaces: rpc_dpa_ifs,
    }))
}

// XXX TODO XXX
// Remove before final commit
// XXX TODO XXX
pub(crate) async fn set_dpa_network_observation_status(
    api: &Api,
    request: Request<::rpc::forge::DpaNetworkObservationSetRequest>,
) -> Result<Response<::rpc::forge::DpaInterface>, Status> {
    log_request_data(&request);

    let req = request.into_inner();

    let id = req.id.ok_or(CarbideError::InvalidArgument(
        "at least one ID must be provided to find_dpa_interfaces_by_ids".to_string(),
    ))?;

    // Prepare our txn to grab the dpa interfaces from the DB
    let mut txn = api.txn_begin().await?;

    let dpa_ifs_int = db::dpa_interface::find_by_ids(&mut txn, &[id], false).await?;

    if dpa_ifs_int.len() != 1 {
        return Err(CarbideError::InvalidArgument(
            "ID could not be used to locate interface".to_string(),
        )
        .into());
    }

    let dpa_if_int = dpa_ifs_int[0].clone();

    let observation = DpaInterfaceNetworkStatusObservation {
        observed_at: chrono::Utc::now(),
        network_config_version: Some(dpa_if_int.network_config.version),
    };

    db::dpa_interface::update_network_observation(&dpa_if_int, &mut txn, &observation).await?;

    txn.commit().await?;

    Ok(Response::new(dpa_if_int.into()))
}

// Scout is asking us what it should do. We found the machine in DpaProvisioning state.
// So look at each DPA interface and make it progress through the statemachine.
// If there is work to be done, we return Action::MlxReport, and ExtraInfo.
// The ExtraInfo is an array of key value pairs. The key will be the pci_name of the
// mlx device to act on. And the value is a DpaCommand structure.
pub(crate) async fn process_scout_req(
    api: &Api,
    txn: &mut PgConnection,
    machine_id: MachineId,
) -> CarbideResult<(Action, Option<ForgeAgentControlExtraInfo>)> {
    if !api.runtime_config.is_dpa_enabled() {
        return Ok((Action::Noop, None));
    }

    let dpa_snapshots = db::dpa_interface::find_by_machine_id(txn, &machine_id).await?;

    if dpa_snapshots.is_empty() {
        tracing::error!(
            "process_scout_req no dpa_snapshots for machine: {:#?}",
            machine_id
        );
        return Ok((Action::Noop, None));
    }

    let mut pair: Vec<KeyValuePair> = Vec::new();

    for sn in &dpa_snapshots {
        let cstate = sn.controller_state.value.clone();
        let dev_name = &sn.pci_name;

        let dpa_cmd = match cstate {
            DpaInterfaceControllerState::Provisioning
            | DpaInterfaceControllerState::Ready
            | DpaInterfaceControllerState::WaitingForSetVNI
            | DpaInterfaceControllerState::Assigned
            | DpaInterfaceControllerState::WaitingForResetVNI => continue,

            DpaInterfaceControllerState::Unlocking => {
                let key = crate::dpa::lockdown::build_supernic_lockdown_key(
                    txn,
                    sn.id,
                    &*api.credential_provider,
                )
                .await
                .map_err(|e| {
                    CarbideError::GenericErrorFromReport(eyre!(
                        "failed to build unlock key for DPA {dev_name}: {e}"
                    ))
                })?;

                tracing::info!("Unlocking DPA {:#?}", dev_name);
                DpaCommand {
                    op: OpCode::Unlock { key },
                }
            }

            DpaInterfaceControllerState::ApplyProfile => {
                let profstr = api.runtime_config.get_dpa_profile("Bluefield3".to_string());
                tracing::info!("Applying profile for DPA {:#?}", dev_name);
                DpaCommand {
                    op: OpCode::ApplyProfile {
                        profile_str: profstr,
                    },
                }
            }

            DpaInterfaceControllerState::Locking => {
                let key = crate::dpa::lockdown::build_supernic_lockdown_key(
                    txn,
                    sn.id,
                    &*api.credential_provider,
                )
                .await
                .map_err(|e| {
                    CarbideError::GenericErrorFromReport(eyre!(
                        "failed to build lock key for DPA {dev_name}: {e}"
                    ))
                })?;

                tracing::info!("Locking DPA {:#?}", dev_name);
                DpaCommand {
                    op: OpCode::Lock { key },
                }
            }
        };

        match serde_json::to_string(&dpa_cmd) {
            Ok(cmdstr) => pair.push(KeyValuePair {
                key: dev_name.clone(),
                value: cmdstr,
            }),
            Err(e) => {
                tracing::info!(
                    "process_scout_req Error encoding DpaCommand {e} for dpa: {:#?}",
                    sn
                );
            }
        }
    }

    let facr = ForgeAgentControlExtraInfo { pair };

    Ok((Action::MlxAction, Some(facr)))
}

// Find the DPA object in the given vector of DPA objects
// which matches the mac address in the device device info
// Just do a linear search for matching mac address given that
// the Vec<DpaInterface> is not expected to be less than a dozen entries.
fn get_dpa_by_mac(devinfo: &MlxDeviceInfo, dpas: Vec<DpaInterface>) -> CarbideResult<DpaInterface> {
    dpas.into_iter()
        .find(|dpa| dpa.mac_address.to_string() == devinfo.base_mac)
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "mac_addr",
            id: devinfo.base_mac.to_string(),
        })
}

// The scout is sending us an mlx observation report. The report will
// consist of a vector of observations, one for each mlx device.
// Based on what is being reported, we update the card_state of the
// corresponding DB entry. This update is noticed by the DPA statecontroller
// and will cause it to advance to the next state.
async fn process_mlx_observation(
    api: &Api,
    request: tonic::Request<mlx_device_pb::PublishMlxObservationReportRequest>,
) -> CarbideResult<()> {
    // Prepare our txn to grab the dpa interfaces from the DB
    let mut txn = api.txn_begin().await?;

    let req = request.into_inner();

    let Some(rep) = req.report else {
        tracing::error!("process_mlx_observation without report req: {:#?}", req);
        return Err(CarbideError::GenericErrorFromReport(eyre!(
            "process_mlx_observation without report req: {:#?}",
            req
        )));
    };

    let Some(mid) = rep.machine_id else {
        tracing::error!(
            "process_mlx_observation without machine_id report: {:#?}",
            rep
        );
        return Err(CarbideError::GenericErrorFromReport(eyre!(
            "process_mlx_observation without machine_id report: {:#?}",
            rep
        )));
    };

    let dpa_snapshots = db::dpa_interface::find_by_machine_id(&mut txn, &mid).await?;

    if dpa_snapshots.is_empty() {
        tracing::error!(
            "process_mlx_observation no dpa snapshots for machine: {:#?}",
            mid
        );
        return Err(CarbideError::GenericErrorFromReport(eyre!(
            "process_mlx_observation no dpa snapshots for machine: {:#?}",
            mid
        )));
    }

    for obs in rep.observations {
        let Some(devinfo) = obs.device_info else {
            tracing::error!(
                "process_mlx_observation no device_info observation: {:#?}",
                obs
            );
            continue;
        };

        let mut dpa = match get_dpa_by_mac(&devinfo, dpa_snapshots.clone()) {
            Ok(dpa) => dpa,
            Err(e) => {
                tracing::error!(
                    "process_mlx_observation dpa not found for device {:#?} error: {:#?}",
                    devinfo,
                    e
                );
                continue;
            }
        };

        let mut cstate = dpa.card_state.unwrap_or(CardState {
            lockmode: None,
            profile: None,
            profile_synced: None,
        });

        if obs.lock_status.is_some() {
            let ls = match DpaLockMode::try_from(obs.lock_status.unwrap()) {
                Ok(ls) => ls,
                Err(e) => {
                    tracing::error!("process_mlx_observation Error from LockStatus::try_from {e}");
                    continue;
                }
            };

            cstate.lockmode = Some(ls);
        }

        if obs.profile_name.is_some() {
            cstate.profile = obs.profile_name;
        }

        if obs.profile_synced.is_some() {
            cstate.profile_synced = obs.profile_synced;
        }

        dpa.card_state = Some(cstate);

        match dpa_interface::update_card_state(&mut txn, dpa.clone()).await {
            Ok(_id) => (),
            Err(e) => {
                tracing::error!("process_mlx_observation update_card_state error: {e}");
            }
        }
    }

    txn.commit().await?;

    Ok(())
}

// Scout is telling Carbide the mlx device configuration in its machine
pub(crate) async fn publish_mlx_device_report(
    api: &Api,
    request: Request<mlx_device_pb::PublishMlxDeviceReportRequest>,
) -> Result<Response<mlx_device_pb::PublishMlxDeviceReportResponse>, Status> {
    // TODO(chet): Integrate this once it's time. For now, just log
    // that a report was received, that we can successfully convert
    // it from an RPC message back to an MlxDeviceReport, and drop it.
    log_request_data(&request);
    let req = request.into_inner();

    if !api.runtime_config.is_dpa_enabled() {
        return Ok(Response::new(
            mlx_device_pb::PublishMlxDeviceReportResponse {},
        ));
    }

    if let Some(report_pb) = req.report {
        let report: MlxDeviceReport = report_pb
            .try_into()
            .map_err(|e: String| Status::internal(e))?;
        tracing::info!(
            "received MlxDeviceReport hostname={} device_count={}",
            report.hostname,
            report.devices.len(),
        );

        // Without a machine_id, we can't create dpa interfaces
        if report.machine_id.is_some() {
            let mut spx_nics: i32 = 0;

            let mid = report.machine_id.unwrap();

            for dev in report.devices {
                // XXX TODO XXX
                // Change this to base device detection using part numbers rather
                // than device description.
                // XXX TODO XXX
                if dev.device_description.is_some() && dev.base_mac.is_some() {
                    let descr = dev.device_description.unwrap();
                    if descr.contains("SuperNIC") {
                        spx_nics += 1;

                        let mac = dev.base_mac.unwrap();
                        let dpa_info = NewDpaInterface {
                            machine_id: mid,
                            mac_address: mac,
                            device_type: dev.device_type,
                            pci_name: dev.pci_name,
                        };

                        match create_internal(api, dpa_info).await {
                            Ok(dpa_out) => {
                                tracing::info!("created dpa: {:#?}", dpa_out);
                            }
                            Err(e) => {
                                tracing::info!("create dpa error: {:#?}", e);
                            }
                        }
                    }
                } else {
                    tracing::warn!("Missing part, device desc or mac: {:#?}", dev);
                }
            }

            tracing::info!(
                "spx nics count: {spx_nics} machine_id: {:#?}",
                report.machine_id
            );
        } else {
            tracing::warn!("MlxDeviceReport without machine_id: {:#?}", report);
        }
    } else {
        tracing::warn!("no embedded MlxDeviceReport published");
    }
    Ok(Response::new(
        mlx_device_pb::PublishMlxDeviceReportResponse {},
    ))
}

// Scout is telling carbide the observed status (locking status, card mode) of the
// mlx devices in its host
pub(crate) async fn publish_mlx_observation_report(
    api: &Api,
    request: Request<mlx_device_pb::PublishMlxObservationReportRequest>,
) -> Result<Response<mlx_device_pb::PublishMlxObservationReportResponse>, Status> {
    log_request_data(&request);

    if !api.runtime_config.is_dpa_enabled() {
        return Ok(Response::new(
            mlx_device_pb::PublishMlxObservationReportResponse {},
        ));
    }

    process_mlx_observation(api, request).await?;

    Ok(Response::new(
        mlx_device_pb::PublishMlxObservationReportResponse {},
    ))
}
