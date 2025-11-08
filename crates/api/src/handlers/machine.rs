/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;

use ::rpc::forge as rpc;
use forge_uuid::machine::MachineId;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{LoadSnapshotOptions, ManagedHostStateSnapshot};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

pub(crate) async fn get_machine(
    api: &Api,
    request: Request<MachineId>,
) -> Result<Response<rpc::Machine>, Status> {
    log_request_data(&request);
    let machine_id = convert_and_log_machine_id(Some(&request.into_inner()))?;

    let mut txn = api.txn_begin("get_machine").await?;

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &machine_id,
        LoadSnapshotOptions {
            include_history: true,
            include_instance_data: false,
            host_health_config: api.runtime_config.host_health,
        },
    )
    .await?
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    txn.commit().await?;

    let rpc_machine = snapshot
        .rpc_machine_state(match machine_id.machine_type().is_dpu() {
            true => Some(&machine_id),
            false => None,
        })
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "machine",
            id: machine_id.to_string(),
        })?;
    Ok(Response::new(rpc_machine))
}

pub(crate) async fn find_machine_ids(
    api: &Api,
    request: Request<rpc::MachineSearchConfig>,
) -> Result<Response<::rpc::common::MachineIdList>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin("find_machines").await?;

    let search_config = request.into_inner().try_into()?;

    let machine_ids = db::machine::find_machine_ids(&mut txn, search_config).await?;

    Ok(Response::new(::rpc::common::MachineIdList {
        machine_ids: machine_ids.into_iter().collect(),
    }))
}

pub(crate) async fn find_machines_by_ids(
    api: &Api,
    request: Request<::rpc::forge::MachinesByIdsRequest>,
) -> Result<Response<::rpc::MachineList>, Status> {
    log_request_data(&request);
    let request = request.into_inner();

    let mut txn = api.txn_begin("find_machines_by_ids").await?;

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

    let mut txn = api.txn_begin("find_machine_state_histories").await?;

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

    let mut txn = api.txn_begin("find_machine_health_histories").await?;

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

pub(crate) async fn find_machines(
    api: &Api,
    request: Request<rpc::MachineSearchQuery>,
) -> Result<Response<rpc::MachineList>, Status> {
    log_request_data(&request);
    let request = request.into_inner();

    let mut txn = api.txn_begin("find_machines").await?;

    let search_config = request
        .search_config
        .map(MachineSearchConfig::try_from)
        .transpose()
        .map_err(CarbideError::from)?
        .unwrap_or_default();

    let machine_ids: Vec<MachineId> = match (request.id, request.fqdn) {
        (Some(id), _) => {
            let machine_id = convert_and_log_machine_id(Some(&id))?;
            vec![machine_id]
        }
        (None, Some(fqdn)) => match db::machine::find_id_by_fqdn(&mut txn, &fqdn).await? {
            Some(id) => vec![id],
            None => vec![],
        },
        (None, None) => db::machine::find_machine_ids(&mut txn, search_config.clone()).await?,
    };

    let snapshots = db::managed_host::load_by_machine_ids(
        &mut txn,
        &machine_ids,
        LoadSnapshotOptions {
            include_history: search_config.include_history,
            include_instance_data: false,
            host_health_config: api.runtime_config.host_health,
        },
    )
    .await?;

    txn.commit().await?;

    Ok(Response::new(snapshot_map_to_rpc_machines(snapshots)))
}

pub(crate) async fn machine_set_auto_update(
    api: &Api,
    request: Request<rpc::MachineSetAutoUpdateRequest>,
) -> Result<Response<rpc::MachineSetAutoUpdateResponse>, Status> {
    log_request_data(&request);

    let request = request.into_inner();

    let mut txn = api.txn_begin("machine_set_auto_update").await?;

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
