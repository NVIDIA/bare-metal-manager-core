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

use ::rpc::forge as rpc;
use db::ObjectFilter;
use db::managed_host::load_snapshot;
use model::machine::LoadSnapshotOptions;
use model::machine::machine_search_config::MachineSearchConfig;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

pub(crate) async fn modify_dpf_state(
    api: &Api,
    request: Request<rpc::ModifyDpfStateRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let request = request.get_ref();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;
    log_machine_id(&machine_id);

    if machine_id.machine_type().is_dpu() {
        return Err(Status::invalid_argument("Only host id is expected!!"));
    }

    let mut txn = api.txn_begin().await?;
    let machine_snapshot = load_snapshot(&mut txn, &machine_id, LoadSnapshotOptions::default())
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "snapshot",
            id: machine_id.to_string(),
        })?;

    db::machine::modify_dpf_state(&mut txn, &machine_id, request.dpf_enabled).await?;

    // Keep DPUs also in sync.
    for dpu in machine_snapshot.dpu_snapshots {
        db::machine::modify_dpf_state(&mut txn, &dpu.id, request.dpf_enabled).await?;
    }
    txn.commit().await?;

    Ok(Response::new(()))
}

// Since this function sends only a bool with ids, we might not need pagination for this.
pub(crate) async fn get_dpf_state(
    api: &Api,
    request: Request<rpc::GetDpfStateRequest>,
) -> Result<Response<rpc::DpfStateResponse>, Status> {
    log_request_data(&request);
    let request = request.get_ref();

    for machine_id in &request.machine_ids {
        if machine_id.machine_type().is_dpu() {
            return Err(Status::invalid_argument("Only host id is expected!!"));
        }
    }

    let mut txn = api.txn_begin().await?;
    let filter = if request.machine_ids.is_empty() {
        ObjectFilter::All
    } else {
        ObjectFilter::List(&request.machine_ids)
    };

    let dpf_states = db::machine::find(&mut txn, filter, MachineSearchConfig::default()).await?;
    txn.commit().await?;

    Ok(Response::new(rpc::DpfStateResponse {
        dpf_states: dpf_states
            .into_iter()
            .map(|machine| machine.into())
            .collect(),
    }))
}
