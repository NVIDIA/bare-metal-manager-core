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

//! Operator-driven release of the DPF maintenance holds that park DPUs while a
//! changed DPUService waits to roll out.
//!
//! Carbide releases these on its own, but only for idle hosts, and only when the
//! site has left the automatic rollout enabled. Neither is always true: a site
//! can turn it off and drive rollouts by hand, and a host that never reaches
//! `Ready` -- stranded, say, by the very DPUService version the operator is
//! trying to replace -- can never be released automatically at all.
//!
//! This relaxes the host-state requirement and nothing else. Every DPU is still
//! checked against its DPUDeployment before its hold is lifted.

use std::collections::{HashMap, HashSet};

use ::rpc::forge as rpc;
use carbide_machine_controller::dpu_service_sync::{ReleaseOutcome, TenantPolicy, release_hold};
use carbide_uuid::machine::MachineId;
use db::managed_host::load_snapshot;
use model::machine::LoadSnapshotOptions;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine_pending_action::MachinePendingActionActor;
use model::machine_pending_action::MachinePendingActionKind::DpuServiceSync;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

/// Ceiling on machines per release call.
///
/// The automatic path is paced by the state controller's bounded concurrency.
/// A direct RPC has no such bound, and `list | xargs release` would otherwise
/// reconstruct the fleet-wide form this API deliberately omits. Batching stays
/// possible, but only in visible, deliberate chunks.
const MAX_RELEASE_BATCH: usize = 256;

/// Lists what DPF is waiting on: the whole worklist, or one machine's history.
pub(crate) async fn list_pending_dpu_service_syncs(
    api: &Api,
    request: Request<rpc::ListPendingDpuServiceSyncsRequest>,
) -> Result<Response<rpc::ListPendingDpuServiceSyncsResponse>, Status> {
    log_request_data(&request);
    let machine_id = request.get_ref().machine_id;

    let mut txn = api.txn_begin().await?;
    let actions = match machine_id {
        Some(machine_id) => {
            db::machine_pending_action::find_all_for_machine(&mut txn, &machine_id).await?
        }
        None => db::machine_pending_action::find_all_outstanding(&mut txn, DpuServiceSync).await?,
    };

    // One query each for state and tenancy rather than a pair per machine: the
    // worklist is fleet-sized when nothing has been released for a while.
    let machine_ids: Vec<MachineId> = actions.iter().map(|action| action.machine_id).collect();
    let states = machine_states(&mut txn, &machine_ids).await?;
    let instances =
        db::instance::find_by_machine_ids(&mut txn, &machine_ids.iter().collect::<Vec<_>>())
            .await?
            .into_iter()
            .map(|instance| (instance.machine_id, instance.id))
            .collect::<HashMap<_, _>>();
    txn.commit().await?;

    let pending = actions
        .into_iter()
        .map(|action| rpc::PendingDpuServiceSync {
            machine_id: Some(action.machine_id),
            requested_at: Some(action.requested_at.into()),
            state: states
                .get(&action.machine_id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            instance_id: instances.get(&action.machine_id).copied(),
            completed_at: action.completed_at.map(Into::into),
            // Left absent while outstanding. `UpdateInitiator::AdminCli` is zero,
            // so a default here would misreport every waiting machine as
            // operator-completed.
            completed_by: action.completed_by.map(|actor| {
                match actor {
                    MachinePendingActionActor::Automatic => rpc::UpdateInitiator::Automatic,
                    MachinePendingActionActor::AdminCli => rpc::UpdateInitiator::AdminCli,
                }
                .into()
            }),
        })
        .collect();

    Ok(Response::new(rpc::ListPendingDpuServiceSyncsResponse {
        pending,
    }))
}

/// Releases the DPF maintenance hold for the named machines.
pub(crate) async fn release_dpu_service_sync_hold(
    api: &Api,
    request: Request<rpc::ReleaseDpuServiceSyncHoldRequest>,
) -> Result<Response<rpc::ReleaseDpuServiceSyncHoldResponse>, Status> {
    log_request_data(&request);

    let Some(dpf_sdk) = api.dpf_sdk.as_ref() else {
        return Err(CarbideError::InvalidArgument(
            "DPF is not enabled on this nico instance".to_string(),
        )
        .into());
    };

    let (machine_ids, tenant_policy) = resolve_target(api, request.get_ref()).await?;
    validate(api, &machine_ids).await?;

    // One short transaction per machine rather than one spanning the batch. A
    // rollback partway would undo completions for holds that are already gone
    // externally, leaving the release done but the action still saying it is
    // owed -- the one outcome worse than not having released at all.
    let mut results = Vec::with_capacity(machine_ids.len());
    for machine_id in machine_ids {
        let status = release_one(api, dpf_sdk.as_ref(), machine_id, &tenant_policy).await;
        results.push(status);
    }

    Ok(Response::new(rpc::ReleaseDpuServiceSyncHoldResponse {
        results,
    }))
}

/// Turns the request's target into the machines to act on and the tenant policy
/// that applies to them.
async fn resolve_target(
    api: &Api,
    request: &rpc::ReleaseDpuServiceSyncHoldRequest,
) -> Result<(Vec<MachineId>, TenantPolicy), Status> {
    use rpc::release_dpu_service_sync_hold_request::Target;

    match request.target.as_ref() {
        Some(Target::MachineIds(list)) => Ok((
            list.machine_ids.clone(),
            // Naming a machine says nothing about the tenant that may be on it.
            TenantPolicy::RefuseIfAssigned,
        )),
        Some(Target::InstanceId(instance_id)) => {
            let mut txn = api.txn_begin().await?;
            let instance = db::instance::find_by_id(&mut txn, *instance_id)
                .await?
                .ok_or_else(|| CarbideError::NotFoundError {
                    kind: "instance",
                    id: instance_id.to_string(),
                })?;
            txn.commit().await?;

            // Consent is for this instance, not for the host: if it has been
            // reallocated since, the new tenant has agreed to nothing.
            Ok((
                vec![instance.machine_id],
                TenantPolicy::AllowNamedInstance(*instance_id),
            ))
        }
        None => Err(CarbideError::InvalidArgument(
            "a target is required: either machine_ids or instance_id".to_string(),
        )
        .into()),
    }
}

/// Rejects the whole request before anything irreversible happens.
///
/// Releasing is an external action that cannot be undone, so a malformed batch
/// must not release half of itself first. It also keeps `FAILED` meaning
/// "retry": a mistyped machine id is not retryable and would be actively
/// misleading reported that way.
async fn validate(api: &Api, machine_ids: &[MachineId]) -> Result<(), Status> {
    if machine_ids.is_empty() {
        return Err(CarbideError::InvalidArgument("no machines were named".to_string()).into());
    }
    if machine_ids.len() > MAX_RELEASE_BATCH {
        return Err(CarbideError::InvalidArgument(format!(
            "at most {MAX_RELEASE_BATCH} machines may be released per call, got {}",
            machine_ids.len()
        ))
        .into());
    }

    // A DPU id is refused rather than resolved to its host: the hold is per
    // node, so honouring it would quietly widen the request from one DPU to
    // every DPU on that host.
    let dpu_ids: Vec<String> = machine_ids
        .iter()
        .filter(|machine_id| machine_id.machine_type().is_dpu())
        .map(ToString::to_string)
        .collect();
    if !dpu_ids.is_empty() {
        return Err(CarbideError::InvalidArgument(format!(
            "only host ids are expected, got DPU ids: {}",
            dpu_ids.join(", ")
        ))
        .into());
    }

    let mut txn = api.txn_begin().await?;
    let found = db::machine::find(
        &mut txn,
        db::ObjectFilter::List(machine_ids),
        MachineSearchConfig::default(),
    )
    .await?
    .into_iter()
    .map(|machine| machine.id)
    .collect::<HashSet<_>>();
    txn.commit().await?;

    let missing: Vec<String> = machine_ids
        .iter()
        .filter(|machine_id| !found.contains(*machine_id))
        .map(ToString::to_string)
        .collect();
    if !missing.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "machine",
            id: missing.join(", "),
        }
        .into());
    }

    Ok(())
}

/// Releases one host's hold, reporting what happened rather than failing the
/// call: a batch is expected to contain machines that decline for good reasons.
async fn release_one(
    api: &Api,
    dpf_sdk: &dyn carbide_machine_controller::dpf::DpfOperations,
    machine_id: MachineId,
    tenant_policy: &TenantPolicy,
) -> rpc::DpuServiceSyncReleaseResult {
    use rpc::DpuServiceSyncReleaseStatus as ProtoStatus;

    let (status, detail) = match release_one_inner(api, dpf_sdk, machine_id, tenant_policy).await {
        Ok(None) => (ProtoStatus::NotPending, String::new()),
        Ok(Some(ReleaseOutcome::Released)) => (ProtoStatus::Released, String::new()),
        Ok(Some(ReleaseOutcome::DeferredDpuOutdated { dpu })) => (
            ProtoStatus::DeferredDpuOutdated,
            format!("DPU {dpu} does not match its DPUDeployment and awaits reprovisioning"),
        ),
        Ok(Some(ReleaseOutcome::DeferredUnknown { dpu, reason })) => (
            ProtoStatus::DeferredUnknown,
            format!("could not evaluate DPU {dpu}: {reason}"),
        ),
        Ok(Some(ReleaseOutcome::DeferredHostAssigned { instance })) => (
            ProtoStatus::DeferredHostAssigned,
            format!("host is assigned to instance {instance}; name that instance to release it"),
        ),
        Ok(Some(ReleaseOutcome::Failed { reason })) => (ProtoStatus::Failed, reason),
        Err(reason) => (ProtoStatus::Failed, reason),
    };

    rpc::DpuServiceSyncReleaseResult {
        machine_id: Some(machine_id),
        status: status.into(),
        detail,
    }
}

/// `Ok(None)` means nothing was owed for this machine.
async fn release_one_inner(
    api: &Api,
    dpf_sdk: &dyn carbide_machine_controller::dpf::DpfOperations,
    machine_id: MachineId,
    tenant_policy: &TenantPolicy,
) -> Result<Option<ReleaseOutcome>, String> {
    let mut txn = api
        .txn_begin()
        .await
        .map_err(|error| format!("could not begin a transaction: {error}"))?;

    let outstanding =
        db::machine_pending_action::is_outstanding(&mut txn, &machine_id, DpuServiceSync)
            .await
            .map_err(|error| format!("could not read the pending action: {error}"))?;
    if !outstanding {
        return Ok(None);
    }

    let snapshot = load_snapshot(&mut txn, &machine_id, LoadSnapshotOptions::default())
        .await
        .map_err(|error| format!("could not load the machine snapshot: {error}"))?
        .ok_or_else(|| format!("no snapshot for machine {machine_id}"))?;

    let policy = match tenant_policy {
        TenantPolicy::RefuseIfAssigned => TenantPolicy::RefuseIfAssigned,
        TenantPolicy::AllowNamedInstance(instance_id) => {
            TenantPolicy::AllowNamedInstance(*instance_id)
        }
    };

    let outcome = release_hold(
        dpf_sdk,
        &mut txn,
        &snapshot.host_snapshot,
        &snapshot.dpu_snapshots,
        policy,
        MachinePendingActionActor::AdminCli,
    )
    .await;

    txn.commit()
        .await
        .map_err(|error| format!("could not commit the release: {error}"))?;

    Ok(Some(outcome))
}

/// The managed state of each machine, for the worklist's "why is this waiting"
/// column.
async fn machine_states(
    txn: &mut db::Transaction<'_>,
    machine_ids: &[MachineId],
) -> Result<HashMap<MachineId, String>, Status> {
    if machine_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let machines = db::machine::find(
        txn,
        db::ObjectFilter::List(machine_ids),
        MachineSearchConfig::default(),
    )
    .await?;
    Ok(machines
        .into_iter()
        .map(|machine| (machine.id, machine.current_state().to_string()))
        .collect())
}
