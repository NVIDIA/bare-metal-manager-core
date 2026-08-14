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

//! Releases the DPF maintenance hold for hosts whose DPUs are already running
//! the software their DPUDeployment declares.
//!
//! A DPUService change (helm chart or image version) drives every affected DPU
//! into the NodeEffect phase, where DPF waits for permission to disrupt it.
//! Granting that permission is only correct for a DPU that is otherwise up to
//! date: one still awaiting reprovisioning is about to have its OS replaced, and
//! the new services may not run on the OS currently installed.
//!
//! Scope: this decides *when* a declared service version reaches a DPU, not
//! *whether* that version belongs there. It asks only whether the DPU matches
//! its DPUDeployment, so a deployment that pairs a service version with an
//! incompatible BFB is rolled out faithfully. Keeping those versions coherent is
//! the operator's responsibility, deliberately -- a compatibility check here
//! would also reject the test builds that qualifying a new service depends on.
//!
//! Runs from the `Ready` arm only. `Ready` is not the only state where releasing
//! a hold would be safe -- `HostInit` has provisioned DPUs and no tenant either
//! -- but keeping the automatic path narrow means it can never collide with the
//! DPF states where NICo itself drives DPU operations.
//!
//! The accepted cost is that a host which never reaches `Ready` never receives a
//! service update. That matters most when the update *is* the fix: a DPUService
//! version that breaks host provisioning strands hosts in `HostInit`, and they
//! cannot be repaired by the automatic path. Recovering those is an explicit
//! operator action rather than something this handler infers.

use carbide_dpf::sdk::{dpu_cr_name, dpu_node_cr_name};
use model::machine::{Machine, ManagedHostState, ManagedHostStateSnapshot};
use model::machine_pending_action::MachinePendingActionKind::DpuServiceSync;
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::MachineStateHandlerContextObjects;
use crate::dpf::DpfOperations;

/// Performs the DPU-side work a host owes, recorded as a pending action while
/// the host was busy elsewhere.
///
/// Only [`DpuServiceSync`] exists today: release the maintenance hold once every
/// one of the host's DPUs matches its owning DPUDeployment.
///
/// Always reports [`StateHandlerOutcome::do_nothing`]: this is background work
/// that must never preempt a lifecycle or operator-requested transition, and it
/// drives no state change of its own. Failures are logged rather than returned
/// for the same reason — the pending marker survives, so the next sweep retries.
pub(super) async fn handle_pending_dpu_actions(
    dpf_sdk: Option<&dyn DpfOperations>,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let host = &mh_snapshot.host_snapshot;

    if !ctx.services.site_config.dpu_service_sync_enabled || !host.config.dpf.used_for_ingestion {
        return Ok(StateHandlerOutcome::do_nothing());
    }

    // `used_for_ingestion` does not guarantee the SDK was configured.
    let Some(dpf_sdk) = dpf_sdk else {
        return Ok(StateHandlerOutcome::do_nothing());
    };

    // The marker is what keeps ordinary Ready sweeps off the Kubernetes API:
    // without one, DPF is not waiting on this host and there is nothing to do.
    //
    // A database failure here is logged like every other failure in this
    // function rather than returned. Propagating would abort the rest of Ready's
    // work for the sake of a background task, and the marker survives either way.
    match pending_sync_is_outstanding(ctx, host).await {
        Ok(true) => {}
        Ok(false) => return Ok(StateHandlerOutcome::do_nothing()),
        Err(error) => {
            tracing::warn!(
                machine_id = %host.id,
                %error,
                "Could not read the host's pending DPU actions"
            );
            return Ok(StateHandlerOutcome::do_nothing());
        }
    }

    let Some(node_id) = host.dpf_id() else {
        tracing::warn!(
            machine_id = %host.id,
            "Host has no BMC MAC, so its DPF node cannot be identified"
        );
        return Ok(StateHandlerOutcome::do_nothing());
    };
    let node_name = dpu_node_cr_name(&node_id);

    // "Every DPU is current" is only a reason to release the hold when there is
    // at least one DPU to have checked. An empty snapshot means the host's DPUs
    // could not be resolved, not that they are all up to date, and releasing on
    // it would grant DPF permission having verified nothing.
    if mh_snapshot.dpu_snapshots.is_empty() {
        tracing::warn!(
            machine_id = %host.id,
            "Host has no DPU snapshots, so its DPUs cannot be checked for currency"
        );
        return Ok(StateHandlerOutcome::do_nothing());
    }

    // The hold is per node, so every DPU on the host must be up to date before
    // it is safe to lift. A DPU that is still outdated keeps its reprovision,
    // and this host keeps its marker for a later sweep to retry.
    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
        let Some(device_id) = dpu_snapshot.dpf_id() else {
            tracing::warn!(
                machine_id = %host.id,
                dpu_machine_id = %dpu_snapshot.id,
                "DPU has no BMC MAC, so its DPU CR cannot be identified"
            );
            return Ok(StateHandlerOutcome::do_nothing());
        };

        match dpf_sdk
            .is_dpu_outdated(&dpu_cr_name(&device_id, &node_id))
            .await
        {
            Ok(false) => {}
            Ok(true) => {
                tracing::info!(
                    machine_id = %host.id,
                    dpu_machine_id = %dpu_snapshot.id,
                    "Holding the DPF maintenance hold: DPU still awaits reprovisioning"
                );
                return Ok(StateHandlerOutcome::do_nothing());
            }
            Err(error) => {
                tracing::warn!(
                    machine_id = %host.id,
                    dpu_machine_id = %dpu_snapshot.id,
                    %error,
                    "Could not determine whether the DPU is up to date"
                );
                return Ok(StateHandlerOutcome::do_nothing());
            }
        }
    }

    // The tenant check that let this host through ran against the snapshot the
    // iteration opened with, and the DPU checks since have cost a Kubernetes
    // round trip each. Allocation commits under a row lock this handler does not
    // hold, so an instance can appear in that window.
    //
    // The transitions elsewhere in `Ready` do not need this: they only propose a
    // new state and lose harmlessly to the optimistic-concurrency version check.
    // Releasing a hold is an external action that cannot be taken back, so it
    // re-reads instead. That narrows the window to this query plus the patch
    // rather than closing it; the marker survives, so a host that slips through
    // is caught on the sweep after its instance is gone.
    match host_has_instance(ctx, host).await {
        Ok(false) => {}
        Ok(true) => {
            tracing::info!(
                machine_id = %host.id,
                "Host was assigned while its DPUs were being checked; keeping the hold"
            );
            return Ok(StateHandlerOutcome::do_nothing());
        }
        Err(error) => {
            tracing::warn!(
                machine_id = %host.id,
                %error,
                "Could not confirm the host is still unassigned; keeping the hold"
            );
            return Ok(StateHandlerOutcome::do_nothing());
        }
    }

    if let Err(error) = dpf_sdk.release_maintenance_hold(&node_name).await {
        tracing::warn!(
            machine_id = %host.id,
            node = %node_name,
            %error,
            "Failed to release the DPF maintenance hold for DPU service sync"
        );
        return Ok(StateHandlerOutcome::do_nothing());
    }

    // Only now, after a release that actually succeeded. A DPU already sitting
    // in NodeEffect does not re-enter it, so the watcher will not re-fire; a
    // marker cleared on any other path is a signal lost until a watcher relist.
    //
    // Failing to record the completion is the safe direction: the marker stays
    // outstanding and the next sweep releases an already-released hold, which is
    // a no-op.
    if let Err(error) = complete_pending_sync(ctx, host).await {
        tracing::warn!(
            machine_id = %host.id,
            %error,
            "Released the hold but could not record the action as completed"
        );
        return Ok(StateHandlerOutcome::do_nothing());
    }

    tracing::info!(
        machine_id = %host.id,
        node = %node_name,
        dpu_count = mh_snapshot.dpu_snapshots.len(),
        "Released the DPF maintenance hold so DPU services can roll out"
    );
    Ok(StateHandlerOutcome::do_nothing())
}

/// Whether an instance is currently assigned to this host, read fresh rather
/// than from the iteration's snapshot.
async fn host_has_instance(
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    host: &Machine,
) -> Result<bool, StateHandlerError> {
    let mut conn = ctx.services.db_pool.acquire().await?;
    Ok(db::instance::find_id_by_machine_id(&mut conn, &host.id)
        .await?
        .is_some())
}

async fn pending_sync_is_outstanding(
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    host: &Machine,
) -> Result<bool, StateHandlerError> {
    let mut conn = ctx.services.db_pool.acquire().await?;
    Ok(db::machine_pending_action::is_outstanding(&mut *conn, &host.id, DpuServiceSync).await?)
}

/// Marks this host's pending DPU service sync as done.
///
/// Callable from the DPF provisioning handler as well: releasing a node's hold
/// there satisfies any sync recorded for it, and the watcher cannot tell the two
/// causes apart when it writes the marker.
pub(super) async fn complete_pending_sync(
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    host: &Machine,
) -> Result<bool, StateHandlerError> {
    let mut conn = ctx.services.db_pool.acquire().await?;
    Ok(db::machine_pending_action::complete(&mut conn, &host.id, DpuServiceSync).await?)
}
