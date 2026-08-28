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

use carbide_uuid::machine::{DpuMachineId, MachineInterfaceId, StableHostMachineId};
use model::machine::ManagedHostState;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine_boot_interface::{
    BootInterfaceSelectionSource, MachineBootInterface, MachineBootInterfaceTarget,
    canonical_redfish_boot_interface_id,
};
use model::network_segment::NetworkSegmentType;

use crate::api::Api;
use crate::{CarbideError, CarbideResult};

/// Identifies a host interface directly or through its attached DPU.
#[derive(Clone, Copy)]
pub(super) enum PrimaryInterfaceSelector {
    /// Selects the host interface with this ID.
    Interface(MachineInterfaceId),
    /// Selects the host interface attached to this DPU.
    Dpu(DpuMachineId),
}

/// Describes work the caller must perform after the primary interface update commits.
pub(super) struct PrimaryInterfaceUpdate {
    /// Whether the machine controller should be woken to reconcile the target.
    pub(super) reconciliation_needed: bool,
}

/// Builds a desired boot target from a MAC address and optional Redfish interface ID.
/// Missing or blank interface IDs use the MAC address by itself.
fn boot_target_for_interface(
    mac_address: mac_address::MacAddress,
    interface_id: Option<String>,
) -> MachineBootInterfaceTarget {
    match interface_id
        .as_deref()
        .and_then(canonical_redfish_boot_interface_id)
    {
        Some(interface_id) => MachineBootInterfaceTarget::Pair(MachineBootInterface {
            mac_address,
            interface_id: interface_id.to_string(),
        }),
        None => MachineBootInterfaceTarget::MacOnly(mac_address),
    }
}

/// Moves the database primary and desired boot target atomically using Site Explorer's shared
/// lock order. Commits before returning; the caller owns controller wakeup and post-commit work.
pub(super) async fn update_primary_interface(
    api: &Api,
    host_machine_id: StableHostMachineId,
    selector: PrimaryInterfaceSelector,
    force_reconcile: bool,
) -> CarbideResult<PrimaryInterfaceUpdate> {
    // Take the Admin lock permit first so excess requests wait without using database connections.
    let _admin_admission = db::machine_interface::admin_lock_admission().await;
    let mut txn = api.txn_begin().await?;

    // Site Explorer takes these locks before it changes interface ownership.
    // Matching that order keeps an operator write from deadlocking discovery.
    db::machine_interface::lock_all_admin_segments(&mut txn).await?;
    let interface_snapshots = db::machine_interface::find_by_machine_id_for_update(
        &mut txn,
        host_machine_id.as_machine_id(),
    )
    .await?;
    let machine = db::machine::find_one(
        &mut txn,
        host_machine_id.as_machine_id(),
        MachineSearchConfig {
            for_update: true,
            ..Default::default()
        },
    )
    .await?
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "Machine",
        id: host_machine_id.to_string(),
    })?;

    let new_primary_interface_id = match selector {
        PrimaryInterfaceSelector::Interface(interface_id) => interface_id,
        PrimaryInterfaceSelector::Dpu(dpu_machine_id) => {
            if !interface_snapshots.iter().any(|interface| {
                interface
                    .attached_dpu_machine_id
                    .is_some_and(|machine_id| machine_id.machine_type().is_dpu())
            }) {
                return Err(CarbideError::FailedPrecondition(format!(
                    "host {host_machine_id} has no DPUs; set-primary-dpu does not apply to zero-DPU hosts"
                )));
            }

            interface_snapshots
                .iter()
                .find(|interface| {
                    interface.attached_dpu_machine_id.as_ref()
                        == Some(dpu_machine_id.as_machine_id())
                })
                .map(|interface| interface.id)
                .ok_or_else(|| {
                    CarbideError::InvalidArgument(format!(
                        "DPU {dpu_machine_id} has no interface on host {host_machine_id}"
                    ))
                })?
        }
    };

    // Keep the current primary's ID and Admin status to clear its flag, preserve its address, and log it.
    let current_primary_interface = interface_snapshots
        .iter()
        .find(|interface| interface.primary_interface);
    let current_primary_interface_id = current_primary_interface.map(|interface| interface.id);
    let current_primary_is_admin = current_primary_interface
        .is_some_and(|interface| interface.network_segment_type == Some(NetworkSegmentType::Admin));

    let new_primary_interface = interface_snapshots
        .iter()
        .find(|interface| interface.id == new_primary_interface_id)
        .ok_or_else(|| {
            CarbideError::InvalidArgument(format!(
                "interface {new_primary_interface_id} not found on host {host_machine_id}"
            ))
        })?;
    let boot_target = boot_target_for_interface(
        new_primary_interface.mac_address,
        new_primary_interface.boot_interface_id.clone(),
    );
    let primary_is_unchanged = new_primary_interface.primary_interface;
    // Selecting the current primary can still record operator intent or
    // refresh its Redfish interface ID. Reject the request only when the
    // complete target and `Operator` source are already recorded. Forced
    // reconciliation still opens a new desired generation.
    let selected_target_is_already_operator = machine
        .config
        .boot_interface_selection
        .is_some_and(|selection| selection.source == BootInterfaceSelectionSource::Operator)
        && machine
            .config
            .desired_boot_interface
            .as_ref()
            .is_some_and(|desired| desired.value == boot_target);
    if primary_is_unchanged && !force_reconcile && selected_target_is_already_operator {
        return Err(CarbideError::InvalidArgument(
            "requested interface is already the operator-selected primary interface".to_string(),
        ));
    }

    // Hosts with DPU-backed Admin interfaces keep their primary on Admin for DHCP/DNS ownership.
    let host_has_dpu_backed_admin_interface = interface_snapshots.iter().any(|interface| {
        interface
            .attached_dpu_machine_id
            .is_some_and(|machine_id| machine_id.machine_type().is_dpu())
            && interface.network_segment_type == Some(NetworkSegmentType::Admin)
    });
    if host_has_dpu_backed_admin_interface
        && new_primary_interface.network_segment_type != Some(NetworkSegmentType::Admin)
    {
        return Err(CarbideError::InvalidArgument(format!(
            "interface {new_primary_interface_id} is not on the admin segment; a \
             DPU-managed host's primary interface must be an admin interface"
        )));
    }

    // Lock the Instance against deletion between this snapshot and its network configuration write.
    let instance =
        db::instance::find_live_by_machine_id_for_update(&mut txn, host_machine_id.as_machine_id())
            .await?;
    let reconciliation_is_pending = machine.pending_boot_interface_config_version().is_some();
    let reconciliation_is_eligible =
        matches!(machine.current_state(), ManagedHostState::Ready) && instance.is_none();

    if !primary_is_unchanged {
        tracing::info!(
            machine_id = %host_machine_id,
            new_primary_interface_id = %new_primary_interface_id,
            previous_primary_interface_id = ?current_primary_interface_id,
            "Moving host primary interface",
        );

        // Preserve the active admin address before moving the primary flag. A
        // host with no current admin primary skips this pass so the write can
        // repair that broken state in the post-move reconciliation below.
        if current_primary_is_admin {
            db::machine_interface::reconcile_admin_addresses_for_host(
                &mut txn,
                host_machine_id.as_machine_id(),
            )
            .await?;
        }

        if let Some(current_primary_interface_id) = current_primary_interface_id {
            db::machine_interface::set_primary_interface(
                &current_primary_interface_id,
                false,
                &mut txn,
            )
            .await?;
        }
        db::machine_interface::set_primary_interface(&new_primary_interface_id, true, &mut txn)
            .await?;
        db::machine_interface::reconcile_admin_addresses_for_host(
            &mut txn,
            host_machine_id.as_machine_id(),
        )
        .await?;

        let (network_config, network_config_version) =
            db::machine::get_network_config(txn.as_pgconn(), host_machine_id.as_machine_id())
                .await?
                .take();
        // The Machine row was locked before this version was read, so another transaction cannot
        // change the version before this update. The update must therefore match one row.
        if !db::machine::try_update_network_config(
            &mut txn,
            host_machine_id.as_machine_id(),
            network_config_version,
            &network_config,
        )
        .await?
        {
            return Err(CarbideError::Internal {
                message: format!(
                    "network configuration update for machine {host_machine_id} returned no row \
                     at version {network_config_version} while the machine record was locked"
                ),
            });
        }

        if let Some(instance) = &instance {
            db::instance::update_network_config(
                &mut txn,
                instance.id,
                instance.network_config_version,
                &instance.config.network,
                true,
            )
            .await?;
        }
    }

    let desired_update = if force_reconcile {
        db::machine_desired_boot_interface::force_set(
            &mut txn,
            host_machine_id.as_host_machine_id(),
            &boot_target,
            BootInterfaceSelectionSource::Operator,
        )
        .await?
    } else {
        db::machine_desired_boot_interface::set(
            &mut txn,
            host_machine_id.as_host_machine_id(),
            &boot_target,
            BootInterfaceSelectionSource::Operator,
        )
        .await?
    };

    txn.commit().await?;

    Ok(PrimaryInterfaceUpdate {
        reconciliation_needed: reconciliation_is_eligible
            && (reconciliation_is_pending || desired_update.desired_changed),
    })
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;

    use super::*;

    #[test]
    fn boot_target_normalizes_interface_ids() {
        let (mac, id) = ("00:00:5e:00:53:02".parse().unwrap(), "NIC.Slot.7-1-1");
        let pair = |interface_id: &str| {
            MachineBootInterfaceTarget::Pair(MachineBootInterface {
                mac_address: mac,
                interface_id: interface_id.to_string(),
            })
        };
        let mac_only = || MachineBootInterfaceTarget::MacOnly(mac);
        value_scenarios!(run = |input: Option<&str>| {
            boot_target_for_interface(mac, input.map(str::to_string))
        };
            "complete" { Some(id) => pair(id), }
            "padded" { Some(" \tNIC.Slot.7-1-1\n ") => pair(id), }
            "blank" { Some("\t\n") => mac_only(), }
            "missing" { None => mac_only(), }
        );
    }
}
