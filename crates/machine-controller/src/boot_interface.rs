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
//! Resolving how to target a host's boot interface for Redfish setup calls.

use carbide_redfish::boot_interface::BootInterfaceTarget;
use carbide_uuid::machine::MachineInterfaceId;
use model::machine::{
    BootInterfaceCandidate, MachineInterfaceSnapshot, ManagedHostStateSnapshot,
    pick_boot_interface_candidate,
};
use model::predicted_machine_interface::PredictedMachineInterface;

/// A selected boot-interface target and whether it already has an owned row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBootInterface {
    pub machine_interface_id: Option<MachineInterfaceId>,
    pub target: BootInterfaceTarget,
}

/// Resolve the host's selected boot interface across owned rows and pending
/// predictions.
///
/// The shared candidate picker lets a declared primary prediction outrank an
/// interim owned row until the declared NIC takes its first lease. Otherwise an
/// owned row wins, with a sole non-primary prediction used only when no row is
/// selectable. A captured Redfish interface id completes the target pair; until
/// then the target contains only the selected MAC.
///
/// `machine_interface_id` remains `None` for a prediction, allowing the durable
/// synchronization state to notice first-lease promotion and retarget to the
/// newly owned row.
pub fn resolved_boot_interface(
    mh_snapshot: &ManagedHostStateSnapshot,
    predictions: &[PredictedMachineInterface],
) -> Option<ResolvedBootInterface> {
    resolved_boot_interface_from_stores(&mh_snapshot.host_snapshot.status.interfaces, predictions)
}

/// Resolve from freshly loaded owned rows and predictions.
///
/// Transactional callers use this after locking both stores so first-lease
/// promotion cannot leave them resolving against an older machine snapshot.
pub fn resolved_boot_interface_from_stores(
    interfaces: &[MachineInterfaceSnapshot],
    predictions: &[PredictedMachineInterface],
) -> Option<ResolvedBootInterface> {
    pick_boot_interface_candidate(interfaces, predictions).map(resolved_from_candidate)
}

fn resolved_from_candidate(candidate: BootInterfaceCandidate<'_>) -> ResolvedBootInterface {
    let mac_address = candidate.mac_address();
    ResolvedBootInterface {
        machine_interface_id: candidate.machine_interface_id(),
        target: candidate.boot_interface().map_or(
            BootInterfaceTarget::MacOnly(mac_address),
            BootInterfaceTarget::Pair,
        ),
    }
}

/// Resolve only the Redfish target for callers that do not need to distinguish
/// a pending prediction from an owned interface.
pub fn boot_interface_target(
    mh_snapshot: &ManagedHostStateSnapshot,
    predictions: &[PredictedMachineInterface],
) -> Option<BootInterfaceTarget> {
    resolved_boot_interface(mh_snapshot, predictions).map(|resolved| resolved.target)
}

/// What a Redfish boot step should do with a host's boot interface.
///
/// Separates "not ready yet" from "broken". A zero-DPU host (policy `Ignore` or
/// `Nic`) boots from a plain NIC that takes its first HostInband lease only
/// after the host comes up, so until then it has no boot interface to resolve --
/// the controller should wait, not fail. A host with managed DPUs always has its
/// DPU-facing primary set at promotion, so a missing boot interface there is a
/// configuration fault.
#[derive(Debug)]
pub enum BootInterfaceResolution {
    /// The boot interface resolved; target it.
    Ready(ResolvedBootInterface),
    /// A zero-DPU host with no boot interface yet -- neither a real row nor a
    /// usable prediction -- so wait for its boot NIC to appear.
    AwaitingNic,
    /// A host that should already have a boot interface is missing one.
    Missing,
}

/// Resolve this host's boot interface for a Redfish boot step, classifying a
/// missing one as either "wait for the NIC" (zero-DPU) or "fault".
pub fn resolve_boot_interface(
    mh_snapshot: &ManagedHostStateSnapshot,
    predictions: &[PredictedMachineInterface],
) -> BootInterfaceResolution {
    classify_boot_interface(
        resolved_boot_interface(mh_snapshot, predictions),
        mh_snapshot.has_managed_dpus(),
    )
}

/// The decision behind [`resolve_boot_interface`], split out from the snapshot
/// lookup so it can be unit-tested directly.
fn classify_boot_interface(
    boot_interface: Option<ResolvedBootInterface>,
    has_managed_dpus: bool,
) -> BootInterfaceResolution {
    match boot_interface {
        Some(target) => BootInterfaceResolution::Ready(target),
        None if !has_managed_dpus => BootInterfaceResolution::AwaitingNic,
        None => BootInterfaceResolution::Missing,
    }
}

#[cfg(test)]
mod tests {
    use mac_address::MacAddress;
    use model::machine_boot_interface::MachineBootInterface;
    use model::network_segment::NetworkSegmentType;

    use super::*;

    fn prediction(mac: &str, boot_interface_id: Option<&str>) -> PredictedMachineInterface {
        PredictedMachineInterface {
            id: uuid::Uuid::nil(),
            machine_id: "fm100ds7blqjsadm2uuh3qqbf1h7k8pmf47um6v9uckrg7l03po8mhqgvng"
                .parse()
                .unwrap(),
            mac_address: mac.parse().unwrap(),
            expected_network_segment_type: NetworkSegmentType::HostInband,
            boot_interface_id: boot_interface_id.map(String::from),
            primary_interface: false,
        }
    }

    #[test]
    fn predicted_pair_keeps_its_pending_row_identity() {
        let prediction = prediction("20:00:00:00:00:01", Some("NIC.Embedded.1-1-1"));
        assert_eq!(
            resolved_from_candidate(BootInterfaceCandidate::Prediction(&prediction)),
            ResolvedBootInterface {
                machine_interface_id: None,
                target: BootInterfaceTarget::Pair(MachineBootInterface {
                    mac_address: "20:00:00:00:00:01".parse().unwrap(),
                    interface_id: "NIC.Embedded.1-1-1".to_string(),
                }),
            },
        );
    }

    #[test]
    fn prediction_without_an_id_targets_only_its_mac() {
        let prediction = prediction("20:00:00:00:00:01", None);
        assert_eq!(
            resolved_from_candidate(BootInterfaceCandidate::Prediction(&prediction)),
            ResolvedBootInterface {
                machine_interface_id: None,
                target: BootInterfaceTarget::MacOnly("20:00:00:00:00:01".parse().unwrap(),),
            },
        );
    }

    #[test]
    fn classify_waits_for_a_zero_dpu_host_without_a_boot_interface() {
        // The zero-DPU host's boot NIC has not taken its first lease yet: wait
        // for it instead of faulting.
        assert!(matches!(
            classify_boot_interface(None, false),
            BootInterfaceResolution::AwaitingNic
        ));
    }

    #[test]
    fn classify_faults_when_a_dpu_host_has_no_boot_interface() {
        // A host with managed DPUs always has its DPU-facing primary set at
        // promotion, so a missing boot interface is a real fault.
        assert!(matches!(
            classify_boot_interface(None, true),
            BootInterfaceResolution::Missing
        ));
    }

    #[test]
    fn classify_uses_the_resolved_interface_when_present() {
        let target = ResolvedBootInterface {
            machine_interface_id: None,
            target: BootInterfaceTarget::MacOnly(MacAddress::new([0, 0, 0, 0, 0, 1])),
        };
        assert!(matches!(
            classify_boot_interface(Some(target), false),
            BootInterfaceResolution::Ready(_)
        ));
    }
}
