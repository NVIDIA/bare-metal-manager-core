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
use model::machine::ManagedHostStateSnapshot;

/// Resolve how to target this host's boot interface for Redfish setup calls.
///
/// Uses the host's primary `machine_interface`: when that row has a captured
/// Redfish interface id, the full pair is returned (enabling the MAC-first /
/// interface-id fallback); otherwise it targets the MAC alone. Both come from the
/// same row, so the pair can never name a different interface than the MAC.
///
/// Returns `None` only when the host has no boot interface at all (e.g. only the
/// BMC has been discovered, or the primary NIC hasn't appeared yet).
pub fn boot_interface_target(
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Option<BootInterfaceTarget> {
    if let Some(boot_interface) = mh_snapshot.boot_interface() {
        return Some(BootInterfaceTarget::Pair(boot_interface));
    }
    mh_snapshot
        .boot_interface_mac()
        .map(BootInterfaceTarget::MacOnly)
}

/// What a Redfish boot step should do with a host's boot interface.
///
/// Separates "not ready yet" from "broken". A zero-DPU host (`NoDpu` or
/// `NicMode`) boots from a plain NIC that takes its first HostInband lease only
/// after the host comes up, so until then it has no boot interface to
/// resolve -- the controller should wait, not fail. A host with managed DPUs
/// always has its DPU-facing primary set at promotion, so a missing boot
/// interface there is a genuine fault.
#[derive(Debug)]
pub enum BootInterfaceResolution {
    /// The boot interface resolved; target it.
    Ready(BootInterfaceTarget),
    /// A zero-DPU host whose boot NIC has not been discovered yet -- wait.
    AwaitingNic,
    /// A host that should already have a boot interface is missing one.
    Missing,
}

/// Resolve this host's boot interface for a Redfish boot step, classifying a
/// missing one as either "wait for the NIC" (zero-DPU) or "fault".
pub fn resolve_boot_interface(mh_snapshot: &ManagedHostStateSnapshot) -> BootInterfaceResolution {
    classify_boot_interface(
        boot_interface_target(mh_snapshot),
        mh_snapshot.has_managed_dpus(),
    )
}

/// The decision behind [`resolve_boot_interface`], split out from the snapshot
/// lookup so it can be unit-tested directly.
fn classify_boot_interface(
    boot_interface: Option<BootInterfaceTarget>,
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

    use super::*;

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
        let target = BootInterfaceTarget::MacOnly(MacAddress::new([0, 0, 0, 0, 0, 1]));
        assert!(matches!(
            classify_boot_interface(Some(target), false),
            BootInterfaceResolution::Ready(_)
        ));
    }
}
