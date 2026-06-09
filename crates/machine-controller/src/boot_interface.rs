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
