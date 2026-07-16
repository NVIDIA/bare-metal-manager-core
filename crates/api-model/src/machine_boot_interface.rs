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
use carbide_utils::none_if_empty::NoneIfEmpty;
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

/// A host's boot interface, identified by *both* its MAC address and its
/// vendor-native Redfish `EthernetInterface.Id`.
///
/// Both fields are always present: a `MachineBootInterface` is only ever
/// constructed from a fully-populated pair, captured while the MAC was still
/// reported by Redfish. Carrying both identifiers is what makes boot-interface
/// operations resilient -- callers target the MAC first and fall back to the
/// [stable] `interface_id`, so the boot interface stays addressable even if one
/// identifier becomes unavailable. That happens, for example, after a DPU
/// `DpuMode` -> `NicMode` flip: some vendor BIOSes stop probing the adapter and
/// the MAC drops out of `NetworkDeviceFunctions` / `EthernetInterfaces` /
/// `NetworkAdapters`, leaving the `interface_id` as the reliable handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MachineBootInterface {
    /// MAC address of the boot interface.
    pub mac_address: MacAddress,
    /// Vendor-native Redfish `EthernetInterface.Id` of the boot interface
    /// (e.g. `"NIC.Slot.7-1-1"`).
    pub interface_id: String,
}

impl MachineBootInterface {
    /// Builds a `MachineBootInterface` from the optional `(mac, interface_id)`
    /// parts of a record, returning `Some` only when *both* are present and the
    /// interface id is non-empty.
    ///
    /// This is the single place the "only retain a fully-populated boot
    /// interface" rule is enforced: a partial pair (a missing MAC, or a missing
    /// or empty interface id) yields `None`, so callers keep the last-known-good
    /// record rather than persisting a half-empty one.
    pub fn from_parts(
        mac_address: Option<MacAddress>,
        interface_id: Option<String>,
    ) -> Option<Self> {
        Some(Self {
            mac_address: mac_address?,
            interface_id: interface_id.none_if_empty()?,
        })
    }

    /// [`Self::from_parts`] for records whose MAC is always present (interface
    /// rows, predictions): only the interface id can be missing.
    pub fn for_mac(mac_address: MacAddress, interface_id: Option<String>) -> Option<Self> {
        Self::from_parts(Some(mac_address), interface_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_parts_requires_both() {
        let mac = MacAddress::new([1, 2, 3, 4, 5, 6]);

        assert_eq!(
            MachineBootInterface::from_parts(Some(mac), Some("NIC.Slot.7-1-1".to_string())),
            Some(MachineBootInterface {
                mac_address: mac,
                interface_id: "NIC.Slot.7-1-1".to_string(),
            })
        );
        assert_eq!(
            MachineBootInterface::from_parts(Some(mac), None),
            None,
            "a present MAC with no interface id is not fully populated"
        );
        assert_eq!(
            MachineBootInterface::from_parts(Some(mac), Some(String::new())),
            None,
            "a present MAC with an empty interface id is not fully populated"
        );
        assert_eq!(
            MachineBootInterface::from_parts(None, Some("NIC.Slot.7-1-1".to_string())),
            None,
            "an interface id with no MAC is not fully populated"
        );
        assert_eq!(MachineBootInterface::from_parts(None, None), None);
    }
}
