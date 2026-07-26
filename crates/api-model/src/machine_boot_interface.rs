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
/// reported by Redfish. When this complete pair is available, boot-interface
/// callers pass both identifiers to `libredfish` as one `BootInterfaceRef::Pair`;
/// callers without an `interface_id` target the MAC alone. This allows each
/// vendor to use the identifier its implementation expects. Dell uses
/// `interface_id` directly, which keeps the boot interface addressable after a
/// BlueField operating-mode flip removes its MAC from `NetworkDeviceFunctions`,
/// `EthernetInterfaces`, and `NetworkAdapters`.
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

/// The logical boot-interface target NICo asked a Redfish backend to assess for
/// a machine-setup observation.
///
/// Newer endpoint records retain the complete [`MachineBootInterface`] pair.
/// Older records may only have the MAC, which remains a valid selector but
/// must stay distinguishable from a pair. A backend may match with only the
/// identifiers its read path supports -- NvRedfish currently uses the MAC --
/// while this value keeps the `Pair` identity NICo requested. The state
/// controller can therefore compare the logical target with its current target
/// before trusting the associated setup status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum MachineBootInterfaceTarget {
    /// Both the MAC and vendor-native Redfish interface id are known.
    Pair(MachineBootInterface),
    /// Only the MAC is known.
    MacOnly(MacAddress),
}

impl MachineBootInterfaceTarget {
    /// Builds the strongest usable target from an endpoint record.
    ///
    /// A MAC plus a non-empty interface id becomes [`Self::Pair`]. A MAC
    /// without an id remains [`Self::MacOnly`], while an id without a MAC
    /// cannot identify an interface and yields `None`.
    pub fn from_parts(
        mac_address: Option<MacAddress>,
        interface_id: Option<String>,
    ) -> Option<Self> {
        let mac_address = mac_address?;
        Some(match interface_id.none_if_empty() {
            Some(interface_id) => Self::Pair(MachineBootInterface {
                mac_address,
                interface_id,
            }),
            None => Self::MacOnly(mac_address),
        })
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;

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

    #[test]
    fn target_from_parts_preserves_the_available_selector() {
        let mac = MacAddress::new([1, 2, 3, 4, 5, 6]);

        value_scenarios!(run = |(mac_address, interface_id)| {
            MachineBootInterfaceTarget::from_parts(mac_address, interface_id)
        };
            "complete pair" {
                (Some(mac), Some("NIC.Slot.7-1-1".to_string())) =>
                    Some(MachineBootInterfaceTarget::Pair(MachineBootInterface {
                        mac_address: mac,
                        interface_id: "NIC.Slot.7-1-1".to_string(),
                    })),
            }

            "legacy MAC only" {
                (Some(mac), None) => Some(MachineBootInterfaceTarget::MacOnly(mac)),
            }

            "empty interface id is MAC only" {
                (Some(mac), Some(String::new())) =>
                    Some(MachineBootInterfaceTarget::MacOnly(mac)),
            }

            "interface id without MAC" {
                (None, Some("NIC.Slot.7-1-1".to_string())) => None,
            }

            "no target parts" {
                (None, None) => None,
            }
        );
    }
}
