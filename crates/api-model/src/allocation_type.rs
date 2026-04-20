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

use serde::{Deserialize, Serialize};

use crate::address_selection_strategy::AddressSelectionStrategy;

/// Distinguishes how an IP address was allocated to a machine interface,
/// and are generally derived from the AddressSelectionStrategy used.
///
/// - `Dhcp`: These addresses allocated and managed by carbide-dhcp,
///   or a DHCP service that integrates directly with carbide-api.
/// - `Static`: These addresses are assigned and managed explicitly by
///   an operator or operator-provided configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AllocationType {
    Dhcp,
    Static,
}

/// The result of assigning a static address, indicating what
/// previously existed for that address family on the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignStaticResult {
    /// No prior address existed for this family.
    Assigned,
    /// An existing static address was replaced.
    ReplacedStatic,
    /// An existing DHCP allocation was replaced.
    ///
    /// If you "replace" a DHCP allocation with the same address
    /// (effectively making a static DHCP  reservation), then it's
    /// basically a no-op.
    ///
    /// If you replace a DHCP allocation with a static address that
    /// is within a Carbide-managed network, then the next time the
    /// machine renews its lease, carbide-dhcp -> carbide-api will
    /// flow, and carbide-api will see the new IP and naturally
    /// return it. MOST DHCP clients will accept this new IP and
    /// reconfigure. SOME DHCP clients will see this is NOT their
    /// original offer, and re-DHCPDISCOVER, at which point the
    /// carbide-dhcp -> carbide-api flow will naturally return
    /// the static reservation anyway. It will be a small hiccup
    /// in a sense, but the client will never lose it's address,
    /// and will just re-discover to the same address.
    ///
    /// If you replace a DHCP allocation with a static address that
    /// is OUTSIDE a Carbide-managed network, then we will now assume
    /// that device is where you say it is. But it's important to
    /// understand a bit of a nuance, as soon as that previous DHCP
    /// allocation is deleted, it is eligible for re-assignment,
    /// meaning if your device is still holding onto that IP (before
    /// it's next renewal), there will potentially be a period of time
    /// where there are duplicate IP conflicts. We can definitely
    /// do some work to make sure these things are mitigated, but
    /// I also think replacing DHCP -> static reservations comes
    /// with some "use at your own risk" in general. We can improve
    /// on it if needed.
    ReplacedDhcp,
}

impl From<AssignStaticResult> for rpc::forge::AssignStaticAddressStatus {
    fn from(result: AssignStaticResult) -> Self {
        match result {
            AssignStaticResult::Assigned => rpc::forge::AssignStaticAddressStatus::Assigned,
            AssignStaticResult::ReplacedStatic => {
                rpc::forge::AssignStaticAddressStatus::ReplacedStatic
            }
            AssignStaticResult::ReplacedDhcp => rpc::forge::AssignStaticAddressStatus::ReplacedDhcp,
        }
    }
}

impl From<AddressSelectionStrategy> for AllocationType {
    fn from(strategy: AddressSelectionStrategy) -> Self {
        match strategy {
            AddressSelectionStrategy::NextAvailableIp => AllocationType::Dhcp,
            AddressSelectionStrategy::Automatic => AllocationType::Dhcp,
            AddressSelectionStrategy::NextAvailablePrefix(_) => AllocationType::Dhcp,
            AddressSelectionStrategy::StaticAddress(_) => AllocationType::Static,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn next_available_ip_is_dhcp() {
        assert_eq!(
            AllocationType::from(AddressSelectionStrategy::NextAvailableIp),
            AllocationType::Dhcp,
        );
    }

    #[test]
    fn automatic_is_dhcp() {
        assert_eq!(
            AllocationType::from(AddressSelectionStrategy::Automatic),
            AllocationType::Dhcp,
        );
    }

    #[test]
    fn next_available_prefix_is_dhcp() {
        assert_eq!(
            AllocationType::from(AddressSelectionStrategy::NextAvailablePrefix(30)),
            AllocationType::Dhcp,
        );
    }

    #[test]
    fn static_address_is_static() {
        assert_eq!(
            AllocationType::from(AddressSelectionStrategy::StaticAddress(
                Ipv4Addr::new(10, 0, 0, 1).into()
            )),
            AllocationType::Static,
        );
    }

    #[test]
    fn serde_roundtrip() {
        let dhcp: AllocationType = serde_json::from_str(r#""dhcp""#).unwrap();
        assert_eq!(dhcp, AllocationType::Dhcp);

        let static_: AllocationType = serde_json::from_str(r#""static""#).unwrap();
        assert_eq!(static_, AllocationType::Static);

        assert_eq!(
            serde_json::to_string(&AllocationType::Dhcp).unwrap(),
            r#""dhcp""#
        );
        assert_eq!(
            serde_json::to_string(&AllocationType::Static).unwrap(),
            r#""static""#
        );
    }
}
