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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use super::*;
    use crate::address_selection_strategy::AddressSelectionStrategy;

    // Total `From<AddressSelectionStrategy>` conversions: every strategy maps to an
    // allocation type. The conversion is infallible, so each row is a plain value
    // checked with `check_values`. Strategies that carry data are exercised across
    // boundary payloads (prefix length extremes, IPv4 vs IPv6 static addresses) to
    // confirm the discriminant alone — not the payload — drives the result.
    #[test]
    fn strategy_maps_to_allocation_type() {
        check_values(
            [
                Check {
                    scenario: "next available ip -> dhcp",
                    input: AddressSelectionStrategy::NextAvailableIp,
                    expect: AllocationType::Dhcp,
                },
                Check {
                    scenario: "automatic alias -> dhcp",
                    input: AddressSelectionStrategy::Automatic,
                    expect: AllocationType::Dhcp,
                },
                Check {
                    scenario: "next available prefix /30 -> dhcp",
                    input: AddressSelectionStrategy::NextAvailablePrefix(30),
                    expect: AllocationType::Dhcp,
                },
                Check {
                    scenario: "next available prefix /0 (boundary low) -> dhcp",
                    input: AddressSelectionStrategy::NextAvailablePrefix(0),
                    expect: AllocationType::Dhcp,
                },
                Check {
                    scenario: "next available prefix /32 -> dhcp",
                    input: AddressSelectionStrategy::NextAvailablePrefix(32),
                    expect: AllocationType::Dhcp,
                },
                Check {
                    scenario: "next available prefix /128 -> dhcp",
                    input: AddressSelectionStrategy::NextAvailablePrefix(128),
                    expect: AllocationType::Dhcp,
                },
                Check {
                    scenario: "next available prefix /255 (boundary high) -> dhcp",
                    input: AddressSelectionStrategy::NextAvailablePrefix(u8::MAX),
                    expect: AllocationType::Dhcp,
                },
                Check {
                    scenario: "static ipv4 -> static",
                    input: AddressSelectionStrategy::StaticAddress(
                        Ipv4Addr::new(10, 0, 0, 1).into(),
                    ),
                    expect: AllocationType::Static,
                },
                Check {
                    scenario: "static ipv4 unspecified (0.0.0.0) -> static",
                    input: AddressSelectionStrategy::StaticAddress(Ipv4Addr::UNSPECIFIED.into()),
                    expect: AllocationType::Static,
                },
                Check {
                    scenario: "static ipv4 broadcast (255.255.255.255) -> static",
                    input: AddressSelectionStrategy::StaticAddress(Ipv4Addr::BROADCAST.into()),
                    expect: AllocationType::Static,
                },
                Check {
                    scenario: "static ipv6 -> static",
                    input: AddressSelectionStrategy::StaticAddress(
                        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).into(),
                    ),
                    expect: AllocationType::Static,
                },
                Check {
                    scenario: "static ipv6 unspecified (::) -> static",
                    input: AddressSelectionStrategy::StaticAddress(Ipv6Addr::UNSPECIFIED.into()),
                    expect: AllocationType::Static,
                },
                Check {
                    scenario: "static ipv6 localhost (::1) -> static",
                    input: AddressSelectionStrategy::StaticAddress(Ipv6Addr::LOCALHOST.into()),
                    expect: AllocationType::Static,
                },
            ],
            AllocationType::from,
        );
    }

    // Serialization: each `AllocationType` variant renders to its snake_case wire
    // form. Total operation, so the produced string is checked directly.
    #[test]
    fn serializes_to_snake_case() {
        check_values(
            [
                Check {
                    scenario: "dhcp",
                    input: AllocationType::Dhcp,
                    expect: r#""dhcp""#.to_string(),
                },
                Check {
                    scenario: "static",
                    input: AllocationType::Static,
                    expect: r#""static""#.to_string(),
                },
            ],
            |value| serde_json::to_string(&value).expect("serialization is infallible"),
        );
    }

    // JSON round-trip: serialize each variant and deserialize it back, asserting
    // both the wire form and that it survives the trip. The closure returns the
    // wire string plus the recovered value so each row pins down both directions.
    #[test]
    fn serde_roundtrip() {
        check_cases(
            [
                Case {
                    scenario: "dhcp",
                    input: AllocationType::Dhcp,
                    expect: Yields((r#""dhcp""#.to_string(), AllocationType::Dhcp)),
                },
                Case {
                    scenario: "static",
                    input: AllocationType::Static,
                    expect: Yields((r#""static""#.to_string(), AllocationType::Static)),
                },
            ],
            // serialize, then deserialize the wire form back into a value
            |value| {
                let wire = serde_json::to_string(&value).map_err(drop)?;
                let recovered: AllocationType = serde_json::from_str(&wire).map_err(drop)?;
                Ok::<_, ()>((wire, recovered))
            },
        );
    }

    // Deserialization from the wire: accepted snake_case forms recover their
    // variant; anything else (wrong case, unknown tag, wrong JSON type, malformed)
    // is rejected. `serde_json::Error` is not `PartialEq`, so failures use `Fails`
    // with `.map_err(drop)`.
    #[test]
    fn deserializes_known_forms_and_rejects_the_rest() {
        check_cases(
            [
                Case {
                    scenario: "dhcp",
                    input: r#""dhcp""#,
                    expect: Yields(AllocationType::Dhcp),
                },
                Case {
                    scenario: "static",
                    input: r#""static""#,
                    expect: Yields(AllocationType::Static),
                },
                Case {
                    scenario: "wrong case rejected",
                    input: r#""Dhcp""#,
                    expect: Fails,
                },
                Case {
                    scenario: "uppercase rejected",
                    input: r#""STATIC""#,
                    expect: Fails,
                },
                Case {
                    scenario: "unknown variant rejected",
                    input: r#""bootp""#,
                    expect: Fails,
                },
                Case {
                    scenario: "empty string rejected",
                    input: r#""""#,
                    expect: Fails,
                },
                Case {
                    scenario: "leading whitespace in tag rejected",
                    input: r#"" dhcp""#,
                    expect: Fails,
                },
                Case {
                    scenario: "number rejected",
                    input: "0",
                    expect: Fails,
                },
                Case {
                    scenario: "null rejected",
                    input: "null",
                    expect: Fails,
                },
                Case {
                    scenario: "object rejected",
                    input: r#"{"dhcp":true}"#,
                    expect: Fails,
                },
                Case {
                    scenario: "malformed json rejected",
                    input: r#""dhcp"#,
                    expect: Fails,
                },
            ],
            |wire| serde_json::from_str::<AllocationType>(wire).map_err(drop),
        );
    }

    // Derived `PartialEq`/`Eq` over both `AllocationType` and `AssignStaticResult`:
    // a variant equals only itself. `AssignStaticResult` has no other pure logic, so
    // equality across its full variant set is its coverage.
    #[test]
    fn variants_compare_by_identity() {
        check_values(
            [
                Check {
                    scenario: "dhcp == dhcp",
                    input: (AllocationType::Dhcp, AllocationType::Dhcp),
                    expect: true,
                },
                Check {
                    scenario: "static == static",
                    input: (AllocationType::Static, AllocationType::Static),
                    expect: true,
                },
                Check {
                    scenario: "dhcp != static",
                    input: (AllocationType::Dhcp, AllocationType::Static),
                    expect: false,
                },
            ],
            |(left, right)| left == right,
        );

        check_values(
            [
                Check {
                    scenario: "assigned == assigned",
                    input: (AssignStaticResult::Assigned, AssignStaticResult::Assigned),
                    expect: true,
                },
                Check {
                    scenario: "replaced static == replaced static",
                    input: (
                        AssignStaticResult::ReplacedStatic,
                        AssignStaticResult::ReplacedStatic,
                    ),
                    expect: true,
                },
                Check {
                    scenario: "replaced dhcp == replaced dhcp",
                    input: (
                        AssignStaticResult::ReplacedDhcp,
                        AssignStaticResult::ReplacedDhcp,
                    ),
                    expect: true,
                },
                Check {
                    scenario: "assigned != replaced static",
                    input: (
                        AssignStaticResult::Assigned,
                        AssignStaticResult::ReplacedStatic,
                    ),
                    expect: false,
                },
                Check {
                    scenario: "replaced static != replaced dhcp",
                    input: (
                        AssignStaticResult::ReplacedStatic,
                        AssignStaticResult::ReplacedDhcp,
                    ),
                    expect: false,
                },
                Check {
                    scenario: "assigned != replaced dhcp",
                    input: (
                        AssignStaticResult::Assigned,
                        AssignStaticResult::ReplacedDhcp,
                    ),
                    expect: false,
                },
            ],
            |(left, right)| left == right,
        );
    }
}
