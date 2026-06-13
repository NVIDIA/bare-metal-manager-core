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
/// A representation of an address family, which makes certain APIs more
/// composable if we can construct this as a type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IpAddressFamily {
    Ipv4,
    Ipv6,
}

impl IpAddressFamily {
    /// Returns the prefix length for a single interface address in this family
    /// (32 for IPv4, 128 for IPv6).
    pub const fn interface_prefix_len(self) -> u8 {
        match self {
            IpAddressFamily::Ipv4 => 32,
            IpAddressFamily::Ipv6 => 128,
        }
    }

    /// pg_family returns the Postgre `family()` integer for
    /// this address family (4 for IPv4, 6 for IPv6).
    pub const fn pg_family(self) -> i32 {
        match self {
            IpAddressFamily::Ipv4 => 4,
            IpAddressFamily::Ipv6 => 6,
        }
    }
}

pub trait IdentifyAddressFamily {
    /// Return the address family for this value.
    fn address_family(&self) -> IpAddressFamily;

    /// Check whether this value matches the specified `address_family`.
    fn is_address_family(&self, address_family: IpAddressFamily) -> bool {
        address_family == self.address_family()
    }

    fn require_address_family_or_else<F, E>(
        self,
        address_family: IpAddressFamily,
        err: F,
    ) -> Result<Self, E>
    where
        Self: Sized,
        F: FnOnce(Self) -> E,
    {
        match self.is_address_family(address_family) {
            true => Ok(self),
            false => Err(err(self)),
        }
    }
}

impl IdentifyAddressFamily for std::net::IpAddr {
    fn address_family(&self) -> IpAddressFamily {
        use IpAddressFamily::*;
        match self {
            std::net::IpAddr::V4(_) => Ipv4,
            std::net::IpAddr::V6(_) => Ipv6,
        }
    }
}

impl IdentifyAddressFamily for ipnet::IpNet {
    fn address_family(&self) -> IpAddressFamily {
        use IpAddressFamily::*;
        match self {
            ipnet::IpNet::V4(_) => Ipv4,
            ipnet::IpNet::V6(_) => Ipv6,
        }
    }
}

#[cfg(feature = "ipnetwork")]
impl IdentifyAddressFamily for ipnetwork::IpNetwork {
    fn address_family(&self) -> IpAddressFamily {
        use IpAddressFamily::*;
        match self {
            ipnetwork::IpNetwork::V4(_) => Ipv4,
            ipnetwork::IpNetwork::V6(_) => Ipv6,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};
    use ipnet::IpNet;

    use super::*;

    #[test]
    fn test_interface_prefix_len() {
        check_values(
            [
                Check {
                    scenario: "ipv4 is /32",
                    input: IpAddressFamily::Ipv4,
                    expect: 32,
                },
                Check {
                    scenario: "ipv6 is /128",
                    input: IpAddressFamily::Ipv6,
                    expect: 128,
                },
            ],
            |family| family.interface_prefix_len(),
        );
    }

    #[test]
    fn test_pg_family() {
        check_values(
            [
                Check {
                    scenario: "ipv4 is postgres family 4",
                    input: IpAddressFamily::Ipv4,
                    expect: 4,
                },
                Check {
                    scenario: "ipv6 is postgres family 6",
                    input: IpAddressFamily::Ipv6,
                    expect: 6,
                },
            ],
            |family| family.pg_family(),
        );
    }

    #[test]
    fn test_ipaddr_address_family() {
        check_values(
            [
                Check {
                    scenario: "ipv4 loopback",
                    input: "127.0.0.1",
                    expect: IpAddressFamily::Ipv4,
                },
                Check {
                    scenario: "ipv4 unspecified",
                    input: "0.0.0.0",
                    expect: IpAddressFamily::Ipv4,
                },
                Check {
                    scenario: "ipv4 broadcast",
                    input: "255.255.255.255",
                    expect: IpAddressFamily::Ipv4,
                },
                Check {
                    scenario: "ipv4 routable",
                    input: "10.0.0.1",
                    expect: IpAddressFamily::Ipv4,
                },
                Check {
                    scenario: "ipv6 loopback",
                    input: "::1",
                    expect: IpAddressFamily::Ipv6,
                },
                Check {
                    scenario: "ipv6 unspecified",
                    input: "::",
                    expect: IpAddressFamily::Ipv6,
                },
                Check {
                    scenario: "ipv6 unique-local",
                    input: "fd00::1",
                    expect: IpAddressFamily::Ipv6,
                },
                Check {
                    scenario: "ipv6 link-local",
                    input: "fe80::1",
                    expect: IpAddressFamily::Ipv6,
                },
                Check {
                    scenario: "ipv4-mapped ipv6 stays ipv6",
                    input: "::ffff:192.0.2.1",
                    expect: IpAddressFamily::Ipv6,
                },
            ],
            |s| s.parse::<IpAddr>().unwrap().address_family(),
        );
    }

    #[test]
    fn test_ipnet_address_family() {
        check_values(
            [
                Check {
                    scenario: "ipv4 host route",
                    input: "10.0.0.1/32",
                    expect: IpAddressFamily::Ipv4,
                },
                Check {
                    scenario: "ipv4 default route",
                    input: "0.0.0.0/0",
                    expect: IpAddressFamily::Ipv4,
                },
                Check {
                    scenario: "ipv4 subnet",
                    input: "192.168.0.0/24",
                    expect: IpAddressFamily::Ipv4,
                },
                Check {
                    scenario: "ipv6 host route",
                    input: "fd00::1/128",
                    expect: IpAddressFamily::Ipv6,
                },
                Check {
                    scenario: "ipv6 default route",
                    input: "::/0",
                    expect: IpAddressFamily::Ipv6,
                },
                Check {
                    scenario: "ipv6 subnet",
                    input: "2001:db8::/64",
                    expect: IpAddressFamily::Ipv6,
                },
            ],
            |s| s.parse::<IpNet>().unwrap().address_family(),
        );
    }

    #[test]
    fn test_is_address_family() {
        struct Row {
            value: &'static str,
            family: IpAddressFamily,
        }

        check_values(
            [
                Check {
                    scenario: "ipv4 matches ipv4",
                    input: Row {
                        value: "10.0.0.1",
                        family: IpAddressFamily::Ipv4,
                    },
                    expect: true,
                },
                Check {
                    scenario: "ipv4 does not match ipv6",
                    input: Row {
                        value: "10.0.0.1",
                        family: IpAddressFamily::Ipv6,
                    },
                    expect: false,
                },
                Check {
                    scenario: "ipv6 matches ipv6",
                    input: Row {
                        value: "fd00::1",
                        family: IpAddressFamily::Ipv6,
                    },
                    expect: true,
                },
                Check {
                    scenario: "ipv6 does not match ipv4",
                    input: Row {
                        value: "fd00::1",
                        family: IpAddressFamily::Ipv4,
                    },
                    expect: false,
                },
            ],
            |row| {
                row.value
                    .parse::<IpAddr>()
                    .unwrap()
                    .is_address_family(row.family)
            },
        );
    }

    #[test]
    fn test_require_address_family_or_else() {
        struct Row {
            value: &'static str,
            required: IpAddressFamily,
        }

        check_cases(
            [
                Case {
                    scenario: "ipv4 required and present yields the address",
                    input: Row {
                        value: "127.0.0.1",
                        required: IpAddressFamily::Ipv4,
                    },
                    expect: Yields("127.0.0.1".parse::<IpAddr>().unwrap()),
                },
                Case {
                    scenario: "ipv6 required and present yields the address",
                    input: Row {
                        value: "fd00::1",
                        required: IpAddressFamily::Ipv6,
                    },
                    expect: Yields("fd00::1".parse::<IpAddr>().unwrap()),
                },
                Case {
                    scenario: "ipv6 required but ipv4 given fails",
                    input: Row {
                        value: "127.0.0.1",
                        required: IpAddressFamily::Ipv6,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "ipv4 required but ipv6 given fails",
                    input: Row {
                        value: "fd00::1",
                        required: IpAddressFamily::Ipv4,
                    },
                    expect: Fails,
                },
            ],
            |row| {
                let addr = row.value.parse::<IpAddr>().unwrap();
                addr.require_address_family_or_else(row.required, |_| ())
            },
        );
    }

    #[test]
    fn test_require_address_family_or_else_passes_value_to_err() {
        // The error closure receives the rejected value; assert it is threaded
        // through so callers can fold the original address into their error.
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        Case {
            scenario: "rejected value reaches the error closure",
            input: addr,
            expect: FailsWith(addr),
        }
        .check(|addr| {
            addr.require_address_family_or_else(IpAddressFamily::Ipv6, |rejected| rejected)
        });
    }
}
