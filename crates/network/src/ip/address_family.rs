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
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_require_address_family_or_else() {
        let addr = IpAddr::from_str("127.0.0.1").unwrap();

        // The above is an IPv4 address, so it should come out the other side
        // as an Ok variant.
        assert_eq!(
            addr.require_address_family_or_else(IpAddressFamily::Ipv4, |_| {}),
            Ok(addr),
        );

        assert_eq!(
            addr.require_address_family_or_else(IpAddressFamily::Ipv6, |_| 42),
            Err(42)
        )
    }
}
