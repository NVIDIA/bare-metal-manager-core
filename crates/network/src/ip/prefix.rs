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
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{AddrParseError, PrefixLenError};
// These are part of our public API because of the conversion traits.
pub use ipnet::{IpNet, Ipv4Net, Ipv6Net};
#[cfg(feature = "ipnetwork")]
pub use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

use super::address_family::{IdentifyAddressFamily, IpAddressFamily};

//
// Type definitions
//

/// This is a type that represents an IP prefix, which matches 0 or more leading
/// address bits with the remainder being unspecified or "don't-care". This
/// type uses the ipnet network types internally, but is stricter on what can be
/// parsed and stored. Here, we require that all bits after the prefix are set
/// to zero, so that there's no way to confuse this with an network interface
/// address (which has the same general representation but has a different
/// usage).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpPrefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}

impl IdentifyAddressFamily for IpPrefix {
    fn address_family(&self) -> IpAddressFamily {
        match self {
            IpPrefix::V4(_) => IpAddressFamily::Ipv4,
            IpPrefix::V6(_) => IpAddressFamily::Ipv6,
        }
    }
}

impl IpPrefix {
    pub fn contains<P: ToPrefix>(&self, other: P) -> bool {
        let other = other.to_prefix();
        use IpPrefix::*;
        match (self, &other) {
            (V4(prefix), V4(other_prefix)) => prefix.contains(other_prefix),
            (V6(prefix), V6(other_prefix)) => prefix.contains(other_prefix),
            _ => false,
        }
    }

    pub fn get_sibling(&self) -> Option<Self> {
        use IpPrefix::*;
        match self {
            V4(ipv4_prefix) => ipv4_prefix.get_sibling().map(V4),
            V6(ipv6_prefix) => ipv6_prefix.get_sibling().map(V6),
        }
    }

    pub fn bifurcate(&self) -> Option<(Self, Self)> {
        use IpPrefix::*;
        match self {
            V4(ipv4_prefix) => ipv4_prefix
                .bifurcate()
                .map(|(even, odd)| (V4(even), V4(odd))),
            V6(ipv6_prefix) => ipv6_prefix
                .bifurcate()
                .map(|(even, odd)| (V6(even), V6(odd))),
        }
    }

    pub fn get_last_subprefix(&self) -> Self {
        use IpPrefix::*;
        match self {
            V4(ipv4_prefix) => V4(ipv4_prefix.get_last_subprefix()),
            V6(ipv6_prefix) => V6(ipv6_prefix.get_last_subprefix()),
        }
    }

    pub fn try_aggregate(&self, other: &Self) -> Option<Self> {
        use IpPrefix::*;
        match (self, other) {
            (V4(p1), V4(p2)) => p1.try_aggregate(p2).map(V4),
            (V6(p1), V6(p2)) => p1.try_aggregate(p2).map(V6),
            _ => None,
        }
    }
}

/// A representation of an IPv4 prefix. The bits after the end of the length of
/// the prefix are guaranteed to be zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Ipv4Prefix {
    prefix: Ipv4Net,
}

impl Ipv4Prefix {
    pub fn contains(&self, other: &Self) -> bool {
        self.prefix.contains(&other.prefix)
    }

    pub fn get_sibling(&self) -> Option<Self> {
        let prefix_length = self.prefix.prefix_len();
        match prefix_length {
            0 => None,
            n @ (1..=32) => {
                // We just need to flip the last prefix bit.
                let addr = self.prefix.addr();
                let addr_bits = addr.to_bits();
                let shift_amount = 32 - n;
                let single_bit_flip = 0x1u32 << shift_amount;
                let sibling_addr_bits = addr_bits ^ single_bit_flip;
                let sibling_addr = Ipv4Addr::from_bits(sibling_addr_bits);
                let sibling_prefix = Ipv4Net::new_assert(sibling_addr, prefix_length);
                Some(Self {
                    prefix: sibling_prefix,
                })
            }
            _ => unreachable!(),
        }
    }

    /// Attempt to split this prefix into the more specific prefixes that cover
    /// the same total address space. Returns None if `self` is a /32.
    pub fn bifurcate(&self) -> Option<(Self, Self)> {
        let prefix_length = self.prefix.prefix_len();
        match prefix_length {
            n @ (0..=31) => {
                // One of the returned outputs will be the same address
                // with the prefix one longer, but the other (the "odd" branch)
                // needs to have a bit flipped to 1 first.
                let addr_bits = self.prefix.addr().to_bits();
                let single_bit_flip = 0x80_00_00_00u32 >> n;
                let odd_addr_bits = addr_bits | single_bit_flip;

                let even_addr = Ipv4Addr::from_bits(addr_bits);
                let odd_addr = Ipv4Addr::from_bits(odd_addr_bits);

                let new_prefix_length = n + 1;
                let even_net = Ipv4Net::new_assert(even_addr, new_prefix_length);
                let odd_net = Ipv4Net::new_assert(odd_addr, new_prefix_length);

                let even_prefix = Self { prefix: even_net };
                let odd_prefix = Self { prefix: odd_net };
                Some((even_prefix, odd_prefix))
            }
            _ => None,
        }
    }

    /// Get the final and smallest sub-prefix of this prefix. This is equivalent
    /// to the all-ones address converted to a /32.
    pub fn get_last_subprefix(&self) -> Self {
        self.prefix.broadcast().to_v4_prefix()
    }

    pub fn try_aggregate(&self, other: &Self) -> Option<Self> {
        match (self, other, self.prefix.supernet(), other.prefix.supernet()) {
            // If one prefix contains the other, return the containing prefix.
            (p1, p2, _, _) if p1.contains(p2) => Some(*p1),
            (p1, p2, _, _) if p2.contains(p1) => Some(*p2),
            // If both prefixes have the same supernet, we can aggregate them
            // into that supernet.
            (_, _, Some(super1), Some(super2)) if super1 == super2 => Some(Self { prefix: super1 }),
            _ => None,
        }
    }

    pub fn into_inner(self) -> Ipv4Net {
        let Self { prefix } = self;
        prefix
    }
}

/// A representation of an IPv6 prefix. The bits after the end of the length of
/// the prefix are guaranteed to be zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Ipv6Prefix {
    prefix: Ipv6Net,
}

impl Ipv6Prefix {
    pub fn contains(&self, other: &Self) -> bool {
        self.prefix.contains(&other.prefix)
    }

    pub fn get_sibling(&self) -> Option<Self> {
        let prefix_length = self.prefix.prefix_len();
        match prefix_length {
            0 => None,
            n if n <= 128 => {
                // We just need to flip the last prefix bit.
                let addr = self.prefix.addr();
                let addr_bits = addr.to_bits();
                let shift_amount = 128 - n;
                let single_bit_flip = 0x1u128 << shift_amount;
                let sibling_addr_bits = addr_bits ^ single_bit_flip;
                let sibling_addr = Ipv6Addr::from_bits(sibling_addr_bits);
                let sibling_prefix = Ipv6Net::new_assert(sibling_addr, prefix_length);
                Some(Self {
                    prefix: sibling_prefix,
                })
            }
            _ => unreachable!(),
        }
    }

    /// Attempt to split this prefix into the more specific prefixes that cover
    /// the same total address space. Returns None if `self` is a /128.
    pub fn bifurcate(&self) -> Option<(Self, Self)> {
        let prefix_length = self.prefix.prefix_len();
        match prefix_length {
            n @ (0..=127) => {
                // One of the returned outputs will be the same address
                // with the prefix one longer, but the other (the "odd" branch)
                // needs to have a bit flipped to 1 first.
                let even_addr_bits = self.prefix.addr().to_bits();
                let single_bit_flip = 0x8000_0000_0000_0000u128 >> n;
                let odd_addr_bits = even_addr_bits | single_bit_flip;

                let even_addr = Ipv6Addr::from_bits(even_addr_bits);
                let odd_addr = Ipv6Addr::from_bits(odd_addr_bits);

                let new_prefix_length = n + 1;
                let even_net = Ipv6Net::new_assert(even_addr, new_prefix_length);
                let odd_net = Ipv6Net::new_assert(odd_addr, new_prefix_length);

                let even_prefix = Self { prefix: even_net };
                let odd_prefix = Self { prefix: odd_net };
                Some((even_prefix, odd_prefix))
            }
            _ => None,
        }
    }

    /// Get the final and smallest sub-prefix of this prefix. This is equivalent
    /// to the all-ones address converted to a /128.
    pub fn get_last_subprefix(&self) -> Self {
        self.prefix.broadcast().to_v6_prefix()
    }

    pub fn try_aggregate(&self, other: &Self) -> Option<Self> {
        match (self, other, self.prefix.supernet(), other.prefix.supernet()) {
            // If one prefix contains the other, return the containing prefix.
            (p1, p2, _, _) if p1.contains(p2) => Some(*p1),
            (p1, p2, _, _) if p2.contains(p1) => Some(*p2),
            // If both prefixes have the same supernet, we can aggregate them
            // into that supernet.
            (_, _, Some(super1), Some(super2)) if super1 == super2 => Some(Self { prefix: super1 }),
            _ => None,
        }
    }

    pub fn into_inner(self) -> Ipv6Net {
        let Self { prefix } = self;
        prefix
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PrefixError {
    #[error(
        "Prefix not in canonical representation (address bits after prefix must be set to zero)"
    )]
    NonCanonicalRepresentation,

    #[error("Parse error: {0}")]
    ParseError(#[from] AddrParseError),

    #[error("Prefix length error: {0}")]
    BadPrefixLength(#[from] PrefixLenError),
}

//
// Trait definitions
//

/// Basic common operations on a prefix
pub trait Prefix {
    fn prefix_length(&self) -> usize;
}

/// ToPrefix can be implemented for something like a network or address where
/// we can create a prefix through some trivial operation like appending /32 or
/// truncating the trailing address bits.
pub trait ToPrefix {
    /// Create an IpPrefix from a source type.
    fn to_prefix(&self) -> IpPrefix;
}

pub trait ToV4Prefix {
    /// Create an Ipv4Prefix from a source type.
    fn to_v4_prefix(&self) -> Ipv4Prefix;
}

pub trait ToV6Prefix {
    /// Create an Ipv6Prefix from a source type.
    fn to_v6_prefix(&self) -> Ipv6Prefix;
}

//
// Functions
//

pub use super::ipset::aggregate_prefixes as aggregate;

//
// Implementations of our traits
//

impl Prefix for Ipv4Prefix {
    fn prefix_length(&self) -> usize {
        self.prefix.prefix_len() as usize
    }
}

impl Prefix for Ipv6Prefix {
    fn prefix_length(&self) -> usize {
        self.prefix.prefix_len() as usize
    }
}

impl Prefix for IpPrefix {
    fn prefix_length(&self) -> usize {
        match self {
            IpPrefix::V4(v4) => v4.prefix_length(),
            IpPrefix::V6(v6) => v6.prefix_length(),
        }
    }
}

impl<B> ToPrefix for B
where
    B: Borrow<IpPrefix>,
{
    fn to_prefix(&self) -> IpPrefix {
        *self.borrow()
    }
}

impl ToPrefix for Ipv4Prefix {
    fn to_prefix(&self) -> IpPrefix {
        IpPrefix::V4(*self)
    }
}

impl ToPrefix for Ipv6Prefix {
    fn to_prefix(&self) -> IpPrefix {
        IpPrefix::V6(*self)
    }
}

impl ToPrefix for IpAddr {
    fn to_prefix(&self) -> IpPrefix {
        match self {
            IpAddr::V4(ipv4_addr) => IpPrefix::V4(ipv4_addr.to_v4_prefix()),
            IpAddr::V6(ipv6_addr) => IpPrefix::V6(ipv6_addr.to_v6_prefix()),
        }
    }
}

impl ToPrefix for Ipv4Addr {
    fn to_prefix(&self) -> IpPrefix {
        IpPrefix::V4(self.to_v4_prefix())
    }
}

impl ToPrefix for Ipv6Addr {
    fn to_prefix(&self) -> IpPrefix {
        IpPrefix::V6(self.to_v6_prefix())
    }
}

impl ToPrefix for IpNet {
    fn to_prefix(&self) -> IpPrefix {
        match self {
            IpNet::V4(ipv4_net) => IpPrefix::V4(ipv4_net.to_v4_prefix()),
            IpNet::V6(ipv6_net) => IpPrefix::V6(ipv6_net.to_v6_prefix()),
        }
    }
}

impl ToV4Prefix for Ipv4Addr {
    fn to_v4_prefix(&self) -> Ipv4Prefix {
        // Ipv4Net::from can construct a /32 for us.
        Ipv4Prefix {
            prefix: Ipv4Net::from(*self),
        }
    }
}

impl ToV4Prefix for Ipv4Net {
    fn to_v4_prefix(&self) -> Ipv4Prefix {
        Ipv4Prefix {
            prefix: self.trunc(),
        }
    }
}

impl ToV6Prefix for Ipv6Addr {
    fn to_v6_prefix(&self) -> Ipv6Prefix {
        // Ipv6Net::from can construct a /128 for us.
        Ipv6Prefix {
            prefix: Ipv6Net::from(*self),
        }
    }
}

impl ToV6Prefix for Ipv6Net {
    fn to_v6_prefix(&self) -> Ipv6Prefix {
        Ipv6Prefix {
            prefix: self.trunc(),
        }
    }
}

// Other stdlib trait implementations

impl Ord for IpPrefix {
    fn cmp(&self, other: &Self) -> Ordering {
        use IpPrefix::*;
        match (self, other) {
            (V4(_), V6(_)) => Ordering::Less,
            (V6(_), V4(_)) => Ordering::Greater,
            (V4(p1), V4(p2)) => p1.cmp(p2),
            (V6(p1), V6(p2)) => p1.cmp(p2),
        }
    }
}

impl PartialOrd for IpPrefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpPrefix::V4(ipv4_prefix) => ipv4_prefix.fmt(f),
            IpPrefix::V6(ipv6_prefix) => ipv6_prefix.fmt(f),
        }
    }
}

impl Display for Ipv4Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.prefix.fmt(f)
    }
}
impl Display for Ipv6Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.prefix.fmt(f)
    }
}

impl FromStr for IpPrefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IpNet::from_str(s)
            .map_err(PrefixError::from)
            .and_then(IpPrefix::try_from)
    }
}

impl FromStr for Ipv4Prefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv4Net::from_str(s)
            .map_err(PrefixError::from)
            .and_then(Ipv4Prefix::try_from)
    }
}

impl FromStr for Ipv6Prefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv6Net::from_str(s)
            .map_err(PrefixError::from)
            .and_then(Ipv6Prefix::try_from)
    }
}

impl TryFrom<IpNet> for IpPrefix {
    type Error = PrefixError;

    fn try_from(value: IpNet) -> Result<Self, Self::Error> {
        match value {
            IpNet::V4(ipv4_net) => Ipv4Prefix::try_from(ipv4_net).map(Self::V4),
            IpNet::V6(ipv6_net) => Ipv6Prefix::try_from(ipv6_net).map(Self::V6),
        }
    }
}

impl TryFrom<Ipv4Net> for Ipv4Prefix {
    type Error = PrefixError;

    fn try_from(value: Ipv4Net) -> Result<Self, Self::Error> {
        let is_canonical_representation = value.addr() == value.network();
        is_canonical_representation
            .then_some(Self { prefix: value })
            .ok_or(PrefixError::NonCanonicalRepresentation)
    }
}

impl TryFrom<Ipv6Net> for Ipv6Prefix {
    type Error = PrefixError;

    fn try_from(value: Ipv6Net) -> Result<Self, Self::Error> {
        let is_canonical_representation = value.addr() == value.network();
        is_canonical_representation
            .then_some(Self { prefix: value })
            .ok_or(PrefixError::NonCanonicalRepresentation)
    }
}

impl TryFrom<(IpAddr, u8)> for IpPrefix {
    type Error = PrefixError;

    fn try_from(value: (IpAddr, u8)) -> Result<Self, Self::Error> {
        let (addr, prefix_length) = value;
        IpNet::new(addr, prefix_length)
            .map_err(PrefixError::from)
            .and_then(Self::try_from)
    }
}

impl From<IpPrefix> for IpNet {
    fn from(value: IpPrefix) -> Self {
        match value {
            IpPrefix::V4(v4) => IpNet::V4(v4.into()),
            IpPrefix::V6(v6) => IpNet::V6(v6.into()),
        }
    }
}

impl From<Ipv4Prefix> for Ipv4Net {
    fn from(value: Ipv4Prefix) -> Self {
        value.prefix
    }
}

impl From<Ipv6Prefix> for Ipv6Net {
    fn from(value: Ipv6Prefix) -> Self {
        value.prefix
    }
}

#[cfg(feature = "ipnetwork")]
impl From<Ipv4Prefix> for ipnetwork::Ipv4Network {
    fn from(value: Ipv4Prefix) -> Self {
        let prefix = value.prefix;
        let addr = prefix.addr();
        let length = prefix.prefix_len();
        // If Ipv4Network::new() doesn't accept what we got out of
        // ipnet::Ipv4Net, something has gone very wrong and we should just
        // panic.
        Self::new(addr, length).expect(
        "Ipv4Network::new() returned an unexpected Err (this shouldn't happen, please file a bug)"
    )
    }
}

#[cfg(feature = "ipnetwork")]
impl From<Ipv6Prefix> for ipnetwork::Ipv6Network {
    fn from(value: Ipv6Prefix) -> Self {
        let prefix = value.prefix;
        let addr = prefix.addr();
        let length = prefix.prefix_len();
        // If Ipv6Network::new() doesn't accept what we got out of
        // ipnet::Ipv6Net, something has gone very wrong and we should just
        // panic.
        Self::new(addr, length).expect(
        "Ipv6Network::new() returned an unexpected Err (this shouldn't happen, please file a bug)"
    )
    }
}

#[cfg(feature = "ipnetwork")]
impl TryFrom<ipnetwork::IpNetwork> for IpPrefix {
    type Error = PrefixError;

    fn try_from(value: ipnetwork::IpNetwork) -> Result<Self, Self::Error> {
        let addr = value.ip();
        let prefix_length = value.prefix();
        IpNet::new(addr, prefix_length)
            .map_err(PrefixError::from)
            .and_then(Self::try_from)
    }
}

//
// Implementations of foreign traits on our types
//

// This implementation is not particularly elegant but sqlx doesn't give
// us the tools we'd to do it properly. Really what we want is the generic
// equivalent of `PgTypeInfo::CIDR`, but even if we wanted to implement
// `sqlx::Type<Postgres>` without being generic over the database, that `CIDR`
// item is private and we can't reference it. So, let's just use the ipnetwork
// implementation as a stepping stone.
#[cfg(feature = "sqlx")]
impl<DB> sqlx::Type<DB> for IpPrefix
where
    DB: sqlx::Database,
    IpNetwork: sqlx::Type<DB>,
{
    fn type_info() -> <DB as sqlx::Database>::TypeInfo {
        ipnetwork::IpNetwork::type_info()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_prefix() {
        let good_v4 = "192.168.0.0/16";
        Ipv4Prefix::from_str(good_v4).expect("Couldn't parse good IPv4 prefix");

        let bad_v4 = "192.168.1.2/16"; // should be 192.168.0.0/16 as in `good_v4` above.
        Ipv4Prefix::from_str(bad_v4)
            .expect_err("Unexpectedly parsed IPv4 prefix with non-canonical representation");

        let bad_v4 = "192.168.0.0/33";
        Ipv4Prefix::from_str(bad_v4)
            .expect_err("Unexpectedly parsed IPv4 prefix with an invalid length");

        let good_v6 = "2001:DB8::/48";
        Ipv6Prefix::from_str(good_v6).expect("Couldn't parse good IPv6 prefix");

        let bad_v6 = "2001:DB8::2/64";
        Ipv6Prefix::from_str(bad_v6)
            .expect_err("Unexpectedly parsed IPv6 prefix with non-canonical representation");
    }

    #[test]
    fn test_address_family() {
        let v4_prefix = IpPrefix::from_str("10.0.0.0/8").expect("Couldn't parse prefix");
        assert!(v4_prefix.is_address_family(IpAddressFamily::Ipv4));

        let wrong_address_family_error =
            v4_prefix.require_address_family_or_else(IpAddressFamily::Ipv6, |_| 42);
        assert_eq!(wrong_address_family_error, Err(42));
    }

    #[test]
    fn test_contains() {
        let v4_prefix = IpPrefix::from_str("10.0.0.0/8").expect("Couldn't parse prefix");
        let v4_addr = IpAddr::from_str("10.0.0.1").expect("Couldn't parse IPv4 address");
        assert!(v4_prefix.contains(v4_addr));
        let v6_addr = IpAddr::from_str("2001:DB8::1").expect("Couldn't parse IPv6 address");
        assert!(!v4_prefix.contains(v6_addr));
    }

    #[test]
    fn test_ordering() {
        let p1 = IpPrefix::from_str("10.0.0.0/8").unwrap();
        let p2 = IpPrefix::from_str("10.0.0.0/16").unwrap();
        let p3 = IpPrefix::from_str("2001:DB8::/32").unwrap();
        // Two prefixes with the same address but different lengths should be
        // ordered such that the shorter prefix is first.
        assert_eq!(p1.cmp(&p2), Ordering::Less);
        // An IPv4 prefix should be ordered before an IPv6 prefix.
        assert_eq!(p2.cmp(&p3), Ordering::Less);
    }

    #[test]
    fn test_bifurcate() {
        let p1 = IpPrefix::from_str("10.0.0.0/24").unwrap();
        let children = p1.bifurcate().expect("Could not bifurcate p1");
        let (p2, p3) = children;
        let p2_expected = IpPrefix::from_str("10.0.0.0/25").unwrap();
        let p3_expected = IpPrefix::from_str("10.0.0.128/25").unwrap();
        assert_eq!(p2, p2_expected);
        assert_eq!(p3, p3_expected);
    }

    #[test]
    fn test_sibling() {
        let p1 = IpPrefix::from_str("10.0.0.0/24").unwrap();
        let p2 = IpPrefix::from_str("10.0.1.0/24").unwrap();
        assert_eq!(p1.get_sibling(), Some(p2));

        let p3 = IpPrefix::from_str("2001:db8:0000::/34").unwrap();
        let p4 = IpPrefix::from_str("2001:db8:4000::/34").unwrap();
        assert_eq!(p3.get_sibling(), Some(p4));
    }
}
