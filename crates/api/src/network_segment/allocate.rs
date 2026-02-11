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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use model::network_prefix::NewNetworkPrefix;
use model::network_segment::NewNetworkSegment;
use sqlx::PgConnection;

use crate::{CarbideError, CarbideResult};

/// ip_to_u128 converts an IP address to its u128 representation.
/// IPv4 addresses are zero-extended (u32 → u128), and IPv6 are native u128.
fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) as u128,
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// u128_to_ip converts a u128 back to an IP address of the appropriate family.
fn u128_to_ip(val: u128, is_v6: bool) -> IpAddr {
    if is_v6 {
        IpAddr::V6(Ipv6Addr::from(val))
    } else {
        IpAddr::V4(Ipv4Addr::from(val as u32))
    }
}

/// max_prefix_bits returns the maximum prefix length for the address
/// family (32 for IPv4, 128 for IPv6).
fn max_prefix_bits(prefix: &IpNetwork) -> u32 {
    if prefix.is_ipv6() { 128 } else { 32 }
}

/// wrap_to_prefix_start returns `addr` if it falls within the VPC prefix,
/// otherwise wraps around to the start of the VPC prefix.
fn wrap_to_prefix_start(addr: IpAddr, vpc_prefix: &IpNetwork) -> IpAddr {
    let addr_u128 = ip_to_u128(addr);
    let network_u128 = ip_to_u128(vpc_prefix.network());
    let broadcast_u128 = ip_to_u128(vpc_prefix.broadcast());
    if addr_u128 < network_u128 || addr_u128 > broadcast_u128 {
        vpc_prefix.network()
    } else {
        addr
    }
}

/// PrefixAllocator allocates a prefix of given length from a VPC prefix.
/// Works with both IPv4 and IPv6 address families.
///
/// The prefix length is validated at construction time via [`PrefixAllocator::new`],
/// so all internal arithmetic (including the iterator) can rely on the prefix
/// being valid for the address family without additional checks.
#[derive(Debug)]
pub struct PrefixAllocator {
    vpc_prefix_id: VpcPrefixId,
    vpc_prefix: IpNetwork,
    last_used_prefix: Option<IpNetwork>,
    prefix: u8,
}

/// PrefixIterator is an Iterator that steps through candidate subnets of a
/// given prefix length within a parent VPC prefix, using u128 arithmetic
/// for both IPv4 and IPv6.
#[derive(Debug)]
struct PrefixIterator {
    vpc_prefix: IpNetwork,
    prefix: u8,
    current_item: u128,
    // We cache this based on `vpc_prefix` to avoid re-checking the address
    // family on every iteration.
    is_v6: bool,
    first_iter: bool,
}

/// networks_overlap returns true if two networks overlap (as in
/// one contains the other's network address).
fn networks_overlap(a: IpNetwork, b: IpNetwork) -> bool {
    a.contains(b.network()) || b.contains(a.network())
}

impl PrefixAllocator {
    fn iter(&self) -> PrefixIterator {
        let is_v6 = self.vpc_prefix.is_ipv6();

        // When resuming after a previous allocation, seed the iterator with
        // the broadcast address of the last used prefix and set first_iter to
        // false. The first call to next() will then use bit-shifting to
        // advance to the next aligned subnet boundary — the same result
        // get_next_usable_address used to compute as a separate step.
        //
        // When starting fresh, seed with the VPC prefix's network address and
        // set first_iter to true so the first call returns it directly
        // (bit-shifting would skip past it).
        let (start, first_iter) = if let Some(last_used_prefix) = self.last_used_prefix {
            (ip_to_u128(last_used_prefix.broadcast()), false)
        } else {
            (ip_to_u128(self.vpc_prefix.network()), true)
        };

        PrefixIterator {
            vpc_prefix: self.vpc_prefix,
            prefix: self.prefix,
            current_item: start,
            is_v6,
            first_iter,
        }
    }

    pub fn new(
        vpc_prefix_id: VpcPrefixId,
        vpc_prefix: IpNetwork,
        last_used_prefix: Option<IpNetwork>,
        prefix: u8,
    ) -> CarbideResult<PrefixAllocator> {
        let max_bits = max_prefix_bits(&vpc_prefix) as u8;
        if prefix > max_bits {
            return Err(CarbideError::InvalidArgument(format!(
                "prefix length {prefix} exceeds maximum for address family ({max_bits})"
            )));
        }
        if prefix <= vpc_prefix.prefix() {
            return Err(CarbideError::InvalidArgument(format!(
                "prefix length {prefix} must be greater than VPC prefix length {}",
                vpc_prefix.prefix()
            )));
        }

        Ok(Self {
            vpc_prefix_id,
            vpc_prefix,
            last_used_prefix,
            prefix,
        })
    }

    // As of now this is only used by FNN.
    pub async fn allocate_network_segment(
        &self,
        txn: &mut PgConnection,
        vpc_id: VpcId,
    ) -> CarbideResult<(NetworkSegmentId, IpNetwork)> {
        let prefix = self.next_free_prefix(txn).await?;

        let name = format!("vpc_prefix_{}", prefix.network());
        let segment_id = NetworkSegmentId::new();

        // Note: There is a database constraint `no_gateway_on_ipv6` ensuring
        // IPv6 prefixes must have gateway IS NULL. IPv6 uses RAs (Router
        // Advertisements) instead of explicit gateways.
        let gateway = if prefix.is_ipv4() {
            Some(prefix.network())
        } else {
            None
        };

        let ns = NewNetworkSegment {
            id: segment_id,
            name,
            subdomain_id: None,
            vpc_id: Some(vpc_id),
            mtu: 9000, // Default value.
            prefixes: vec![NewNetworkPrefix {
                prefix,
                gateway,
                num_reserved: 0,
            }],
            vlan_id: None,
            vni: None,
            segment_type: model::network_segment::NetworkSegmentType::Tenant,
            can_stretch: Some(false), // All segments allocated here are FNN linknets.
        };

        let mut segment = db::network_segment::persist(
            ns,
            txn,
            model::network_segment::NetworkSegmentControllerState::Provisioning,
        )
        .await?;

        for prefix in &mut segment.prefixes {
            db::network_prefix::set_vpc_prefix(prefix, txn, &self.vpc_prefix_id, &self.vpc_prefix)
                .await?;
        }

        Ok((segment.id, prefix))
    }

    pub async fn next_free_prefix(&self, txn: &mut PgConnection) -> CarbideResult<IpNetwork> {
        let vpc_str = self.vpc_prefix.to_string();
        let used_prefixes = db::network_prefix::containing_prefix(txn, vpc_str.as_str())
            .await?
            .iter()
            .map(|x| x.prefix)
            .collect_vec();

        // Reminder that `new()` already validated self.prefix > self.vpc_prefix.prefix().
        let total_network_possible: u128 = 1u128 << (self.prefix - self.vpc_prefix.prefix()) as u32;
        let mut current_iteration: u128 = 0;
        let mut allocator_itr = self.iter();

        loop {
            let Some(next_address) = allocator_itr.next() else {
                return Err(CarbideError::internal("Prefix exhausted.".to_string()));
            };

            if !used_prefixes
                .iter()
                .any(|x| networks_overlap(*x, next_address))
            {
                return Ok(next_address);
            }

            if current_iteration > total_network_possible {
                return Err(CarbideError::internal(format!(
                    "IP address exhausted: {}",
                    self.vpc_prefix
                )));
            }
            current_iteration += 1;
        }
    }
}

/// PrefixIterator is only constructed by `PrefixAllocator::iter`, which
/// guarantees that `self.prefix` is a valid prefix length for the address
/// family, meaning the `IpNetwork::new(...).unwrap()` calls below are safe.
impl Iterator for PrefixIterator {
    type Item = IpNetwork;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first_iter {
            self.first_iter = false;
            let ip = u128_to_ip(self.current_item, self.is_v6);
            return Some(IpNetwork::new(ip, self.prefix).unwrap());
        }

        let max_bits = max_prefix_bits(&self.vpc_prefix);
        // Number of host bits in the needed prefix.
        let host_bits: u32 = max_bits - self.prefix as u32;
        // Mask for the network portion of the address.
        let prefix_network_subnet: u128 = if host_bits >= 128 {
            0
        } else {
            u128::MAX << host_bits
        };

        // Advance to the next network address at the correct prefix boundary.
        let next_address = (((self.current_item & prefix_network_subnet) >> host_bits)
            .wrapping_add(1))
            << host_bits;

        let ip = wrap_to_prefix_start(u128_to_ip(next_address, self.is_v6), &self.vpc_prefix);
        self.current_item = ip_to_u128(ip);
        Some(IpNetwork::new(ip, self.prefix).unwrap())
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv6Addr;

    use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

    use crate::network_segment::allocate::PrefixAllocator;

    #[test]
    fn test_next_iter() {
        let allocator = PrefixAllocator::new(
            uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f").into(),
            IpNetwork::V4(Ipv4Network::new("10.0.0.248".parse().unwrap(), 29).unwrap()),
            None,
            31,
        )
        .unwrap();

        let mut it = allocator.iter();

        assert_eq!(
            IpNetwork::V4(Ipv4Network::new("10.0.0.248".parse().unwrap(), 31).unwrap()),
            it.next().unwrap()
        );
        assert_eq!(
            IpNetwork::V4(Ipv4Network::new("10.0.0.250".parse().unwrap(), 31).unwrap()),
            it.next().unwrap()
        );
        assert_eq!(
            IpNetwork::V4(Ipv4Network::new("10.0.0.252".parse().unwrap(), 31).unwrap()),
            it.next().unwrap()
        );
        assert_eq!(
            IpNetwork::V4(Ipv4Network::new("10.0.0.254".parse().unwrap(), 31).unwrap()),
            it.next().unwrap()
        );
        // wrap around condition
        assert_eq!(
            IpNetwork::V4(Ipv4Network::new("10.0.0.248".parse().unwrap(), 31).unwrap()),
            it.next().unwrap()
        );
    }

    #[test]
    fn test_next_iter_overflow() {
        let allocator = PrefixAllocator::new(
            uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f").into(),
            IpNetwork::V4(Ipv4Network::new("202.164.25.0".parse().unwrap(), 30).unwrap()),
            None,
            31,
        )
        .unwrap();

        let mut it = allocator.iter();

        assert_eq!(
            IpNetwork::V4(Ipv4Network::new("202.164.25.0".parse().unwrap(), 31).unwrap()),
            it.next().unwrap()
        );
        assert_eq!(
            IpNetwork::V4(Ipv4Network::new("202.164.25.2".parse().unwrap(), 31).unwrap()),
            it.next().unwrap()
        );
        // Overflow condition.
        assert_eq!(
            IpNetwork::V4(Ipv4Network::new("202.164.25.0".parse().unwrap(), 31).unwrap()),
            it.next().unwrap()
        );
    }

    #[test]
    fn test_next_iter_ipv6() {
        // /120 VPC prefix with /127 linknets — 128 possible /127 subnets.
        let allocator = PrefixAllocator::new(
            uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f").into(),
            IpNetwork::V6(Ipv6Network::new("fd00::100".parse().unwrap(), 120).unwrap()),
            None,
            127,
        )
        .unwrap();

        let mut it = allocator.iter();

        assert_eq!(
            IpNetwork::V6(
                Ipv6Network::new(
                    Ipv6Addr::from(0xfd00_0000_0000_0000_0000_0000_0000_0100u128),
                    127
                )
                .unwrap()
            ),
            it.next().unwrap()
        );
        assert_eq!(
            IpNetwork::V6(
                Ipv6Network::new(
                    Ipv6Addr::from(0xfd00_0000_0000_0000_0000_0000_0000_0102u128),
                    127
                )
                .unwrap()
            ),
            it.next().unwrap()
        );
        assert_eq!(
            IpNetwork::V6(
                Ipv6Network::new(
                    Ipv6Addr::from(0xfd00_0000_0000_0000_0000_0000_0000_0104u128),
                    127
                )
                .unwrap()
            ),
            it.next().unwrap()
        );
    }

    #[test]
    fn test_next_iter_ipv6_wrap_around() {
        // /126 VPC prefix — only 4 addresses aka 2 possible /127 subnets.
        let allocator = PrefixAllocator::new(
            uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f").into(),
            IpNetwork::V6(Ipv6Network::new("fd00::4".parse().unwrap(), 126).unwrap()),
            None,
            127,
        )
        .unwrap();

        let mut it = allocator.iter();

        assert_eq!(
            IpNetwork::V6(
                Ipv6Network::new(
                    Ipv6Addr::from(0xfd00_0000_0000_0000_0000_0000_0000_0004u128),
                    127
                )
                .unwrap()
            ),
            it.next().unwrap()
        );
        assert_eq!(
            IpNetwork::V6(
                Ipv6Network::new(
                    Ipv6Addr::from(0xfd00_0000_0000_0000_0000_0000_0000_0006u128),
                    127
                )
                .unwrap()
            ),
            it.next().unwrap()
        );
        // Wrap around
        assert_eq!(
            IpNetwork::V6(
                Ipv6Network::new(
                    Ipv6Addr::from(0xfd00_0000_0000_0000_0000_0000_0000_0004u128),
                    127
                )
                .unwrap()
            ),
            it.next().unwrap()
        );
    }

    #[test]
    fn test_next_iter_ipv6_with_last_used() {
        // /120 VPC prefix, last_used_prefix at the first /127 subnet.
        let allocator = PrefixAllocator::new(
            uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f").into(),
            IpNetwork::V6(Ipv6Network::new("fd00::100".parse().unwrap(), 120).unwrap()),
            Some(IpNetwork::V6(
                Ipv6Network::new(
                    Ipv6Addr::from(0xfd00_0000_0000_0000_0000_0000_0000_0100u128),
                    127,
                )
                .unwrap(),
            )),
            127,
        )
        .unwrap();

        let mut it = allocator.iter();

        // Should start after the last used /127, i.e. at fd00::102.
        assert_eq!(
            IpNetwork::V6(
                Ipv6Network::new(
                    Ipv6Addr::from(0xfd00_0000_0000_0000_0000_0000_0000_0102u128),
                    127
                )
                .unwrap()
            ),
            it.next().unwrap()
        );
    }
}
