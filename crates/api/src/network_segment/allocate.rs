/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::net::Ipv4Addr;

use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use ipnetwork::Ipv4Network;
use itertools::Itertools;
use model::network_prefix::NewNetworkPrefix;
use model::network_segment::NewNetworkSegment;
use sqlx::PgConnection;

use crate::{CarbideError, CarbideResult};

/// Ipv4PrefixAllocator to allocate a prefix of given length from given vpc_prefix field.
#[derive(Debug)]
pub struct Ipv4PrefixAllocator {
    vpc_prefix_id: VpcPrefixId,
    vpc_prefix: Ipv4Network,
    last_used_prefix: Option<Ipv4Network>,
    prefix: u8,
}

// A iterator keeping track of previously allocated item.
#[derive(Debug)]
struct Ipv4PrefixIterator {
    vpc_prefix: Ipv4Network,
    prefix: u8,
    current_item: Ipv4Addr,
    first_iter: bool,
}

/// This function returns the IP which is just next the boundary of last allocated prefix.
/// Problem with this approach is that if prefix changes e.g. 31 to 27, the next IP of /31 is not a
/// valid network address for /27. In this case this function ignores such address and moves to the
/// valid /27 network. Handles wrap-around conditions also.
fn get_next_usable_address(ip: Ipv4Addr, vpc_prefix: Ipv4Network, needed_prefix: u8) -> Ipv4Addr {
    let next_address = u32::from_be_bytes(ip.octets()).wrapping_add(1);
    let mut next_address = Ipv4Addr::from(next_address);
    let next_prefix = Ipv4Network::new(next_address, needed_prefix).unwrap();

    if next_address != next_prefix.network() {
        // The next_address is not at the beginning of prefix boundary. In this case, take the
        // broadcast address of prefix and take first address from it.
        let next_address_u32 = u32::from_be_bytes(next_prefix.broadcast().octets()).wrapping_add(1);
        next_address = Ipv4Addr::from(next_address_u32);
    }

    if next_address < vpc_prefix.network() || next_address > vpc_prefix.broadcast() {
        // reset to the first address.
        vpc_prefix.network()
    } else {
        next_address
    }
}

impl Ipv4PrefixAllocator {
    fn iter(&self) -> Ipv4PrefixIterator {
        let next_usable_address = if let Some(last_used_prefix) = self.last_used_prefix {
            get_next_usable_address(last_used_prefix.broadcast(), self.vpc_prefix, self.prefix)
        } else {
            self.vpc_prefix.network()
        };

        Ipv4PrefixIterator {
            vpc_prefix: self.vpc_prefix,
            prefix: self.prefix,
            current_item: next_usable_address,
            first_iter: true,
        }
    }

    pub fn new(
        vpc_prefix_id: VpcPrefixId,
        vpc_prefix: Ipv4Network,
        last_used_prefix: Option<Ipv4Network>,
        prefix: u8,
    ) -> Ipv4PrefixAllocator {
        Self {
            vpc_prefix_id,
            vpc_prefix,
            last_used_prefix,
            prefix,
        }
    }

    // This should only be used by FNN code.
    pub async fn allocate_network_segment(
        &self,
        txn: &mut PgConnection,
        vpc_id: VpcId,
    ) -> CarbideResult<(NetworkSegmentId, Ipv4Network)> {
        let prefix = self.next_free_prefix(txn).await?;

        let name = format!("vpc_prefix_{}", prefix.network());
        let segment_id = NetworkSegmentId::new();

        let ns = NewNetworkSegment {
            id: segment_id,
            name,
            subdomain_id: None,
            vpc_id: Some(vpc_id),
            mtu: 9000, // Default value
            prefixes: vec![NewNetworkPrefix {
                prefix: prefix.into(),
                gateway: Some(prefix.network().into()),
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
            db::network_prefix::set_vpc_prefix(
                prefix,
                txn,
                &self.vpc_prefix_id,
                &ipnetwork::IpNetwork::V4(self.vpc_prefix),
            )
            .await?;
        }

        Ok((segment.id, prefix))
    }

    pub async fn next_free_prefix(&self, txn: &mut PgConnection) -> CarbideResult<Ipv4Network> {
        let vpc_str = self.vpc_prefix.to_string();
        let used_prefixes = db::network_prefix::containing_prefix(txn, vpc_str.as_str())
            .await?
            .iter()
            .filter_map(|x| match x.prefix {
                ipnetwork::IpNetwork::V4(ipv4net) => Some(ipv4net),
                _ => None,
            })
            .collect_vec();

        if self.prefix <= self.vpc_prefix.prefix() {
            return Err(CarbideError::InvalidArgument(format!(
                "vpc prefix {} is smaller than requested prefix {}",
                self.vpc_prefix.prefix(),
                self.prefix
            )));
        }
        let total_network_possible = 2_u32.pow((self.prefix - self.vpc_prefix.prefix()) as u32);
        let mut current_iteration = 0_u32;
        let mut allocator_itr = self.iter();

        loop {
            let Some(next_address) = allocator_itr.next() else {
                return Err(CarbideError::internal("Prefix exhausted.".to_string()));
            };

            if !used_prefixes.iter().any(|x| x.overlaps(next_address)) {
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

const MAX_PREFIX_LEN: u32 = 32_u32;
impl Iterator for Ipv4PrefixIterator {
    type Item = Ipv4Network;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first_iter {
            self.first_iter = false;
            return Some(Ipv4Network::new(self.current_item, self.prefix).unwrap());
        }
        let current_item = u32::from_be_bytes(self.current_item.octets());

        // Number of host bits in needed prefix.
        let host_bits: u32 = MAX_PREFIX_LEN - self.prefix as u32;
        // Binary representation of needed prefix network subnet bits. e.g.
        // /27 = 11111111.11111111.11111111.11100000
        let prefix_network_subnet = u32::MAX << host_bits;

        // Take the network address from the current item and increase it by one to get the next
        // network address. e.g.
        // current_item = 192.168.50.64
        // current_item & prefix_network_subnet = 11000000.10101000.00110010.01000000
        // >> host_bits =  00000110000001010100000110010010 => +1 = 00000110000001010100000110010011
        // => 11000000.10101000.00110010.01100000 => 192.168.50.96
        let next_address =
            (((current_item & prefix_network_subnet) >> host_bits).wrapping_add(1)) << host_bits;
        let next_address = Ipv4Addr::from(next_address);

        let next_address = if next_address > self.vpc_prefix.broadcast()
            || next_address < self.vpc_prefix.network()
        {
            // wrap around or overflow condition
            // network() is the first address of the subnet and broadcast() the last possible.
            self.vpc_prefix.network()
        } else {
            next_address
        };

        self.current_item = next_address;
        Some(Ipv4Network::new(next_address, self.prefix).unwrap())
    }
}

#[cfg(test)]
mod test {
    use ipnetwork::Ipv4Network;

    use crate::network_segment::allocate::Ipv4PrefixAllocator;

    #[test]
    fn test_next_iter() {
        let allocator = Ipv4PrefixAllocator::new(
            uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f").into(),
            Ipv4Network::new("10.0.0.248".parse().unwrap(), 29).unwrap(),
            None,
            31,
        );

        let mut it = allocator.iter();

        assert_eq!(
            Ipv4Network::new("10.0.0.248".parse().unwrap(), 31).unwrap(),
            it.next().unwrap()
        );
        assert_eq!(
            Ipv4Network::new("10.0.0.250".parse().unwrap(), 31).unwrap(),
            it.next().unwrap()
        );
        assert_eq!(
            Ipv4Network::new("10.0.0.252".parse().unwrap(), 31).unwrap(),
            it.next().unwrap()
        );
        assert_eq!(
            Ipv4Network::new("10.0.0.254".parse().unwrap(), 31).unwrap(),
            it.next().unwrap()
        );
        // wrap around condition
        assert_eq!(
            Ipv4Network::new("10.0.0.248".parse().unwrap(), 31).unwrap(),
            it.next().unwrap()
        );
    }

    #[test]
    fn test_next_iter_overflow() {
        let allocator = Ipv4PrefixAllocator::new(
            uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f").into(),
            Ipv4Network::new("202.164.25.0".parse().unwrap(), 30).unwrap(),
            None,
            31,
        );

        let mut it = allocator.iter();

        assert_eq!(
            Ipv4Network::new("202.164.25.0".parse().unwrap(), 31).unwrap(),
            it.next().unwrap()
        );
        assert_eq!(
            Ipv4Network::new("202.164.25.2".parse().unwrap(), 31).unwrap(),
            it.next().unwrap()
        );
        // Overflow condition.
        assert_eq!(
            Ipv4Network::new("202.164.25.0".parse().unwrap(), 31).unwrap(),
            it.next().unwrap()
        );
    }
}
