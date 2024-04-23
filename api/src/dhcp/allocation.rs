/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::net::IpAddr;

use ipnetwork::IpNetwork;
use patricia_tree::PatriciaMap;
use sqlx::{Postgres, Transaction};

use crate::{
    db::{
        address_selection_strategy::AddressSelectionStrategy, network_segment::NetworkSegment,
        DatabaseError,
    },
    CarbideError, CarbideResult,
};

#[async_trait::async_trait]
pub trait UsedIpResolver {
    // Method to get used IP for implementor.
    async fn used_ips(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<(IpAddr,)>, DatabaseError>;
}

#[derive(thiserror::Error, Debug)]
pub enum DhcpError {
    #[error("Missing circuit id received for instance id: {0}")]
    MissingCircuitId(uuid::Uuid),

    #[error("Missing circuit id received for machine id: {0}")]
    MissingCircuitIdForMachine(String),

    #[error("Invalid circuit id received for instance id: {0}, circuit_id: {1}")]
    InvalidCircuitId(uuid::Uuid, String),

    #[error("DHCP request received for invalid or non-configured interface for instance id: {0}, circuit_id: {1}")]
    InvalidInterface(uuid::Uuid, String),

    #[error("Prefix: {0} has exhausted all address space")]
    PrefixExhausted(IpAddr),

    #[error("Strategy not implemented yet.")]
    StrategyNotImplemented,

    #[error("Only IPV4 is supported. Got prefix: {0}")]
    OnlyIpv4Supported(IpNetwork),
}

// Trying to decouple from NetworkSegment as much as possible.
#[derive(Debug)]
pub struct Prefix {
    id: uuid::Uuid,
    prefix: IpNetwork,
    gateway: Option<IpAddr>,
    num_reserved: i32,
}

pub struct IpAllocator {
    prefixes: Vec<Prefix>,
    used_ips: Vec<(IpAddr,)>,
}

impl IpAllocator {
    pub async fn new(
        txn: &mut Transaction<'_, Postgres>,
        segment: &NetworkSegment,
        used_ip_resolver: &impl UsedIpResolver,
        address_strategy: AddressSelectionStrategy<'_>,
    ) -> Result<Self, CarbideError> {
        match address_strategy {
            AddressSelectionStrategy::Automatic => {
                let used_ips = used_ip_resolver.used_ips(&mut *txn).await?;

                Ok(IpAllocator {
                    prefixes: segment
                        .prefixes
                        .iter()
                        .map(|x| Prefix {
                            id: x.id,
                            prefix: x.prefix,
                            gateway: x.gateway,
                            num_reserved: x.num_reserved,
                        })
                        .collect(),
                    used_ips,
                })
            }
            _ => Err(CarbideError::from(DhcpError::StrategyNotImplemented)),
        }
    }

    // Populate and return the excluded_ips in this segment_prefix
    // Excluded ips include currently in use ips as well as the broadcast address,
    // gateway address and the reserved ips.
    pub fn get_excluded(&self, segment_prefix: &Prefix) -> PatriciaMap<()> {
        let mut excluded_ips: PatriciaMap<()> = PatriciaMap::new();

        excluded_ips.extend(
            self.used_ips
                .iter()
                .filter(|(ip,)| segment_prefix.prefix.contains(*ip))
                .map(|(ip,)| (to_vec(ip), ())),
        );

        // TODO: add gateway to the list of used IPs above?
        if let Some(gateway) = segment_prefix.gateway {
            excluded_ips.insert(to_vec(&gateway), ());
        }

        // Exclude the first "N" number of addresses
        //
        // The gateway will be excluded separately, so if `num_reserved` == 1` and that's
        // also the gateway address, then we'll exclude the same address twice, and you'll
        // get the second address.
        //
        excluded_ips.extend(
            segment_prefix
                .prefix
                .iter()
                .take(segment_prefix.num_reserved as usize)
                .map(|ip| (to_vec(&ip), ())),
        );

        if segment_prefix.prefix.prefix() < 31 {
            // Drop inetwork address.
            excluded_ips.insert(to_vec(&segment_prefix.prefix.network()), ());

            // Drop broadcast address.
            excluded_ips.insert(to_vec(&segment_prefix.prefix.broadcast()), ());
        }

        excluded_ips
    }

    // Return the number of available ips in this network segment
    pub fn num_free(&mut self) -> u32 {
        if self.prefixes.is_empty() {
            return 0;
        }

        let segment_prefix = &self.prefixes[0];
        if !segment_prefix.prefix.is_ipv4() {
            return 0;
        }

        let mut nfree: u32;

        let nfree_sz = segment_prefix.prefix.size();

        match nfree_sz {
            ipnetwork::NetworkSize::V4(nf) => nfree = nf,
            ipnetwork::NetworkSize::V6(_n128) => {
                return 0;
            }
        }

        let excluded_ips = self.get_excluded(segment_prefix);

        nfree -= excluded_ips.len() as u32;

        nfree
    }
}

impl Iterator for IpAllocator {
    /// The Item is a tuple that returns the prefix ID and the allocated IP for that prefix
    type Item = (uuid::Uuid, CarbideResult<IpAddr>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.prefixes.is_empty() {
            return None;
        }
        let segment_prefix = self.prefixes.remove(0);
        if !segment_prefix.prefix.is_ipv4() {
            return Some((
                segment_prefix.id,
                Err(CarbideError::from(DhcpError::OnlyIpv4Supported(
                    segment_prefix.prefix,
                ))),
            ));
        }

        let excluded_ips = self.get_excluded(&segment_prefix);

        // Iterate over all the IPs until we find one that's not in the map, that's our
        // first free IPs
        let mut maybe_first_free_ip = None;
        for address in segment_prefix.prefix.iter() {
            if !excluded_ips.contains_key(to_vec(&address)) {
                maybe_first_free_ip = Some(address);
                break;
            }
        }
        match maybe_first_free_ip {
            None => Some((
                segment_prefix.id,
                Err(DhcpError::PrefixExhausted(segment_prefix.prefix.ip()).into()),
            )),
            Some(ip) => Some((segment_prefix.id, Ok(ip))),
        }
    }
}

/// This looks dumb, because octets() isn't on IpAddr, only on IpXAddr
///
/// https://github.com/rust-lang/rfcs/issues/1881
///
pub fn to_vec(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_allocation() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.1.1.0/24".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.1.1.1".parse().unwrap())),
                num_reserved: 1,
            }],
            used_ips: vec![],
        };

        // Prefix 24 means 256 ips in subnet.
        //     num_reserved: 1
        //     gateway: 1
        //     broadcast: 1
        // network is part of num_reserved. So nfree is 256 - 3 = 253
        let nfree = allocator.num_free();
        assert_eq!(nfree, 253);

        let result = allocator.next().unwrap();
        assert_eq!(result.0, prefix_id);
        assert_eq!("10.1.1.2".parse::<IpAddr>().unwrap(), result.1.unwrap());
        assert!(allocator.next().is_none());

        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.1.1.0/24".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.1.1.1".parse().unwrap())),
                num_reserved: 1,
            }],
            used_ips: vec![(IpAddr::V4("10.1.1.2".parse().unwrap()),)], // The address we allocated above when we called next()
        };
        let nfree = allocator.num_free();
        assert_eq!(nfree, 252);
    }

    #[test]
    fn test_ip_allocation_ipv6_fail() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V6("ff01::0/32".parse().unwrap()),
                gateway: None,
                num_reserved: 1,
            }],
            used_ips: vec![],
        };
        let result = allocator.next().unwrap();
        assert_eq!(result.0, prefix_id);
        assert!(result.1.is_err());
        assert!(allocator.next().is_none());
    }

    #[test]
    fn test_ip_allocation_ipv4_and_6() {
        let prefix_id1 = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");
        let prefix_id2 = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1201");
        let mut allocator = IpAllocator {
            prefixes: vec![
                Prefix {
                    id: prefix_id1,
                    prefix: IpNetwork::V4("10.1.1.0/24".parse().unwrap()),
                    gateway: Some(IpAddr::V4("10.1.1.1".parse().unwrap())),
                    num_reserved: 1,
                },
                Prefix {
                    id: prefix_id2,
                    prefix: IpNetwork::V6("ff01::0/32".parse().unwrap()),
                    gateway: None,
                    num_reserved: 1,
                },
            ],
            used_ips: vec![],
        };
        let result = allocator.next().unwrap();
        assert_eq!(result.0, prefix_id1);
        assert_eq!("10.1.1.2".parse::<IpAddr>().unwrap(), result.1.unwrap());
        let result = allocator.next().unwrap();
        assert_eq!(result.0, prefix_id2);
        assert!(result.1.is_err());
        assert!(allocator.next().is_none());
    }

    #[test]
    fn test_ip_allocation_prefix_exhausted() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.1.1.0/30".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.1.1.1".parse().unwrap())),
                num_reserved: 4,
            }],
            used_ips: vec![],
        };

        let nfree = allocator.num_free();
        assert_eq!(nfree, 0);

        let result = allocator.next().unwrap();
        assert_eq!(result.0, prefix_id);
        assert!(result.1.is_err());
        assert!(allocator.next().is_none());
    }
    #[test]
    fn test_ip_allocation_broadcast_address_is_excluded() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.217.4.160/30".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.217.4.161".parse().unwrap())),
                num_reserved: 3,
            }],
            used_ips: vec![],
        };
        assert!(allocator.next().unwrap().1.is_err());
    }
    #[test]
    fn test_ip_allocation_network_broadcast_address_is_excluded() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");
        let allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.217.4.160/30".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.217.4.161".parse().unwrap())),
                num_reserved: 0,
            }],
            used_ips: vec![],
        };
        let result = allocator.map(|x| x.1.unwrap()).collect::<Vec<IpAddr>>()[0];
        assert_eq!(result, IpAddr::V4("10.217.4.162".parse().unwrap()));
    }
    #[test]
    fn test_ip_allocation_with_used_ips() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.217.4.160/28".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.217.4.161".parse().unwrap())),
                num_reserved: 1,
            }],
            used_ips: vec![
                (IpAddr::V4("10.217.4.162".parse().unwrap()),),
                (IpAddr::V4("10.217.4.163".parse().unwrap()),),
            ],
        };

        // Prefix: 28 means 16 ips in subnet
        //     Gateway : 1
        //     Reserved : 1
        //     Broadcast: 1
        //     Used_IPs: 2
        // nfree = 16 - 5 = 11
        let nfree = allocator.num_free();
        assert_eq!(nfree, 11);

        let result = allocator.map(|x| x.1.unwrap()).collect::<Vec<IpAddr>>()[0];
        assert_eq!(result, IpAddr::V4("10.217.4.164".parse().unwrap()));
    }
}

#[test]
fn test_to_vec_function() {
    let ip4_octs: Vec<u8> = vec![10, 217, 4, 160];
    let ip4_addr: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(
        ip4_octs[0],
        ip4_octs[1],
        ip4_octs[2],
        ip4_octs[3],
    ));

    let ret_octs: Vec<u8> = to_vec(&ip4_addr);

    assert_eq!(ret_octs.len(), 4);

    for i in 0..4 {
        assert_eq!(ret_octs[i], ip4_octs[i]);
    }
}
