/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use sqlx::{self, Postgres, Transaction};

use crate::{
    db::{address_selection_strategy::AddressSelectionStrategy, network_segment::NetworkSegment},
    CarbideError, CarbideResult,
};

#[async_trait::async_trait]
pub trait FreeIpResolver {
    // Method to get used IP for implementor.
    async fn used_ips(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<Vec<(IpNetwork,)>>;
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
struct Prefix {
    prefix: IpNetwork,
    gateway: Option<IpNetwork>,
    num_reserved: i32,
}

pub struct IpAllocator {
    prefixes: Vec<Prefix>,
    used_ips: Vec<(IpNetwork,)>,
}

impl IpAllocator {
    pub async fn new(
        txn: &mut Transaction<'_, Postgres>,
        segment: &NetworkSegment,
        free_ip_resolver: &impl FreeIpResolver,
        address_strategy: AddressSelectionStrategy<'_>,
    ) -> Result<Self, CarbideError> {
        match address_strategy {
            AddressSelectionStrategy::Automatic => {
                let used_ips = free_ip_resolver.used_ips(&mut *txn).await?;

                Ok(IpAllocator {
                    prefixes: segment
                        .prefixes
                        .iter()
                        .map(|x| Prefix {
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
}

impl Iterator for IpAllocator {
    type Item = CarbideResult<IpAddr>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.prefixes.is_empty() {
            return None;
        }
        let segment_prefix = self.prefixes.remove(0);
        if !segment_prefix.prefix.is_ipv4() {
            return Some(Err(CarbideError::from(DhcpError::OnlyIpv4Supported(
                segment_prefix.prefix,
            ))));
        }

        let mut excluded_ips: PatriciaMap<()> = PatriciaMap::new();

        /// This looks dumb, because octets() isn't on IpAddr, only on IpXAddr
        ///
        /// https://github.com/rust-lang/rfcs/issues/1881
        ///
        fn to_vec(addr: &IpAddr) -> Vec<u8> {
            match addr {
                IpAddr::V4(address) => address.octets().to_vec(),
                IpAddr::V6(address) => address.octets().to_vec(),
            }
        }

        excluded_ips.extend(self.used_ips.iter().filter_map(|(ip,)| {
            segment_prefix
                .prefix
                .contains(ip.ip())
                .then(|| (to_vec(&ip.ip()), ()))
        }));

        // TODO: add gateway to the list of used IPs above?
        if let Some(gateway) = segment_prefix.gateway {
            excluded_ips.insert(to_vec(&gateway.ip()), ());
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

        // Iterate over all the IPs until we find one that's not in the map, that's our
        // first free IPs
        Some(
            segment_prefix
                .prefix
                .iter()
                .find_map(|address| {
                    excluded_ips
                        .get(to_vec(&address))
                        .is_none()
                        .then_some(address)
                })
                .ok_or_else(|| DhcpError::PrefixExhausted(segment_prefix.prefix.ip()))
                .map_err(CarbideError::from),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_allocation() {
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                prefix: IpNetwork::V4("10.1.1.0/24".parse().unwrap()),
                gateway: Some(IpNetwork::V4("10.1.1.1".parse().unwrap())),
                num_reserved: 1,
            }],
            used_ips: vec![],
        };
        assert_eq!(
            "10.1.1.2".parse::<IpAddr>().unwrap(),
            allocator.next().unwrap().unwrap()
        );
        assert!(allocator.next().is_none());
    }

    #[test]
    fn test_ip_allocation_ipv6_fail() {
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                prefix: IpNetwork::V6("ff01::0/32".parse().unwrap()),
                gateway: None,
                num_reserved: 1,
            }],
            used_ips: vec![],
        };
        assert!(allocator.next().unwrap().is_err());
        assert!(allocator.next().is_none());
    }

    #[test]
    fn test_ip_allocation_ipv4_and_6() {
        let mut allocator = IpAllocator {
            prefixes: vec![
                Prefix {
                    prefix: IpNetwork::V4("10.1.1.0/24".parse().unwrap()),
                    gateway: Some(IpNetwork::V4("10.1.1.1".parse().unwrap())),
                    num_reserved: 1,
                },
                Prefix {
                    prefix: IpNetwork::V6("ff01::0/32".parse().unwrap()),
                    gateway: None,
                    num_reserved: 1,
                },
            ],
            used_ips: vec![],
        };
        assert_eq!(
            "10.1.1.2".parse::<IpAddr>().unwrap(),
            allocator.next().unwrap().unwrap()
        );
        assert!(allocator.next().unwrap().is_err());
        assert!(allocator.next().is_none());
    }

    #[test]
    fn test_ip_allocation_prefix_exhausted() {
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                prefix: IpNetwork::V4("10.1.1.0/30".parse().unwrap()),
                gateway: Some(IpNetwork::V4("10.1.1.1".parse().unwrap())),
                num_reserved: 4,
            }],
            used_ips: vec![],
        };
        assert!(allocator.next().unwrap().is_err());
        assert!(allocator.next().is_none());
    }
}
