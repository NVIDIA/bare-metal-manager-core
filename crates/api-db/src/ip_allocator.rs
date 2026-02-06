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

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use carbide_uuid::instance::InstanceId;
use carbide_uuid::network::NetworkPrefixId;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use model::address_selection_strategy::AddressSelectionStrategy;
use model::network_prefix::NetworkPrefix;
use model::network_segment::NetworkSegment;
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

#[async_trait::async_trait]
pub trait UsedIpResolver<DB>
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    // used_ips is expected to return used (or allocated)
    // IPs as reported by whoever implements this trait.
    async fn used_ips(&self, txn: &mut DB) -> Result<Vec<IpAddr>, DatabaseError>;

    // Method to get used/allocated IPs for implementor.
    // Since the allocated IPs may actually be allocated
    // networks (like in the case of FNN), this returns
    // IpNetworks (and, coincidentally, the Postgres `inet`
    // type supports this, since `inet` supports the
    // ability to set a prefix length (with /32 being the
    // implied default).
    async fn used_prefixes(&self, txn: &mut DB) -> Result<Vec<IpNetwork>, DatabaseError>;
}

#[derive(thiserror::Error, Debug)]
pub enum DhcpError {
    #[error("Missing circuit id received for instance id: {0}")]
    MissingCircuitId(InstanceId),

    #[error("Missing circuit id received for machine id: {0}")]
    MissingCircuitIdForMachine(String),

    #[error("Prefix: {0} has exhausted all address space")]
    PrefixExhausted(IpAddr),

    #[error("Only IPV4 is supported. Got prefix: {0}")]
    OnlyIpv4Supported(IpNetwork),
}

// Trying to decouple from NetworkSegment as much as possible.
#[derive(Debug)]
pub struct Prefix {
    pub id: NetworkPrefixId,
    pub prefix: IpNetwork,
    pub gateway: Option<IpAddr>,
    pub num_reserved: i32,
}

// NetworkDetails is a small struct used primarily
// by next_available_prefix, which is populated based
// on an input IpNetwork and prefix_length.
struct NetworkDetails {
    // base_ip is the base IP of the source IpNetwork.
    // In the case of next_available_prefix, this ends
    // up being used to iterate by `network_size` up
    // until `broadcast_ip` is reached.
    base_ip: u128,

    // broadcast_ip is the broadcast IP of the source
    // IpNetwork, and ultimately ends up being used
    // to end the search iteration.
    broadcast_ip: u128,

    // network_size is the size of the network that
    // we're trying to allocate. It just takes
    // the prefix length and turns it into the network
    // size, allowing the search iteration to step
    // by `network_size`.
    network_size: u128,
}

/// IpAllocator is used to allocate the next available IP(s)
/// for a given network segment. It scans over all available
/// prefixes, getting the already-allocated IPs for each
/// prefix, and then attempting to allocate a new network
/// of size prefix_length.
///
/// This used to simply allocate a single IP. However, with
/// FNN, allocations changed from a single IP to multiple IPs,
/// more specifically, a /30 network per DPU, so we had to
/// change from finding the next available IP address to instead
/// finding the next available *network* address.
pub struct IpAllocator {
    prefixes: Vec<Prefix>,
    used_ips: Vec<IpNetwork>,
    prefix_length: u8,
}

impl IpAllocator {
    pub async fn new<DB>(
        db: &mut DB,
        segment: &NetworkSegment,
        used_ip_resolver: Box<dyn UsedIpResolver<DB> + Send>,
        address_strategy: AddressSelectionStrategy,
        prefix_length: u8,
    ) -> DatabaseResult<Self>
    where
        for<'db> &'db mut DB: DbReader<'db>,
    {
        match address_strategy {
            AddressSelectionStrategy::Automatic => {
                let used_ips = used_ip_resolver.used_prefixes(db).await?;

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
                    prefix_length,
                })
            }
        }
    }

    /// get_allocated populates and returns already-allocated IPs
    /// in the given segment_prefix, which includes the:
    ///
    ///   - Gateway address (if set).
    ///   - Any reserved IPs (derived from `num_reserved`).
    ///   - Used IP networks already allocated to tenants, which could
    ///     be a /32, a /30 (in the case of FNN), etc.
    ///
    /// This works by building a list of already-allocated IP networks
    /// in a given segment prefix (by calling build_allocated_networks, which
    /// takes the segment prefix to find the next available IP in, and the
    /// existing tenant-mapped IPs), and then collapsing them down, where
    /// collapsing means removing duplicate IpNetworks, removing smaller
    /// IpNetworks which are covered by larger IpNetworks, etc.
    pub fn get_allocated(&self, segment_prefix: &Prefix) -> DatabaseResult<Vec<IpNetwork>> {
        let allocated_ips = build_allocated_networks(segment_prefix, &self.used_ips)?;
        Ok(collapse_allocated_networks(&allocated_ips))
    }

    /// num_free returns the number of available IPs in this network segment
    /// by getting the size of the network segment, then subtracting the number
    /// of IPs in use by allocated networks in the segment.
    pub fn num_free(&mut self) -> DatabaseResult<u32> {
        if self.prefixes.is_empty() {
            return Ok(0);
        }

        let segment_prefix = &self.prefixes[0];
        if !segment_prefix.prefix.is_ipv4() {
            return Err(DatabaseError::from(DhcpError::OnlyIpv4Supported(
                segment_prefix.prefix,
            )));
        }

        let total_ips = get_network_size(&segment_prefix.prefix)?;

        let allocated_ips = self
            .get_allocated(segment_prefix)
            .map_err(|e| DatabaseError::internal(format!("failed to get_allocated: {e}")))?;

        let total_allocated: u32 =
            allocated_ips
                .iter()
                .try_fold(0, |total_allocated, allocated_ip| {
                    Ok::<u32, DatabaseError>(total_allocated + get_network_size(allocated_ip)?)
                })?;

        Ok(total_ips - total_allocated)
    }
}

impl Iterator for IpAllocator {
    // The Item is a tuple that returns the prefix ID and the
    // allocated network for that prefix.
    type Item = (NetworkPrefixId, DatabaseResult<IpNetwork>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.prefixes.is_empty() {
            return None;
        }
        let segment_prefix = self.prefixes.remove(0);
        if !segment_prefix.prefix.is_ipv4() {
            return Some((
                segment_prefix.id,
                Err(DatabaseError::from(DhcpError::OnlyIpv4Supported(
                    segment_prefix.prefix,
                ))),
            ));
        }

        let allocated_ips = match self.get_allocated(&segment_prefix) {
            Ok(allocated) => allocated,
            Err(e) => {
                return Some((
                    segment_prefix.id,
                    Err(DatabaseError::internal(format!(
                        "failed to get allocated IPs for prefix: {} (err: {})",
                        segment_prefix.prefix, e
                    ))),
                ));
            }
        };

        // And now get the next available network prefix of prefix_length
        // from the segment prefix, taking into account any existing
        // allocated IPs (see the docstring for get_allocated for an explanation
        // about what allocated IPs are).
        let next_available_prefix =
            match next_available_prefix(segment_prefix.prefix, self.prefix_length, allocated_ips) {
                Ok(prefix) => prefix,
                Err(e) => {
                    return Some((
                        segment_prefix.id,
                        Err(DatabaseError::internal(format!(
                            "failed to get next available for prefix: {} (err: {})",
                            segment_prefix.prefix, e
                        ))),
                    ));
                }
            };

        match next_available_prefix {
            None => Some((
                segment_prefix.id,
                Err(DhcpError::PrefixExhausted(segment_prefix.prefix.ip()).into()),
            )),
            Some(network) => Some((segment_prefix.id, Ok(network))),
        }
    }
}

/// This is a simple function which shortcuts all the IpAllocator logic for the specific case where
/// we know we only want a single IPv4 /32. It finds the next IP in a single database query, which
/// can be much faster than loading all used IP's from the database and selecting the next one
/// locally, especially during ingestion when we are allocating lots of IP's at once.
pub async fn next_machine_interface_v4_ip(
    txn: &mut PgConnection,
    prefix: &NetworkPrefix,
) -> DatabaseResult<Option<IpAddr>> {
    if prefix.gateway.is_none() {
        let nr = prefix.num_reserved.max(2); // Reserve network and gateway addresses at least
        let query = r#"
SELECT ($1::inet + ip_series.n)::inet AS ip
FROM generate_series($3, (1 << (32 - $2)) - 2) AS ip_series(n)
LEFT JOIN machine_interface_addresses AS mia
  ON mia.address = ($1::inet + ip_series.n)::inet
WHERE mia.address IS NULL
ORDER BY ip
LIMIT 1;
    "#;

        sqlx::query_scalar(query)
            .bind(prefix.prefix.ip())
            .bind(prefix.prefix.prefix() as i32)
            .bind(nr)
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    } else {
        let nr = prefix.num_reserved.max(1); // Reserve network address at least
        let gw = prefix.gateway.unwrap();
        let query = r#"
SELECT ($1::inet + ip_series.n)::inet AS ip
FROM generate_series($3, (1 << (32 - $2)) - 2) AS ip_series(n)
LEFT JOIN machine_interface_addresses AS mia
  ON mia.address = ($1::inet + ip_series.n)::inet
WHERE mia.address IS NULL
  AND ($1::inet + ip_series.n)::inet <> $4::inet
ORDER BY ip
LIMIT 1;
    "#;

        sqlx::query_scalar(query)
            .bind(prefix.prefix.ip())
            .bind(prefix.prefix.prefix() as i32)
            .bind(nr)
            .bind(gw)
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }
}

/// build_allocated_networks builds a list of IpNetworks that have
/// already been allocated for a given segment prefix. This includes:
///
///   - Gateway address (if set).
///   - Any reserved IPs (derived from `num_reserved`).
///   - Used IP networks already allocated to tenants, which could
///     be a /32, a /30 (in the case of FNN), etc.
///
/// The reason IpNetworks are returned, and not IpAddr, is primary
/// for cases like FNN, where something larger than a /32 may be
/// allocated to a tenant interface.
fn build_allocated_networks(
    segment_prefix: &Prefix,
    used_ips: &[IpNetwork],
) -> DatabaseResult<Vec<IpNetwork>> {
    let mut allocated_ips: Vec<IpNetwork> = Vec::new();

    // First, if the segment prefix has a configured gateway (which comes
    // from the `network_prefixes` table), make sure to add the gateway
    // to already-allocated IPs.
    if let Some(gateway) = segment_prefix.gateway
        && segment_prefix.prefix.contains(gateway)
    {
        allocated_ips.push(IpNetwork::new(gateway, 32)?);
    }

    // Next, exclude the first "N" number of addresses in the segment
    // from being allocated to a tenant -- just treat them as allocated.
    //
    // If the first address also happens to be the gateway address, and
    // the gateway address is set for this network prefix, then it just
    // gets added twice (and will be de-duplicated later).
    for next_ip in segment_prefix
        .prefix
        .iter()
        .take(segment_prefix.num_reserved as usize)
    {
        let next_net = IpNetwork::new(next_ip, 32)?;
        allocated_ips.push(next_net);
    }

    // And if the segment we're allocating from is a /30 or larger,
    // drop the network and broadcast addresses from being
    // assignable to tenants.
    //
    // TODO(chet): Do we still want this here, and/or do we
    // want to change it in some way?
    if segment_prefix.prefix.prefix() < 31 {
        allocated_ips.push(IpNetwork::new(segment_prefix.prefix.network(), 32)?);
        allocated_ips.push(IpNetwork::new(segment_prefix.prefix.broadcast(), 32)?);
    }

    // Finally, add all of the aleady-allocated networks that were pulled
    // from the database for this segment, adding them in if they are
    // contained within the current segment prefix being worked on.
    allocated_ips.extend(
        used_ips
            .iter()
            .filter(|allocated| segment_prefix.prefix.contains(allocated.network())),
    );

    Ok(allocated_ips)
}

// collapse_allocated_networks takes a list of allocated CIDRs,
// which can be a mix of networks with varying prefix lengths,
// including /32 (single IP), and /30 (FNN), and returns a
// [collapsed] list of allocated networks.
//
// This will weed out any smaller networks which are covered by
// larger networks, dropping duplicate nework entries, etc.
fn collapse_allocated_networks(input_networks: &[IpNetwork]) -> Vec<IpNetwork> {
    let mut collapsed_networks: Vec<&IpNetwork> = input_networks.iter().collect();

    // Sort the input `allocated_cidrs` in descending order. The
    // idea here is we start with smaller networks in an outer
    // iteration, and then check to see if any of the larger
    // networks [below] contain the smaller ones.
    // parsed_allocated_cidrs.sort_by(|a, b| b.prefix().cmp(&a.prefix()));
    collapsed_networks.sort_by_key(|b| std::cmp::Reverse(b.prefix()));

    // And now iterate over the allocated CIDRs and check
    // to see if any of the smaller networks are covered
    // by the larger ones.
    collapsed_networks
        .drain(..)
        .fold(BTreeSet::new(), |mut btree_set, this_network| {
            if !btree_set
                .iter()
                .any(|existing_net: &IpNetwork| existing_net.contains(this_network.network()))
            {
                btree_set.insert(*this_network);
            }
            btree_set
        })
        .into_iter()
        .collect()
}

/// get_network_size wraps IpNetwork.size() with a check to make sure
/// the IpNetwork is an IPv4 network (since we currently don't support
/// IPv6 networks).
fn get_network_size(ip_network: &IpNetwork) -> DatabaseResult<u32> {
    match ip_network.size() {
        ipnetwork::NetworkSize::V4(total_ips) => Ok(total_ips),
        ipnetwork::NetworkSize::V6(_) => Err(DatabaseError::from(DhcpError::OnlyIpv4Supported(
            *ip_network,
        ))),
    }
}

// get_network_details computes some details to be
// used by next_available_prefix, including the
// base IP for the network segment, the broadcast IP,
// and the network_size of the new allocation that we're
// trying to.. well.. allocate.
//
// You'll notice this stores values as u128 -- this is
// just to make it easier for stepping in the search
// loop, since I can just current_ip += network_size.
fn get_network_details(network_segment: &IpNetwork, prefix_length: u8) -> NetworkDetails {
    let (base_ip, network_size, broadcast_ip) = match network_segment {
        IpNetwork::V4(net) => {
            let base_ip = u32::from(net.network());
            let network_size = 1 << (32 - prefix_length);
            let broadcast_ip = u32::from(net.broadcast());
            (base_ip as u128, network_size as u128, broadcast_ip as u128)
        }
        IpNetwork::V6(net) => {
            let base_ip = u128::from(net.network());
            let network_size = 1 << (128 - prefix_length);
            let broadcast_ip = u128::from(net.broadcast());
            (base_ip, network_size, broadcast_ip)
        }
    };

    NetworkDetails {
        base_ip,
        network_size,
        broadcast_ip,
    }
}

/// build_candidate_subnet builds the next candidate network
/// prefix. Even though we currently don't support IPv6 yet,
/// we allow for V6 here.
fn build_candidate_subnet(
    network: IpNetwork,
    current_ip: u128,
    prefix_length: u8,
) -> DatabaseResult<IpNetwork> {
    match network {
        IpNetwork::V4(_) => {
            let ipv4_net = Ipv4Network::new(Ipv4Addr::from(current_ip as u32), prefix_length)?;
            Ok(IpNetwork::V4(ipv4_net))
        }
        IpNetwork::V6(_) => {
            let ipv6_net = Ipv6Network::new(Ipv6Addr::from(current_ip), prefix_length)?;
            Ok(IpNetwork::V6(ipv6_net))
        }
    }
}

// next_available_prefix takes an network prefix from
// a network segment, the current allocated CIDRs within
// that prefix, and the size of the next prefix you would
// like to allocate. It then finds the next valid subnet
// of the provided prefix length that can be allocated.
//
// Note that this will fill in fragmentation. For example,
// if you allocate some /32, such that a /30 needs to skip
// to the next valid/allocatable /30, there will of course
// be some fragmentation. However, if you then ask for a /32
// or a /31, it will be able to allocate that next subnet
// within the available space; we try not to waste IPs!
fn next_available_prefix(
    network_segment: IpNetwork,
    prefix_length: u8,
    allocated_networks: Vec<IpNetwork>,
) -> DatabaseResult<Option<IpNetwork>> {
    if prefix_length <= network_segment.prefix() {
        return Err(DatabaseError::internal(format!(
            "requested prefix length ({}) must be greater than the network segment prefix length ({})",
            prefix_length,
            network_segment.prefix()
        )));
    }

    // Now take the starting IP from the input `network_prefix`,
    // and scan the entire range (up until the broadcast IP), stepping
    // by the network size for each iteration.
    let network_details = get_network_details(&network_segment, prefix_length);
    let mut current_ip = network_details.base_ip;
    while current_ip <= network_details.broadcast_ip {
        // Define the next candidate subnet, and then check allocated_networks
        // to see if there is any relationship between the candidate and each
        // allocated network.
        let candidate_subnet = build_candidate_subnet(network_segment, current_ip, prefix_length)?;
        let is_allocated = allocated_networks.iter().any(|allocated_network| {
            allocated_network.contains(candidate_subnet.network())
                || candidate_subnet.contains(allocated_network.network())
        });

        // If it isn't allocated, we have our candidate!
        if !is_allocated {
            return Ok(Some(candidate_subnet));
        }

        // Otherwise, jump to the next network based on the
        // requested prefix_length, and see if the next candidate
        // subnet is our winner winner chicken dinner.
        current_ip += network_details.network_size;
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_allocation() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let prefix_length = 32;
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.1.1.0/24".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.1.1.1".parse().unwrap())),
                num_reserved: 1,
            }],
            used_ips: vec![],
            prefix_length,
        };

        // Prefix 24 means 256 ips in subnet.
        //     num_reserved: 1
        //     gateway: 1
        //     broadcast: 1
        // network is part of num_reserved. So nfree is 256 - 3 = 253
        let nfree = allocator.num_free().unwrap();
        assert_eq!(nfree, 253);

        let result = allocator.next().unwrap();
        let expected: IpNetwork = format!("10.1.1.2/{prefix_length}").parse().unwrap();
        assert_eq!(result.0, prefix_id);
        assert_eq!(result.1.unwrap(), expected);
        assert!(allocator.next().is_none());

        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.1.1.0/24".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.1.1.1".parse().unwrap())),
                num_reserved: 1,
            }],
            used_ips: vec!["10.1.1.2".parse().unwrap()], // The address we allocated above when we called next()
            prefix_length: 32,
        };
        let nfree = allocator.num_free().unwrap();
        assert_eq!(nfree, 252);
    }

    #[test]
    fn test_ip_allocation_ipv6_fail() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V6("ff01::0/32".parse().unwrap()),
                gateway: None,
                num_reserved: 1,
            }],
            used_ips: vec![],
            prefix_length: 32,
        };
        let result = allocator.next().unwrap();
        assert_eq!(result.0, prefix_id);
        assert!(result.1.is_err());
        assert!(allocator.next().is_none());
    }

    #[test]
    fn test_ip_allocation_ipv4_and_6() {
        let prefix_id1 = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let prefix_id2 = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1201").into();
        let prefix_length = 32;
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
            prefix_length,
        };
        let result = allocator.next().unwrap();
        let expected: IpNetwork = format!("10.1.1.2/{prefix_length}").parse().unwrap();
        assert_eq!(result.0, prefix_id1);
        assert_eq!(result.1.unwrap(), expected);

        let result = allocator.next().unwrap();
        assert_eq!(result.0, prefix_id2);
        assert!(result.1.is_err());
        assert!(allocator.next().is_none());
    }

    #[test]
    fn test_ip_allocation_prefix_exhausted() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.1.1.0/30".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.1.1.1".parse().unwrap())),
                num_reserved: 4,
            }],
            used_ips: vec![],
            prefix_length: 32,
        };

        let nfree = allocator.num_free().unwrap();
        assert_eq!(nfree, 0);

        let result = allocator.next().unwrap();
        assert_eq!(result.0, prefix_id);
        assert!(result.1.is_err());
        assert!(allocator.next().is_none());
    }
    #[test]
    fn test_ip_allocation_broadcast_address_is_excluded() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.217.4.160/30".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.217.4.161".parse().unwrap())),
                num_reserved: 3,
            }],
            used_ips: vec![],
            prefix_length: 32,
        };
        assert!(allocator.next().unwrap().1.is_err());
    }
    #[test]
    fn test_ip_allocation_network_broadcast_address_is_excluded() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let prefix_length = 32;
        let allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.217.4.160/30".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.217.4.161".parse().unwrap())),
                num_reserved: 0,
            }],
            used_ips: vec![],
            prefix_length,
        };
        let result = allocator.map(|x| x.1.unwrap()).collect::<Vec<IpNetwork>>()[0];
        let expected: IpNetwork = format!("10.217.4.162/{prefix_length}").parse().unwrap();
        assert_eq!(result, expected);
    }
    #[test]
    fn test_ip_allocation_with_used_ips() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let prefix_length = 32;
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.217.4.160/28".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.217.4.161".parse().unwrap())),
                num_reserved: 1,
            }],
            used_ips: vec![
                "10.217.4.162".parse().unwrap(),
                "10.217.4.163".parse().unwrap(),
            ],
            prefix_length,
        };

        // Prefix: 28 means 16 ips in subnet
        //     Gateway : 1
        //     Reserved : 1
        //     Broadcast: 1
        //     Used_IPs: 2
        // nfree = 16 - 5 = 11
        let nfree = allocator.num_free().unwrap();
        assert_eq!(nfree, 11);

        let result = allocator.map(|x| x.1.unwrap()).collect::<Vec<IpNetwork>>()[0];
        let expected: IpNetwork = format!("10.217.4.164/{prefix_length}").parse().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    // test getting the next /30 from the IpAllocator
    // since .164 is already allocated, the allocator
    // should need to skip to the next valid /30, which
    // ends up being .168/30.
    fn test_ip_allocation_with_used_networks() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let prefix = IpNetwork::V4("10.217.4.0/24".parse().unwrap());
        let prefix_length = 30;
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix,
                gateway: Some(IpAddr::V4("10.217.4.1".parse().unwrap())),
                num_reserved: 1,
            }],
            // The /32 is implied on the end of used_ips, and
            // this results in IpNetworks with a /32.
            used_ips: vec![
                "10.217.4.2".parse().unwrap(),
                "10.217.4.3".parse().unwrap(),
                "10.217.4.4".parse().unwrap(),
            ],
            prefix_length,
        };

        // Prefix: /24 means 256 starting IPs, and it
        // also means the network and broadcast addresses
        // will be reserved, so:
        //
        // - 1x gateway
        // - 1x num_reserved (which overlaps with gateway)
        // - 1x network
        // - 1x broadcast
        // - 3x used
        //
        // Which is an effective 6x reserved, which leaves
        // us with 250 free IPs.
        assert_eq!(256, get_network_size(&prefix).unwrap());
        let nfree = allocator.num_free().unwrap();
        assert_eq!(250, nfree);

        let result = allocator.map(|x| x.1.unwrap()).collect::<Vec<IpNetwork>>()[0];
        let expected: IpNetwork = format!("10.217.4.8/{prefix_length}").parse().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    // test_ip_allocation_with_used_fnn_networks is similar
    // to test_ip_allocation_with_used_networks above, except
    // used_ips are actually /30.
    fn test_ip_allocation_with_used_fnn_networks() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let prefix = IpNetwork::V4("10.217.4.0/24".parse().unwrap());
        let prefix_length = 30;
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix,
                gateway: Some(IpAddr::V4("10.217.4.1".parse().unwrap())),
                num_reserved: 1,
            }],
            used_ips: vec![
                "10.217.4.4/30".parse().unwrap(),
                "10.217.4.8/30".parse().unwrap(),
                "10.217.4.12/30".parse().unwrap(),
            ],
            prefix_length,
        };

        // Prefix: /24 means 256 starting IPs, and it
        // also means the network and broadcast addresses
        // will be reserved, so:
        //
        // - 1x gateway
        // - 1x num_reserved (which overlaps with gateway)
        // - 1x network
        // - 1x broadcast
        // - 3x used /30's (12 IPs)
        //
        // Which is an effective 15x reserved, which leaves
        // us with 241 free IPs.
        assert_eq!(256, get_network_size(&prefix).unwrap());
        let nfree = allocator.num_free().unwrap();
        assert_eq!(241, nfree);

        let result = allocator.map(|x| x.1.unwrap()).collect::<Vec<IpNetwork>>()[0];
        let expected: IpNetwork = format!("10.217.4.16/{prefix_length}").parse().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_generate_network_details() {
        let network_prefix = "192.168.1.0/24";
        let prefix_length = 30;
        let network: IpNetwork = network_prefix.parse().unwrap();
        let network_details = get_network_details(&network, prefix_length);
        assert_eq!(
            Ipv4Addr::from(network_details.base_ip as u32).to_string(),
            "192.168.1.0"
        );
        assert_eq!(
            Ipv4Addr::from(network_details.broadcast_ip as u32).to_string(),
            "192.168.1.255"
        );
        assert_eq!(network_details.network_size, 4);
    }

    #[test]
    fn test_get_network_size() {
        let v4_network = "192.168.1.0/24".parse().unwrap();
        let v6_network = "2012:db9::/32".parse().unwrap();
        let v4_size = get_network_size(&v4_network);
        assert!(v4_size.is_ok());
        assert_eq!(256, v4_size.unwrap());
        let v6_size = get_network_size(&v6_network);
        assert!(v6_size.is_err());
    }

    #[test]
    fn test_collapse_allocated_with_duplicate_and_covered() {
        // 192.168.1.0/32 is dropped as a duplicate,
        // and 192.168.1.4/30 contains 192.168.1.4/31,
        // so 192.168.1.4/31 is dropped also.
        let allocated_cidrs = vec![
            "192.168.1.0/32".parse().unwrap(),
            "192.168.1.0/32".parse().unwrap(),
            "192.168.1.4/31".parse().unwrap(),
            "192.168.1.4/30".parse().unwrap(),
        ];
        let allocated_networks = collapse_allocated_networks(&allocated_cidrs);
        assert_eq!(2, allocated_networks.len());
    }

    #[test]
    fn test_v4_candidate() {
        let cidr = "192.168.1.0/24".parse().unwrap();
        let prefix_length = 30;
        let allocated_cidrs = vec![
            "192.168.1.0/32".parse().unwrap(),
            "192.168.1.4/30".parse().unwrap(),
        ];
        let next_prefix = next_available_prefix(cidr, prefix_length, allocated_cidrs).unwrap();
        assert!(next_prefix.is_some_and(|prefix| prefix.to_string() == "192.168.1.8/30"));
    }

    #[test]
    fn test_v4_single_ip_candidate() {
        let cidr = "192.168.1.0/24".parse().unwrap();
        let prefix_length = 32;
        let allocated_cidrs = vec![
            "192.168.1.0/32".parse().unwrap(),
            "192.168.1.4/30".parse().unwrap(),
        ];
        let maybe_next_prefix =
            next_available_prefix(cidr, prefix_length, allocated_cidrs).unwrap();
        assert!(maybe_next_prefix.is_some_and(|prefix| prefix.to_string() == "192.168.1.1/32"));
        let next_prefix = maybe_next_prefix.unwrap();
        assert_eq!(next_prefix.ip().to_string(), "192.168.1.1");
    }

    #[test]
    fn test_v4_candidate_with_duplicate() {
        let cidr = "192.168.1.0/24".parse().unwrap();
        let prefix_length = 30;
        let allocated_cidrs = vec![
            "192.168.1.0/32".parse().unwrap(),
            "192.168.1.0/32".parse().unwrap(),
            "192.168.1.4/30".parse().unwrap(),
        ];
        let next_prefix = next_available_prefix(cidr, prefix_length, allocated_cidrs).unwrap();
        assert!(next_prefix.is_some_and(|prefix| prefix.to_string() == "192.168.1.8/30"));
    }

    #[test]
    fn test_v4_candidate_with_covered() {
        let cidr = "192.168.1.0/24".parse().unwrap();
        let prefix_length = 30;
        let allocated_cidrs = vec![
            "192.168.1.0/32".parse().unwrap(),
            "192.168.1.0/32".parse().unwrap(),
            "192.168.1.4/31".parse().unwrap(),
            "192.168.1.4/30".parse().unwrap(),
        ];
        let next_prefix = next_available_prefix(cidr, prefix_length, allocated_cidrs).unwrap();
        assert!(next_prefix.is_some_and(|prefix| prefix.to_string() == "192.168.1.8/30"));
    }

    #[test]
    fn test_v6_candidate() {
        // Ode to the 2012 Aston Martin DB9.
        let cidr = "2012:db9::/32".parse().unwrap();
        let prefix_length = 64;
        let allocated_cidrs = vec![
            "2012:db9::/64".parse().unwrap(),
            "2012:db9:0:1::/64".parse().unwrap(),
        ];
        let next_prefix = next_available_prefix(cidr, prefix_length, allocated_cidrs).unwrap();
        assert!(next_prefix.is_some_and(|prefix| prefix.to_string() == "2012:db9:0:2::/64"));
    }
}
