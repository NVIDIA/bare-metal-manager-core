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
    address_strategy: AddressSelectionStrategy,
}

impl IpAllocator {
    pub async fn new<DB>(
        db: &mut DB,
        segment: &NetworkSegment,
        used_ip_resolver: Box<dyn UsedIpResolver<DB> + Send>,
        address_strategy: AddressSelectionStrategy,
    ) -> DatabaseResult<Self>
    where
        for<'db> &'db mut DB: DbReader<'db>,
    {
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
            address_strategy,
        })
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

        let total_ips = get_network_size(&segment_prefix.prefix);

        let allocated_ips = self
            .get_allocated(segment_prefix)
            .map_err(|e| DatabaseError::internal(format!("failed to get_allocated: {e}")))?;

        let total_allocated: u32 = allocated_ips
            .iter()
            .map(get_network_size)
            .fold(0u32, |acc, size| acc.saturating_add(size));

        Ok(total_ips.saturating_sub(total_allocated))
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

        // Resolve the prefix_length to allocate based on the strategy
        // and the current prefix's address family.
        let prefix_length = match self.address_strategy {
            AddressSelectionStrategy::NextAvailableIp | AddressSelectionStrategy::Automatic => {
                if segment_prefix.prefix.is_ipv4() {
                    32
                } else {
                    128
                }
            }
            AddressSelectionStrategy::NextAvailablePrefix(len) => len,
        };

        // And now get the next available network prefix of prefix_length
        // from the segment prefix, taking into account any existing
        // allocated IPs (see the docstring for get_allocated for an explanation
        // about what allocated IPs are).
        let next_available_prefix =
            match next_available_prefix(segment_prefix.prefix, prefix_length, allocated_ips) {
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

/// NOTE(chet): This has been deprecated, but I'm keeping it here for reference
/// just incase the topic comes up again, and/or we want to revisit a SQL
/// based allocation fast-path again. The reasons this is being deprecated
/// are because its introduction actually dropped support for dual-stacking
/// environments, and because it cannot actually support IPv6 allocation. It
/// ends up being a little complicated to try to leverage this for IPv4 single
/// IP allocations amidst IPv6 allocations. BUT, we should definitely always
/// be looking into more efficient ways of bulk allocation.
///
/// next_machine_interface_v4_ip is a SQL fast-path for allocating a single
/// IPv4 address from a prefix.
///
/// This finds the next available IP in a single database query by using
/// `generate_series()` to enumerate all candidate addresses and LEFT JOIN
/// against already-allocated addresses. This is much faster than the
/// Rust-based `IpAllocator` (which loads all used IPs into memory) during
/// bulk operations like ingestion.
///
/// This is permanently IPv4-only for two reasons:
///
/// 1. `generate_series()` uses PostgreSQL `bigint` (64-bit). IPv6 addresses
///    are 128-bit — there is no native 128-bit integer type in PostgreSQL.
/// 2. `generate_series()` materializes the entire range in memory. Even a
///    /96 prefix has ~4 billion addresses; a /64 has 2^64. The query would
///    either OOM or take effectively forever.
///
/// IPv6 allocation uses the Rust-based `IpAllocator` instead, which uses
/// u128 math and steps through candidate subnets without enumerating the
/// full address space. See `machine_interface::create()` for the fallback.
pub async fn next_machine_interface_v4_ip(
    txn: &mut PgConnection,
    prefix: &NetworkPrefix,
) -> DatabaseResult<Option<IpAddr>> {
    if prefix.prefix.is_ipv6() {
        return Ok(None);
    }
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
        allocated_ips.push(IpNetwork::new(gateway, max_prefix_len(gateway))?);
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
        let next_net = IpNetwork::new(next_ip, max_prefix_len(next_ip))?;
        allocated_ips.push(next_net);
    }

    // If the segment is large enough to have distinct network and broadcast
    // addresses, drop them from being assignable to tenants.
    // IPv4: /30 or larger (prefix < 31). IPv6: /126 or larger (prefix < 127).
    let should_reserve_network_broadcast = match segment_prefix.prefix {
        IpNetwork::V4(v4) => v4.prefix() < 31,
        IpNetwork::V6(v6) => v6.prefix() < 127,
    };
    if should_reserve_network_broadcast {
        let network_addr = segment_prefix.prefix.network();
        let broadcast_addr = segment_prefix.prefix.broadcast();
        allocated_ips.push(IpNetwork::new(network_addr, max_prefix_len(network_addr))?);
        allocated_ips.push(IpNetwork::new(
            broadcast_addr,
            max_prefix_len(broadcast_addr),
        )?);
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

/// get_network_size returns the number of addresses in an IP network as a u32.
///
/// TODO(chet): It looks like this got introduced for reporting nubmer of free
/// IPs available to allocate within a given prefix, and there wasn't really a
/// consideration for IPv6. This will need to be changed to be at least u64,
/// and since protobuf only supports up to u64, we might need to split the u128
/// into 2x u64, or maybe just limit it at u64. So for now, for IPv6 networks
/// larger than 2^32, this result is going to be capped at u32::MAX.
fn get_network_size(ip_network: &IpNetwork) -> u32 {
    match ip_network.size() {
        ipnetwork::NetworkSize::V4(total_ips) => total_ips,
        ipnetwork::NetworkSize::V6(total_ips) => u32::try_from(total_ips).unwrap_or(u32::MAX),
    }
}

/// Returns the maximum prefix length for a single host address (32 for IPv4, 128 for IPv6).
fn max_prefix_len(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
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
        let address_strategy = AddressSelectionStrategy::NextAvailableIp;
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.1.1.0/24".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.1.1.1".parse().unwrap())),
                num_reserved: 1,
            }],
            used_ips: vec![],
            address_strategy,
        };

        // Prefix 24 means 256 ips in subnet.
        //     num_reserved: 1
        //     gateway: 1
        //     broadcast: 1
        // network is part of num_reserved. So nfree is 256 - 3 = 253.
        let nfree = allocator.num_free().unwrap();
        assert_eq!(nfree, 253);

        let result = allocator.next().unwrap();
        let expected: IpNetwork = "10.1.1.2/32".parse().unwrap();
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
            // The address we allocated above when we called next().
            used_ips: vec!["10.1.1.2".parse().unwrap()],
            address_strategy,
        };
        let nfree = allocator.num_free().unwrap();
        assert_eq!(nfree, 252);
    }

    #[test]
    fn test_ip_allocation_ipv6() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let address_strategy = AddressSelectionStrategy::NextAvailableIp;
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                // Use /112 (65536 addresses).
                prefix: IpNetwork::V6("2001:db8::0/112".parse().unwrap()),
                gateway: None,
                num_reserved: 1,
            }],
            used_ips: vec![],
            address_strategy,
        };
        let result = allocator.next().unwrap();
        assert_eq!(result.0, prefix_id);
        // Reserved: 1 (network address 2001:db8::0), network addr, broadcast addr.
        // Next available after those: 2001:db8::1.
        let allocated = result.1.unwrap();
        assert_eq!(allocated.to_string(), "2001:db8::1/128");
        assert!(allocator.next().is_none());
    }

    #[test]
    fn test_ip_allocation_ipv4_and_6() {
        // AddressSelectionStrategy::NextAvailableIp allocates single IPs: /32 from
        // IPv4 prefixes and /128 from IPv6 prefixes.
        let prefix_id1 = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let prefix_id2 = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1201").into();
        let address_strategy = AddressSelectionStrategy::NextAvailableIp;
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
                    prefix: IpNetwork::V6("2001:db8::0/112".parse().unwrap()),
                    gateway: None,
                    num_reserved: 1,
                },
            ],
            used_ips: vec![],
            address_strategy,
        };

        // First: IPv4 allocation — /32 from /24
        let result = allocator.next().unwrap();
        assert_eq!(result.0, prefix_id1);
        assert_eq!(result.1.unwrap().to_string(), "10.1.1.2/32");

        // Second: IPv6 allocation — /128 from /112
        let result = allocator.next().unwrap();
        assert_eq!(result.0, prefix_id2);
        assert_eq!(result.1.unwrap().to_string(), "2001:db8::1/128");
        assert!(allocator.next().is_none());
    }

    #[test]
    fn test_ip_allocation_prefix_exhausted() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let address_strategy = AddressSelectionStrategy::NextAvailableIp;
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.1.1.0/30".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.1.1.1".parse().unwrap())),
                num_reserved: 4,
            }],
            used_ips: vec![],
            address_strategy,
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
        let address_strategy = AddressSelectionStrategy::NextAvailableIp;
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.217.4.160/30".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.217.4.161".parse().unwrap())),
                num_reserved: 3,
            }],
            used_ips: vec![],
            address_strategy,
        };
        assert!(allocator.next().unwrap().1.is_err());
    }
    #[test]
    fn test_ip_allocation_network_broadcast_address_is_excluded() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let address_strategy = AddressSelectionStrategy::NextAvailableIp;
        let allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                prefix: IpNetwork::V4("10.217.4.160/30".parse().unwrap()),
                gateway: Some(IpAddr::V4("10.217.4.161".parse().unwrap())),
                num_reserved: 0,
            }],
            used_ips: vec![],
            address_strategy,
        };
        let result = allocator.map(|x| x.1.unwrap()).collect::<Vec<IpNetwork>>()[0];
        let expected: IpNetwork = "10.217.4.162/32".parse().unwrap();
        assert_eq!(result, expected);
    }
    #[test]
    fn test_ip_allocation_with_used_ips() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let address_strategy = AddressSelectionStrategy::NextAvailableIp;
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
            address_strategy,
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
        let expected: IpNetwork = "10.217.4.164/32".parse().unwrap();
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
            address_strategy: AddressSelectionStrategy::NextAvailablePrefix(30),
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
        assert_eq!(256, get_network_size(&prefix));
        let nfree = allocator.num_free().unwrap();
        assert_eq!(250, nfree);

        let result = allocator.map(|x| x.1.unwrap()).collect::<Vec<IpNetwork>>()[0];
        let expected: IpNetwork = "10.217.4.8/30".parse().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    // test_ip_allocation_with_used_fnn_networks is similar
    // to test_ip_allocation_with_used_networks above, except
    // used_ips are actually /30.
    fn test_ip_allocation_with_used_fnn_networks() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let prefix = IpNetwork::V4("10.217.4.0/24".parse().unwrap());
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
            address_strategy: AddressSelectionStrategy::NextAvailablePrefix(30),
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
        assert_eq!(256, get_network_size(&prefix));
        let nfree = allocator.num_free().unwrap();
        assert_eq!(241, nfree);

        let result = allocator.map(|x| x.1.unwrap()).collect::<Vec<IpNetwork>>()[0];
        let expected: IpNetwork = "10.217.4.16/30".parse().unwrap();
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
        assert_eq!(256, get_network_size(&v4_network));

        // IPv6 /112 has 65536 addresses — fits in u32.
        let v6_small: IpNetwork = "2001:db8::/112".parse().unwrap();
        assert_eq!(65536, get_network_size(&v6_small));

        // IPv6 /32 has 2^96 addresses — capped at u32::MAX.
        // See comments in get_network_size for more info
        // about that. We'll need to improve this at some point.
        let v6_large: IpNetwork = "2012:db9::/32".parse().unwrap();
        assert_eq!(u32::MAX, get_network_size(&v6_large));
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

    #[test]
    fn test_ipv6_allocation_single_address() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let address_strategy = AddressSelectionStrategy::NextAvailableIp;
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                // /112 has 65536 addresses — small enough for the test to reason about
                prefix: IpNetwork::V6("2001:db8:abcd::0/112".parse().unwrap()),
                gateway: None,
                num_reserved: 3,
            }],
            used_ips: vec!["2001:db8:abcd::3/128".parse().unwrap()],
            address_strategy,
        };

        // /112 = 65536 addresses
        // Reserved: 3 (::0, ::1, ::2)
        // Network addr (::0) overlaps with reserved
        // Broadcast addr (::ffff)
        // Used: ::3
        // So allocated = 3 reserved + 1 broadcast + 1 used = 5
        // Free = 65536 - 5 = 65531
        let nfree = allocator.num_free().unwrap();
        assert_eq!(nfree, 65531);

        // Next available after reserved (::0, ::1, ::2) and used (::3): should be ::4
        let result = allocator.next().unwrap();
        assert_eq!(result.0, prefix_id);
        assert_eq!(result.1.unwrap().to_string(), "2001:db8:abcd::4/128");
    }

    #[test]
    fn test_ipv6_num_free_capped() {
        let prefix_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let address_strategy = AddressSelectionStrategy::NextAvailableIp;
        let mut allocator = IpAllocator {
            prefixes: vec![Prefix {
                id: prefix_id,
                // /64 has 2^64 addresses, which is above u32::MAX.
                prefix: IpNetwork::V6("2001:db8:1::/64".parse().unwrap()),
                gateway: None,
                num_reserved: 0,
            }],
            used_ips: vec![],
            address_strategy,
        };

        // num_free should be capped at u32::MAX (not overflow or error),
        // but again, this is all because of get_network_size(), which
        // we need to enhance to not be limited to u32.
        let nfree = allocator.num_free().unwrap();
        // The total is u32::MAX, allocated is small, but subtraction
        // saturates so we get something close to u32::MAX
        assert!(nfree > u32::MAX - 100);
    }

    #[test]
    fn test_ipv6_build_allocated_networks() {
        let prefix = Prefix {
            id: uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into(),
            prefix: IpNetwork::V6("2001:db8:abcd::0/112".parse().unwrap()),
            gateway: None,
            num_reserved: 2,
        };
        let used_ips = vec![];
        let allocated = build_allocated_networks(&prefix, &used_ips).unwrap();

        // Should have: 2 reserved (::0, ::1) + network (::0) + broadcast (::ffff)
        // The network address overlaps with the first reserved, so after collapse
        // we should have distinct /128 entries
        for net in &allocated {
            assert!(
                net.prefix() == 128,
                "Expected /128 for single IPv6 addresses, got /{}",
                net.prefix()
            );
        }
        // At minimum: ::0, ::1, ::ffff
        assert!(
            allocated.len() >= 3,
            "Expected at least 3 allocated networks for IPv6 prefix with 2 reserved"
        );
    }
}
