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
use std::collections::HashSet;
use std::net::IpAddr;
use std::ops::DerefMut;

use carbide_uuid::instance::InstanceId;
use carbide_uuid::network::{NetworkPrefixId, NetworkSegmentId};
use forge_network::virtualization::get_host_ip;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use model::ConfigValidationError;
use model::address_selection_strategy::AddressSelectionStrategy;
use model::instance::config::network::{
    InstanceInterfaceConfig, InstanceNetworkConfig, NetworkDetails,
};
use model::instance_address::InstanceAddress;
use model::machine::Machine;
use model::network_prefix::NetworkPrefix;
use model::network_segment::{
    NetworkSegment, NetworkSegmentControllerState, NetworkSegmentSearchConfig, NetworkSegmentType,
};
use sqlx::{FromRow, PgConnection, PgTransaction, query_as};

use super::{ObjectColumnFilter, network_segment};
use crate::ip_allocator::{IpAllocator, UsedIpResolver};
use crate::{DatabaseError, DatabaseResult, Transaction};

#[derive(Copy, Clone)]
pub struct PrefixColumn;

impl super::ColumnInfo<'_> for PrefixColumn {
    type TableType = InstanceAddress;
    type ColumnType = IpNetwork;

    fn column_name(&self) -> &'static str {
        "prefix"
    }
}

pub async fn find_by_address(
    txn: &mut PgConnection,
    address: IpAddr,
) -> Result<Option<InstanceAddress>, DatabaseError> {
    let query = "SELECT * FROM instance_addresses WHERE address = $1::inet";
    sqlx::query_as(query)
        .bind(address)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find_by_instance_id_and_segment_id(
    txn: &mut PgConnection,
    instance_id: &InstanceId,
    segment_id: &NetworkSegmentId,
) -> Result<Option<InstanceAddress>, DatabaseError> {
    let query = "SELECT * FROM instance_addresses WHERE instance_id=$1 AND segment_id=$2";

    sqlx::query_as(query)
        .bind(instance_id)
        .bind(segment_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find_by_prefix(
    txn: &mut PgConnection,
    prefix: IpNetwork,
) -> Result<Option<InstanceAddress>, DatabaseError> {
    let mut query = crate::FilterableQueryBuilder::new("SELECT * FROM instance_addresses")
        .filter(&ObjectColumnFilter::One(PrefixColumn, &prefix));

    query
        .build_query_as()
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))
}

pub async fn delete(txn: &mut PgConnection, instance_id: InstanceId) -> Result<(), DatabaseError> {
    // Lock MUST be taken by calling function.
    let query = "DELETE FROM instance_addresses WHERE instance_id=$1 RETURNING id";
    let _: Vec<(InstanceId,)> = sqlx::query_as(query)
        .bind(instance_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn delete_addresses(
    txn: &mut PgConnection,
    addresses: &[&IpAddr],
) -> Result<(), DatabaseError> {
    // Lock MUST be taken by calling function.
    let query = "DELETE FROM instance_addresses WHERE address=ANY($1)";
    sqlx::query(query)
        .bind(addresses)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

fn validate(
    segments: &Vec<NetworkSegment>,
    instance_network: &InstanceNetworkConfig,
    segment_ids_using_vpc_prefix: &[NetworkSegmentId],
) -> DatabaseResult<()> {
    if segments.len() != instance_network.interfaces.len() {
        // Missing at least one segment in db.
        return Err(ConfigValidationError::UnknownSegments.into());
    }

    let mut vpc_ids = HashSet::new();

    for segment in segments {
        if segment.is_marked_as_deleted() {
            // TODO: Single error for not ready and deleted?
            return Err(ConfigValidationError::NetworkSegmentToBeDeleted(segment.id).into());
        }

        // If segment is created using vpc_prefix id, it will not be in Ready state by now.
        if !segment_ids_using_vpc_prefix.contains(&segment.id) {
            match &segment.controller_state.value {
                NetworkSegmentControllerState::Ready => {}
                _ => {
                    return Err(ConfigValidationError::NetworkSegmentNotReady(
                        segment.id,
                        format!("{:?}", segment.controller_state.value),
                    )
                    .into());
                }
            }
        }

        match segment.vpc_id {
            Some(x) => {
                vpc_ids.insert(x);
            }
            None => {
                return Err(ConfigValidationError::VpcNotAttachedToSegment(segment.id).into());
            }
        };
    }

    if vpc_ids.len() != 1 {
        return Err(ConfigValidationError::MultipleVpcFound.into());
    }

    Ok(())
}

/// Counts the amount of addresses that have been allocated for a given segment
pub async fn count_by_segment_id(
    txn: &mut PgConnection,
    segment_id: &NetworkSegmentId,
) -> Result<usize, DatabaseError> {
    let query = "
SELECT count(*)
FROM instance_addresses
INNER JOIN network_prefixes ON network_prefixes.segment_id = instance_addresses.segment_id
WHERE network_prefixes.segment_id = $1::uuid";
    let (address_count,): (i64,) = query_as(query)
        .bind(segment_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(address_count.max(0) as usize)
}

/// Tries to allocate IP addresses for a tenant network configuration
/// Returns the updated configuration which includes allocated addresses
#[allow(txn_held_across_await)]
pub async fn allocate(
    txn: &mut PgConnection,
    instance_id: InstanceId,
    mut updated_config: InstanceNetworkConfig,
    machine: &Machine,
) -> DatabaseResult<InstanceNetworkConfig> {
    // We expect only one ipv4 prefix. Also Ipv6 is not supported yet.
    // We're potentially about to insert a couple rows, so create a savepoint.
    let mut inner_txn = Transaction::begin_inner(txn).await?;

    let segment_ids = updated_config
        .interfaces
        .iter()
        .filter_map(|x| x.network_segment_id)
        .collect_vec();

    let segment_ids_using_vpc_prefix = updated_config
        .interfaces
        .iter()
        .filter_map(|x| {
            if let Some(NetworkDetails::VpcPrefixId(_)) = x.network_details {
                x.network_segment_id
            } else {
                None
            }
        })
        .collect_vec();

    if segment_ids.len() != updated_config.interfaces.len() {
        return Err(DatabaseError::NetworkSegmentNotAllocated);
    }

    let segments = crate::network_segment::find_by(
        &mut inner_txn,
        ObjectColumnFilter::List(network_segment::IdColumn, &segment_ids),
        NetworkSegmentSearchConfig::default(),
    )
    .await?;

    validate(&segments, &updated_config, &segment_ids_using_vpc_prefix)?;

    let query = "LOCK TABLE instance_addresses IN ACCESS EXCLUSIVE MODE";
    sqlx::query(query)
        .execute(inner_txn.as_pgconn())
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    // Assign all addresses in one shot.
    for iface in &mut updated_config.interfaces {
        if !iface.ip_addrs.is_empty() {
            // IP is already allocated. Don't assign new IP.
            continue;
        }

        let segment = match segments
            .iter()
            .find(|x| iface.network_segment_id.map(|a| a == x.id).unwrap_or(false))
        {
            Some(x) => x,
            None => {
                if let Some(segment_id) = iface.network_segment_id {
                    return Err(DatabaseError::FindOneReturnedNoResultsError(
                        segment_id.into(),
                    ));
                }
                return Err(DatabaseError::NetworkSegmentNotAllocated);
            }
        };

        let valid_prefixes = segment
            .prefixes
            .iter()
            .filter(|x| x.prefix.is_ipv4())
            .cloned()
            .collect_vec();

        if valid_prefixes.len() > 1 {
            return Err(DatabaseError::FindOneReturnedManyResultsError(
                segment.id.into(),
            ));
        }

        let Some(network_prefix) = valid_prefixes.into_iter().next() else {
            tracing::error!(
                segment_id = %segment.id,
                "No prefix is attached to segment.",
            );
            return Err(DatabaseError::FindOneReturnedNoResultsError(
                segment.id.into(),
            ));
        };

        // Hydrate iface with network addresses, returning the assigned addresses
        let addresses = if segment.segment_type == NetworkSegmentType::HostInband {
            // For host-inband network segments, the instance interface *is* the host interface,
            // and we simply use the hosts's address.
            iface.assign_ips_from((machine, &network_prefix))?
        } else {
            // Use the UsedOverlayNetworkIpResolver, which specifically looks at
            // the instance addresses table in the database for finding
            // the next available IP prefix allocation (with [assumed] support for
            // allocations of varying-sized networks).
            let busy_ips = network_prefix
                .svi_ip
                .iter()
                .copied()
                .collect::<Vec<IpAddr>>();

            let dhcp_handler: Box<dyn UsedIpResolver + Send> =
                Box::new(UsedOverlayNetworkIpResolver {
                    segment_id: segment.id,
                    busy_ips,
                });

            // TODO(chet): FNN will be leveraging the IpAllocator to allocate
            // a /30 for a tenant instance (or, at least, something other than
            // a /32). For now, hard-code 32 as the length -- the plan is to
            // update the InstanceInterfaceConfig to request the prefix_length.
            let ip_allocator = IpAllocator::new(
                &mut inner_txn,
                segment,
                dhcp_handler,
                AddressSelectionStrategy::Automatic,
                32,
            )
            .await?;

            iface.assign_ips_from(ip_allocator)?
        };

        let query = "INSERT INTO instance_addresses (instance_id, address, segment_id, prefix)
                         VALUES ($1::uuid, $2, $3::uuid, $4::cidr)";

        for address in addresses {
            sqlx::query(query)
                .bind(instance_id)
                // eg. 10.3.2.1/30
                .bind(address.ip())
                // eg. 10.3.2.0/30
                .bind(segment.id)
                .bind(IpNetwork::new(address.network(), address.prefix())?)
                .fetch_all(inner_txn.as_pgconn())
                .await
                .map_err(|e| DatabaseError::query(query, e))?;
        }
    }

    inner_txn.commit().await?;

    Ok(updated_config)
}

pub struct UsedOverlayNetworkIpResolver {
    pub segment_id: NetworkSegmentId,
    // All the IPs which can not be allocated, e.g. SVI IP.
    pub busy_ips: Vec<IpAddr>,
}

#[async_trait::async_trait]
impl UsedIpResolver for UsedOverlayNetworkIpResolver {
    // DEPRECATED
    // With the introduction of `used_prefixes()` this is no
    // longer an accurate approach for finding all allocated
    // IPs in a segment, since used_ips() completely ignores
    // the fact wider prefixes may have been allocated.
    //
    // used_ips returns the used (or allocated) IPs for instances
    // in a given network segment.
    //
    // More specifically, this is intended to specifically
    // target the `address` column of the `instance_addresses`
    // table, in which a single /32 is stored (although, as an
    // `inet`, it could techincally also have a prefix length).
    async fn used_ips(&self, txn: &mut PgConnection) -> Result<Vec<IpAddr>, DatabaseError> {
        // IpAddrContainer is a small private struct used
        // for binding the result of the subsequent SQL
        // query, so we can implement FromRow and return
        // a Vec<IpAddr> a bit more easily.
        #[derive(FromRow)]
        struct IpAddrContainer {
            address: IpAddr,
        }

        let query: &str = "
SELECT address FROM instance_addresses
INNER JOIN network_segments ON instance_addresses.segment_id = network_segments.id
WHERE network_segments.id = $1::uuid";

        let containers: Vec<IpAddrContainer> = sqlx::query_as(query)
            .bind(self.segment_id)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        let mut used_ips: Vec<IpAddr> = containers.iter().map(|c| c.address).collect();
        used_ips.extend(self.busy_ips.iter());
        Ok(used_ips)
    }

    // used_prefixes returns the used (or allocated) prefixes
    // for instances in a given network segment.
    //
    // More specifically, this is intended to specifically
    // target the `prefix` column of the `instance_addresses`
    // table, which is a `cidr` type. It could contain as
    // small as a /32 (for single IP instance allocations,
    // which would effectively match the `address` column),
    // or a /30 (for FNN prefix allocations), where the `address`
    // column would contain the host IP allocated from the
    // /30 prefix.
    async fn used_prefixes(&self, txn: &mut PgConnection) -> Result<Vec<IpNetwork>, DatabaseError> {
        // IpNetworkContainer is a small private struct used
        // for binding the result of the subsequent SQL
        // query, so we can implement FromRow and return
        // a Vec<IpNetwork> a bit more easily.
        #[derive(FromRow)]
        struct IpNetworkContainer {
            prefix: IpNetwork,
        }

        let query: &str = "
SELECT instance_addresses.prefix as prefix FROM instance_addresses
INNER JOIN network_segments ON instance_addresses.segment_id = network_segments.id
WHERE network_segments.id = $1::uuid";

        let containers: Vec<IpNetworkContainer> = sqlx::query_as(query)
            .bind(self.segment_id)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        Ok(containers.iter().map(|c| c.prefix).collect())
    }
}

/// Get IP addresses from Source, write them to self, and return them. Currently can come from an
/// IpAllocator, or from a host snapshot.
trait AssignIpsFrom<Source> {
    fn assign_ips_from(&mut self, source: Source) -> DatabaseResult<Vec<IpNetwork>>;
}

impl AssignIpsFrom<(&Machine, &NetworkPrefix)> for InstanceInterfaceConfig {
    // Zero-dpu config: For machines without DPUs, the machines's interface will be on an
    // HostInband network segment, which will be the same segment as the instance wants. In
    // this case, the host's interface *is* the instance interface, so we copy the config from it.
    fn assign_ips_from(
        &mut self,
        source: (&Machine, &NetworkPrefix),
    ) -> DatabaseResult<Vec<IpNetwork>> {
        let (machine, network_prefix) = source;

        // Find which interface on the machine is in this prefix
        let host_interfaces_in_instance_segment = machine
            .interfaces
            .iter()
            .filter(|i| {
                self.network_segment_id
                    .map(|a| a == i.segment_id)
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();

        if host_interfaces_in_instance_segment.len() > 1 {
            tracing::error!(
                "Managed host has multiple interfaces in the desired network segment. Cannot know which to assign to the instance config."
            );
            return Err(DatabaseError::FindOneReturnedManyResultsError(
                self.network_segment_id
                    .map(uuid::Uuid::from)
                    .unwrap_or_default(),
            ));
        }

        let Some(inband_host_interface) = host_interfaces_in_instance_segment.into_iter().next()
        else {
            return Err(DatabaseError::InvalidConfiguration(
                ConfigValidationError::NetworkSegmentUnavailableOnHost,
            ));
        };

        let matching_addresses = inband_host_interface
            .addresses
            .iter()
            .copied()
            .filter(|a| network_prefix.prefix.contains(*a))
            .collect::<Vec<_>>();

        if matching_addresses.len() > 1 {
            tracing::warn!(
                machine_id = %machine.id,
                prefix = %network_prefix.prefix,
                "Multiple IP addresses on managed host in the same network prefix, picking the first one to assign to instance"
            )
        }

        let Some(address) = matching_addresses.into_iter().next() else {
            return Err(DatabaseError::InvalidConfiguration(
                ConfigValidationError::NetworkSegmentUnavailableOnHost,
            ));
        };

        self.ip_addrs.insert(network_prefix.id, address);

        self.host_inband_mac_address = Some(inband_host_interface.mac_address);

        // Also write out the gateway for the network segment's prefix. Unlike the interface_prefixes
        // field (which is a /32 or /30 for just this instance, for hosts with DPUs),
        // segment_gateway is the gateway for the entire network segment.
        //
        // This is currently only used for zero-DPU instances, where the instance's interface is
        // equivalent to the host's interface, and the tenant needs to know the gateway and prefix
        // to use for configuration.
        if let Some(prefix_gateway) = network_prefix.gateway {
            // gateway_as_network is the IP address of the gateway with the prefix length
            // appended. Example:
            // prefix_gateway: 192.168.1.1
            // network_prefix.prefix: 192.168.1.0/24
            // gateway_as_network: 192.168.1.1/24
            let gateway_as_network =
                IpNetwork::new(prefix_gateway, network_prefix.prefix.prefix())?;
            self.network_segment_gateways
                .insert(network_prefix.id, gateway_as_network);
        }

        Ok(vec![IpNetwork::new(
            address,
            network_prefix.prefix.prefix(),
        )?])
    }
}

impl AssignIpsFrom<IpAllocator> for InstanceInterfaceConfig {
    fn assign_ips_from(&mut self, ip_allocator: IpAllocator) -> DatabaseResult<Vec<IpNetwork>> {
        let mut addresses = Vec::new();
        for (prefix_id, allocated_prefix) in ip_allocator {
            let allocated_prefix = allocated_prefix?;

            // This is used to populate the database (and the InstanceInterfaceConfig
            // ip_addrs) with the host IP, meaning, if the instance-allocated prefix
            // is a /32 IpNetwork, it will be the IP. If it's a /30 (say, for FNN), it
            // will grab the 4th IP (the 2nd IP of the 2nd /31) to be handed back
            // as the visibly-assigned IP address for the instance.
            let host_ip = get_host_ip(&allocated_prefix)?;
            self.ip_addrs.insert(prefix_id, host_ip);
            self.interface_prefixes.insert(prefix_id, allocated_prefix);

            addresses.push(IpNetwork::new(host_ip, allocated_prefix.prefix())?);
        }

        Ok(addresses)
    }
}

pub async fn allocate_svi_ip(
    // Note: This is a PgTransaction, not a PgConnection, because we will be doing table locking,
    // which must happen in a transaction.
    txn: &mut PgTransaction<'_>,
    segment: &NetworkSegment,
) -> DatabaseResult<(NetworkPrefixId, IpAddr)> {
    let dhcp_handler: Box<dyn UsedIpResolver + Send> = Box::new(UsedOverlayNetworkIpResolver {
        segment_id: segment.id,
        busy_ips: vec![],
    });

    // If either requested addresses are auto-generated, we lock the entire table
    let query = "LOCK TABLE instance_addresses IN ACCESS EXCLUSIVE MODE";
    sqlx::query(query)
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    let mut addresses_allocator = IpAllocator::new(
        txn,
        segment,
        dhcp_handler,
        AddressSelectionStrategy::Automatic,
        32,
    )
    .await?;

    // Carbide supports only one prefix that too Ipv4 only.
    match addresses_allocator.next() {
        Some((id, Ok(address))) => Ok((id, address.ip())),
        Some((_, Err(err))) => Err(err),
        _ => Err(DatabaseError::ResourceExhausted(format!(
            "Unable to allocate SVI IP for : No free IPs in segment {}.",
            segment.id
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use carbide_uuid::vpc::VpcId;
    use chrono::Utc;
    use config_version::{ConfigVersion, Versioned};
    use model::instance::config::network::{InstanceInterfaceConfig, InterfaceFunctionId};
    use model::network_segment::NetworkSegmentType;
    use uuid::Uuid;

    use super::*;

    fn create_valid_validation_data() -> Vec<NetworkSegment> {
        let vpc_id = VpcId::from_str("11609f10-c11d-1101-3261-6293ea0c0100").unwrap();
        let network_segments: Vec<NetworkSegment> = InterfaceFunctionId::iter_all()
            .enumerate()
            .map(|(idx, _function_id)| {
                let id = format!("91609f10-c91d-470d-a260-6293ea0c00{idx:02}");
                let version = ConfigVersion::initial();
                NetworkSegment {
                    id: NetworkSegmentId::from_str(&id).unwrap(),
                    version,
                    name: id,
                    subdomain_id: None,
                    vpc_id: Some(vpc_id),
                    mtu: 1500,
                    created: Utc::now(),
                    updated: Utc::now(),
                    deleted: None,
                    prefixes: Vec::new(),
                    controller_state: Versioned {
                        value: NetworkSegmentControllerState::Ready,
                        version,
                    },
                    controller_state_outcome: None,
                    history: Vec::new(),
                    vlan_id: None,
                    vni: None,
                    segment_type: NetworkSegmentType::Tenant,
                    can_stretch: None,
                }
            })
            .collect_vec();

        network_segments
    }

    const BASE_SEGMENT_ID: uuid::Uuid = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c0000");
    fn create_valid_network_config() -> InstanceNetworkConfig {
        let interfaces: Vec<InstanceInterfaceConfig> = InterfaceFunctionId::iter_all()
            .enumerate()
            .map(|(idx, function_id)| {
                let network_segment_id: NetworkSegmentId =
                    Uuid::from_u128(BASE_SEGMENT_ID.as_u128() + idx as u128).into();
                InstanceInterfaceConfig {
                    function_id,
                    network_segment_id: Some(network_segment_id),
                    network_details: Some(
                        model::instance::config::network::NetworkDetails::NetworkSegment(
                            network_segment_id,
                        ),
                    ),
                    ip_addrs: HashMap::default(),
                    interface_prefixes: HashMap::default(),
                    network_segment_gateways: HashMap::default(),
                    host_inband_mac_address: None,
                    device_locator: None,
                    internal_uuid: uuid::Uuid::new_v4(),
                }
            })
            .collect();

        InstanceNetworkConfig { interfaces }
    }

    #[test]
    fn instance_address_segment_validation() {
        let data = create_valid_validation_data();
        let config = create_valid_network_config();
        let x = super::validate(&data, &config, &[]);
        assert!(x.is_ok());
    }

    #[test]
    fn validate_missing_segment_in_db_fail() {
        let mut data = create_valid_validation_data();
        let config = create_valid_network_config();
        data.swap_remove(10);
        assert!(super::validate(&data, &config, &[]).is_err());
    }

    #[test]
    fn validate_multiple_vpc_must_fail() {
        let mut data = create_valid_validation_data();
        let config = create_valid_network_config();
        data[0].vpc_id = Some(uuid::Uuid::new_v4().into());
        assert!(super::validate(&data, &config, &[]).is_err());
    }

    #[test]
    fn validate_missing_vpc_fail() {
        let mut data = create_valid_validation_data();
        let config = create_valid_network_config();
        data[2].vpc_id = None;
        assert!(super::validate(&data, &config, &[]).is_err());
    }

    #[test]
    fn validate_marked_deleted_segment_fail() {
        let mut data = create_valid_validation_data();
        let config = create_valid_network_config();
        data[12].deleted = Some(Utc::now());
        assert!(super::validate(&data, &config, &[]).is_err());
    }

    #[test]
    fn validate_not_ready_segment_fail() {
        let mut data = create_valid_validation_data();
        let config = create_valid_network_config();
        data[9].controller_state.value = NetworkSegmentControllerState::Provisioning;
        assert!(super::validate(&data, &config, &[]).is_err());
    }
}
