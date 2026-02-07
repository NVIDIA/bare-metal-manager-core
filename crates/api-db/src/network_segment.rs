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
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::Deref;

use ::rpc::forge as rpc;
use carbide_uuid::machine::MachineId;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use config_version::ConfigVersion;
use futures::StreamExt;
use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use model::address_selection_strategy::AddressSelectionStrategy;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::network_segment::{
    NetworkSegment, NetworkSegmentControllerState, NetworkSegmentSearchConfig, NetworkSegmentType,
    NewNetworkSegment,
};
use sqlx::{PgConnection, PgTransaction};

use crate::db_read::DbReader;
use crate::instance_address::UsedOverlayNetworkIpResolver;
use crate::ip_allocator::{IpAllocator, UsedIpResolver};
use crate::machine_interface::UsedAdminNetworkIpResolver;
use crate::{
    ColumnInfo, DatabaseError, DatabaseResult, FilterableQueryBuilder, ObjectColumnFilter,
};

#[derive(Copy, Clone)]
pub struct IdColumn;
impl ColumnInfo<'_> for IdColumn {
    type TableType = NetworkSegment;
    type ColumnType = NetworkSegmentId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Copy, Clone)]
pub struct VpcColumn;
impl ColumnInfo<'_> for VpcColumn {
    type TableType = NetworkSegment;
    type ColumnType = VpcId;

    fn column_name(&self) -> &'static str {
        "vpc_id"
    }
}

const NETWORK_SEGMENT_SNAPSHOT_QUERY_TEMPLATE: &str = r#"
     SELECT
        ns.*,
        COALESCE(prefixes_agg.json, '[]'::json) AS prefixes
        __HISTORY_SELECT__
     FROM network_segments ns
     LEFT JOIN LATERAL (
        SELECT np.segment_id,
            json_agg(np.*) AS json
        FROM network_prefixes np
        WHERE np.segment_id = ns.id
        GROUP BY np.segment_id
     ) AS prefixes_agg ON true
     __HISTORY_JOIN__
"#;

lazy_static! {
    static ref NETWORK_SEGMENT_SNAPSHOT_QUERY: String = NETWORK_SEGMENT_SNAPSHOT_QUERY_TEMPLATE
        .replace("__HISTORY_SELECT__", "")
        .replace("__HISTORY_JOIN__", "");

    static ref NETWORK_SEGMENT_SNAPSHOT_WITH_HISTORY_QUERY: String = NETWORK_SEGMENT_SNAPSHOT_QUERY_TEMPLATE
        .replace("__HISTORY_JOIN__", r#"
            LEFT JOIN LATERAL (
                SELECT h.segment_id,
                    json_agg(json_build_object('segment_id', h.segment_id, 'state', h.state::text, 'state_version', h.state_version, 'timestamp', h."timestamp")) AS json
                FROM network_segment_state_history h
                WHERE h.segment_id = ns.id
                GROUP BY h.segment_id
            ) AS history_agg ON true"#)
        .replace("__HISTORY_SELECT__", ", COALESCE(history_agg.json, '[]'::json) AS history");
}

pub async fn persist(
    value: NewNetworkSegment,
    txn: &mut PgConnection,
    initial_state: NetworkSegmentControllerState,
) -> Result<NetworkSegment, DatabaseError> {
    let version = ConfigVersion::initial();

    let query = "INSERT INTO network_segments (
                id,
                name,
                subdomain_id,
                vpc_id,
                mtu,
                version,
                controller_state_version,
                controller_state,
                vlan_id,
                vni_id,
                network_segment_type,
                can_stretch)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id";
    let segment_id: NetworkSegmentId = sqlx::query_as(query)
        .bind(value.id)
        .bind(&value.name)
        .bind(value.subdomain_id)
        .bind(value.vpc_id)
        .bind(value.mtu)
        .bind(version)
        .bind(version)
        .bind(sqlx::types::Json(&initial_state))
        .bind(value.vlan_id)
        .bind(value.vni)
        .bind(value.segment_type)
        .bind(value.can_stretch)
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    crate::network_prefix::create_for(txn, &segment_id, &value.prefixes).await?;
    crate::network_segment_state_history::persist(txn, segment_id, &initial_state, version).await?;

    find_by(
        txn,
        ObjectColumnFilter::One(IdColumn, &segment_id),
        Default::default(),
    )
    .await?
    .pop()
    .ok_or_else(|| {
        DatabaseError::new(
            "finding just-created network segment",
            sqlx::Error::RowNotFound,
        )
    })
}

pub async fn for_vpc(
    txn: &mut PgConnection,
    vpc_id: VpcId,
) -> Result<Vec<NetworkSegment>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            "{} WHERE ns.vpc_id=$1::uuid",
            NETWORK_SEGMENT_SNAPSHOT_QUERY.deref()
        );
    }
    let results: Vec<NetworkSegment> = {
        sqlx::query_as(&query)
            .bind(vpc_id)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(&query, e))?
    };

    Ok(results)
}

pub async fn for_relay(
    txn: &mut PgConnection,
    relay: IpAddr,
) -> DatabaseResult<Option<NetworkSegment>> {
    lazy_static! {
        static ref query: String = format!(
            r#"{}
                INNER JOIN network_prefixes ON network_prefixes.segment_id = ns.id
                WHERE $1::inet <<= network_prefixes.prefix"#,
            NETWORK_SEGMENT_SNAPSHOT_QUERY.deref()
        );
    }
    let mut results = sqlx::query_as(&query)
        .bind(IpNetwork::from(relay))
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(&query, e))?;

    match results.len() {
        0 | 1 => Ok(results.pop()),
        _ => Err(DatabaseError::internal(format!(
            "Multiple network segments defined for relay address {relay}"
        ))),
    }
}

pub async fn for_segment_type(
    txn: &mut PgConnection,
    relay: IpAddr,
    segment_type: NetworkSegmentType,
) -> DatabaseResult<Option<NetworkSegment>> {
    lazy_static! {
        static ref query: String = format!(
            r#"{}
                INNER JOIN network_prefixes ON network_prefixes.segment_id = ns.id
                WHERE $1::inet <<= network_prefixes.prefix
                AND $2 = ns.network_segment_type
                "#,
            NETWORK_SEGMENT_SNAPSHOT_QUERY.deref()
        );
    }
    let mut results = sqlx::query_as(&query)
        .bind(IpNetwork::from(relay))
        .bind(segment_type)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(&query, e))?;

    if results.len() > 1 {
        tracing::trace!(
            "Multiple network segments defined for segment_type {} and relay address {}",
            segment_type.to_string(),
            relay.to_string()
        );
    }
    Ok(results.pop())
}

/// Retrieves the IDs of all network segments.
/// If `segment_type` is specified, only IDs of segments that match the specific type are returned.
pub async fn list_segment_ids(
    txn: &mut PgConnection,
    segment_type: Option<NetworkSegmentType>,
) -> Result<Vec<NetworkSegmentId>, DatabaseError> {
    let (query, mut segment_id_stream) = if let Some(segment_type) = segment_type {
        let query = "SELECT id FROM network_segments where network_segment_type=$1";
        let stream = sqlx::query_as(query).bind(segment_type).fetch(txn);
        (query, stream)
    } else {
        let query = "SELECT id FROM network_segments";
        let stream = sqlx::query_as(query).fetch(txn);
        (query, stream)
    };

    let mut results = Vec::new();
    while let Some(maybe_id) = segment_id_stream.next().await {
        let id = maybe_id.map_err(|e| DatabaseError::query(query, e))?;
        results.push(id);
    }

    Ok(results)
}

pub async fn find_ids(
    txn: &mut PgConnection,
    filter: rpc::NetworkSegmentSearchFilter,
) -> Result<Vec<NetworkSegmentId>, DatabaseError> {
    // build query
    let mut builder = sqlx::QueryBuilder::new("SELECT s.id FROM network_segments AS s");
    let mut has_filter = false;
    if let Some(tenant_org_id) = &filter.tenant_org_id {
        builder.push(" JOIN vpcs AS v ON s.vpc_id = v.id WHERE v.organization_id = ");
        builder.push_bind(tenant_org_id);
        has_filter = true;
    }
    if let Some(name) = &filter.name {
        if has_filter {
            builder.push(" AND s.name = ");
        } else {
            builder.push(" WHERE s.name = ");
        }
        builder.push_bind(name);
    }

    let query = builder.build_query_as();
    let ids: Vec<NetworkSegmentId> = query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("network_segment::find_ids", e))?;

    Ok(ids)
}

pub async fn find_by<'a, C: ColumnInfo<'a, TableType = NetworkSegment>, DB>(
    conn: &mut DB,
    filter: ObjectColumnFilter<'a, C>,
    search_config: NetworkSegmentSearchConfig,
) -> Result<Vec<NetworkSegment>, DatabaseError>
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    let mut query = FilterableQueryBuilder::new(if search_config.include_history {
        NETWORK_SEGMENT_SNAPSHOT_WITH_HISTORY_QUERY.deref()
    } else {
        NETWORK_SEGMENT_SNAPSHOT_QUERY.deref()
    })
    .filter(&filter);

    let mut all_records = query
        .build_query_as()
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))?;

    if search_config.include_num_free_ips {
        update_num_free_ips_into_prefix_list(conn, &mut all_records).await?;
    }
    Ok(all_records)
}

/// Find network segments attached to a machine through machine_interfaces, optionally of a certain type
pub async fn find_ids_by_machine_id(
    txn: &mut PgConnection,
    machine_id: &::carbide_uuid::machine::MachineId,
    network_segment_type: Option<NetworkSegmentType>,
) -> Result<Vec<NetworkSegmentId>, DatabaseError> {
    let result = batch_find_ids_by_machine_ids(txn, &[*machine_id], network_segment_type).await?;

    Ok(result.get(machine_id).cloned().unwrap_or_default())
}

/// Batch find network segments attached to multiple machines through machine_interfaces.
/// Returns a HashMap mapping each machine ID to its list of segment IDs.
pub async fn batch_find_ids_by_machine_ids(
    txn: &mut PgConnection,
    machine_ids: &[MachineId],
    network_segment_type: Option<NetworkSegmentType>,
) -> Result<HashMap<MachineId, Vec<NetworkSegmentId>>, DatabaseError> {
    if machine_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let mut query = sqlx::QueryBuilder::new(
        r#"SELECT mi.machine_id, ns.id FROM machines m
                LEFT JOIN machine_interfaces mi ON (mi.machine_id = m.id)
                INNER JOIN network_segments ns ON (ns.id = mi.segment_id)
                WHERE mi.machine_id = ANY("#,
    );

    query.push_bind(
        machine_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>(),
    );
    query.push(")");

    if let Some(network_segment_type) = network_segment_type {
        query
            .push(" AND ns.network_segment_type = ")
            .push_bind(network_segment_type);
    }

    let rows: Vec<(String, NetworkSegmentId)> = query
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))?;

    let mut result: HashMap<MachineId, Vec<NetworkSegmentId>> = HashMap::new();
    for (machine_id_str, segment_id) in rows {
        if let Ok(machine_id) = machine_id_str.parse::<MachineId>() {
            result.entry(machine_id).or_default().push(segment_id);
        }
    }

    Ok(result)
}

async fn update_num_free_ips_into_prefix_list<DB>(
    conn: &mut DB,
    all_records: &mut [NetworkSegment],
) -> Result<(), DatabaseError>
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    for record in all_records.iter_mut().filter(|s| !s.prefixes.is_empty()) {
        let mut busy_ips = vec![];
        for prefix in &record.prefixes {
            if let Some(svi_ip) = prefix.svi_ip {
                busy_ips.push(svi_ip);
            }
        }
        let dhcp_handler: Box<dyn UsedIpResolver<DB> + Send> = if record.segment_type.is_tenant() {
            // Note on UsedOverlayNetworkIpResolver:
            // In this case, the IpAllocator isn't being used to iterate to get
            // the next available prefix_length allocation -- it's actually just
            // being used to get the number of free IPs left in a given tenant
            // network segment, so just hard-code a /32 prefix_length. NOW.. on
            // one hand, you could say the prefix_length doesn't matter here,
            // because this is really just here to get the number of free IPs left
            // in a network segment. BUT, on the other hand, do we care about the
            // number of free IPs left, or the number of free instance allocations
            // left? For example, if we're allocating /30's, we might be more
            // interested in knowing we can allocate 4 more machines (and not 16
            // more IPs).
            Box::new(UsedOverlayNetworkIpResolver {
                segment_id: record.id,
                busy_ips,
            })
        } else {
            // Note on UsedAdminNetworkIpResolver:
            // In this case, the IpAllocator isn't being used to iterate to get
            // the next available prefix_length allocation -- it's actually just
            // being used to get the number of free IPs left in a given admin
            // network segment, so just hard-code a /32 prefix_length. Unlike the
            // tenant segments, the admin segments are always (at least for the
            // foreseeable future) just going to allocate a /32 for the machine
            // interface.
            Box::new(UsedAdminNetworkIpResolver {
                segment_id: record.id,
                busy_ips,
            })
        };

        let mut allocated_addresses = IpAllocator::new(
            &mut *conn,
            record,
            dhcp_handler,
            AddressSelectionStrategy::NextAvailableIp,
        )
        .await
        .map_err(|e| {
            DatabaseError::new(
                "IpAllocator.new error",
                sqlx::Error::Io(std::io::Error::other(e.to_string())),
            )
        })?;

        let nfree = allocated_addresses.num_free().map_err(|e| {
            DatabaseError::new(
                "IpAllocator.num_free error",
                sqlx::Error::Io(std::io::Error::other(e.to_string())),
            )
        })?;

        record.prefixes[0].num_free_ips = nfree;
    }

    Ok(())
}

/// Updates the network segment state that is owned by the state controller
/// under the premise that the current controller state version didn't change.
///
/// Returns `true` if the state could be updated, and `false` if the object
/// either doesn't exist anymore or is at a different version.
pub async fn try_update_controller_state(
    txn: &mut PgConnection,
    segment_id: NetworkSegmentId,
    expected_version: ConfigVersion,
    new_state: &NetworkSegmentControllerState,
) -> Result<bool, DatabaseError> {
    let next_version = expected_version.increment();

    let query = "UPDATE network_segments SET controller_state_version=$1, controller_state=$2::json where id=$3::uuid AND controller_state_version=$4 returning id";
    let query_result: Result<NetworkSegmentId, _> = sqlx::query_as(query)
        .bind(next_version)
        .bind(sqlx::types::Json(new_state))
        .bind(segment_id)
        .bind(expected_version)
        .fetch_one(&mut *txn)
        .await;

    match query_result {
        Ok(_segment_id) => {
            crate::network_segment_state_history::persist(
                &mut *txn,
                segment_id,
                new_state,
                next_version,
            )
            .await?;
            Ok(true)
        }
        Err(sqlx::Error::RowNotFound) => Ok(false),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

pub async fn update_controller_state_outcome(
    txn: &mut PgConnection,
    segment_id: NetworkSegmentId,
    outcome: PersistentStateHandlerOutcome,
) -> Result<(), DatabaseError> {
    let query = "UPDATE network_segments SET controller_state_outcome=$1::json WHERE id=$2";
    sqlx::query(query)
        .bind(sqlx::types::Json(outcome))
        .bind(segment_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn set_vpc_id_and_can_stretch(
    value: &NetworkSegment,
    txn: &mut PgConnection,
    vpc_id: VpcId,
) -> Result<(), DatabaseError> {
    let query = "UPDATE network_segments SET vpc_id=$1, can_stretch=true WHERE id=$2";
    sqlx::query(query)
        .bind(vpc_id)
        .bind(value.id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn mark_as_deleted(
    value: &NetworkSegment,
    txn: &mut PgConnection,
) -> DatabaseResult<NetworkSegmentId> {
    // This check is not strictly necessary here, since the segment state machine
    // will also wait until all allocated addresses have been freed before actually
    // deleting the segment. However it gives the user some early feedback for
    // the commmon case, which allows them to free resources
    let num_machine_interfaces =
        crate::machine_interface::count_by_segment_id(txn, &value.id).await?;
    if num_machine_interfaces > 0 {
        return DatabaseResult::Err(DatabaseError::NetworkSegmentDelete(
            "Network Segment can't be deleted with associated MachineInterface".to_string(),
        ));
    }
    let num_instance_addresses =
        crate::instance_address::count_by_segment_id(txn, &value.id).await?;
    if num_instance_addresses > 0 {
        return DatabaseResult::Err(DatabaseError::NetworkSegmentDelete(
            "Network Segment can't be deleted while addresses on the segment are allocated to instances".to_string(),
        ));
    }

    let query = "UPDATE network_segments SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING id";
    let id = sqlx::query_as(query)
        .bind(value.id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(id)
}

pub async fn final_delete(
    segment_id: NetworkSegmentId,
    txn: &mut PgConnection,
) -> Result<NetworkSegmentId, DatabaseError> {
    crate::network_prefix::delete_for_segment(segment_id, txn).await?;

    let query = "DELETE FROM network_segments WHERE id=$1::uuid RETURNING id";
    let segment: NetworkSegmentId = sqlx::query_as(query)
        .bind(segment_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(segment)
}

pub async fn find_by_name(
    txn: &mut PgConnection,
    name: &str,
) -> Result<NetworkSegment, DatabaseError> {
    lazy_static! {
        static ref query: String =
            format!("{} WHERE name = $1", NETWORK_SEGMENT_SNAPSHOT_QUERY.deref());
    }
    sqlx::query_as(&query)
        .bind(name)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(&query, e))
}

/// This method returns Admin network segment.
pub async fn admin(txn: &mut PgConnection) -> Result<NetworkSegment, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            "{} WHERE network_segment_type = 'admin'",
            NETWORK_SEGMENT_SNAPSHOT_QUERY.deref()
        );
    }
    let mut segments: Vec<NetworkSegment> = sqlx::query_as(&query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(&query, e))?;

    if segments.is_empty() {
        return Err(DatabaseError::query(&query, sqlx::Error::RowNotFound));
    }

    Ok(segments.remove(0))
}

/// Are queried segment in ready state?
/// Returns true if all segments are in Ready state, else false
pub async fn are_network_segments_ready<DB>(
    conn: &mut DB,
    segment_ids: &[NetworkSegmentId],
) -> Result<bool, DatabaseError>
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    let segments = find_by(
        conn,
        ObjectColumnFilter::List(IdColumn, segment_ids),
        NetworkSegmentSearchConfig::default(),
    )
    .await?;

    Ok(!segments
        .iter()
        .any(|x| x.controller_state.value != NetworkSegmentControllerState::Ready))
}

/// This function is different from `mark_as_deleted` as no validation is checked here and it
/// takes a list of ids to reduce db handling time.
/// Instance is already deleted immediately before this.
pub async fn mark_as_deleted_no_validation(
    txn: &mut PgConnection,
    network_segment_ids: &[NetworkSegmentId],
) -> DatabaseResult<NetworkSegmentId> {
    let query =
        "UPDATE network_segments SET updated=NOW(), deleted=NOW() WHERE id=ANY($1) RETURNING id";
    let id = sqlx::query_as(query)
        .bind(network_segment_ids)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(id)
}

/// SVI IP is needed for Network Segments attached to FNN VPCs.
/// Usually third IP of a prefix is used as SVI IP. In case, first 3 IPs are not reserved,
/// carbide will pick any available free IP and store it in DB for further use.
pub async fn allocate_svi_ip(
    value: &NetworkSegment,
    // Note: This is a PgTransaction, not a PgConnection, because we will be doing table locking,
    // which must happen in a transaction.
    txn: &mut PgTransaction<'_>,
) -> Result<IpAddr, DatabaseError> {
    let Some(ipv4_prefix) = value.prefixes.iter().find(|x| x.prefix.is_ipv4()) else {
        return Err(DatabaseError::NotFoundError {
            kind: "ipv4_prefix",
            id: value.id.to_string(),
        });
    };

    if let Some(svi_ip) = ipv4_prefix.svi_ip {
        // SVI IP is already allocated.
        return Ok(svi_ip);
    }

    let (prefix_id, svi_ip) = if ipv4_prefix.num_reserved < 3 {
        // Need to allocate a IP from prefix.
        if !value.segment_type.is_tenant() {
            crate::machine_interface::allocate_svi_ip(txn, value).await?
        } else {
            crate::instance_address::allocate_svi_ip(txn, value).await?
        }
    } else {
        // Pick the third IP to use as SVI IP.
        (
            ipv4_prefix.id,
            ipv4_prefix.prefix.iter().nth(2).ok_or_else(|| {
                DatabaseError::internal(format!(
                    "Prefix {} does not have 3 valid IPs.",
                    ipv4_prefix.id
                ))
            })?,
        )
    };

    crate::network_prefix::set_svi_ip(txn, prefix_id, &svi_ip).await?;

    Ok(svi_ip)
}
