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
use std::fmt;
use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use crate::db::address_selection_strategy::AddressSelectionStrategy;
use crate::db::instance_address::UsedOverlayNetworkIpResolver;
use crate::db::machine_interface::UsedAdminNetworkIpResolver;
use crate::db::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter};
use crate::dhcp::allocation::{IpAllocator, UsedIpResolver};
use crate::model::controller_outcome::PersistentStateHandlerOutcome;
use crate::model::network_segment::{state_sla, NetworkDefinition, NetworkDefinitionSegmentType};
use crate::{
    db::{
        self,
        instance_address::InstanceAddress,
        network_prefix::{NetworkPrefix, NewNetworkPrefix},
        network_segment_state_history::NetworkSegmentStateHistory,
        DatabaseError,
    },
    model::network_segment::NetworkSegmentControllerState,
};
use crate::{CarbideError, CarbideResult};
use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use ::rpc::protos::forge::TenantState;
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use forge_uuid::{domain::DomainId, network::NetworkSegmentId, vpc::VpcId};
use futures::StreamExt;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{Column, FromRow, Postgres, Row, Transaction};

const DEFAULT_MTU_TENANT: i32 = 9000;
const DEFAULT_MTU_OTHER: i32 = 1500;

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

#[derive(Debug, Copy, Clone, Default)]
pub struct NetworkSegmentSearchConfig {
    pub include_history: bool,
    pub include_num_free_ips: bool,
}

impl From<rpc::NetworkSegmentSearchConfig> for NetworkSegmentSearchConfig {
    fn from(value: rpc::NetworkSegmentSearchConfig) -> Self {
        NetworkSegmentSearchConfig {
            include_history: value.include_history,
            include_num_free_ips: value.include_num_free_ips,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkSegment {
    pub id: NetworkSegmentId,
    pub version: ConfigVersion,
    pub name: String,
    pub subdomain_id: Option<DomainId>,
    pub vpc_id: Option<VpcId>,
    pub mtu: i32,

    pub controller_state: Versioned<NetworkSegmentControllerState>,

    /// The result of the last attempt to change state
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,

    pub prefixes: Vec<NetworkPrefix>,
    /// History of state changes.
    pub history: Vec<NetworkSegmentStateHistory>,

    pub vlan_id: Option<i16>, // vlan_id are [0-4096) range, enforced via DB constraint
    pub vni: Option<i32>,

    pub segment_type: NetworkSegmentType,

    pub can_stretch: Option<bool>,
}

impl NetworkSegment {
    /// Returns whether the segment was deleted by the user
    pub fn is_marked_as_deleted(&self) -> bool {
        self.deleted.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "network_segment_type_t")]
pub enum NetworkSegmentType {
    Tenant = 0,
    Admin,
    Underlay,
    HostInband,
}

impl NetworkSegmentType {
    pub fn is_tenant(&self) -> bool {
        matches!(
            self,
            NetworkSegmentType::Tenant | NetworkSegmentType::HostInband
        )
    }
}

#[derive(Debug)]
pub struct NewNetworkSegment {
    pub id: NetworkSegmentId,
    pub name: String,
    pub subdomain_id: Option<DomainId>,
    pub vpc_id: Option<VpcId>,
    pub mtu: i32,
    pub prefixes: Vec<NewNetworkPrefix>,
    pub vlan_id: Option<i16>,
    pub vni: Option<i32>,
    pub segment_type: NetworkSegmentType,
    pub can_stretch: Option<bool>,
}

impl TryFrom<i32> for NetworkSegmentType {
    type Error = RpcDataConversionError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            x if x == rpc::NetworkSegmentType::Tenant as i32 => NetworkSegmentType::Tenant,
            x if x == rpc::NetworkSegmentType::Admin as i32 => NetworkSegmentType::Admin,
            x if x == rpc::NetworkSegmentType::Underlay as i32 => NetworkSegmentType::Underlay,
            x if x == rpc::NetworkSegmentType::HostInband as i32 => NetworkSegmentType::HostInband,
            _ => {
                return Err(RpcDataConversionError::InvalidNetworkSegmentType(value));
            }
        })
    }
}

impl FromStr for NetworkSegmentType {
    type Err = CarbideError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "tenant" => NetworkSegmentType::Tenant,
            "admin" => NetworkSegmentType::Admin,
            "tor" => NetworkSegmentType::Underlay,
            "host_inband" => NetworkSegmentType::HostInband,
            _ => {
                return Err(CarbideError::DatabaseTypeConversionError(format!(
                    "Invalid segment type {} reveived from Database.",
                    s
                )))
            }
        })
    }
}

impl fmt::Display for NetworkSegmentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tenant => write!(f, "tenant"),
            Self::Admin => write!(f, "admin"),
            Self::Underlay => write!(f, "tor"),
            Self::HostInband => write!(f, "host_inband"),
        }
    }
}

const NETWORK_SEGMENT_SNAPSHOT_QUERY_TEMPLATE: &str = r#"
    WITH
        prefixes_agg AS (
            SELECT np.segment_id,
                json_agg(np.*) AS json
            FROM network_prefixes np
            GROUP BY np.segment_id
        )
        __HISTORY_AGG__
     SELECT
        ns.*,
        COALESCE(prefixes_agg.json, '[]'::json) AS prefixes
        __HISTORY_SELECT__
     FROM network_segments ns
     LEFT JOIN prefixes_agg ON prefixes_agg.segment_id = ns.id
     __HISTORY_JOIN__
"#;

lazy_static! {
    static ref NETWORK_SEGMENT_SNAPSHOT_QUERY: String = NETWORK_SEGMENT_SNAPSHOT_QUERY_TEMPLATE
        .replace("__HISTORY_AGG__", "")
        .replace("__HISTORY_SELECT__", "")
        .replace("__HISTORY_JOIN__", "");

    static ref NETWORK_SEGMENT_SNAPSHOT_WITH_HISTORY_QUERY: String = NETWORK_SEGMENT_SNAPSHOT_QUERY_TEMPLATE
        .replace("__HISTORY_AGG__", r#"
            , history_agg AS (
                SELECT h.segment_id,
                    json_agg(json_build_object('segment_id', h.segment_id, 'state', h.state::text, 'state_version', h.state_version, 'timestamp', h."timestamp")) AS json
                FROM network_segment_state_history h
                GROUP BY h.segment_id
            )"#)
        .replace("__HISTORY_SELECT__", ", COALESCE(history_agg.json, '[]'::json) AS history")
        .replace("__HISTORY_JOIN__", "LEFT JOIN history_agg ON history_agg.segment_id = ns.id");
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for NetworkSegment {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state: sqlx::types::Json<NetworkSegmentControllerState> =
            row.try_get("controller_state")?;
        let state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome")?;

        let prefixes_json: sqlx::types::Json<Vec<Option<NetworkPrefix>>> =
            row.try_get("prefixes")?;
        let prefixes = prefixes_json.0.into_iter().flatten().collect();

        let history = if let Some(column) = row.columns().iter().find(|c| c.name() == "history") {
            let value: sqlx::types::Json<Vec<Option<NetworkSegmentStateHistory>>> =
                row.try_get(column.ordinal())?;
            value.0.into_iter().flatten().collect()
        } else {
            Vec::new()
        };

        Ok(NetworkSegment {
            id: row.try_get("id")?,
            version: row.try_get("version")?,
            name: row.try_get("name")?,
            subdomain_id: row.try_get("subdomain_id")?,
            vpc_id: row.try_get("vpc_id")?,
            controller_state: Versioned::new(
                controller_state.0,
                row.try_get("controller_state_version")?,
            ),
            controller_state_outcome: state_outcome.map(|x| x.0),
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
            mtu: row.try_get("mtu")?,
            prefixes,
            history,
            vlan_id: row.try_get("vlan_id").unwrap_or_default(),
            vni: row.try_get("vni_id").unwrap_or_default(),
            segment_type: row.try_get("network_segment_type")?,
            can_stretch: row.try_get("can_stretch")?,
        })
    }
}

/// Converts from Protobuf NetworkSegmentCreationRequest into NewNetworkSegment
///
/// subdomain_id - Converting from Protobuf UUID(String) to Rust UUID type can fail.
/// Use try_from in order to return a Result where Result is an error if the conversion
/// from String -> UUID fails
///
impl TryFrom<rpc::NetworkSegmentCreationRequest> for NewNetworkSegment {
    type Error = CarbideError;

    fn try_from(value: rpc::NetworkSegmentCreationRequest) -> Result<Self, Self::Error> {
        if value.prefixes.is_empty() {
            return Err(CarbideError::InvalidArgument(
                "Prefixes are empty.".to_string(),
            ));
        }

        let prefixes = value
            .prefixes
            .into_iter()
            .map(NewNetworkPrefix::try_from)
            .collect::<Result<Vec<NewNetworkPrefix>, CarbideError>>()?;

        if prefixes.iter().any(|ip| ip.prefix.ip().is_ipv6()) {
            return Err(CarbideError::InvalidArgument(
                "IPv6 is not yet supported.".to_string(),
            ));
        }

        let id = match value.id {
            Some(v) => NetworkSegmentId::try_from(v)?,
            None => uuid::Uuid::new_v4().into(),
        };

        let segment_type: NetworkSegmentType = value.segment_type.try_into()?;
        if segment_type == NetworkSegmentType::Tenant
            && prefixes.iter().any(|ip| ip.prefix.prefix() >= 31)
        {
            return Err(CarbideError::InvalidArgument(
                "Prefix 31 and 32 are not allowed.".to_string(),
            ));
        }

        // This TryFrom implementation is part of the API handler logic for
        // network segment creation, and is not used by FNN. Therefore, the only
        // type of tenant segment we could be creating is a stretchable one.
        let can_stretch = matches!(segment_type, NetworkSegmentType::Tenant).then_some(true);

        Ok(NewNetworkSegment {
            id,
            name: value.name,
            subdomain_id: match value.subdomain_id {
                Some(v) => Some(DomainId::try_from(v)?),
                None => None,
            },
            vpc_id: match value.vpc_id {
                Some(v) => Some(VpcId::try_from(v)?),
                None => None,
            },
            mtu: value.mtu.unwrap_or(match segment_type {
                NetworkSegmentType::Tenant => DEFAULT_MTU_TENANT,
                _ => DEFAULT_MTU_OTHER,
            }),
            prefixes,
            vlan_id: None,
            vni: None,
            segment_type,
            can_stretch,
        })
    }
}

///
/// Marshal a Data Object (NetworkSegment) into an RPC NetworkSegment
///
/// subdomain_id - Rust UUID -> ProtoBuf UUID(String) cannot fail, so convert it or return None
///
impl TryFrom<NetworkSegment> for rpc::NetworkSegment {
    type Error = CarbideError;
    fn try_from(src: NetworkSegment) -> Result<Self, Self::Error> {
        // Note that even thought the segment might already be ready,
        // we only return `Ready` after
        // the state machine also noticed that. Otherwise we would need to also
        // allow address allocation before the controller state is ready, which
        // spreads out the state mismatch to a lot more places.
        let mut state = match &src.controller_state.value {
            NetworkSegmentControllerState::Provisioning => TenantState::Provisioning,
            NetworkSegmentControllerState::Ready => TenantState::Ready,
            NetworkSegmentControllerState::Deleting { .. } => TenantState::Terminating,
        };
        // If deletion is requested, we immediately overwrite the state to terminating.
        // Even though the state controller hasn't caught up - it eventually will
        if src.is_marked_as_deleted() {
            state = TenantState::Terminating;
        }

        let mut history = Vec::with_capacity(src.history.len());

        for state in src.history {
            history.push(rpc::NetworkSegmentStateHistory::try_from(state)?);
        }

        let flags: Vec<i32> = {
            use rpc::NetworkSegmentFlag::*;

            let mut flags = vec![];

            let can_stretch = src.can_stretch.unwrap_or_else(|| {
                // If the segment's can_stretch flag is NULL in the database,
                // we're going to have to go off of what an FNN-created
                // segment's prefixes would look like, and then assume any such
                // FNN segment is _not_ stretchable.
                src.prefixes.iter().all(|p| !p.smells_like_fnn())
            });
            if can_stretch {
                flags.push(CanStretch);
            }

            // Just so a gRPC client can tell the difference between a missing
            // `flags` field and an empty one.
            if flags.is_empty() {
                flags.push(NoOp);
            }

            flags.into_iter().map(|flag| flag as i32).collect()
        };

        Ok(rpc::NetworkSegment {
            id: Some(src.id.into()),
            version: src.version.version_string(),
            name: src.name,
            subdomain_id: src.subdomain_id.map(::rpc::common::Uuid::from),
            mtu: Some(src.mtu),
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
            prefixes: src
                .prefixes
                .into_iter()
                .map(rpc::NetworkPrefix::from)
                .collect_vec(),
            vpc_id: src.vpc_id.map(::rpc::common::Uuid::from),
            state: state as i32,
            state_reason: src.controller_state_outcome.map(|r| r.into()),
            state_sla: Some(
                state_sla(&src.controller_state.value, &src.controller_state.version).into(),
            ),
            history,
            segment_type: src.segment_type as i32,
            flags,
        })
    }
}

impl NewNetworkSegment {
    pub fn build_from(
        name: &str,
        domain_id: DomainId,
        value: &NetworkDefinition,
    ) -> Result<Self, CarbideError> {
        let prefix = NewNetworkPrefix {
            prefix: value.prefix.parse()?,
            gateway: Some(value.gateway.parse()?),
            num_reserved: value.reserve_first,
        };
        Ok(NewNetworkSegment {
            id: uuid::Uuid::new_v4().into(),
            name: name.to_string(), // Set by the caller later
            subdomain_id: Some(domain_id),
            vpc_id: None,
            mtu: value.mtu,
            prefixes: vec![prefix],
            vlan_id: None,
            vni: None,
            segment_type: match value.segment_type {
                NetworkDefinitionSegmentType::Admin => NetworkSegmentType::Admin,
                NetworkDefinitionSegmentType::Underlay => NetworkSegmentType::Underlay,
            },
            can_stretch: None,
        })
    }

    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
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
            .bind(self.id)
            .bind(&self.name)
            .bind(self.subdomain_id)
            .bind(self.vpc_id)
            .bind(self.mtu)
            .bind(version)
            .bind(version)
            .bind(sqlx::types::Json(&initial_state))
            .bind(self.vlan_id)
            .bind(self.vni)
            .bind(self.segment_type)
            .bind(self.can_stretch)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        NetworkPrefix::create_for(txn, &segment_id, self.vlan_id, &self.prefixes).await?;
        NetworkSegmentStateHistory::persist(txn, segment_id, &initial_state, version).await?;

        NetworkSegment::find_by(
            txn,
            ObjectColumnFilter::One(IdColumn, &segment_id),
            Default::default(),
        )
        .await?
        .pop()
        .ok_or_else(|| {
            DatabaseError::new(
                file!(),
                line!(),
                "finding just-created network segment",
                sqlx::Error::RowNotFound,
            )
        })
    }
}

impl NetworkSegment {
    pub async fn for_vpc(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        vpc_id: uuid::Uuid,
    ) -> Result<Vec<Self>, DatabaseError> {
        lazy_static! {
            static ref query: String = format!(
                "{} WHERE ns.vpc_id=$1::uuid",
                NETWORK_SEGMENT_SNAPSHOT_QUERY.deref()
            );
        }
        let results: Vec<NetworkSegment> = {
            sqlx::query_as(&query)
                .bind(vpc_id)
                .fetch_all(txn.deref_mut())
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))?
        };

        Ok(results)
    }

    pub async fn for_relay(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        relay: IpAddr,
    ) -> CarbideResult<Option<Self>> {
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
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), &query, e)))?;

        match results.len() {
            0 | 1 => Ok(results.pop()),
            _ => Err(CarbideError::internal(format!(
                "Multiple network segments defined for relay address {relay}"
            ))),
        }
    }

    /// Retrieves the IDs of all network segments.
    /// If `segment_type` is specified, only IDs of segments that match the specific type are returned.
    pub async fn list_segment_ids(
        txn: &mut Transaction<'_, Postgres>,
        segment_type: Option<NetworkSegmentType>,
    ) -> Result<Vec<NetworkSegmentId>, DatabaseError> {
        let (query, mut segment_id_stream) = if let Some(segment_type) = segment_type {
            let query = "SELECT id FROM network_segments where network_segment_type=$1";
            let stream = sqlx::query_as(query)
                .bind(segment_type)
                .fetch(txn.deref_mut());
            (query, stream)
        } else {
            let query = "SELECT id FROM network_segments";
            let stream = sqlx::query_as(query).fetch(txn.deref_mut());
            (query, stream)
        };

        let mut results = Vec::new();
        while let Some(maybe_id) = segment_id_stream.next().await {
            let id = maybe_id.map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
            results.push(id);
        }

        Ok(results)
    }

    pub async fn find_ids(
        txn: &mut Transaction<'_, Postgres>,
        filter: rpc::NetworkSegmentSearchFilter,
    ) -> Result<Vec<NetworkSegmentId>, CarbideError> {
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
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "network_segment::find_ids", e))?;

        Ok(ids)
    }

    pub async fn find_by<'a, C: ColumnInfo<'a, TableType = NetworkSegment>>(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: ObjectColumnFilter<'a, C>,
        search_config: NetworkSegmentSearchConfig,
    ) -> Result<Vec<Self>, DatabaseError> {
        let mut query = FilterableQueryBuilder::new(if search_config.include_history {
            NETWORK_SEGMENT_SNAPSHOT_WITH_HISTORY_QUERY.deref()
        } else {
            NETWORK_SEGMENT_SNAPSHOT_QUERY.deref()
        })
        .filter(&filter);

        let mut all_records = query
            .build_query_as()
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query.sql(), e))?;

        if search_config.include_num_free_ips {
            Self::update_num_free_ips_into_prefix_list(txn, &mut all_records).await?;
        }
        Ok(all_records)
    }

    /// Find network segments attached to a machine through machine_interfaces, optionally of a certain type
    pub async fn find_ids_by_machine_id(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_id: &forge_uuid::machine::MachineId,
        network_segment_type: Option<NetworkSegmentType>,
    ) -> Result<Vec<NetworkSegmentId>, DatabaseError> {
        let mut query = sqlx::QueryBuilder::new(
            r#"SELECT ns.id FROM machines m
                LEFT JOIN machine_interfaces mi ON (mi.machine_id = m.id)
                INNER JOIN network_segments ns ON (ns.id = mi.segment_id)
                WHERE mi.machine_id =
            "#,
        );

        query.push_bind(machine_id);

        if let Some(network_segment_type) = network_segment_type {
            query
                .push(" AND ns.network_segment_type = ")
                .push_bind(network_segment_type);
        }

        let network_segment_ids = query
            .build_query_as()
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query.sql(), e))?;

        Ok(network_segment_ids)
    }

    async fn update_num_free_ips_into_prefix_list(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        all_records: &mut [NetworkSegment],
    ) -> Result<(), DatabaseError> {
        for record in all_records.iter_mut().filter(|s| !s.prefixes.is_empty()) {
            let mut busy_ips = vec![];
            for prefix in &record.prefixes {
                if let Some(svi_ip) = prefix.svi_ip {
                    busy_ips.push(svi_ip);
                }
            }
            let dhcp_handler: Box<dyn UsedIpResolver + Send> = if record.segment_type.is_tenant() {
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
                txn,
                record,
                dhcp_handler,
                AddressSelectionStrategy::Automatic,
                32,
            )
            .await
            .map_err(|e| {
                DatabaseError::new(
                    file!(),
                    line!(),
                    "IpAllocator.new error",
                    sqlx::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )),
                )
            })?;

            let nfree = allocated_addresses.num_free().map_err(|e| {
                DatabaseError::new(
                    file!(),
                    line!(),
                    "IpAllocator.num_free error",
                    sqlx::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )),
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
        txn: &mut Transaction<'_, Postgres>,
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
            .fetch_one(txn.deref_mut())
            .await;

        match query_result {
            Ok(_segment_id) => {
                NetworkSegmentStateHistory::persist(&mut *txn, segment_id, new_state, next_version)
                    .await?;
                Ok(true)
            }
            Err(sqlx::Error::RowNotFound) => Ok(false),
            Err(e) => Err(DatabaseError::new(file!(), line!(), query, e)),
        }
    }

    pub async fn update_controller_state_outcome(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        segment_id: NetworkSegmentId,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE network_segments SET controller_state_outcome=$1::json WHERE id=$2";
        sqlx::query(query)
            .bind(sqlx::types::Json(outcome))
            .bind(segment_id)
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn set_vpc_id_and_can_stretch(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
        vpc_id: VpcId,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE network_segments SET vpc_id=$1, can_stretch=true WHERE id=$2";
        sqlx::query(query)
            .bind(vpc_id.0)
            .bind(self.id)
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub fn id(&self) -> &NetworkSegmentId {
        &self.id
    }

    pub async fn mark_as_deleted(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<NetworkSegmentId> {
        // This check is not strictly necessary here, since the segment state machine
        // will also wait until all allocated addresses have been freed before actually
        // deleting the segment. However it gives the user some early feedback for
        // the commmon case, which allows them to free resources
        let num_machine_interfaces =
            db::machine_interface::count_by_segment_id(txn, self.id()).await?;
        if num_machine_interfaces > 0 {
            return CarbideResult::Err(CarbideError::NetworkSegmentDelete(
                "Network Segment can't be deleted with associated MachineInterface".to_string(),
            ));
        }
        let num_instance_addresses = InstanceAddress::count_by_segment_id(txn, *self.id()).await?;
        if num_instance_addresses > 0 {
            return CarbideResult::Err(CarbideError::NetworkSegmentDelete(
                "Network Segment can't be deleted while addresses on the segment are allocated to instances".to_string(),
            ));
        }

        let query =
            "UPDATE network_segments SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING id";
        let id = sqlx::query_as(query)
            .bind(self.id)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(id)
    }

    pub async fn final_delete(
        segment_id: NetworkSegmentId,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<NetworkSegmentId, DatabaseError> {
        NetworkPrefix::delete_for_segment(segment_id, txn).await?;

        let query = "DELETE FROM network_segments WHERE id=$1::uuid RETURNING id";
        let segment: NetworkSegmentId = sqlx::query_as(query)
            .bind(segment_id)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(segment)
    }

    pub async fn find_by_circuit_id(
        txn: &mut Transaction<'_, Postgres>,
        circuit_id: &str,
    ) -> Result<Self, DatabaseError> {
        lazy_static! {
            static ref query: String = format!(
                r#"{}
                INNER JOIN network_prefixes ON network_prefixes.segment_id = ns.id
                WHERE network_prefixes.circuit_id=$1"#,
                NETWORK_SEGMENT_SNAPSHOT_QUERY.deref()
            );
        }
        sqlx::query_as(&query)
            .bind(circuit_id)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))
    }

    pub async fn find_by_name(
        txn: &mut Transaction<'_, Postgres>,
        name: &str,
    ) -> Result<Self, DatabaseError> {
        lazy_static! {
            static ref query: String =
                format!("{} WHERE name = $1", NETWORK_SEGMENT_SNAPSHOT_QUERY.deref());
        }
        let segment: Self = sqlx::query_as(&query)
            .bind(name)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))?;
        Ok(segment)
    }

    /// This method returns Admin network segment.
    pub async fn admin(txn: &mut Transaction<'_, Postgres>) -> Result<Self, DatabaseError> {
        lazy_static! {
            static ref query: String = format!(
                "{} WHERE network_segment_type = 'admin'",
                NETWORK_SEGMENT_SNAPSHOT_QUERY.deref()
            );
        }
        let mut segments: Vec<NetworkSegment> = sqlx::query_as(&query)
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))?;

        if segments.is_empty() {
            return Err(DatabaseError::new(
                file!(),
                line!(),
                &query,
                sqlx::Error::RowNotFound,
            ));
        }

        Ok(segments.remove(0))
    }

    /// Are queried segment in ready state?
    /// Returns true if all segments are in Ready state, else false
    pub async fn are_network_segments_ready(
        txn: &mut Transaction<'_, Postgres>,
        segment_ids: &[NetworkSegmentId],
    ) -> Result<bool, DatabaseError> {
        let segments = NetworkSegment::find_by(
            txn,
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
        txn: &mut Transaction<'_, Postgres>,
        network_segment_ids: &[NetworkSegmentId],
    ) -> CarbideResult<NetworkSegmentId> {
        let query = "UPDATE network_segments SET updated=NOW(), deleted=NOW() WHERE id=ANY($1) RETURNING id";
        let id = sqlx::query_as(query)
            .bind(network_segment_ids)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(id)
    }

    /// SVI IP is needed for Network Segments attached to FNN VPCs.
    /// Usually third IP of a prefix is used as SVI IP. In case, first 3 IPs are not reserved,
    /// carbide will pick any available free IP and store it in DB for further use.
    pub async fn allocate_svi_ip(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<IpAddr, CarbideError> {
        let Some(ipv4_prefix) = self.prefixes.iter().find(|x| x.prefix.is_ipv4()) else {
            return Err(CarbideError::NotFoundError {
                kind: "ipv4_prefix",
                id: self.id.to_string(),
            });
        };

        if let Some(svi_ip) = ipv4_prefix.svi_ip {
            // SVI IP is already allocated.
            return Ok(svi_ip);
        }

        let (prefix_id, svi_ip) = if ipv4_prefix.num_reserved < 3 {
            // Need to allocate a IP from prefix.
            if !self.segment_type.is_tenant() {
                db::machine_interface::allocate_svi_ip(txn, self).await?
            } else {
                db::instance_address::allocate_svi_ip(txn, self).await?
            }
        } else {
            // Pick the third IP to use as SVI IP.
            (
                ipv4_prefix.id,
                ipv4_prefix.prefix.iter().nth(2).ok_or_else(|| {
                    CarbideError::internal(format!(
                        "Prefix {} does not have 3 valid IPs.",
                        ipv4_prefix.id
                    ))
                })?,
            )
        };

        NetworkPrefix::set_svi_ip(txn, prefix_id, &svi_ip)
            .await
            .map_err(CarbideError::from)?;

        Ok(svi_ip)
    }
}
