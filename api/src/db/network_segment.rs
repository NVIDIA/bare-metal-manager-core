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
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::db::address_selection_strategy::AddressSelectionStrategy;
use crate::db::domain::DomainId;
use crate::db::machine_interface::UsedAdminNetworkIpResolver;
use crate::db::vpc::VpcId;
use crate::dhcp::allocation::IpAllocator;
use ::rpc::forge as rpc;
use ::rpc::protos::forge::TenantState;
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use futures::StreamExt;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgHasArrayType, PgRow, PgTypeInfo};
use sqlx::{FromRow, Postgres, Row, Transaction, Type};

use crate::model::controller_outcome::PersistentStateHandlerOutcome;
use crate::model::network_segment::{NetworkDefinition, NetworkDefinitionSegmentType};
use crate::model::RpcDataConversionError;
use crate::{
    db::{
        instance_address::InstanceAddress,
        machine_interface::MachineInterface,
        network_prefix::{NetworkPrefix, NewNetworkPrefix},
        network_segment_state_history::NetworkSegmentStateHistory,
        DatabaseError,
    },
    model::network_segment::NetworkSegmentControllerState,
};
use crate::{CarbideError, CarbideResult};
use tonic::Status;

const DEFAULT_MTU_TENANT: i32 = 9000;
const DEFAULT_MTU_OTHER: i32 = 1500;

/// NetworkSegmentId is a strongly typed UUID specific to a network
/// segment ID, with trait implementations allowing it to be passed
/// around as a UUID, an RPC UUID, bound to sqlx queries, etc. This
/// is similar to what we do for MachineId, VpcId, InstanceId, and
/// basically all of the IDs in measured boot.
#[derive(
    Debug, Clone, Copy, FromRow, Type, Serialize, Deserialize, PartialEq, Eq, Hash, Default,
)]
#[sqlx(type_name = "UUID")]
pub struct NetworkSegmentId(pub uuid::Uuid);

impl From<NetworkSegmentId> for uuid::Uuid {
    fn from(id: NetworkSegmentId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for NetworkSegmentId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl FromStr for NetworkSegmentId {
    type Err = RpcDataConversionError;
    fn from_str(input: &str) -> Result<Self, RpcDataConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            RpcDataConversionError::InvalidUuid("NetworkSegmentId", input.to_string())
        })?))
    }
}

impl fmt::Display for NetworkSegmentId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<NetworkSegmentId> for ::rpc::common::Uuid {
    fn from(val: NetworkSegmentId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<::rpc::common::Uuid> for NetworkSegmentId {
    type Error = RpcDataConversionError;
    fn try_from(msg: ::rpc::common::Uuid) -> Result<Self, RpcDataConversionError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<&::rpc::common::Uuid> for NetworkSegmentId {
    type Error = RpcDataConversionError;
    fn try_from(msg: &::rpc::common::Uuid) -> Result<Self, RpcDataConversionError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<::rpc::common::Uuid>> for NetworkSegmentId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<::rpc::common::Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            // TODO(chet): Maybe this isn't the right place for this, since
            // depending on the proto message, the field name can differ (which
            // should actually probably be standardized anyway), or we can just
            // take a similar approach to ::InvalidUuid can say "field of type"?
            return Err(CarbideError::MissingArgument("segment_id").into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

impl NetworkSegmentId {
    pub fn from_grpc(msg: Option<::rpc::common::Uuid>) -> Result<Self, Status> {
        Self::try_from(msg)
            .map_err(|e| Status::invalid_argument(format!("bad grpc network segment ID: {}", e)))
    }
}

impl PgHasArrayType for NetworkSegmentId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}

///
/// A parameter to find() to filter resources by NetworkSegmentId;
///
#[derive(Clone)]
pub enum NetworkSegmentIdKeyedObjectFilter<'a> {
    /// Don't filter by NetworkSegmentId
    All,

    /// Filter by a list of NetworkSegmentIds
    List(&'a [NetworkSegmentId]),

    /// Retrieve a single resource
    One(NetworkSegmentId),
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
}

impl NetworkSegment {
    /// Returns whether the segment was deleted by the user
    pub fn is_marked_as_deleted(&self) -> bool {
        self.deleted.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
#[sqlx(type_name = "network_segment_type_t")]
pub enum NetworkSegmentType {
    Tenant = 0,
    Admin,
    Underlay,
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
}

impl TryFrom<i32> for NetworkSegmentType {
    type Error = RpcDataConversionError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            x if x == rpc::NetworkSegmentType::Tenant as i32 => NetworkSegmentType::Tenant,
            x if x == rpc::NetworkSegmentType::Admin as i32 => NetworkSegmentType::Admin,
            x if x == rpc::NetworkSegmentType::Underlay as i32 => NetworkSegmentType::Underlay,
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
        }
    }
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for NetworkSegment {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let config_version_str: &str = row.try_get("version")?;
        let version = config_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let controller_state_version_str: &str = row.try_get("controller_state_version")?;
        let controller_state_version = controller_state_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let controller_state: sqlx::types::Json<NetworkSegmentControllerState> =
            row.try_get("controller_state")?;
        let state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome")?;

        Ok(NetworkSegment {
            id: row.try_get("id")?,
            version,
            name: row.try_get("name")?,
            subdomain_id: row.try_get("subdomain_id")?,
            vpc_id: row.try_get("vpc_id")?,
            controller_state: Versioned::new(controller_state.0, controller_state_version),
            controller_state_outcome: state_outcome.map(|x| x.0),
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
            mtu: row.try_get("mtu")?,
            prefixes: Vec::new(),
            history: Vec::new(),
            vlan_id: row.try_get("vlan_id").unwrap_or_default(),
            vni: row.try_get("vni_id").unwrap_or_default(),
            segment_type: row.try_get("network_segment_type")?,
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
            history,
            segment_type: src.segment_type as i32,
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
        })
    }

    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
        initial_state: NetworkSegmentControllerState,
    ) -> Result<NetworkSegment, DatabaseError> {
        let version = ConfigVersion::initial();
        let version_string = version.version_string();

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
                network_segment_type)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *";
        let mut segment: NetworkSegment = sqlx::query_as(query)
            .bind(self.id)
            .bind(&self.name)
            .bind(self.subdomain_id)
            .bind(self.vpc_id)
            .bind(self.mtu)
            .bind(&version_string)
            .bind(&version_string)
            .bind(sqlx::types::Json(&initial_state))
            .bind(self.vlan_id)
            .bind(self.vni)
            .bind(self.segment_type)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        segment.prefixes =
            NetworkPrefix::create_for(txn, &segment.id, self.vlan_id, &self.prefixes).await?;

        NetworkSegmentStateHistory::persist(txn, segment.id, &initial_state, version).await?;

        Ok(segment)
    }
}

impl NetworkSegment {
    pub async fn for_vpc(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        vpc_id: uuid::Uuid,
    ) -> Result<Vec<Self>, DatabaseError> {
        let results: Vec<NetworkSegment> = {
            let query = "SELECT * FROM network_segments WHERE vpc_id=$1::uuid";
            sqlx::query_as(query)
                .bind(vpc_id)
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        };

        Ok(results)
    }

    pub async fn for_relay(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        relay: IpAddr,
    ) -> CarbideResult<Option<Self>> {
        let query = r#"SELECT network_segments.*
            FROM network_segments
            INNER JOIN network_prefixes ON network_prefixes.segment_id = network_segments.id
            WHERE $1::inet <<= network_prefixes.prefix"#;
        let mut results = sqlx::query_as(query)
            .bind(IpNetwork::from(relay))
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        match results.len() {
            0 => Ok(None),
            1 => {
                let mut segment: NetworkSegment = results.remove(0);

                let query = "SELECT * FROM network_prefixes WHERE segment_id=$1::uuid";
                segment.prefixes = sqlx::query_as(query)
                    .bind(segment.id())
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| {
                        CarbideError::from(DatabaseError::new(file!(), line!(), query, e))
                    })?;

                Ok(Some(segment))
            }
            _ => Err(CarbideError::MultipleNetworkSegmentsForRelay(relay)),
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
            let stream = sqlx::query_as::<_, NetworkSegmentId>(query)
                .bind(segment_type)
                .fetch(&mut **txn);
            (query, stream)
        } else {
            let query = "SELECT id FROM network_segments";
            let stream = sqlx::query_as::<_, NetworkSegmentId>(query).fetch(&mut **txn);
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
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "network_segment::find_ids", e))?;

        Ok(ids)
    }

    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: NetworkSegmentIdKeyedObjectFilter<'_>,
        search_config: NetworkSegmentSearchConfig,
    ) -> Result<Vec<Self>, DatabaseError> {
        let base_query = "SELECT * FROM network_segments {where}".to_owned();

        let mut all_records: Vec<NetworkSegment> = match filter {
            NetworkSegmentIdKeyedObjectFilter::All => {
                sqlx::query_as::<_, NetworkSegment>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "network_segments All", e))?
            }

            NetworkSegmentIdKeyedObjectFilter::List(uuids) => sqlx::query_as::<_, NetworkSegment>(
                &base_query.replace("{where}", "WHERE network_segments.id=ANY($1)"),
            )
            .bind(uuids)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "network_segments List", e))?,
            NetworkSegmentIdKeyedObjectFilter::One(uuid) => sqlx::query_as::<_, NetworkSegment>(
                &base_query.replace("{where}", "WHERE network_segments.id=$1"),
            )
            .bind(uuid)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "network_segments One", e))?,
        };

        Self::update_prefix_into_network_segment_list(txn, search_config, &mut all_records).await?;
        Ok(all_records)
    }

    async fn update_prefix_into_network_segment_list(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        search_config: NetworkSegmentSearchConfig,
        all_records: &mut Vec<NetworkSegment>,
    ) -> Result<(), DatabaseError> {
        let all_uuids = all_records
            .iter()
            .map(|record| record.id)
            .collect::<Vec<NetworkSegmentId>>();

        // TODO(ajf): N+1 query alert.  Optimize later.

        let mut grouped_prefixes = NetworkPrefix::find_by_segment(
            &mut *txn,
            NetworkSegmentIdKeyedObjectFilter::List(&all_uuids),
        )
        .await?
        .into_iter()
        .into_group_map_by(|prefix| prefix.segment_id);

        let mut state_history = if search_config.include_history {
            NetworkSegmentStateHistory::find_by_segment_ids(&mut *txn, &all_uuids).await?
        } else {
            HashMap::new()
        };

        for record in all_records {
            if let Some(prefixes) = grouped_prefixes.remove(&record.id) {
                record.prefixes = prefixes;

                if search_config.include_num_free_ips && !record.prefixes.is_empty() {
                    if record.segment_type == crate::db::network_segment::NetworkSegmentType::Tenant
                    {
                        let dhcp_handler =
                            crate::db::instance_address::UsedOverlayNetworkIpResolver {
                                segment_id: record.id,
                            };

                        let mut allocated_addresses = IpAllocator::new(
                            txn,
                            record,
                            &dhcp_handler,
                            AddressSelectionStrategy::Automatic,
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

                        let nfree = allocated_addresses.num_free();

                        record.prefixes[0].num_free_ips = nfree;
                    } else {
                        let dhcp_handler = UsedAdminNetworkIpResolver {
                            segment_id: record.id,
                        };

                        let mut allocated_addresses = IpAllocator::new(
                            txn,
                            record,
                            &dhcp_handler,
                            AddressSelectionStrategy::Automatic,
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

                        let nfree = allocated_addresses.num_free();

                        record.prefixes[0].num_free_ips = nfree;
                    }
                }
            } else {
                tracing::warn!(
                    record_id = %record.id,
                    record_name = record.name,
                    "Network has no prefixes?",
                );
            }

            if search_config.include_history {
                if let Some(history) = state_history.remove(&record.id) {
                    record.history = history;
                } else {
                    tracing::warn!(
                        record_id = %record.id,
                        record_name = record.name,
                        "Network has no history yet.",
                    );
                }
            }
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
        let expected_version_str = expected_version.version_string();
        let next_version = expected_version.increment();
        let next_version_str = next_version.version_string();

        let query = "UPDATE network_segments SET controller_state_version=$1, controller_state=$2::json where id=$3::uuid AND controller_state_version=$4 returning id";
        let query_result: Result<NetworkSegmentId, _> = sqlx::query_as(query)
            .bind(&next_version_str)
            .bind(sqlx::types::Json(new_state))
            .bind(segment_id)
            .bind(&expected_version_str)
            .fetch_one(&mut **txn)
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
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub fn subdomain_id(&self) -> Option<&DomainId> {
        self.subdomain_id.as_ref()
    }

    pub fn id(&self) -> &NetworkSegmentId {
        &self.id
    }

    pub async fn mark_as_deleted(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<NetworkSegment> {
        // This check is not strictly necessary here, since the segment state machine
        // will also wait until all allocated addresses have been freed before actually
        // deleting the segment. However it gives the user some early feedback for
        // the commmon case, which allows them to free resources
        let num_machine_interfaces = MachineInterface::count_by_segment_id(txn, self.id()).await?;
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
            "UPDATE network_segments SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING *";
        let segment: NetworkSegment = sqlx::query_as(query)
            .bind(self.id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(segment)
    }

    pub async fn final_delete(
        segment_id: NetworkSegmentId,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<NetworkSegmentId, DatabaseError> {
        NetworkPrefix::delete_for_segment(segment_id, txn).await?;

        let query = "DELETE FROM network_segments WHERE id=$1::uuid RETURNING id";
        let segment: NetworkSegmentId = sqlx::query_as(query)
            .bind(segment_id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(segment)
    }

    pub async fn find_by_circuit_id(
        txn: &mut Transaction<'_, Postgres>,
        circuit_id: &str,
    ) -> Result<Self, DatabaseError> {
        let query = "
SELECT network_segments.* FROM network_segments
INNER JOIN network_prefixes ON network_prefixes.segment_id = network_segments.id
WHERE network_prefixes.circuit_id=$1";
        sqlx::query_as(query)
            .bind(circuit_id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_name(
        txn: &mut Transaction<'_, Postgres>,
        name: &str,
    ) -> Result<Self, DatabaseError> {
        let query = "SELECT * from network_segments WHERE name = $1";
        sqlx::query_as(query)
            .bind(name)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    /// This method returns Admin network segment.
    pub async fn admin(txn: &mut Transaction<'_, Postgres>) -> Result<Self, DatabaseError> {
        let query = "SELECT * FROM network_segments WHERE network_segment_type = 'admin'";
        let mut segments: Vec<NetworkSegment> =
            sqlx::query_as(query)
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        if segments.is_empty() {
            return Err(DatabaseError::new(
                file!(),
                line!(),
                query,
                sqlx::Error::RowNotFound,
            ));
        }

        Self::update_prefix_into_network_segment_list(
            txn,
            NetworkSegmentSearchConfig::default(),
            &mut segments,
        )
        .await?;

        Ok(segments.remove(0))
    }

    /// The result of the last state controller iteration, if any
    pub fn current_state_iteration_outcome(&self) -> Option<PersistentStateHandlerOutcome> {
        self.controller_state_outcome.clone()
    }
}
