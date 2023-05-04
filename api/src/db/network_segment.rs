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
use std::convert::TryFrom;
use std::net::IpAddr;
use std::str::FromStr;

use ::rpc::forge as rpc;
use ::rpc::protos::forge::TenantState;
use chrono::prelude::*;
use futures::StreamExt;
use ipnetwork::{IpNetwork, IpNetworkError};
use itertools::Itertools;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Transaction};
use sqlx::{Postgres, Row};
use uuid::Uuid;

use crate::model::RpcDataConversionError;
use crate::{
    db::{
        instance_address::InstanceAddress,
        machine_interface::MachineInterface,
        network_prefix::{NetworkPrefix, NewNetworkPrefix},
        network_segment_state_history::NetworkSegmentStateHistory,
        DatabaseError, UuidKeyedObjectFilter,
    },
    model::{
        config_version::{ConfigVersion, Versioned},
        network_segment::NetworkSegmentControllerState,
    },
};
use crate::{CarbideError, CarbideResult};

#[derive(Debug, Clone, Default)]
pub struct NetworkSegmentSearchConfig {
    pub include_history: bool,
}

impl From<rpc::NetworkSegmentSearchConfig> for NetworkSegmentSearchConfig {
    fn from(value: rpc::NetworkSegmentSearchConfig) -> Self {
        NetworkSegmentSearchConfig {
            include_history: value.include_history,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkSegment {
    pub id: Uuid,
    pub version: ConfigVersion,
    pub name: String,
    pub subdomain_id: Option<Uuid>,
    pub vpc_id: Option<Uuid>,
    pub mtu: i32,

    pub controller_state: Versioned<NetworkSegmentControllerState>,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,

    pub prefixes: Vec<NetworkPrefix>,
    /// Whether VPC had been configured on all prefixes
    pub resource_groups_created: bool,
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
    pub name: String,
    pub subdomain_id: Option<Uuid>,
    pub vpc_id: Option<Uuid>,
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

        Ok(NetworkSegment {
            id: row.try_get("id")?,
            version,
            name: row.try_get("name")?,
            subdomain_id: row.try_get("subdomain_id")?,
            vpc_id: row.try_get("vpc_id")?,
            controller_state: Versioned::new(controller_state.0, controller_state_version),
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
            mtu: row.try_get("mtu")?,
            prefixes: Vec::new(),
            resource_groups_created: false,
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

        if value
            .prefixes
            .iter()
            .map(|x| x.prefix.parse::<IpNetwork>())
            .collect::<Result<Vec<_>, IpNetworkError>>()
            .map_err(CarbideError::from)?
            .iter()
            .any(|ip| ip.ip().is_ipv6())
        {
            return Err(CarbideError::InvalidArgument(
                "IPv6 is not yet supported.".to_string(),
            ));
        }

        Ok(NewNetworkSegment {
            name: value.name,
            subdomain_id: match value.subdomain_id {
                Some(v) => Some(uuid::Uuid::try_from(v)?),
                None => None,
            },
            vpc_id: match value.vpc_id {
                Some(v) => Some(uuid::Uuid::try_from(v)?),
                None => None,
            },
            mtu: value.mtu.unwrap_or(1500i32), // Set a default of 1500 if there is none specified
            prefixes: value
                .prefixes
                .into_iter()
                .map(NewNetworkPrefix::try_from)
                .collect::<Result<Vec<NewNetworkPrefix>, CarbideError>>()?,
            vlan_id: None,
            vni: None,
            segment_type: value.segment_type.try_into()?,
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
        // Note that even thought the segment might already be ready in terms
        // of `resource_groups_created == true`, we only return `Ready` after
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
            version: src.version.to_version_string(),
            name: src.name,
            subdomain_id: src.subdomain_id.map(rpc::Uuid::from),
            mtu: Some(src.mtu),
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
            prefixes: src
                .prefixes
                .into_iter()
                .map(rpc::NetworkPrefix::from)
                .collect_vec(),
            vpc_id: src.vpc_id.map(rpc::Uuid::from),
            state: state as i32,
            history,
            segment_type: src.segment_type as i32,
        })
    }
}

impl NewNetworkSegment {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<NetworkSegment, DatabaseError> {
        let version = ConfigVersion::initial();
        let version_string = version.to_version_string();
        let controller_state = NetworkSegmentControllerState::Provisioning;

        let query = "INSERT INTO network_segments (
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
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *";
        let mut segment: NetworkSegment = sqlx::query_as(query)
            .bind(&self.name)
            .bind(self.subdomain_id)
            .bind(self.vpc_id)
            .bind(self.mtu)
            .bind(&version_string)
            .bind(&version_string)
            .bind(sqlx::types::Json(&controller_state))
            .bind(self.vlan_id)
            .bind(self.vni)
            .bind(self.segment_type)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        segment.prefixes = NetworkPrefix::create_for(txn, &segment.id, &self.prefixes).await?;
        segment.update_prefix_state(&mut *txn).await?;

        NetworkSegmentStateHistory::persist(txn, segment.id, &controller_state, version).await?;

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
                .fetch_all(&mut *txn)
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
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        match results.len() {
            0 => Ok(None),
            1 => {
                let mut segment: NetworkSegment = results.remove(0);

                // NOTE(jdg): results shouldn't include any deleted segments, so we can ignore checks against deleted segments in prefixes for the following section
                let query = "SELECT * FROM network_prefixes WHERE segment_id=$1::uuid";
                segment.prefixes = sqlx::query_as(query)
                    .bind(segment.id())
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| {
                        CarbideError::from(DatabaseError::new(file!(), line!(), query, e))
                    })?;
                segment.update_prefix_state(&mut *txn).await?;

                Ok(Some(segment))
            }
            _ => Err(CarbideError::MultipleNetworkSegmentsForRelay(relay)),
        }
    }

    /// Retrieves the IDs of all network segments
    ///
    /// * `txn` - A reference to a currently open database transaction
    ///
    pub async fn list_segment_ids(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<Uuid>, DatabaseError> {
        let query = "SELECT id FROM network_segments";
        let mut results = Vec::new();
        let mut segment_id_stream = sqlx::query_as::<_, NetworkSegmentId>(query).fetch(txn);
        while let Some(maybe_id) = segment_id_stream.next().await {
            let id = maybe_id.map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
            results.push(id.into());
        }

        Ok(results)
    }

    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
        search_config: NetworkSegmentSearchConfig,
    ) -> Result<Vec<Self>, DatabaseError> {
        let base_query = "SELECT * FROM network_segments {where}".to_owned();

        let mut all_records: Vec<NetworkSegment> = match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, NetworkSegment>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "network_segments All", e))?
            }

            UuidKeyedObjectFilter::List(uuids) => sqlx::query_as::<_, NetworkSegment>(
                &base_query.replace("{where}", "WHERE network_segments.id=ANY($1)"),
            )
            .bind(uuids)
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "network_segments List", e))?,
            UuidKeyedObjectFilter::One(uuid) => sqlx::query_as::<_, NetworkSegment>(
                &base_query.replace("{where}", "WHERE network_segments.id=$1"),
            )
            .bind(uuid)
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "network_segments One", e))?,
        };

        let all_uuids = all_records
            .iter()
            .map(|record| record.id)
            .collect::<Vec<Uuid>>();

        // TODO(ajf): N+1 query alert.  Optimize later.

        let mut grouped_prefixes =
            NetworkPrefix::find_by_segment(&mut *txn, UuidKeyedObjectFilter::List(&all_uuids))
                .await?
                .into_iter()
                .into_group_map_by(|prefix| prefix.segment_id);

        let mut state_history = if search_config.include_history {
            NetworkSegmentStateHistory::find_by_segment_ids(&mut *txn, &all_uuids).await?
        } else {
            HashMap::new()
        };

        for record in &mut all_records {
            if let Some(prefixes) = grouped_prefixes.remove(&record.id) {
                record.prefixes = prefixes;
            } else {
                log::warn!("Network {0} ({1}) has no prefixes?", record.id, record.name);
            }
            record.update_prefix_state(&mut *txn).await?;

            if search_config.include_history {
                if let Some(history) = state_history.remove(&record.id) {
                    record.history = history;
                } else {
                    log::warn!(
                        "Network {0} ({1}) has no history yet.",
                        record.id,
                        record.name
                    );
                }
            }
        }

        Ok(all_records)
    }

    /// Updates the network segment state that is owned by the state controller
    /// under the premise that the current controller state version didn't change.
    ///
    /// Returns `true` if the state could be updated, and `false` if the object
    /// either doesn't exist anymore or is at a different version.
    pub async fn try_update_controller_state(
        txn: &mut Transaction<'_, Postgres>,
        segment_id: uuid::Uuid,
        expected_version: ConfigVersion,
        new_state: &NetworkSegmentControllerState,
    ) -> Result<bool, DatabaseError> {
        let expected_version_str = expected_version.to_version_string();
        let next_version = expected_version.increment();
        let next_version_str = next_version.to_version_string();

        let query = "UPDATE network_segments SET controller_state_version=$1, controller_state=$2::json where id=$3::uuid AND controller_state_version=$4 returning id";
        let query_result: Result<NetworkSegmentId, _> = sqlx::query_as(query)
            .bind(&next_version_str)
            .bind(sqlx::types::Json(new_state))
            .bind(segment_id)
            .bind(&expected_version_str)
            .fetch_one(&mut *txn)
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

    pub fn subdomain_id(&self) -> Option<&uuid::Uuid> {
        self.subdomain_id.as_ref()
    }

    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub async fn update_prefix_state(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let prefixes =
            NetworkPrefix::find_by_segment(&mut *txn, UuidKeyedObjectFilter::One(self.id)).await?;
        let prefixes = prefixes.iter().filter(|x| x.prefix.is_ipv4()).collect_vec();

        self.resource_groups_created = !prefixes.iter().any(|x| x.circuit_id.is_none());

        Ok(())
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
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        // TODO: We also can't delete network segments while there are instances
        // attached. Or at least we can't full remove it from the DB, and just it's
        // status to TERMINATING

        Ok(segment)
    }

    pub async fn force_delete(
        segment_id: uuid::Uuid,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<uuid::Uuid, DatabaseError> {
        NetworkPrefix::delete_for_segment(segment_id, txn).await?;

        let query = "DELETE FROM network_segments WHERE id=$1::uuid RETURNING id";
        let segment: NetworkSegmentId = sqlx::query_as(query)
            .bind(segment_id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(segment.0)
    }

    pub async fn update(
        &self,

        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<NetworkSegment, DatabaseError> {
        let query = "
UPDATE network_segments
SET name=$1, subdomain_id=$2, vpc_id=$3, mtu=$4, vlan_id=$5, vni_id=$6, updated=NOW()
WHERE id=$7
RETURNING *";
        let mut segment: NetworkSegment = sqlx::query_as(query)
            .bind(&self.name)
            .bind(self.subdomain_id)
            .bind(self.vpc_id)
            .bind(self.mtu)
            .bind(self.vlan_id)
            .bind(self.vni)
            .bind(self.id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        segment.update_prefix_state(&mut *txn).await?;

        Ok(segment)
    }

    pub async fn find_by_circuit_id(
        txn: &mut Transaction<'_, Postgres>,
        circuit_id: String,
    ) -> Result<Self, DatabaseError> {
        let query = "
SELECT network_segments.* FROM network_segments
INNER JOIN network_prefixes ON network_prefixes.segment_id = network_segments.id
WHERE network_prefixes.circuit_id=$1";
        sqlx::query_as(query)
            .bind(circuit_id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    /// This method returns Admin network segment.
    pub async fn admin(txn: &mut Transaction<'_, Postgres>) -> Result<Self, DatabaseError> {
        let query = "SELECT * FROM network_segments WHERE network_segment_type = 'admin'";
        sqlx::query_as(query)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}

#[derive(Debug, Clone, Copy, FromRow)]
pub struct NetworkSegmentId(uuid::Uuid);

impl From<NetworkSegmentId> for uuid::Uuid {
    fn from(id: NetworkSegmentId) -> Self {
        id.0
    }
}
