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
use std::convert::TryFrom;
use std::net::IpAddr;

use ::rpc::protos::common::forge::TenantState;
use chrono::prelude::*;
use ipnetwork::{IpNetwork, IpNetworkError};
use itertools::Itertools;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Transaction};
use sqlx::{Postgres, Row};
use uuid::Uuid;

use ::rpc::forge as rpc;
use ::rpc::Timestamp;

use crate::db::machine_interface::MachineInterface;
use crate::db::network_prefix::{NetworkPrefix, NewNetworkPrefix};
use crate::model::config_version::ConfigVersion;
use crate::{db::UuidKeyedObjectFilter, CarbideError, CarbideResult};

#[derive(Debug, Clone)]
pub struct NetworkSegment {
    pub id: Uuid,
    pub version: ConfigVersion,
    pub name: String,
    pub subdomain_id: Option<Uuid>,
    pub vpc_id: Option<Uuid>,
    pub mtu: i32,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,

    pub prefixes: Vec<NetworkPrefix>,
    pub state: Option<TenantState>,
}

#[derive(Debug)]
pub struct NewNetworkSegment {
    pub name: String,
    pub subdomain_id: Option<Uuid>,
    pub vpc_id: Option<Uuid>,
    pub mtu: i32,
    pub prefixes: Vec<NewNetworkPrefix>,
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for NetworkSegment {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let config_version_str: &str = row.try_get("version")?;
        let version = config_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        Ok(NetworkSegment {
            id: row.try_get("id")?,
            version,
            name: row.try_get("name")?,
            subdomain_id: row.try_get("subdomain_id")?,
            vpc_id: row.try_get("vpc_id")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
            mtu: row.try_get("mtu")?,
            prefixes: Vec::new(),
            state: None,
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
        Ok(rpc::NetworkSegment {
            id: Some(src.id.into()),
            version: src.version.to_version_string(),
            name: src.name,
            subdomain_id: src.subdomain_id.map(rpc::Uuid::from),
            mtu: Some(src.mtu),

            created: Some(Timestamp {
                seconds: src.created.timestamp(),
                nanos: 0,
            }),

            updated: Some(Timestamp {
                seconds: src.updated.timestamp(),
                nanos: 0,
            }),

            deleted: src.deleted.map(|t| Timestamp {
                seconds: t.timestamp(),
                nanos: 0,
            }),

            prefixes: src
                .prefixes
                .into_iter()
                .map(rpc::NetworkPrefix::from)
                .collect_vec(),
            vpc_id: src.vpc_id.map(rpc::Uuid::from),
            state: src.state.ok_or_else(|| {
                CarbideError::NetworkSegmentNotReady("state is not updated yet.".to_owned())
            })? as i32,
        })
    }
}

impl NewNetworkSegment {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<NetworkSegment> {
        let version = ConfigVersion::initial();
        let version_string = version.to_version_string();

        let mut segment: NetworkSegment = sqlx::query_as("INSERT INTO network_segments (name, subdomain_id, vpc_id, mtu, version) VALUES ($1, $2, $3, $4, $5) RETURNING *")
            .bind(&self.name)
            .bind(self.subdomain_id)
            .bind(self.vpc_id)
            .bind(self.mtu)
            .bind(&version_string)
            .fetch_one(&mut *txn).await?;

        segment.prefixes = NetworkPrefix::create_for(txn, &segment.id, &self.prefixes).await?;
        segment.update_state(&mut *txn).await?;

        Ok(segment)
    }
}

impl NetworkSegment {
    pub async fn for_vpc(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        vpc_id: uuid::Uuid,
    ) -> CarbideResult<Vec<Self>> {
        let results: Vec<NetworkSegment> = {
            sqlx::query_as("SELECT * FROM network_segments WHERE vpc_id=$1::uuid")
                .bind(vpc_id)
                .fetch_all(&mut *txn)
                .await?
        };

        Ok(results)
    }

    pub async fn for_relay(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        relay: IpAddr,
    ) -> CarbideResult<Option<Self>> {
        let mut results = sqlx::query_as(
            r#"SELECT network_segments.* FROM network_segments INNER JOIN network_prefixes ON network_prefixes.segment_id = network_segments.id WHERE network_segments.deleted is NULL AND $1::inet <<= network_prefixes.prefix"#,
        )
            .bind(IpNetwork::from(relay))
            .fetch_all(&mut *txn)
            .await?;

        match results.len() {
            0 => Ok(None),
            1 => {
                let mut segment: NetworkSegment = results.remove(0);

                // NOTE(jdg): results shouldn't include any deleted segments, so we can ignore checks against deleted segments in prefixes for the following section
                segment.prefixes =
                    sqlx::query_as(r#"SELECT * FROM network_prefixes WHERE segment_id=$1::uuid"#)
                        .bind(segment.id())
                        .fetch_all(&mut *txn)
                        .await?;
                segment.update_state(&mut *txn).await?;

                Ok(Some(segment))
            }
            _ => Err(CarbideError::MultipleNetworkSegmentsForRelay(relay)),
        }
    }

    #[tracing::instrument(skip(txn, filter))]
    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> CarbideResult<Vec<Self>> {
        let base_query = "SELECT * FROM network_segments {where}".to_owned();

        let mut all_records: Vec<NetworkSegment> = match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, NetworkSegment>(
                    &base_query.replace("{where}", "WHERE deleted is NULL"),
                )
                .fetch_all(&mut *txn)
                .await?
            }

            UuidKeyedObjectFilter::List(uuids) => {
                sqlx::query_as::<_, NetworkSegment>(&base_query.replace(
                    "{where}",
                    "WHERE network_segments.id=ANY($1) and deleted is NULL",
                ))
                .bind(uuids)
                .fetch_all(&mut *txn)
                .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, NetworkSegment>(&base_query.replace(
                    "{where}",
                    "WHERE network_segments.id=$1 and deleted is NULL",
                ))
                .bind(uuid)
                .fetch_all(&mut *txn)
                .await?
            }
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

        for record in &mut all_records {
            if let Some(prefixes) = grouped_prefixes.remove(&record.id) {
                record.prefixes = prefixes;
            } else {
                log::warn!("Network {0} ({1}) has no prefixes?", record.id, record.name);
            }
            record.update_state(&mut *txn).await?;
        }

        Ok(all_records)
    }

    pub fn subdomain_id(&self) -> Option<&uuid::Uuid> {
        self.subdomain_id.as_ref()
    }

    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub async fn update_state(&mut self, txn: &mut Transaction<'_, Postgres>) -> CarbideResult<()> {
        let prefixes =
            NetworkPrefix::find_by_segment(&mut *txn, UuidKeyedObjectFilter::One(self.id)).await?;
        let prefixes = prefixes.iter().filter(|x| x.prefix.is_ipv4()).collect_vec();

        self.state = Some(if prefixes.iter().any(|x| x.circuit_id.is_none()) {
            // At least one prefix is present with empty circuit id.
            TenantState::Provisioning
        } else {
            // Not even a one prefix found with null circuit id. This means ResourceGroupd creation
            // is successful.
            TenantState::Ready
        });

        Ok(())
    }

    pub async fn delete(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<NetworkSegment> {
        let machine_interfaces = MachineInterface::find_by_segment_id(txn, self.id()).await;
        if let Ok(machine_interfaces) = machine_interfaces {
            if !machine_interfaces.is_empty() {
                return CarbideResult::Err(CarbideError::NetworkSegmentDelete(
                    "Network Segment can't be deleted with associated MachineInterface".to_string(),
                ));
            }
        }

        let segment: NetworkSegment = sqlx::query_as(
            "UPDATE network_segments SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING *",
        )
        .bind(self.id)
        .fetch_one(&mut *txn)
        .await?;

        // TODO: We also can't delete network segments while there are instances
        // attached. Or at least we can't full remove it from the DB, and just it's
        // status to TERMINATING

        Ok(segment)
    }

    pub async fn update(
        &self,

        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<NetworkSegment> {
        let mut segment: NetworkSegment = sqlx::query_as(
            "UPDATE network_segments SET name=$1, subdomain_id=$2, vpc_id=$3, mtu=$4, updated=NOW() WHERE id=$5 RETURNING *",
        )
        .bind(&self.name)
        .bind(self.subdomain_id)
        .bind(self.vpc_id)
        .bind(self.mtu)
        .bind(self.id)
        .fetch_one(&mut *txn)
        .await?;

        segment.update_state(&mut *txn).await?;

        Ok(segment)
    }

    pub async fn find_by_circuit_id(
        txn: &mut Transaction<'_, Postgres>,
        circuit_id: String,
    ) -> CarbideResult<Self> {
        Ok(sqlx::query_as(
            r#"SELECT network_segments.* FROM network_segments 
            INNER JOIN network_prefixes ON network_prefixes.segment_id = network_segments.id 
            WHERE network_segments.deleted is NULL AND network_prefixes.circuit_id=$1"#,
        )
        .bind(circuit_id)
        .fetch_one(&mut *txn)
        .await?)
    }
}
