/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::cmp::{max, min};

use super::DatabaseError;
use super::network_prefix::NetworkPrefix;
use super::vpc_prefix::VpcPrefix;
use crate::CarbideError;
use ::rpc::forge as rpc;
use forge_network::virtualization::VpcVirtualizationType;
use forge_uuid::{vpc::VpcId, vpc_peering::VpcPeeringId};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgConnection, Row};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct VpcPeering {
    pub id: VpcPeeringId,
    pub vpc_id: VpcId,
    pub peer_vpc_id: VpcId,
}

impl VpcPeering {
    pub async fn create(
        txn: &mut PgConnection,
        vpc_id_1: VpcId,
        vpc_id_2: VpcId,
    ) -> Result<Self, CarbideError> {
        let uuid1: Uuid = vpc_id_1.into();
        let uuid2: Uuid = vpc_id_2.into();
        let vpc1_id: Uuid;
        let vpc2_id: Uuid;
        match uuid1.cmp(&uuid2) {
            std::cmp::Ordering::Equal => {
                return Err(CarbideError::InvalidArgument(
                    "Cannot create a peering between the same VPC".to_string(),
                ));
            }
            std::cmp::Ordering::Less | std::cmp::Ordering::Greater => {
                // IDs of peer VPCs should follow canonical ordering
                vpc1_id = min(uuid1, uuid2);
                vpc2_id = max(uuid1, uuid2);
            }
        }

        let query = r#"
            INSERT INTO vpc_peerings (vpc1_id, vpc2_id)
            SELECT $1, $2
            WHERE NOT EXISTS (
                SELECT 1 FROM vpc_peerings WHERE vpc1_id = $1 AND vpc2_id = $2
            )
            RETURNING *
        "#;

        match sqlx::query_as::<_, VpcPeering>(query)
            .bind(vpc1_id)
            .bind(vpc2_id)
            .fetch_one(txn)
            .await
        {
            Ok(vpc_peering) => Ok(vpc_peering),
            Err(sqlx::Error::RowNotFound) => Err(CarbideError::AlreadyFoundError {
                kind: "VpcPeering",
                id: format!("{} and {}", vpc_id_1, vpc_id_2),
            }),

            Err(e) => Err(CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                query,
                e,
            ))),
        }
    }

    pub async fn find_ids(
        txn: &mut PgConnection,
        vpc_id: Option<VpcId>,
    ) -> Result<Vec<VpcPeeringId>, DatabaseError> {
        let mut builder = sqlx::QueryBuilder::new("SELECT id FROM vpc_peerings");

        if let Some(vpc_id) = vpc_id {
            let vpc_id: Uuid = vpc_id.into();
            builder.push(" WHERE vpc1_id = ");
            builder.push_bind(vpc_id);
            builder.push(" OR vpc2_id = ");
            builder.push_bind(vpc_id);
        }

        let query = builder.build_query_as();
        let vpc_peering_ids: Vec<VpcPeeringId> = query
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "vpc_peering::find_ids", e))?;

        Ok(vpc_peering_ids)
    }

    pub async fn find_by_ids(
        txn: &mut PgConnection,
        ids: Vec<Uuid>,
    ) -> Result<Vec<Self>, DatabaseError> {
        let query = "SELECT * FROM vpc_peerings WHERE id=ANY($1)";
        let vpc_peering_list = sqlx::query_as::<_, VpcPeering>(query)
            .bind(ids)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(vpc_peering_list)
    }

    pub async fn delete(txn: &mut PgConnection, vpc_peer_id: Uuid) -> Result<Self, DatabaseError> {
        let query = "DELETE FROM vpc_peerings WHERE id=$1 RETURNING *";
        let vpc_peering = sqlx::query_as::<_, VpcPeering>(query)
            .bind(vpc_peer_id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(vpc_peering)
    }

    pub async fn get_vpc_peer_ids(
        txn: &mut PgConnection,
        vpc_id: VpcId,
    ) -> Result<Vec<VpcId>, DatabaseError> {
        let query = r#"
            SELECT
                CASE
                    WHEN vp.vpc1_id = $1 THEN vp.vpc2_id
                    ELSE vp.vpc1_id
                END AS vpc_peer_id
            FROM vpc_peerings vp
            WHERE vp.vpc1_id = $1 OR vp.vpc2_id = $1
        "#;

        let vpc_id: Uuid = vpc_id.into();
        let vpc_peer_ids = sqlx::query_as(query)
            .bind(vpc_id)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(vpc_peer_ids)
    }

    pub async fn get_vpc_peer_vnis(
        txn: &mut PgConnection,
        vpc_id: VpcId,
        virtualization_types: Vec<VpcVirtualizationType>,
    ) -> Result<Vec<(VpcId, i32)>, DatabaseError> {
        let query = r#"
            SELECT vpcs.id, vpcs.vni
            FROM vpc_peerings vp
            JOIN vpcs ON vpcs.id = CASE
                WHEN vp.vpc1_id = $1 THEN vp.vpc2_id
                ELSE vp.vpc1_id
            END
            WHERE (vp.vpc1_id = $1 OR vp.vpc2_id = $1)
              AND vpcs.network_virtualization_type = ANY($2)
        "#;

        let vpc_id: Uuid = vpc_id.into();
        let peer_vpc_vnis = sqlx::query_as(query)
            .bind(vpc_id)
            .bind(virtualization_types)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(peer_vpc_vnis)
    }

    pub async fn delete_by_vpc_id(
        txn: &mut PgConnection,
        vpc_id: VpcId,
    ) -> Result<(), DatabaseError> {
        let query =
            "DELETE FROM vpc_peerings vp WHERE vp.vpc1_id =$1 OR vp.vpc2_id = $1 RETURNING *";

        let vpc_id: Uuid = vpc_id.into();
        sqlx::query_as::<_, VpcPeering>(query)
            .bind(vpc_id)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }
}

impl<'r> FromRow<'r, PgRow> for VpcPeering {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(VpcPeering {
            id: row.try_get("id")?,
            vpc_id: row.try_get("vpc1_id")?,
            peer_vpc_id: row.try_get("vpc2_id")?,
        })
    }
}

pub async fn get_prefixes_by_vpcs(
    txn: &mut PgConnection,
    vpcs: &Vec<VpcId>,
) -> Result<Vec<String>, CarbideError> {
    let vpc_prefixes = VpcPrefix::find_by_vpcs(txn, vpcs)
        .await
        .map_err(CarbideError::from)?
        .into_iter()
        .map(|vpc_prefix| vpc_prefix.prefix.to_string());
    let vpc_segment_prefixes = NetworkPrefix::find_by_vpcs(txn, vpcs)
        .await
        .map_err(CarbideError::from)?
        .into_iter()
        .map(|segment_prefix| segment_prefix.prefix.to_string());

    Ok(vpc_prefixes.chain(vpc_segment_prefixes).collect())
}

impl From<VpcPeering> for rpc::VpcPeering {
    fn from(db_vpc_peering: VpcPeering) -> Self {
        let VpcPeering {
            id,
            vpc_id,
            peer_vpc_id,
        } = db_vpc_peering;

        let id = Some(id.into());
        let vpc_id = Some(vpc_id.into());
        let peer_vpc_id = Some(peer_vpc_id.into());

        Self {
            id,
            vpc_id,
            peer_vpc_id,
        }
    }
}
