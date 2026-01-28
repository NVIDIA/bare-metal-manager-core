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

use carbide_uuid::vpc::VpcId;
use carbide_uuid::vpc_peering::VpcPeeringId;
use forge_network::virtualization::VpcVirtualizationType;
use model::vpc::VpcPeering;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::DatabaseError;

pub async fn create(
    txn: &mut PgConnection,
    vpc_id_1: VpcId,
    vpc_id_2: VpcId,
) -> Result<VpcPeering, DatabaseError> {
    let uuid1: Uuid = vpc_id_1.into();
    let uuid2: Uuid = vpc_id_2.into();
    let vpc1_id: Uuid;
    let vpc2_id: Uuid;
    match uuid1.cmp(&uuid2) {
        std::cmp::Ordering::Equal => {
            return Err(DatabaseError::InvalidArgument(
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
        Err(sqlx::Error::RowNotFound) => Err(DatabaseError::AlreadyFoundError {
            kind: "VpcPeering",
            id: format!("{vpc_id_1} and {vpc_id_2}"),
        }),

        Err(e) => Err(DatabaseError::query(query, e)),
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
        .map_err(|e| DatabaseError::new("vpc_peering::find_ids", e))?;

    Ok(vpc_peering_ids)
}

pub async fn find_by_ids(
    txn: &mut PgConnection,
    ids: Vec<VpcPeeringId>,
) -> Result<Vec<VpcPeering>, DatabaseError> {
    let query = "SELECT * FROM vpc_peerings WHERE id=ANY($1)";
    let vpc_peering_list = sqlx::query_as::<_, VpcPeering>(query)
        .bind(ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(vpc_peering_list)
}

pub async fn delete(
    txn: &mut PgConnection,
    vpc_peer_id: VpcPeeringId,
) -> Result<VpcPeering, DatabaseError> {
    let query = "DELETE FROM vpc_peerings WHERE id=$1 RETURNING *";
    let vpc_peering = sqlx::query_as::<_, VpcPeering>(query)
        .bind(vpc_peer_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

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
        .map_err(|e| DatabaseError::query(query, e))?;

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
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(peer_vpc_vnis)
}

pub async fn delete_by_vpc_id(txn: &mut PgConnection, vpc_id: VpcId) -> Result<(), DatabaseError> {
    let query = "DELETE FROM vpc_peerings vp WHERE vp.vpc1_id =$1 OR vp.vpc2_id = $1 RETURNING *";

    let vpc_id: Uuid = vpc_id.into();
    sqlx::query_as::<_, VpcPeering>(query)
        .bind(vpc_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn get_prefixes_by_vpcs(
    txn: &mut PgConnection,
    vpcs: &Vec<VpcId>,
) -> Result<Vec<String>, DatabaseError> {
    let vpc_prefixes = crate::vpc_prefix::find_by_vpcs(txn, vpcs)
        .await?
        .into_iter()
        .map(|vpc_prefix| vpc_prefix.config.prefix.to_string());
    let vpc_segment_prefixes = crate::network_prefix::find_by_vpcs(txn, vpcs)
        .await?
        .into_iter()
        .map(|segment_prefix| segment_prefix.prefix.to_string());

    Ok(vpc_prefixes.chain(vpc_segment_prefixes).collect())
}
