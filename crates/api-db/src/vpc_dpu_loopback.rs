/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::net::{IpAddr, Ipv4Addr};

use carbide_uuid::machine::MachineId;
use carbide_uuid::vpc::VpcId;
use model::vpc::VpcDpuLoopback;
use sqlx::PgConnection;

use crate::DatabaseError;

pub async fn persist(
    value: VpcDpuLoopback,
    txn: &mut PgConnection,
) -> Result<VpcDpuLoopback, DatabaseError> {
    let query = "INSERT INTO vpc_dpu_loopbacks (dpu_id, vpc_id, loopback_ip)
                           VALUES ($1, $2, $3) RETURNING *";
    sqlx::query_as(query)
        .bind(value.dpu_id)
        .bind(value.vpc_id)
        .bind(value.loopback_ip)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn delete_and_deallocate(
    common_pools: &model::resource_pool::common::CommonPools,
    dpu_id: &MachineId,
    txn: &mut PgConnection,
    delete_admin_loopback_also: bool,
) -> Result<(), DatabaseError> {
    let mut admin_vpc = None;
    let query = if !delete_admin_loopback_also {
        let admin_segment = crate::network_segment::admin(txn).await?;
        admin_vpc = admin_segment.vpc_id;
        if admin_vpc.is_some() {
            "DELETE FROM vpc_dpu_loopbacks WHERE dpu_id=$1 AND vpc_id != $2 RETURNING *"
        } else {
            tracing::warn!("No VPC is attached to admin segment {}.", admin_segment.id);
            "DELETE FROM vpc_dpu_loopbacks WHERE dpu_id=$1 RETURNING *"
        }
    } else {
        "DELETE FROM vpc_dpu_loopbacks WHERE dpu_id=$1 RETURNING *"
    };

    let mut sqlx_query = sqlx::query_as::<_, VpcDpuLoopback>(query).bind(dpu_id);

    if let Some(admin_vpc) = admin_vpc {
        sqlx_query = sqlx_query.bind(admin_vpc);
    }

    let deleted_loopbacks = sqlx_query
        .fetch_all(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    for value in deleted_loopbacks {
        // We deleted a IP from vpc_dpu_loopback table. Deallocate this IP from common pool.
        let ipv4_addr = match value.loopback_ip {
            IpAddr::V4(ipv4_addr) => ipv4_addr,
            IpAddr::V6(_) => {
                return Err(DatabaseError::InvalidArgument(
                    "Ipv6 is not supported.".to_string(),
                ));
            }
        };

        crate::resource_pool::release(
            &common_pools.ethernet.pool_vpc_dpu_loopback_ip,
            txn,
            ipv4_addr,
        )
        .await?;
    }

    Ok(())
}

pub async fn find(
    txn: &mut PgConnection,
    dpu_id: &MachineId,
    vpc_id: &VpcId,
) -> Result<Option<VpcDpuLoopback>, DatabaseError> {
    let query = "SELECT * from vpc_dpu_loopbacks WHERE dpu_id=$1 AND vpc_id=$2";

    sqlx::query_as(query)
        .bind(dpu_id)
        .bind(vpc_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Allocate loopback ip for a vpc and dpu if not allocated yet.
/// If already allocated, return the value.
pub async fn get_or_allocate_loopback_ip_for_vpc(
    common_pools: &model::resource_pool::common::CommonPools,
    txn: &mut PgConnection,
    dpu_id: &MachineId,
    vpc_id: &VpcId,
) -> Result<Ipv4Addr, DatabaseError> {
    let loopback_ip = match find(txn, dpu_id, vpc_id).await? {
        Some(x) => match x.loopback_ip {
            IpAddr::V4(ipv4_addr) => ipv4_addr,
            IpAddr::V6(_) => {
                return Err(DatabaseError::NotImplemented);
            }
        },
        None => {
            let loopback_ip =
                crate::machine::allocate_vpc_dpu_loopback(common_pools, txn, &dpu_id.to_string())
                    .await?;
            let vpc_dpu_loopback = VpcDpuLoopback::new(*dpu_id, *vpc_id, IpAddr::V4(loopback_ip));
            persist(vpc_dpu_loopback, txn).await?;

            loopback_ip
        }
    };

    Ok(loopback_ip)
}
