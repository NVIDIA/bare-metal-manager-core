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
use std::net::IpAddr;

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
        crate::resource_pool::release(
            &common_pools.ethernet.pool_vpc_dpu_loopback_ip,
            txn,
            value.loopback_ip,
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
) -> Result<IpAddr, DatabaseError> {
    let loopback_ip = match find(txn, dpu_id, vpc_id).await? {
        Some(x) => x.loopback_ip,
        None => {
            let loopback_ip =
                crate::machine::allocate_vpc_dpu_loopback(common_pools, txn, &dpu_id.to_string())
                    .await?;
            let vpc_dpu_loopback = VpcDpuLoopback::new(*dpu_id, *vpc_id, loopback_ip);
            persist(vpc_dpu_loopback, txn).await?;

            loopback_ip
        }
    };

    Ok(loopback_ip)
}
