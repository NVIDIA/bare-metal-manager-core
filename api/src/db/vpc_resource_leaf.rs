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
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row};

use super::machine_interface::MachineInterface;
use super::DatabaseError;
use crate::{CarbideError, CarbideResult};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VpcResourceLeaf {
    id: uuid::Uuid,
    loopback_ip_address: Option<IpAddr>,
}

#[derive(Debug)]
pub struct NewVpcResourceLeaf {
    dpu_machine_id: uuid::Uuid,
}

impl<'r> FromRow<'r, PgRow> for VpcResourceLeaf {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(VpcResourceLeaf {
            id: row.try_get("id")?,
            loopback_ip_address: row.try_get("loopback_ip_address")?,
        })
    }
}

impl VpcResourceLeaf {
    // TODO(ajf): update find() methods to always return a Vec.  Better yet make a findable trait
    // that always return CarbideResult<Vec<T>>
    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        dpu_machine_id: uuid::Uuid,
    ) -> Result<VpcResourceLeaf, DatabaseError> {
        let query = "SELECT * from vpc_resource_leafs WHERE id = $1";
        sqlx::query_as(query)
            .bind(dpu_machine_id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_loopback_ip(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        ip_address: IpAddr,
    ) -> CarbideResult<Option<VpcResourceLeaf>> {
        let query = "SELECT * from vpc_resource_leafs WHERE loopback_ip_address = $1";
        let mut result = sqlx::query_as(query)
            .bind(ip_address)
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        match result.len() {
            0 | 1 => Ok(result.pop()),
            _ => Err(CarbideError::DuplicateLoopbackIPError(ip_address)),
        }
    }

    pub async fn update_loopback_ip_address(
        &mut self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
        ip_address: IpAddr,
    ) -> Result<VpcResourceLeaf, DatabaseError> {
        log::info!(
            "Updating vpc_resource_leaf {} loopback_ip_address to: {ip_address}",
            &self.id
        );

        let query =
            "UPDATE vpc_resource_leafs SET loopback_ip_address=$1::inet where id=$2::uuid RETURNING *";
        let leaf = sqlx::query_as(query)
            .bind(ip_address)
            .bind(self.id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        self.loopback_ip_address = Some(ip_address);
        Ok(leaf)
    }

    /// Returns the ID of the machine object
    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    /// Returns IP Address
    pub fn loopback_ip_address(&self) -> &Option<IpAddr> {
        &self.loopback_ip_address
    }

    pub async fn find_associated_dpu_machine_interface(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        ip_address: IpAddr,
    ) -> Result<MachineInterface, DatabaseError> {
        let query = "
SELECT machine_interfaces.* from machine_interfaces
INNER JOIN machines ON machines.id = machine_interfaces.machine_id
INNER JOIN vpc_resource_leafs ON vpc_resource_leafs.id = machines.vpc_leaf_id
WHERE vpc_resource_leafs.loopback_ip_address = $1";
        sqlx::query_as(query)
            .bind(ip_address)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}

impl NewVpcResourceLeaf {
    pub fn new(dpu_machine_id: uuid::Uuid) -> NewVpcResourceLeaf {
        Self { dpu_machine_id }
    }

    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<VpcResourceLeaf, DatabaseError> {
        let query = "INSERT INTO vpc_resource_leafs (id) VALUES($1::uuid) returning *";
        sqlx::query_as(query)
            .bind(self.dpu_machine_id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}
