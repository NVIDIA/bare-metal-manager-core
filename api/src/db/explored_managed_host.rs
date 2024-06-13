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

use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};
use std::net::IpAddr;

use crate::{
    db::DatabaseError,
    model::site_explorer::{ExploredDpu, ExploredManagedHost},
};

#[derive(Debug, Clone)]
pub struct DbExploredManagedHost {
    /// The IP address of the node we explored
    host_bmc_ip: IpAddr,
    /// Information about explored DPUs
    dpus: Vec<ExploredDpu>,
}

impl<'r> FromRow<'r, PgRow> for DbExploredManagedHost {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let explored_dpus: sqlx::types::Json<Vec<ExploredDpu>> = row.try_get("explored_dpus")?;
        Ok(DbExploredManagedHost {
            host_bmc_ip: row.try_get("host_bmc_ip")?,
            dpus: explored_dpus.0,
        })
    }
}

impl From<DbExploredManagedHost> for ExploredManagedHost {
    fn from(host: DbExploredManagedHost) -> Self {
        Self {
            host_bmc_ip: host.host_bmc_ip,
            dpus: host.dpus,
        }
    }
}

impl DbExploredManagedHost {
    pub async fn find_all(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<ExploredManagedHost>, DatabaseError> {
        let query = "SELECT * FROM explored_managed_hosts ORDER by host_bmc_ip ASC";

        sqlx::query_as::<_, Self>(query)
            .fetch_all(&mut **txn)
            .await
            .map(|hosts| hosts.into_iter().map(Into::into).collect())
            .map_err(|e| DatabaseError::new(file!(), line!(), "explored_managed_hosts find_all", e))
    }

    pub async fn update(
        txn: &mut Transaction<'_, Postgres>,
        explored_hosts: &[ExploredManagedHost],
    ) -> Result<(), DatabaseError> {
        let query = r#"DELETE FROM explored_managed_hosts;"#;
        let _query_result = sqlx::query(query)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e));

        // TODO: Optimize me into a single query
        for host in explored_hosts {
            let query = "
            INSERT INTO explored_managed_hosts (host_bmc_ip, explored_dpus)
            VALUES ($1, $2)";
            let _result = sqlx::query(query)
                .bind(host.host_bmc_ip)
                .bind(sqlx::types::Json(&host.dpus))
                .execute(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        }

        Ok(())
    }
}
