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

use std::net::IpAddr;

use model::site_explorer::{ExploredDpu, ExploredManagedHost};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgConnection, Row};

use crate::DatabaseError;

#[derive(Debug, Clone)]
struct DbExploredManagedHost {
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

pub async fn find_ips(
    txn: &mut PgConnection,
    // filter is currently is empty, so it is a placeholder for the future
    _filter: ::rpc::site_explorer::ExploredManagedHostSearchFilter,
) -> Result<Vec<IpAddr>, DatabaseError> {
    #[derive(Debug, Clone, Copy, FromRow)]
    pub struct ExploredManagedHostIp(IpAddr);
    // grab list of IPs
    let mut builder = sqlx::QueryBuilder::new("SELECT host_bmc_ip FROM explored_managed_hosts");
    let query = builder.build_query_as();
    let ids: Vec<ExploredManagedHostIp> = query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("explored_managed_hosts::find_ips", e))?;
    // Convert to Vec<IpAddr> and return.
    Ok(ids.iter().map(|id| id.0).collect())
}

pub async fn find_by_ips(
    txn: &mut PgConnection,
    ips: Vec<IpAddr>,
) -> Result<Vec<ExploredManagedHost>, DatabaseError> {
    let query = "SELECT * FROM explored_managed_hosts WHERE host_bmc_ip=ANY($1)";

    sqlx::query_as::<_, DbExploredManagedHost>(query)
        .bind(ips)
        .fetch_all(txn)
        .await
        .map(|hosts| hosts.into_iter().map(Into::into).collect())
        .map_err(|e| DatabaseError::new("explored_managed_hosts::find_by_ips", e))
}

pub async fn find_all(txn: &mut PgConnection) -> Result<Vec<ExploredManagedHost>, DatabaseError> {
    let query = "SELECT * FROM explored_managed_hosts ORDER by host_bmc_ip ASC";

    sqlx::query_as::<_, DbExploredManagedHost>(query)
        .fetch_all(txn)
        .await
        .map(|hosts| hosts.into_iter().map(Into::into).collect())
        .map_err(|e| DatabaseError::new("explored_managed_hosts find_all", e))
}

pub async fn update(
    txn: &mut PgConnection,
    explored_hosts: &[&ExploredManagedHost],
) -> Result<(), DatabaseError> {
    let query = r#"DELETE FROM explored_managed_hosts;"#;
    sqlx::query(query)
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    // TODO: Optimize me into a single query
    for host in explored_hosts {
        let query = "
            INSERT INTO explored_managed_hosts (host_bmc_ip, explored_dpus)
            VALUES ($1, $2)";
        sqlx::query(query)
            .bind(host.host_bmc_ip)
            .bind(sqlx::types::Json(&host.dpus))
            .execute(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;
    }

    Ok(())
}

pub async fn delete_by_host_bmc_addr(
    txn: &mut PgConnection,
    addr: IpAddr,
) -> Result<(), DatabaseError> {
    let query = "DELETE FROM explored_managed_hosts WHERE host_bmc_ip = $1";
    sqlx::query(query)
        .bind(addr)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}
