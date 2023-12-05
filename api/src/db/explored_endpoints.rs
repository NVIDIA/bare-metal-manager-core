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
    model::{
        config_version::{ConfigVersion, Versioned},
        site_explorer::EndpointExplorationReport,
    },
};

#[derive(Debug, Clone)]
pub struct ExploredEndpoint {
    /// The IP address of the node we explored
    pub address: IpAddr,
    /// The data we gathered about the node
    pub exploration_report: Versioned<EndpointExplorationReport>,
}

impl<'r> FromRow<'r, PgRow> for ExploredEndpoint {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let exploration_report: sqlx::types::Json<EndpointExplorationReport> =
            row.try_get("exploration_report")?;
        let version_str: &str = row.try_get("version")?;
        let version = version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        Ok(ExploredEndpoint {
            address: row.try_get("address")?,
            exploration_report: Versioned::new(exploration_report.0, version),
        })
    }
}

impl ExploredEndpoint {
    pub async fn find_all(txn: &mut Transaction<'_, Postgres>) -> Result<Vec<Self>, DatabaseError> {
        let query = "SELECT * FROM explored_endpoints";

        sqlx::query_as::<_, Self>(query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "explored_endpoints find_all", e))
    }

    /// Updates the explored information about a node
    ///
    /// This operation will return `Ok(false)` if the entry had been deleted in
    /// the meantime or otherwise modified. It will not fail.
    pub async fn try_update(
        address: IpAddr,
        old_version: ConfigVersion,
        exploration_report: &EndpointExplorationReport,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<bool, DatabaseError> {
        let new_version = old_version.increment();
        let query = "
UPDATE explored_endpoints SET version=$1, exploration_report=$2
WHERE address = $3 AND version=$4";
        let query_result = sqlx::query(query)
            .bind(new_version.version_string())
            .bind(sqlx::types::Json(exploration_report))
            .bind(address)
            .bind(old_version.version_string())
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(query_result.rows_affected() > 0)
    }

    pub async fn insert(
        address: IpAddr,
        exploration_report: &EndpointExplorationReport,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "
        INSERT INTO explored_endpoints (address, exploration_report, version)
        VALUES ($1, $2::json, $3)
        ON CONFLICT DO NOTHING";
        let version = ConfigVersion::initial();
        let _result = sqlx::query(query)
            .bind(address)
            .bind(sqlx::types::Json(&exploration_report))
            .bind(version.version_string())
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    pub async fn delete(
        txn: &mut Transaction<'_, Postgres>,
        address: IpAddr,
    ) -> Result<(), DatabaseError> {
        let query = r#"DELETE FROM explored_endpoints WHERE address=$1"#;
        let _query_result = sqlx::query(query)
            .bind(address)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e));
        Ok(())
    }
}
