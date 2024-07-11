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

use config_version::ConfigVersion;
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use crate::{
    cfg::FirmwareHostComponentType,
    db::DatabaseError,
    model::site_explorer::{EndpointExplorationReport, ExploredEndpoint, PreingestionState},
};

#[derive(Debug, Clone)]
pub struct DbExploredEndpoint {
    /// The IP address of the node we explored
    address: std::net::IpAddr,
    /// The data we gathered about the endpoint
    report: EndpointExplorationReport,
    /// The version of `report`.
    /// Will increase every time the report gets updated.
    report_version: ConfigVersion,
    /// State within preingestion state machine
    preingestion_state: PreingestionState,
    /// Indicates that preingestion is waiting for site explorer to refresh the state
    waiting_for_explorer_refresh: bool,
}

impl<'r> FromRow<'r, PgRow> for DbExploredEndpoint {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let report: sqlx::types::Json<EndpointExplorationReport> =
            row.try_get("exploration_report")?;
        let version_str: &str = row.try_get("version")?;
        let report_version = version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let preingestion_state: sqlx::types::Json<PreingestionState> =
            row.try_get("preingestion_state")?;
        let waiting_for_explorer_refresh = row.try_get("waiting_for_explorer_refresh")?;

        Ok(DbExploredEndpoint {
            address: row.try_get("address")?,
            report: report.0,
            report_version,
            preingestion_state: preingestion_state.0,
            waiting_for_explorer_refresh,
        })
    }
}

impl From<DbExploredEndpoint> for ExploredEndpoint {
    fn from(endpoint: DbExploredEndpoint) -> Self {
        Self {
            address: endpoint.address,
            report: endpoint.report,
            report_version: endpoint.report_version,
            preingestion_state: endpoint.preingestion_state,
            waiting_for_explorer_refresh: endpoint.waiting_for_explorer_refresh,
        }
    }
}

impl DbExploredEndpoint {
    /// find_all returns all explored endpoints that site explorer has been able to probe
    pub async fn find_all(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
        let query = "SELECT * FROM explored_endpoints";

        sqlx::query_as::<_, Self>(query)
            .fetch_all(&mut **txn)
            .await
            .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
            .map_err(|e| DatabaseError::new(file!(), line!(), "explored_endpoints find_all", e))
    }

    /// find_preingest_not_waiting gets everything that is still in preingestion that isn't waiting for site explorer to refresh it again and isn't in an error state.
    pub async fn find_preingest_not_waiting_not_error(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
        let query = "SELECT * FROM explored_endpoints 
                        WHERE (preingestion_state IS NULL OR preingestion_state->'state' != '\"complete\"') 
                            AND waiting_for_explorer_refresh = false 
                            AND (exploration_report->'LastExplorationError' IS NULL OR exploration_report->'LastExplorationError' = 'null');"; // If LastExplorationError is completely notexistant it is NULL, if it is there and indicates a null value it is 'null'.

        sqlx::query_as::<_, Self>(query)
            .fetch_all(&mut **txn)
            .await
            .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
            .map_err(|e| {
                DatabaseError::new(
                    file!(),
                    line!(),
                    "explored_endpoints find_preingest_not_waiting",
                    e,
                )
            })
    }

    /// find_preingest_installing returns the endpoints where wew are waiting for firmware installs
    pub async fn find_preingest_installing(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
        let query = "SELECT * FROM explored_endpoints WHERE preingestion_state->'state' = '\"upgradefirmwarewait\"';";

        sqlx::query_as::<_, Self>(query)
            .fetch_all(&mut **txn)
            .await
            .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
            .map_err(|e| {
                DatabaseError::new(
                    file!(),
                    line!(),
                    "explored_endpoints find_preingest_not_waiting",
                    e,
                )
            })
    }

    /// find_all_no_upgrades returns all explored endpoints that site explorer has been able to probe, but ignores anything currently undergoing an upgrade
    pub async fn find_all_preingestion_complete(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
        let query =
            "SELECT * FROM explored_endpoints WHERE preingestion_state->'state' = '\"complete\"';";

        sqlx::query_as::<_, Self>(query)
            .fetch_all(&mut **txn)
            .await
            .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
            .map_err(|e| {
                DatabaseError::new(
                    file!(),
                    line!(),
                    "explored_endpoints find_all_preingestion_complete",
                    e,
                )
            })
    }

    /// find_all_by_ip returns a list of explored endpoints that match the ip (should be a list of one)
    pub async fn find_all_by_ip(
        address: IpAddr,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
        let query = "SELECT * FROM explored_endpoints WHERE address = $1;";

        sqlx::query_as::<_, Self>(query)
            .bind(address)
            .fetch_all(&mut **txn)
            .await
            .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
            .map_err(|e| {
                DatabaseError::new(
                    file!(),
                    line!(),
                    "explored_endpoints find_all_preingestion_complete",
                    e,
                )
            })
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
UPDATE explored_endpoints SET version=$1, exploration_report=$2, waiting_for_explorer_refresh = false
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

    /// clear_last_known_error clears the last known error in explored_endpoints for the BMC identified by IP
    pub async fn clear_last_known_error(
        address: IpAddr,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        for row in Self::find_all_by_ip(address, txn).await? {
            let mut report = row.report;
            report.last_exploration_error = None;
            Self::try_update(address, row.report_version, &report, txn).await?;
        }

        Ok(())
    }

    /// set_waiting_for_explorer_refresh sets a flag that will be cleared next time try_update runs.
    pub async fn set_waiting_for_explorer_refresh(
        address: IpAddr,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query =
            "UPDATE explored_endpoints SET waiting_for_explorer_refresh = true WHERE address = $1;";
        sqlx::query(query)
            .bind(address)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    /// clear_waiting_for_explorer_refresh is never used in the actual code, only for unit tests.
    pub async fn clear_waiting_for_explorer_refresh(
        address: IpAddr,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query =
            "UPDATE explored_endpoints SET waiting_for_explorer_refresh = false WHERE address = $1;";
        sqlx::query(query)
            .bind(address)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    async fn set_preingestion(
        address: IpAddr,
        state: PreingestionState,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE explored_endpoints SET preingestion_state = $1 WHERE address = $2;";
        sqlx::query(query)
            .bind(sqlx::types::Json(&state))
            .bind(address)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn set_preingestion_recheck_versions(
        address: IpAddr,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let state = PreingestionState::RecheckVersions;
        DbExploredEndpoint::set_preingestion(address, state, txn).await
    }

    pub async fn set_preingestion_waittask(
        address: IpAddr,
        task_id: String,
        final_version: &str,
        upgrade_type: &FirmwareHostComponentType,
        rebooted: bool,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let state = PreingestionState::UpgradeFirmwareWait {
            task_id,
            final_version: final_version.to_owned(),
            upgrade_type: *upgrade_type,
            rebooted,
        };
        DbExploredEndpoint::set_preingestion(address, state, txn).await
    }

    pub async fn set_preingestion_complete(
        address: IpAddr,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let state = PreingestionState::Complete;
        DbExploredEndpoint::set_preingestion(address, state, txn).await
    }

    pub async fn insert(
        address: IpAddr,
        exploration_report: &EndpointExplorationReport,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "
        INSERT INTO explored_endpoints (address, exploration_report, version, preingestion_state)
        VALUES ($1, $2::json, $3, '{\"state\":\"initial\"}')
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
