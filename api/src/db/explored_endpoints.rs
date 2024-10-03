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
use std::ops::DerefMut;

use config_version::ConfigVersion;
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use crate::{
    cfg::FirmwareComponentType,
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
    /// Whether the endpoint will be explored in the next site-explorer run
    exploration_requested: bool,
    /// The last time site explorer issued a redfish call to reset this BMC
    last_redfish_bmc_reset: Option<chrono::DateTime<chrono::Utc>>,
    /// The last time site explorer issued a ipmitool call to reset this BMC
    last_ipmitool_bmc_reset: Option<chrono::DateTime<chrono::Utc>>,
    /// The last time site explorer issued a redfish call to reboot this endpoint
    last_redfish_reboot: Option<chrono::DateTime<chrono::Utc>>,
}

impl<'r> FromRow<'r, PgRow> for DbExploredEndpoint {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let report: sqlx::types::Json<EndpointExplorationReport> =
            row.try_get("exploration_report")?;
        let preingestion_state: sqlx::types::Json<PreingestionState> =
            row.try_get("preingestion_state")?;
        let waiting_for_explorer_refresh = row.try_get("waiting_for_explorer_refresh")?;
        let exploration_requested = row.try_get("exploration_requested")?;
        let last_redfish_bmc_reset = row.try_get("last_redfish_bmc_reset")?;
        let last_ipmitool_bmc_reset = row.try_get("last_ipmitool_bmc_reset")?;
        let last_redfish_reboot = row.try_get("last_redfish_reboot")?;

        Ok(DbExploredEndpoint {
            address: row.try_get("address")?,
            report: report.0,
            report_version: row.try_get("version")?,
            preingestion_state: preingestion_state.0,
            waiting_for_explorer_refresh,
            exploration_requested,
            last_redfish_bmc_reset,
            last_ipmitool_bmc_reset,
            last_redfish_reboot,
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
            exploration_requested: endpoint.exploration_requested,
            last_redfish_bmc_reset: endpoint.last_redfish_bmc_reset,
            last_ipmitool_bmc_reset: endpoint.last_ipmitool_bmc_reset,
            last_redfish_reboot: endpoint.last_redfish_reboot,
        }
    }
}

impl DbExploredEndpoint {
    pub async fn find_ips(
        txn: &mut Transaction<'_, Postgres>,
        // filter is currently is empty, so it is a placeholder for the future
        _filter: ::rpc::site_explorer::ExploredEndpointSearchFilter,
    ) -> Result<Vec<IpAddr>, DatabaseError> {
        #[derive(Debug, Clone, Copy, FromRow)]
        pub struct ExploredEndpointIp(IpAddr);
        // grab list of IPs
        let mut builder = sqlx::QueryBuilder::new("SELECT address FROM explored_endpoints");
        let query = builder.build_query_as();
        let ids: Vec<ExploredEndpointIp> = query
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "explored_endpoints::find_ips", e))?;
        // convert to IpAddr
        let ips: Vec<IpAddr> = ids.iter().map(|id| id.0).collect();
        Ok(ips)
    }

    pub async fn find_by_ips(
        txn: &mut Transaction<'_, Postgres>,
        ips: Vec<IpAddr>,
    ) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
        let query = "SELECT * FROM explored_endpoints WHERE address=ANY($1)";

        sqlx::query_as::<_, Self>(query)
            .bind(ips)
            .fetch_all(txn.deref_mut())
            .await
            .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
            .map_err(|e| DatabaseError::new(file!(), line!(), "explored_endpoints::find_by_ips", e))
    }

    /// find_all returns all explored endpoints that site explorer has been able to probe
    pub async fn find_all(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
        let query = "SELECT * FROM explored_endpoints";

        sqlx::query_as::<_, Self>(query)
            .fetch_all(txn.deref_mut())
            .await
            .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
            .map_err(|e| DatabaseError::new(file!(), line!(), "explored_endpoints find_all", e))
    }

    /// Some endpoints are the OOB of a machine. Those don't have Redfish, are not interesting, we
    /// never want to display those to a user.
    pub async fn find_interesting(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
        let query = r#"SELECT *
            FROM explored_endpoints ee
            LEFT JOIN machine_interface_addresses mia ON ee.address = mia.address
            LEFT JOIN machine_interfaces mi ON mia.interface_id = mi.id
            LEFT JOIN machines m ON mi.machine_id = m.id
            WHERE mia.address IS NULL OR m.id IS NULL"#;

        sqlx::query_as::<_, Self>(query)
            .fetch_all(txn.deref_mut())
            .await
            .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
            .map_err(|e| {
                DatabaseError::new(file!(), line!(), "explored_endpoints find_interesting", e)
            })
    }

    /// find_preingest_not_waiting gets everything that is still in preingestion that isn't waiting for site explorer to refresh it again and isn't in an error state.
    pub async fn find_preingest_not_waiting_not_error(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
        let query = "SELECT * FROM explored_endpoints
                        WHERE (preingestion_state IS NULL OR preingestion_state->'state' != '\"complete\"')
                            AND waiting_for_explorer_refresh = false
                            AND (exploration_report->'LastExplorationError' IS NULL OR exploration_report->'LastExplorationError' = 'null')"; // If LastExplorationError is completely notexistant it is NULL, if it is there and indicates a null value it is 'null'.

        sqlx::query_as::<_, Self>(query)
            .fetch_all(txn.deref_mut())
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
        let query = "SELECT * FROM explored_endpoints WHERE preingestion_state->'state' = '\"upgradefirmwarewait\"'";

        sqlx::query_as::<_, Self>(query)
            .fetch_all(txn.deref_mut())
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
            "SELECT * FROM explored_endpoints WHERE preingestion_state->'state' = '\"complete\"'";

        sqlx::query_as::<_, Self>(query)
            .fetch_all(txn.deref_mut())
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
        let query = "SELECT * FROM explored_endpoints WHERE address = $1";

        sqlx::query_as::<_, Self>(query)
            .bind(address)
            .fetch_all(txn.deref_mut())
            .await
            .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
            .map_err(|e| {
                DatabaseError::new(file!(), line!(), "explored_endpoints find_all_by_ip", e)
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
UPDATE explored_endpoints SET version=$1, exploration_report=$2, waiting_for_explorer_refresh = false, exploration_requested = false
WHERE address = $3 AND version=$4";
        let query_result = sqlx::query(query)
            .bind(new_version)
            .bind(sqlx::types::Json(exploration_report))
            .bind(address)
            .bind(old_version)
            .execute(txn.deref_mut())
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

    /// Sets the `exploration_requested` flag on an explored_endpoint
    ///
    /// Returns Ok(`true`) if the endpoint record is updated and Ok(`false`) if no
    /// record with the given version exists.
    pub async fn re_explore_if_version_matches(
        address: IpAddr,
        version: ConfigVersion,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<bool, DatabaseError> {
        let query =
            "UPDATE explored_endpoints SET exploration_requested = true WHERE address = $1 AND version = $2 RETURNING address";
        let query_result: Result<(IpAddr,), _> = sqlx::query_as(query)
            .bind(address)
            .bind(version)
            .fetch_one(txn.deref_mut())
            .await;

        match query_result {
            Ok((_address,)) => Ok(true),
            Err(e) => match e {
                sqlx::Error::RowNotFound => Ok(false),
                e => Err(DatabaseError::new(file!(), line!(), query, e)),
            },
        }
    }

    /// set_waiting_for_explorer_refresh sets a flag that will be cleared next time try_update runs.
    pub async fn set_waiting_for_explorer_refresh(
        address: IpAddr,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query =
            "UPDATE explored_endpoints SET waiting_for_explorer_refresh = true WHERE address = $1";
        sqlx::query(query)
            .bind(address)
            .execute(txn.deref_mut())
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
            "UPDATE explored_endpoints SET waiting_for_explorer_refresh = false WHERE address = $1";
        sqlx::query(query)
            .bind(address)
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    async fn set_preingestion(
        address: IpAddr,
        state: PreingestionState,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE explored_endpoints SET preingestion_state = $1 WHERE address = $2";
        sqlx::query(query)
            .bind(sqlx::types::Json(&state))
            .bind(address)
            .execute(txn.deref_mut())
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
        upgrade_type: &FirmwareComponentType,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let state = PreingestionState::UpgradeFirmwareWait {
            task_id,
            final_version: final_version.to_owned(),
            upgrade_type: *upgrade_type,
        };
        DbExploredEndpoint::set_preingestion(address, state, txn).await
    }

    pub async fn set_preingestion_reset_for_new_firmware(
        address: IpAddr,
        final_version: &str,
        upgrade_type: &FirmwareComponentType,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let state = PreingestionState::ResetForNewFirmware {
            final_version: final_version.to_owned(),
            upgrade_type: *upgrade_type,
        };
        DbExploredEndpoint::set_preingestion(address, state, txn).await
    }

    pub async fn set_preingestion_new_reported_wait(
        address: IpAddr,
        final_version: &str,
        upgrade_type: &FirmwareComponentType,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let state = PreingestionState::NewFirmwareReportedWait {
            final_version: final_version.to_owned(),
            upgrade_type: *upgrade_type,
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
        INSERT INTO explored_endpoints (address, exploration_report, version, exploration_requested, preingestion_state)
        VALUES ($1, $2::json, $3, false, '{\"state\":\"initial\"}')
        ON CONFLICT DO NOTHING";
        sqlx::query(query)
            .bind(address)
            .bind(sqlx::types::Json(&exploration_report))
            .bind(ConfigVersion::initial())
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    pub async fn delete(
        txn: &mut Transaction<'_, Postgres>,
        address: IpAddr,
    ) -> Result<(), DatabaseError> {
        let query = r#"DELETE FROM explored_endpoints WHERE address=$1"#;
        sqlx::query(query)
            .bind(address)
            .execute(txn.deref_mut())
            .await
            .map(|_| ())
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    /// Search the exploration report for a string anywhere in the JSON.
    /// Used by the MAC address finder.
    pub async fn find_freetext_in_report(
        txn: &mut Transaction<'_, Postgres>,
        to_find: &str,
    ) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
        let query = "SELECT * FROM explored_endpoints WHERE exploration_report::text ilike '%' || $1 || '%'";
        sqlx::query_as::<_, Self>(query)
            .bind(to_find)
            .fetch_all(txn.deref_mut())
            .await
            .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
            .map_err(|e| {
                DatabaseError::new(
                    file!(),
                    line!(),
                    "explored_endpoints find_freetext_in_report",
                    e,
                )
            })
    }

    pub async fn set_last_redfish_bmc_reset(
        address: IpAddr,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query =
            "UPDATE explored_endpoints SET last_redfish_bmc_reset=NOW() WHERE address = $1;";
        sqlx::query(query)
            .bind(address)
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn set_last_ipmitool_bmc_reset(
        address: IpAddr,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query =
            "UPDATE explored_endpoints SET last_ipmitool_bmc_reset=NOW() WHERE address = $1;";
        sqlx::query(query)
            .bind(address)
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn set_last_redfish_reboot(
        address: IpAddr,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE explored_endpoints SET last_redfish_reboot=NOW() WHERE address = $1;";
        sqlx::query(query)
            .bind(address)
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }
}
