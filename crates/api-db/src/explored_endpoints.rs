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

use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use const_format::concatcp;
use mac_address::MacAddress;
use model::firmware::FirmwareComponentType;
use model::machine::pick_boot_interface_candidate;
use model::machine_boot_interface::{MachineBootInterface, MachineBootInterfaceTarget};
use model::site_explorer::{
    EndpointExplorationReport, ExploredEndpoint, InitialBmcResetPhase, InitialResetPhase,
    PowerDrainState, PreingestionState, TimeSyncResetPhase,
};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgConnection, Row};

use crate::db_read::DbReader;
use crate::{BIND_LIMIT, DatabaseError};

#[derive(Debug)]
struct DbExploredEndpoint {
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
    /// The last time site explorer issued a redfish call to power cycle this endpoint
    last_redfish_powercycle: Option<chrono::DateTime<chrono::Utc>>,
    /// whether this host is allowed to power on
    pause_ingestion_and_poweron: bool,
    /// Flag to prevent site explorer from taking remediation actions on redfish errors
    pause_remediation: bool,
    /// The MAC address of the boot interface (primary interface) for this host endpoint
    boot_interface_mac: Option<MacAddress>,
    /// The vendor-native Redfish interface id of the boot interface
    boot_interface_id: Option<String>,
}

#[derive(Debug, FromRow)]
struct LockedBootInterfaceTarget {
    report_version: ConfigVersion,
    boot_interface_mac: Option<MacAddress>,
    boot_interface_id: Option<String>,
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
        let last_redfish_powercycle = row.try_get("last_redfish_powercycle")?;
        let pause_ingestion_and_poweron = row.try_get("pause_ingestion_and_poweron")?;
        let pause_remediation = row.try_get("pause_remediation")?;
        let boot_interface_mac = row.try_get("boot_interface_mac")?;
        let boot_interface_id = row.try_get("boot_interface_id")?;
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
            last_redfish_powercycle,
            pause_ingestion_and_poweron,
            pause_remediation,
            boot_interface_mac,
            boot_interface_id,
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
            last_redfish_powercycle: endpoint.last_redfish_powercycle,
            pause_ingestion_and_poweron: endpoint.pause_ingestion_and_poweron,
            pause_remediation: endpoint.pause_remediation,
            boot_interface_mac: endpoint.boot_interface_mac,
            boot_interface_id: endpoint.boot_interface_id,
        }
    }
}

pub async fn find_ips(
    txn: impl DbReader<'_>,
    // filter is currently is empty, so it is a placeholder for the future
    _filter: model::site_explorer::ExploredEndpointSearchFilter,
) -> Result<Vec<IpAddr>, DatabaseError> {
    #[derive(Debug, Clone, Copy, FromRow)]
    pub struct ExploredEndpointIp(IpAddr);
    // grab list of IPs
    let mut builder = sqlx::QueryBuilder::new("SELECT address FROM explored_endpoints");
    let query = builder.build_query_as();
    let ids: Vec<ExploredEndpointIp> = query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("explored_endpoints::find_ips", e))?;
    // Convert to Vec<IpAddr> and return.
    Ok(ids.iter().map(|id| id.0).collect())
}

pub async fn find_by_ips(
    db: impl DbReader<'_>,
    ips: Vec<IpAddr>,
) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
    let query = "SELECT * FROM explored_endpoints WHERE address=ANY($1)";

    sqlx::query_as::<_, DbExploredEndpoint>(query)
        .bind(ips)
        .fetch_all(db)
        .await
        .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
        .map_err(|e| DatabaseError::new("explored_endpoints::find_by_ips", e))
}

/// Finds and locks one endpoint for a transaction that will also update its
/// managed machine interfaces.
///
/// Call this before locking `machine_interfaces` so boot-interface writers use
/// the same endpoint-before-interface lock order as Site Explorer.
pub async fn find_by_ip_for_update(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<ExploredEndpoint, DatabaseError> {
    find_by_ip_for_update_optional(address, txn)
        .await?
        .ok_or_else(|| DatabaseError::NotFoundError {
            kind: "explored endpoint",
            id: address.to_string(),
        })
}

/// Finds and locks one endpoint when its absence is an expected wait state.
pub async fn find_by_ip_for_update_optional(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<Option<ExploredEndpoint>, DatabaseError> {
    let query = "SELECT * FROM explored_endpoints WHERE address = $1 FOR UPDATE";
    let endpoint = sqlx::query_as::<_, DbExploredEndpoint>(query)
        .bind(address)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(endpoint.map(Into::into))
}

/// Fetches explored DPU endpoints whose reported system serial number is in
/// `serials`. Resolves the host-to-DPU serial join for a page of hosts without
/// loading every explored endpoint. Constrained to DPU reports
/// (`Systems[0].Id == "Bluefield"`) so a host endpoint with a coincidentally
/// matching serial is not pulled in.
///
/// `exploration_report` is the constantly-rewritten site-exploration blob, so we
/// deliberately do not index this JSON path: DPU-endpoint cardinality per site is
/// low and this serves an occasional admin query, so a scoped scan beats taxing
/// the exploration write path with an expression index.
pub async fn find_by_dpu_serial_numbers(
    db: impl DbReader<'_>,
    serials: Vec<String>,
) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
    let query = "SELECT * FROM explored_endpoints \
                 WHERE exploration_report->'Systems'->0->>'SerialNumber' = ANY($1) \
                 AND exploration_report->'Systems'->0->>'Id' = 'Bluefield'";

    sqlx::query_as::<_, DbExploredEndpoint>(query)
        .bind(serials)
        .fetch_all(db)
        .await
        .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
        .map_err(|e| DatabaseError::new("explored_endpoints::find_by_dpu_serial_numbers", e))
}

/// find_all returns all explored endpoints that site explorer has been able to probe
pub async fn find_all(txn: impl DbReader<'_>) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
    let query = "SELECT * FROM explored_endpoints";

    sqlx::query_as::<_, DbExploredEndpoint>(query)
        .fetch_all(txn)
        .await
        .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
        .map_err(|e| DatabaseError::new("explored_endpoints find_all", e))
}

/// The WHERE clause matching endpoints still in preingestion that are neither
/// waiting for a site-explorer refresh nor in an error state. If
/// LastExplorationError is completely nonexistent it is NULL; if it is there
/// and indicates a null value it is 'null'.
///
/// [`find_preingest_not_waiting_not_error`] and
/// [`count_preingest_not_waiting_not_error`] both build their queries from
/// this, so the row-returning and counting variants cannot drift apart.
const PREINGEST_NOT_WAITING_NOT_ERROR_WHERE: &str = "(preingestion_state IS NULL OR preingestion_state->'state' != '\"complete\"')
                            AND waiting_for_explorer_refresh = false
                            AND (exploration_report->'LastExplorationError' IS NULL OR exploration_report->'LastExplorationError' = 'null')";

/// find_preingest_not_waiting gets everything that is still in preingestion that isn't waiting for site explorer to refresh it again and isn't in an error state.
pub async fn find_preingest_not_waiting_not_error(
    txn: impl DbReader<'_>,
) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
    const QUERY: &str = concatcp!(
        "SELECT * FROM explored_endpoints
                        WHERE ",
        PREINGEST_NOT_WAITING_NOT_ERROR_WHERE
    );

    sqlx::query_as::<_, DbExploredEndpoint>(QUERY)
        .fetch_all(txn)
        .await
        .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
        .map_err(|e| DatabaseError::new("explored_endpoints find_preingest_not_waiting", e))
}

/// Counts the endpoints still in preingestion that are neither waiting for a
/// site-explorer refresh nor in an error state.
///
/// Callers that only need the number of such endpoints (e.g. a metric gauge)
/// use this instead of `find_preingest_not_waiting_not_error(..).len()`: it runs
/// the same predicate but selects a scalar `count(*)`, so the database neither
/// returns nor decodes the per-row `exploration_report` jsonb blob. Unlike that
/// row-returning twin, the count also includes rows whose `exploration_report`
/// or `preingestion_state` would fail to deserialize (COUNT never decodes them)
/// — intentional for a metrics counter.
pub async fn count_preingest_not_waiting_not_error(
    txn: impl DbReader<'_>,
) -> Result<i64, DatabaseError> {
    const QUERY: &str = concatcp!(
        "SELECT count(*) FROM explored_endpoints
                        WHERE ",
        PREINGEST_NOT_WAITING_NOT_ERROR_WHERE
    );

    sqlx::query_scalar(QUERY).fetch_one(txn).await.map_err(|e| {
        DatabaseError::new(
            "explored_endpoints count_preingest_not_waiting_not_error",
            e,
        )
    })
}

/// The WHERE clause matching endpoints waiting on a firmware install.
///
/// [`find_preingest_installing`] and [`count_preingest_installing`] both build
/// their queries from this, so the row-returning and counting variants cannot
/// drift apart.
const PREINGEST_INSTALLING_WHERE: &str = "preingestion_state->'state' = '\"upgradefirmwarewait\"'";

/// find_preingest_installing returns the endpoints where we are waiting for firmware installs.
///
/// The metrics caller now uses [`count_preingest_installing`]; this
/// row-returning form remains for callers that need the endpoints themselves
/// and anchors the count's parity test.
pub async fn find_preingest_installing(
    txn: impl DbReader<'_>,
) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
    const QUERY: &str = concatcp!(
        "SELECT * FROM explored_endpoints WHERE ",
        PREINGEST_INSTALLING_WHERE
    );

    sqlx::query_as::<_, DbExploredEndpoint>(QUERY)
        .fetch_all(txn)
        .await
        .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
        .map_err(|e| DatabaseError::new("explored_endpoints find_preingest_installing", e))
}

/// Counts the endpoints waiting for a firmware install to finish.
///
/// The counting counterpart to [`find_preingest_installing`]: callers that only
/// need the number (e.g. a metric gauge) use this so the database returns a
/// single scalar rather than every matching row's `exploration_report` jsonb.
/// Unlike that row-returning twin, the count also includes rows whose
/// `exploration_report` or `preingestion_state` would fail to deserialize
/// (COUNT never decodes them) — intentional for a metrics counter.
pub async fn count_preingest_installing(txn: impl DbReader<'_>) -> Result<i64, DatabaseError> {
    const QUERY: &str = concatcp!(
        "SELECT count(*) FROM explored_endpoints WHERE ",
        PREINGEST_INSTALLING_WHERE
    );

    sqlx::query_scalar(QUERY)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("explored_endpoints count_preingest_installing", e))
}

/// find_all_no_upgrades returns all explored endpoints that site explorer has been able to probe, but ignores anything currently undergoing an upgrade
pub async fn find_all_preingestion_complete(
    txn: &mut PgConnection,
) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
    let query =
        "SELECT * FROM explored_endpoints WHERE preingestion_state->'state' = '\"complete\"'";

    sqlx::query_as::<_, DbExploredEndpoint>(query)
        .fetch_all(txn)
        .await
        .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
        .map_err(|e| DatabaseError::new("explored_endpoints find_all_preingestion_complete", e))
}

/// find_all_by_ip returns a list of explored endpoints that match the ip (should be a list of one)
pub async fn find_all_by_ip(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
    let query = "SELECT * FROM explored_endpoints WHERE address = $1";

    sqlx::query_as::<_, DbExploredEndpoint>(query)
        .bind(address)
        .fetch_all(txn)
        .await
        .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
        .map_err(|e| DatabaseError::new("explored_endpoints find_all_by_ip", e))
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExploredBmcMetadata {
    pub vendor: Option<String>,
    pub ipmi_port: Option<u16>,
}

pub async fn lookup_bmc_metadata_by_ip(
    address: IpAddr,
    db_reader: impl DbReader<'_>,
) -> Result<ExploredBmcMetadata, DatabaseError> {
    let query = "SELECT exploration_report ->> 'Vendor' AS vendor, \
                 exploration_report #>> '{Managers,0,IpmiPort}' AS ipmi_port \
                 FROM explored_endpoints WHERE address = $1";

    let metadata: Option<(Option<String>, Option<String>)> = sqlx::query_as(query)
        .bind(address)
        .fetch_optional(db_reader)
        .await
        .map_err(|e| DatabaseError::new("explored_endpoints lookup_bmc_metadata_by_ip", e))?;

    Ok(
        metadata.map_or_else(ExploredBmcMetadata::default, |(vendor, ipmi_port)| {
            ExploredBmcMetadata {
                vendor,
                ipmi_port: ipmi_port.and_then(|port| port.parse().ok()),
            }
        }),
    )
}

/// Updates the explored information about a node
///
/// This operation will return `Ok(false)` if the entry had been deleted in
/// the meantime or otherwise modified. It will not fail.
pub async fn try_update(
    address: IpAddr,
    old_version: ConfigVersion,
    exploration_report: &EndpointExplorationReport,
    waiting_for_explorer_refresh: bool,
    txn: &mut PgConnection,
) -> Result<bool, DatabaseError> {
    let new_version = old_version.increment();
    let query = "
UPDATE explored_endpoints SET version=$1, exploration_report=$2, waiting_for_explorer_refresh=$3, exploration_requested = false
WHERE address=$4 AND version=$5";
    let query_result = sqlx::query(query)
        .bind(new_version)
        .bind(sqlx::types::Json(exploration_report))
        .bind(waiting_for_explorer_refresh)
        .bind(address)
        .bind(old_version)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(query_result.rows_affected() > 0)
}

/// Updates only the last exploration error and latency in an endpoint's report.
///
/// This preserves the rest of the last successful exploration report while recording
/// an exploration failure. Returns `Ok(false)` if the entry had been deleted in the
/// meantime or otherwise modified. It will not fail for version mismatches.
pub async fn try_update_last_exploration_error(
    address: IpAddr,
    old_version: ConfigVersion,
    error: &model::site_explorer::EndpointExplorationError,
    latency: std::time::Duration,
    txn: &mut PgConnection,
) -> Result<bool, DatabaseError> {
    let new_version = old_version.increment();
    let query = "UPDATE explored_endpoints
SET version=$1,
    exploration_report=jsonb_set(
        jsonb_set(exploration_report, '{LastExplorationError}', $2::jsonb, true),
        '{LastExplorationLatency}', $3::jsonb, true
    ),
    waiting_for_explorer_refresh=true,
    exploration_requested=false
WHERE address=$4 AND version=$5";
    let query_result = sqlx::query(query)
        .bind(new_version)
        .bind(sqlx::types::Json(error))
        .bind(sqlx::types::Json(&latency))
        .bind(address)
        .bind(old_version)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(query_result.rows_affected() > 0)
}

/// Clears the last known error in `explored_endpoints` for the BMC identified by IP.
///
/// Lock the endpoint while reading its report so a concurrent exploration
/// update either commits first and is preserved, or loses its optimistic update
/// after this clear commits.
pub async fn clear_last_known_error(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "SELECT * FROM explored_endpoints WHERE address = $1 FOR UPDATE";
    let Some(row) = sqlx::query_as::<_, DbExploredEndpoint>(query)
        .bind(address)
        .fetch_optional(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?
    else {
        return Ok(());
    };

    let mut report = row.report;
    report.last_exploration_error = None;
    if !try_update(address, row.report_version, &report, true, txn).await? {
        return Err(DatabaseError::ConcurrentModificationError(
            "ExploredEndpoint",
            row.report_version.version_string(),
        ));
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
    txn: &mut PgConnection,
) -> Result<bool, DatabaseError> {
    let query = "UPDATE explored_endpoints SET exploration_requested = true WHERE address = $1 AND version = $2 RETURNING address";
    let query_result: Result<(IpAddr,), _> = sqlx::query_as(query)
        .bind(address)
        .bind(version)
        .fetch_one(txn)
        .await;

    match query_result {
        Ok((_address,)) => Ok(true),
        Err(e) => match e {
            sqlx::Error::RowNotFound => Ok(false),
            e => Err(DatabaseError::query(query, e)),
        },
    }
}

/// set_waiting_for_explorer_refresh sets a flag that will be cleared next time try_update runs.
pub async fn set_waiting_for_explorer_refresh(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query =
        "UPDATE explored_endpoints SET waiting_for_explorer_refresh = true WHERE address = $1";
    sqlx::query(query)
        .bind(address)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

/// Unconditionally set `exploration_requested = true` for a batch of BMC
/// addresses so the site explorer prioritises them on its next tick.
/// Addresses without a row in `explored_endpoints` are silently skipped.
pub async fn request_exploration_for_addresses(
    addresses: &[IpAddr],
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    if addresses.is_empty() {
        return Ok(());
    }
    let query =
        "UPDATE explored_endpoints SET exploration_requested = true WHERE address = ANY($1)";
    sqlx::query(query)
        .bind(addresses)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

async fn set_preingestion(
    address: IpAddr,
    state: PreingestionState,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "UPDATE explored_endpoints SET preingestion_state = $1 WHERE address = $2";
    sqlx::query(query)
        .bind(sqlx::types::Json(&state))
        .bind(address)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn set_preingestion_recheck_versions(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::RecheckVersions;
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_initial_reset(
    address: IpAddr,
    phase: InitialResetPhase,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::InitialReset {
        phase,
        last_time: Utc::now(),
    };
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_initial_bmc_reset(
    address: IpAddr,
    phase: InitialBmcResetPhase,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::InitialBMCReset { phase };
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_set_ntp_servers(
    address: IpAddr,
    set_at: Option<DateTime<Utc>>,
    attempts: u32,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::SetNtpServers { set_at, attempts };
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_time_sync_reset(
    address: IpAddr,
    phase: TimeSyncResetPhase,
    attempt: u32,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::TimeSyncReset {
        phase,
        last_time: Utc::now(),
        attempt,
    };
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_recheck_versions_reason(
    address: IpAddr,
    reason: String,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::RecheckVersionsAfterFailure { reason };
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_waittask(
    address: IpAddr,
    task_id: String,
    final_version: &str,
    upgrade_type: &FirmwareComponentType,
    power_drains_needed: Option<u32>,
    firmware_number: u32,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::UpgradeFirmwareWait {
        task_id,
        final_version: final_version.to_owned(),
        upgrade_type: *upgrade_type,
        power_drains_needed,
        firmware_number: Some(firmware_number),
    };
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_reset_for_new_firmware(
    address: IpAddr,
    final_version: &str,
    upgrade_type: &FirmwareComponentType,
    power_drains_needed: Option<u32>,
    delay_until: Option<time::Duration>,
    last_power_drain_operation: Option<PowerDrainState>,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::ResetForNewFirmware {
        final_version: final_version.to_owned(),
        upgrade_type: *upgrade_type,
        power_drains_needed,
        delay_until: delay_until.map(|x| chrono::Utc::now().timestamp() + x.whole_seconds()),
        last_power_drain_operation,
    };
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_new_reported_wait(
    address: IpAddr,
    final_version: &str,
    upgrade_type: &FirmwareComponentType,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::NewFirmwareReportedWait {
        final_version: final_version.to_owned(),
        upgrade_type: *upgrade_type,
        previous_reset_time: Some(Utc::now().timestamp()),
    };
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_complete(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::Complete;
    set_preingestion(address, state, txn).await
}

pub async fn pregestion_hostboot_time_test(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = r#"UPDATE explored_endpoints SET preingestion_state = jsonb_set(preingestion_state, '{last_time}', '"2020-06-13T00:37:52.150893548Z"') WHERE address = $1"#;
    sqlx::query(query)
        .bind(address)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn set_preingestion_script_running(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::ScriptRunning;
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_bfb_recovery_needed(
    address: IpAddr,
    reason: String,
    host_bmc_ip: IpAddr,
    pre_copy_powercycle: bool,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::BfbRecoveryNeeded {
        reason,
        host_bmc_ip,
        pre_copy_powercycle,
    };
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_bfb_platform_powercycle(
    address: IpAddr,
    host_bmc_ip: IpAddr,
    phase: model::site_explorer::BfbPlatformPowercyclePhase,
    post_install: bool,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::BfbPlatformPowercycle {
        host_bmc_ip,
        phase,
        post_install,
    };
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_bfb_copy_in_progress(
    address: IpAddr,
    host_bmc_ip: IpAddr,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::BfbCopyInProgress {
        started_at: Utc::now(),
        host_bmc_ip,
    };
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_bfb_installation_wait(
    address: IpAddr,
    host_bmc_ip: IpAddr,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::BfbInstallationWait {
        started_at: Utc::now(),
        host_bmc_ip,
    };
    set_preingestion(address, state, txn).await
}

pub async fn set_preingestion_failed(
    address: IpAddr,
    reason: String,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let state = PreingestionState::Failed { reason };
    set_preingestion(address, state, txn).await
}

/// If the endpoint's preingestion is in the terminal `Failed` state, reset it
/// back to `Initial` so preingestion runs again from the top. States other than
/// `Failed` are left untouched, so this is safe to call unconditionally when an
/// operator clears an error. Returns true if a `Failed` state was actually reset.
pub async fn reset_failed_preingestion(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<bool, DatabaseError> {
    let query = "
UPDATE explored_endpoints
SET preingestion_state = '{\"state\":\"initial\"}'
WHERE address = $1 AND preingestion_state->>'state' = 'failed'";
    let result = sqlx::query(query)
        .bind(address)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(result.rows_affected() > 0)
}

pub async fn insert(
    address: IpAddr,
    exploration_report: &EndpointExplorationReport,
    pause_ingestion_and_poweron: bool,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "
        INSERT INTO explored_endpoints (address, exploration_report, version, exploration_requested, preingestion_state, pause_ingestion_and_poweron)
        VALUES ($1, $2::json, $3, false, '{\"state\":\"initial\"}', $4)
        ON CONFLICT DO NOTHING";
    sqlx::query(query)
        .bind(address)
        .bind(sqlx::types::Json(&exploration_report))
        .bind(ConfigVersion::initial())
        .bind(pause_ingestion_and_poweron)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn delete(txn: &mut PgConnection, address: IpAddr) -> Result<(), DatabaseError> {
    let query = r#"DELETE FROM explored_endpoints WHERE address=$1"#;
    sqlx::query(query)
        .bind(address)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn delete_many(
    txn: &mut PgConnection,
    addresses: &[IpAddr],
) -> Result<(), DatabaseError> {
    for chunk in addresses.chunks(BIND_LIMIT) {
        let query = r#"DELETE FROM explored_endpoints WHERE address=ANY($1)"#;
        sqlx::query(query)
            .bind(chunk)
            .execute(&mut *txn)
            .await
            .map(|_| ())
            .map_err(|e| DatabaseError::query(query, e))?
    }
    Ok(())
}

/// Search the exploration report for any explored endpoint with a manager or system interface
/// matching the given MAC address.
///
/// NOTE: This function's query is designed to exactly match with the GIN index
/// explored_endpoints_mac_addresses_idx, to avoid a full scan of all endpoint reports. Do NOT
/// change this query without changing the index to match!
pub async fn find_by_mac_address(
    txn: impl DbReader<'_>,
    mac: MacAddress,
) -> Result<Vec<ExploredEndpoint>, DatabaseError> {
    let query = r#"
            SELECT * FROM explored_endpoints
            WHERE (
                jsonb_path_query_array(exploration_report, '$.Systems[*].EthernetInterfaces[*].MACAddress')
                ||
                jsonb_path_query_array(exploration_report, '$.Managers[*].EthernetInterfaces[*].MACAddress')
            ) @> to_jsonb(ARRAY[$1]);
        "#;
    sqlx::query_as::<_, DbExploredEndpoint>(query)
        // NOTE: Don't just pass mac here, do our own string conversion. Postgres's string
        // conversion will omit zero-padding of the hex values (:1 instead of :01) and the
        // jsonb comparison breaks.
        .bind(mac.to_string())
        .fetch_all(txn)
        .await
        .map(|endpoints| endpoints.into_iter().map(Into::into).collect())
        .map_err(|e| DatabaseError::new("explored_endpoints find_freetext_in_report", e))
}

pub async fn set_last_redfish_bmc_reset(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "UPDATE explored_endpoints SET last_redfish_bmc_reset=NOW() WHERE address = $1;";
    sqlx::query(query)
        .bind(address)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn set_last_ipmitool_bmc_reset(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "UPDATE explored_endpoints SET last_ipmitool_bmc_reset=NOW() WHERE address = $1;";
    sqlx::query(query)
        .bind(address)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn set_last_redfish_reboot(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "UPDATE explored_endpoints SET last_redfish_reboot=NOW() WHERE address = $1;";
    sqlx::query(query)
        .bind(address)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn set_last_redfish_powercycle(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "UPDATE explored_endpoints SET last_redfish_powercycle=NOW() WHERE address = $1;";
    sqlx::query(query)
        .bind(address)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn set_pause_remediation(
    address: IpAddr,
    pause: bool,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "UPDATE explored_endpoints SET pause_remediation = $1 WHERE address = $2";
    sqlx::query(query)
        .bind(pause)
        .bind(address)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

/// Stores a complete boot-interface pair through the same version barrier as
/// [`set_boot_interface_target`].
pub async fn set_boot_interface(
    address: IpAddr,
    boot_interface: &MachineBootInterface,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    set_boot_interface_target(
        address,
        &MachineBootInterfaceTarget::Pair(boot_interface.clone()),
        txn,
    )
    .await?;
    Ok(())
}

/// Stores the endpoint's desired boot-interface target.
///
/// The endpoint row is locked before its target is compared or updated. A
/// target change increments the report version and requests another
/// exploration, making the returned version a baseline that the next
/// correlated observation must exceed.
pub async fn set_boot_interface_target(
    address: IpAddr,
    target: &MachineBootInterfaceTarget,
    txn: &mut PgConnection,
) -> Result<ConfigVersion, DatabaseError> {
    let locked = lock_boot_interface_target(address, txn).await?;
    update_boot_interface_target(address, target, locked, false, txn).await
}

/// Requests a fresh observation of `target`, even when the endpoint already
/// stores that target.
///
/// The returned post-update version is the baseline for deciding whether a
/// later report was produced in response to this request.
pub async fn request_boot_interface_observation(
    address: IpAddr,
    target: &MachineBootInterfaceTarget,
    txn: &mut PgConnection,
) -> Result<ConfigVersion, DatabaseError> {
    let locked = lock_boot_interface_target(address, txn).await?;
    update_boot_interface_target(address, target, locked, true, txn).await
}

/// Persists Site Explorer's inferred boot interface until a managed machine's
/// selected interface owns the endpoint target.
///
/// The endpoint, materialized interfaces, machine selection version, and
/// predictions are locked in that order before resolving the same cross-store
/// candidate used by the API and machine controller. An operator selection
/// therefore cannot be overwritten by a stale inferred default, while a
/// declared primary prediction can become the target before its first lease.
pub async fn set_boot_interface_default(
    address: IpAddr,
    inferred_default: &MachineBootInterface,
    txn: &mut PgConnection,
) -> Result<ConfigVersion, DatabaseError> {
    let locked = lock_boot_interface_target(address, txn).await?;
    let stored_target = MachineBootInterfaceTarget::from_parts(
        locked.boot_interface_mac,
        locked.boot_interface_id.clone(),
    );
    let machine_id =
        crate::machine_topology::find_machine_id_by_bmc_ip(&mut *txn, &address.to_string()).await?;

    let target = match machine_id {
        Some(machine_id) => {
            crate::machine_interface::lock_for_machine(txn, machine_id).await?;
            crate::machine::lock_boot_interface_selection_version(txn, machine_id).await?;
            crate::predicted_machine_interface::lock_for_machine(txn, machine_id).await?;

            let interfaces = crate::machine_interface::find_by_machine_ids(txn, &[machine_id])
                .await?
                .remove(&machine_id)
                .unwrap_or_default();
            let predictions =
                crate::predicted_machine_interface::find_by_machine_id(txn, &machine_id).await?;
            let Some(primary) = pick_boot_interface_candidate(&interfaces, &predictions) else {
                // A zero-DPU host can legitimately rely on the fallback
                // selection before and after its first in-band lease. Its
                // controller-owned endpoint target must remain unchanged.
                tracing::debug!(
                    %machine_id,
                    bmc_ip_address = %address,
                    "Managed host has no boot-capable primary interface row; preserving its endpoint boot-interface target",
                );
                return Ok(locked.report_version);
            };
            let mac_address = primary.mac_address();
            let interface_id = primary
                .boot_interface()
                .map(|boot_interface| boot_interface.interface_id);

            match MachineBootInterfaceTarget::from_parts(Some(mac_address), interface_id)
                .expect("a machine interface always has a MAC address")
            {
                MachineBootInterfaceTarget::MacOnly(_)
                    if inferred_default.mac_address == mac_address =>
                {
                    MachineBootInterfaceTarget::Pair(inferred_default.clone())
                }
                MachineBootInterfaceTarget::MacOnly(_) => stored_target
                    .filter(|stored| match stored {
                        MachineBootInterfaceTarget::Pair(boot_interface) => {
                            boot_interface.mac_address == mac_address
                        }
                        MachineBootInterfaceTarget::MacOnly(stored_mac_address) => {
                            *stored_mac_address == mac_address
                        }
                    })
                    .unwrap_or(MachineBootInterfaceTarget::MacOnly(mac_address)),
                target @ MachineBootInterfaceTarget::Pair(_) => target,
            }
        }
        None => MachineBootInterfaceTarget::Pair(inferred_default.clone()),
    };

    update_boot_interface_target(address, &target, locked, false, txn).await
}

async fn lock_boot_interface_target(
    address: IpAddr,
    txn: &mut PgConnection,
) -> Result<LockedBootInterfaceTarget, DatabaseError> {
    let query = "SELECT version AS report_version, boot_interface_mac, boot_interface_id \
                 FROM explored_endpoints WHERE address = $1 FOR UPDATE";
    sqlx::query_as(query)
        .bind(address)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?
        .ok_or_else(|| DatabaseError::NotFoundError {
            kind: "explored endpoint",
            id: address.to_string(),
        })
}

async fn update_boot_interface_target(
    address: IpAddr,
    target: &MachineBootInterfaceTarget,
    locked: LockedBootInterfaceTarget,
    force_observation: bool,
    txn: &mut PgConnection,
) -> Result<ConfigVersion, DatabaseError> {
    let current =
        MachineBootInterfaceTarget::from_parts(locked.boot_interface_mac, locked.boot_interface_id);
    if !force_observation && current.as_ref() == Some(target) {
        return Ok(locked.report_version);
    }

    let (mac_address, interface_id) = match target {
        MachineBootInterfaceTarget::Pair(boot_interface) => (
            boot_interface.mac_address,
            Some(boot_interface.interface_id.as_str()),
        ),
        MachineBootInterfaceTarget::MacOnly(mac_address) => (*mac_address, None),
    };
    let new_version = locked.report_version.increment();
    let query = "UPDATE explored_endpoints \
                 SET version = $1, boot_interface_mac = $2, boot_interface_id = $3, \
                     waiting_for_explorer_refresh = true, exploration_requested = true \
                 WHERE address = $4 AND version = $5";
    let result = sqlx::query(query)
        .bind(new_version)
        .bind(mac_address)
        .bind(interface_id)
        .bind(address)
        .bind(locked.report_version)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    if result.rows_affected() != 1 {
        return Err(DatabaseError::ConcurrentModificationError(
            "ExploredEndpoint",
            locked.report_version.version_string(),
        ));
    }

    Ok(new_version)
}

pub async fn set_pause_ingestion_and_poweron(
    address: IpAddr,
    value: bool,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query =
        "UPDATE explored_endpoints SET pause_ingestion_and_poweron = $1 WHERE address = $2;";
    sqlx::query(query)
        .bind(value)
        .bind(address)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

#[cfg(test)]
mod count_preingest_tests {
    use super::*;

    /// An `UpgradeFirmwareWait` state — the one the "installing" predicate keys
    /// on. Built from the real enum so the row-returning path can deserialize it.
    fn installing_state() -> PreingestionState {
        PreingestionState::UpgradeFirmwareWait {
            task_id: "task-1".to_string(),
            final_version: "1.2.3".to_string(),
            upgrade_type: FirmwareComponentType::default(),
            power_drains_needed: None,
            firmware_number: None,
        }
    }

    /// Inserts an explored endpoint with a fat, *decodable* `exploration_report`
    /// blob and the given preingestion `state`. Both are built from the real
    /// model types so the row-returning path can deserialize them — which is
    /// exactly the per-row cost the count path avoids.
    async fn seed_endpoint(txn: &mut PgConnection, addr: &str, state: PreingestionState) {
        // A real report with a deliberately large field, so the row-returning
        // path has genuine multi-KB jsonb to decode; the count path never
        // touches it.
        let report = EndpointExplorationReport {
            model: Some("x".repeat(4096)),
            ..Default::default()
        };
        sqlx::query(
            "INSERT INTO explored_endpoints (address, exploration_report, version, preingestion_state, waiting_for_explorer_refresh) \
             VALUES ($1::inet, $2, 'V1-T1733777281821769', $3, false)",
        )
        .bind(addr)
        .bind(sqlx::types::Json(report))
        .bind(sqlx::types::Json(state))
        .execute(&mut *txn)
        .await
        .expect("seed explored_endpoint");
    }

    /// `count_preingest_not_waiting_not_error` returns the same tally as
    /// `find_preingest_not_waiting_not_error(..).len()`. The win: the count
    /// query returns one scalar, whereas the find query returns every matching
    /// row and decodes each row's multi-KB `exploration_report` jsonb — so the
    /// win is rows + per-row jsonb decode, N -> 0.
    #[crate::sqlx_test]
    async fn count_matches_find_not_waiting_not_error(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();
        // Three endpoints still in preingestion (not complete), not waiting, no error.
        seed_endpoint(&mut txn, "10.0.0.1", PreingestionState::Initial).await;
        seed_endpoint(&mut txn, "10.0.0.2", PreingestionState::RecheckVersions).await;
        seed_endpoint(&mut txn, "10.0.0.3", installing_state()).await;
        // One that is complete -> excluded by the predicate.
        seed_endpoint(&mut txn, "10.0.0.4", PreingestionState::Complete).await;

        let rows = find_preingest_not_waiting_not_error(&mut *txn)
            .await
            .unwrap();
        let count = count_preingest_not_waiting_not_error(&mut *txn)
            .await
            .unwrap();

        assert_eq!(rows.len(), 3, "three endpoints match the predicate");
        assert_eq!(count, 3, "count agrees with the row count");
        assert_eq!(count, rows.len() as i64);
    }

    /// `count_preingest_installing` returns the same tally as
    /// `find_preingest_installing(..).len()` without returning/decoding the
    /// per-row jsonb reports.
    #[crate::sqlx_test]
    async fn count_matches_find_installing(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();
        seed_endpoint(&mut txn, "10.0.1.1", installing_state()).await;
        seed_endpoint(&mut txn, "10.0.1.2", installing_state()).await;
        // Not installing -> excluded.
        seed_endpoint(&mut txn, "10.0.1.3", PreingestionState::Initial).await;

        let rows = find_preingest_installing(&mut *txn).await.unwrap();
        let count = count_preingest_installing(&mut *txn).await.unwrap();

        assert_eq!(rows.len(), 2, "two endpoints are installing firmware");
        assert_eq!(count, 2, "count agrees with the row count");
        assert_eq!(count, rows.len() as i64);
    }
}

#[cfg(test)]
mod boot_interface_target_tests {
    use super::*;

    const ADDRESS: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 2, 1));

    async fn endpoint(txn: &mut PgConnection) -> ExploredEndpoint {
        find_all_by_ip(ADDRESS, txn)
            .await
            .expect("query endpoint")
            .into_iter()
            .next()
            .expect("seeded endpoint")
    }

    async fn clear_observation_request(txn: &mut PgConnection) {
        sqlx::query(
            "UPDATE explored_endpoints \
             SET waiting_for_explorer_refresh = false, exploration_requested = false \
             WHERE address = $1",
        )
        .bind(ADDRESS)
        .execute(txn)
        .await
        .expect("clear observation request");
    }

    #[crate::sqlx_test]
    async fn target_changes_and_forced_observations_create_version_barriers(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.expect("begin transaction");
        let stale_report = EndpointExplorationReport::default();
        insert(ADDRESS, &stale_report, false, &mut txn)
            .await
            .expect("seed endpoint");
        let initial_version = find_by_ip_for_update(ADDRESS, &mut txn)
            .await
            .expect("lock endpoint")
            .report_version;
        let boot_interface = MachineBootInterface {
            mac_address: "02:00:00:00:02:01".parse().expect("valid MAC"),
            interface_id: "NIC.Slot.2-1-1".to_string(),
        };
        let pair = MachineBootInterfaceTarget::Pair(boot_interface.clone());

        let pair_baseline = set_boot_interface_target(ADDRESS, &pair, &mut txn)
            .await
            .expect("set complete target");
        assert!(
            !try_update(ADDRESS, initial_version, &stale_report, false, &mut txn,)
                .await
                .expect("reject stale report"),
            "a report using the pre-target version must lose its compare-and-swap update",
        );
        let stored_pair = endpoint(&mut txn).await;
        assert!(pair_baseline.version_nr() > initial_version.version_nr());
        assert_eq!(stored_pair.report_version, pair_baseline);
        assert_eq!(stored_pair.boot_interface_target(), Some(pair.clone()));
        assert!(stored_pair.waiting_for_explorer_refresh);
        assert!(stored_pair.exploration_requested);

        clear_observation_request(&mut txn).await;
        let unchanged_baseline = set_boot_interface_target(ADDRESS, &pair, &mut txn)
            .await
            .expect("retain complete target");
        let unchanged = endpoint(&mut txn).await;
        assert_eq!(unchanged_baseline, pair_baseline);
        assert!(!unchanged.waiting_for_explorer_refresh);
        assert!(!unchanged.exploration_requested);

        let forced_baseline = request_boot_interface_observation(ADDRESS, &pair, &mut txn)
            .await
            .expect("request fresh observation");
        let forced = endpoint(&mut txn).await;
        assert!(forced_baseline.version_nr() > pair_baseline.version_nr());
        assert_eq!(forced.report_version, forced_baseline);
        assert_eq!(forced.boot_interface_target(), Some(pair));
        assert!(forced.waiting_for_explorer_refresh);
        assert!(forced.exploration_requested);

        clear_observation_request(&mut txn).await;
        let mac_only =
            MachineBootInterfaceTarget::MacOnly("02:00:00:00:02:02".parse().expect("valid MAC"));
        let mac_only_baseline = set_boot_interface_target(ADDRESS, &mac_only, &mut txn)
            .await
            .expect("set MAC-only target");
        let stored_mac_only = endpoint(&mut txn).await;
        assert!(mac_only_baseline.version_nr() > forced_baseline.version_nr());
        assert_eq!(stored_mac_only.report_version, mac_only_baseline);
        assert_eq!(stored_mac_only.boot_interface_target(), Some(mac_only));
        assert!(stored_mac_only.waiting_for_explorer_refresh);
        assert!(stored_mac_only.exploration_requested);
    }
}
