/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

mod metrics;

use std::{sync::Arc, time::Duration};

use forge_secrets::credentials::{CredentialKey, CredentialType};
use libredfish::model::task::TaskState;
use opentelemetry::metrics::Meter;
use sqlx::{PgPool, Postgres, Transaction};
use tokio::{
    sync::{oneshot, Mutex},
    task::JoinSet,
};

use self::metrics::PreingestionMetrics;
use crate::{
    cfg::{
        CarbideConfig, FirmwareEntry, FirmwareGlobal, FirmwareHost, FirmwareHostComponentType,
        ParsedHosts,
    },
    db::{explored_endpoints::DbExploredEndpoint, DatabaseError},
    firmware_downloader::FirmwareDownloader,
    model::site_explorer::{ExploredEndpoint, PreingestionState},
    redfish::{RedfishAuth, RedfishClientCreationError, RedfishClientPool},
    CarbideError,
};

/// DatabaseResult is a mirror of CarbideResult, but we should only be bubbling up an error if it was a database error and we need to reconnect.
type DatabaseResult<T> = Result<T, DatabaseError>;

pub struct PreingestionManager {
    static_info: Arc<PreingestionManagerStatic>,
    metric_holder: Arc<metrics::MetricHolder>,
}

struct PreingestionManagerStatic {
    run_interval: Duration,
    max_uploads: i64,
    database_connection: PgPool,
    firmware_global: FirmwareGlobal,
    host_info: ParsedHosts,
    redfish_client_pool: Arc<dyn RedfishClientPool>,
    downloader: FirmwareDownloader,
}

impl PreingestionManager {
    const DB_LOCK_QUERY: &'static str =
        "SELECT pg_try_advisory_xact_lock((SELECT 'preingestion_manager_lock'::regclass::oid)::integer);";

    pub fn new(
        database_connection: sqlx::PgPool,
        config: Arc<CarbideConfig>,
        redfish_client_pool: Arc<dyn RedfishClientPool>,
        meter: Meter,
    ) -> PreingestionManager {
        let hold_period = config
            .firmware_global
            .run_interval
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30))
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(meter, hold_period));
        metric_holder.register_callback();

        PreingestionManager {
            static_info: Arc::new(PreingestionManagerStatic {
                run_interval: config
                    .firmware_global
                    .run_interval
                    .to_std()
                    .unwrap_or(Duration::from_secs(30)),
                max_uploads: config.firmware_global.max_uploads,
                database_connection,
                firmware_global: config.firmware_global.clone(),
                host_info: config.get_parsed_hosts(),
                redfish_client_pool,
                downloader: FirmwareDownloader::new(),
            }),
            metric_holder,
        }
    }

    pub fn start(self) -> eyre::Result<oneshot::Sender<i32>> {
        let (stop_sender, stop_receiver) = oneshot::channel();
        tokio::task::Builder::new()
            .name("preintegration_manager")
            .spawn(async move { self.run(stop_receiver).await })?;
        Ok(stop_sender)
    }

    async fn run(&self, mut stop_receiver: oneshot::Receiver<i32>) {
        loop {
            let res = self.run_single_iteration().await;

            if let Err(e) = &res {
                tracing::warn!("Preingestion manager error: {}", e);
            }

            // If we were able to go through everything (few or no uploads), or if we ran into a database error,
            // we will wait before checking if new state changes need to happen.
            tokio::select! {
                _ = tokio::time::sleep(self.static_info.run_interval) => {},
                _ = &mut stop_receiver => {
                    tracing::info!("Preingestion manager stop was requested");
                    return;
                }
            }
        }
    }

    /// run_single_iteration runs a single iteration of the state machine across all explored endpoints in the preingestion state.
    /// Returns true if we stopped early due to a timeout.
    pub async fn run_single_iteration(&self) -> DatabaseResult<()> {
        let mut metrics = PreingestionMetrics::new();

        let mut txn = self
            .static_info
            .database_connection
            .begin()
            .await
            .map_err(|e| {
                DatabaseError::new(
                    file!(),
                    line!(),
                    "begin PreingestionManager::run_single_iteration",
                    e,
                )
            })?;

        if !sqlx::query_scalar(PreingestionManager::DB_LOCK_QUERY)
            .fetch_one(&mut *txn)
            .await
            .unwrap_or(false)
        {
            // Unable to obtain the lock, we'll sleep and try again later.  There must be another instance of carbide-api running.
            return Ok(());
        }

        let items = DbExploredEndpoint::find_preingest_not_waiting_not_error(&mut txn).await?;
        let mut task_set = JoinSet::new();
        let active_uploads = Arc::new(Mutex::new(0));

        for endpoint in items.iter() {
            let static_info = self.static_info.clone();
            let endpoint = endpoint.clone();
            let active_uploads = active_uploads.clone();
            let _abort_handle = task_set
                .build_task()
                .name(&format!("preingestion {}", endpoint.address))
                .spawn(async move { one_endpoint(static_info, endpoint, active_uploads).await });
        }

        while let Some(result) = task_set.join_next().await {
            match result {
                Ok(result) => match result {
                    Ok(result) => {
                        if result.delayed_upgrade {
                            metrics.delayed_uploading += 1;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error handling preingestion update: {e}");
                    }
                },
                Err(e) => {
                    tracing::error!("Error handling preingestion update: {e}");
                }
            }
        }

        metrics.machines_in_preingestion =
            DbExploredEndpoint::find_preingest_not_waiting_not_error(&mut txn)
                .await?
                .len();
        metrics.waiting_for_installation = DbExploredEndpoint::find_preingest_installing(&mut txn)
            .await?
            .len();

        tracing::info!(
            "Preingestion metrics: in_preingestion {} waiting {} delayed {}",
            metrics.machines_in_preingestion,
            metrics.waiting_for_installation,
            metrics.delayed_uploading,
        );
        self.metric_holder.update_metrics(metrics);

        txn.commit().await.map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "commit PreintegrationManager::run_single_iteration",
                e,
            )
        })?;
        Ok(())
    }
}

struct EndpointResult {
    delayed_upgrade: bool,
}

async fn one_endpoint(
    static_info: Arc<PreingestionManagerStatic>,
    endpoint: ExploredEndpoint,
    active_uploads: Arc<Mutex<i64>>,
) -> DatabaseResult<EndpointResult> {
    let mut txn = static_info.database_connection.begin().await.map_err(|e| {
        DatabaseError::new(
            file!(),
            line!(),
            "begin PreingestionManager::run_single_iteration",
            e,
        )
    })?;

    // Main state machine match.
    let delayed_upgrade = match &endpoint.preingestion_state {
        PreingestionState::Initial => {
            static_info
                .check_firmware_versions_below_preingestion(&mut txn, &endpoint, active_uploads)
                .await?
        }
        PreingestionState::RecheckVersions => {
            static_info
                .start_firmware_uploads_or_continue(&mut txn, &endpoint, active_uploads)
                .await?
        }
        PreingestionState::UpgradeFirmwareWait { task_id } => {
            static_info
                .in_upgrade_firmware_wait(&mut txn, &endpoint, task_id)
                .await?;
            false
        }
        PreingestionState::Complete => {
            // This should have been filtered out by the query that got us this list.
            tracing::info!(
                "Endpoint showed complete preingestion and should not have been here: {endpoint:?}"
            );
            false
        }
    };

    txn.commit().await.map_err(|e| {
        DatabaseError::new(
            file!(),
            line!(),
            "commit PreintegrationManager::run_single_iteration",
            e,
        )
    })?;

    Ok(EndpointResult { delayed_upgrade })
}

impl PreingestionManagerStatic {
    /// find_fw_info_for_host looks up the firmware config for the given endpoint
    fn find_fw_info_for_host(&self, endpoint: &ExploredEndpoint) -> Option<FirmwareHost> {
        let vendor = match &endpoint.report.vendor {
            Some(vendor) => vendor.to_owned(),
            None => {
                // No vendor found for the endpoint, we can't match firmware
                return None;
            }
        };
        let chassis_with_model = endpoint.report.chassis.iter().find(|&x| x.model.is_some());
        let model = match chassis_with_model {
            Some(chassis) => match &chassis.model {
                Some(model) => model.to_owned(),
                None => {
                    // No model found for the endpoint, we can't match firmware
                    return None;
                }
            },
            None => {
                // No chassis with model found for the endpoint, we can't match firmware
                return None;
            }
        };
        self.host_info.find(vendor.to_string(), model)
    }

    /// check_firmware_versions_below_preingestion will check if we actually need to do firmware upgrades before
    /// ingestion can happen, and either kick them off if so otherwise move on.
    async fn check_firmware_versions_below_preingestion(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        endpoint: &ExploredEndpoint,
        active_uploads: Arc<Mutex<i64>>,
    ) -> DatabaseResult<bool> {
        // First, we need to check if it's appropriate to upgrade at this point or wait until later.
        let fw_info = match self.find_fw_info_for_host(endpoint) {
            None => {
                // No desired firmware description found for this host, nothing to do.
                // This is the expected path for DPUs.
                DbExploredEndpoint::set_preingestion_complete(endpoint.address, txn).await?;
                return Ok(false);
            }
            Some(fw_info) => fw_info,
        };
        for (fwtype, desc) in &fw_info.components {
            if let Some(min_preingestion) = &desc.preingest_upgrade_when_below {
                if let Some(current) = find_version(endpoint, &fw_info, *fwtype) {
                    if version_compare::compare(current, min_preingestion)
                        .is_ok_and(|c| c == version_compare::Cmp::Lt)
                    {
                        // One or both of the versions are low enough to absolutely need upgrades first - do them both while we're at it.
                        let delayed_upgrade = self
                            .start_firmware_uploads_or_continue(txn, endpoint, active_uploads)
                            .await?;
                        return Ok(delayed_upgrade);
                    }
                }
            }
        }

        // Good enough for now at least, proceed with ingestion.
        DbExploredEndpoint::set_preingestion_complete(endpoint.address, txn).await?;
        Ok(false)
    }

    /// start_firmware_uploads_or_continue will start a firmware upgrade if any of the endpoint's versions
    /// do not match the desired version.  If they all match, it will continue on.  The upload must complete
    /// before we return; this means only one upload happens at a time, but we don't expect that doing multiples
    /// would make a significant difference, as we're limited by our own upload bandwidth.
    async fn start_firmware_uploads_or_continue(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        endpoint: &ExploredEndpoint,
        active_uploads: Arc<Mutex<i64>>,
    ) -> DatabaseResult<bool> {
        if endpoint.waiting_for_explorer_refresh {
            // We've updated something and are waiting for site explorer to get back around to it
            return Ok(false);
        }

        // Determine if auto updates should be enabled for this host.
        let mut enabled = self.firmware_global.autoupdate;
        if endpoint.report.machine_id.is_some() {
            if self
                .firmware_global
                .host_enable_autoupdate
                .iter()
                .any(|x| *x == endpoint.report.machine_id.as_ref().unwrap().to_string())
            {
                enabled = true;
            }
            if self
                .firmware_global
                .host_disable_autoupdate
                .iter()
                .any(|x| *x == endpoint.report.machine_id.as_ref().unwrap().to_string())
            {
                enabled = false;
            }
        }
        if !enabled {
            // Auto updates are disabled, so call everything "good".
            DbExploredEndpoint::set_preingestion_complete(endpoint.address, txn).await?;
            return Ok(false);
        }

        let fw_info = match self.find_fw_info_for_host(endpoint) {
            None => {
                // No desired firmware description found for this host
                return Ok(false);
            }
            Some(fw_info) => fw_info,
        };

        // Specifying ordering is optional, and defaults to first BMC then UEFI.
        let mut ordering = fw_info.ordering.clone();
        if ordering.is_empty() {
            ordering.push(FirmwareHostComponentType::Bmc);
            ordering.push(FirmwareHostComponentType::Uefi);
        }
        for upgrade_type in ordering {
            let (done, delayed_upgrade) = self
                .start_upgrade_if_needed(endpoint, &fw_info, upgrade_type, &active_uploads, txn)
                .await?;

            if done {
                // We started something and need to wait now, or we had a valid reason not to start and will retry later.
                // In the former case only, the state has been updated.
                return Ok(delayed_upgrade);
            }
        }

        // Nothing needed to be updated, we're complete.
        DbExploredEndpoint::set_preingestion_complete(endpoint.address, txn).await?;
        Ok(false)
    }

    /// First bool is true if started an upgrade, or for some other reason shouldn't check for updating other firmwares.  Second is if we delayed the update.
    async fn start_upgrade_if_needed(
        &self,
        endpoint: &ExploredEndpoint,
        fw_info: &FirmwareHost,
        fw_type: FirmwareHostComponentType,
        active_uploads: &Arc<Mutex<i64>>,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<(bool, bool), DatabaseError> {
        {
            match need_upgrade(endpoint, fw_info, fw_type) {
                None => Ok((false, false)),
                Some(to_install) => {
                    let mut active_uploads = active_uploads.lock().await;
                    if *active_uploads >= self.max_uploads {
                        tracing::info!(
                            "Deferring installation of {:?} on {}, too many uploads already active",
                            to_install,
                            endpoint.address
                        );
                        return Ok((true, true)); // Don't check others
                    }
                    *active_uploads += 1;
                    // Don't keep holding the lock!
                    drop(active_uploads);

                    tracing::info!("Installing {:?} on {}", to_install, endpoint.address);

                    initiate_update(
                        txn,
                        endpoint,
                        &self.redfish_client_pool,
                        &to_install,
                        &self.downloader,
                    )
                    .await?;

                    // initiate_update only returned an error for database issues.  If it truly succeeded, it updated
                    // the database with a new state.  If the firmware download was not yet complete or we had a Redfish
                    // problem (BMC is down or died in the middle, etc.) it will not have returned an error, but it will
                    // not have updated the state either; we will retry the update on the next go.  Either way, we return
                    // true so that we won't try updating other firmware.

                    Ok((true, false))
                }
            }
        }
    }

    /// in_upgrade_firmware_wait triggers when we are waiting for installation of firmware after an upload.
    async fn in_upgrade_firmware_wait(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        endpoint: &ExploredEndpoint,
        task_id: &str,
    ) -> DatabaseResult<()> {
        let redfish_client = match self
            .redfish_client_pool
            .create_client(
                &endpoint.address.to_string(),
                None,
                RedfishAuth::Key(CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                }),
                true,
            )
            .await
            .map_err(|e| match e {
                RedfishClientCreationError::RedfishError(e) => CarbideError::RedfishError(e),
                _ => CarbideError::GenericError(format!("{}", e)),
            }) {
            Ok(redfish_client) => redfish_client,
            Err(e) => {
                tracing::error!("Redfish connection to {} failed: {e}", endpoint.address);
                return Ok(());
            }
        };

        match redfish_client.get_task(task_id).await {
            Ok(task_info) => {
                match task_info.task_state {
                    Some(TaskState::New)
                    | Some(TaskState::Starting)
                    | Some(TaskState::Running)
                    | Some(TaskState::Pending) => {
                        tracing::info!(
                            "Upgrade task for {} not yet complete, current state {:?} message {:?}",
                            endpoint.address,
                            task_info.task_state,
                            task_info.messages,
                        );
                    }
                    Some(TaskState::Completed) => {
                        // Task has completed, update is done and we can clean up.  Site explorer will ingest this next time it runs on this endpoint.
                        tracing::info!(
                            "Marking completion of BMC firmware upgrade for {}",
                            &endpoint.address
                        );
                        DbExploredEndpoint::set_preingestion_recheck_versions(
                            endpoint.address,
                            txn,
                        )
                        .await?;

                        // We need site explorer to requery the version
                        DbExploredEndpoint::set_waiting_for_explorer_refresh(endpoint.address, txn)
                            .await?;
                    }
                    Some(TaskState::Exception)
                    | Some(TaskState::Interrupted)
                    | Some(TaskState::Killed)
                    | Some(TaskState::Cancelled) => {
                        tracing::error!(
                            "Failure in firmware upgrade for {}: {} {:?}",
                            &endpoint.address,
                            task_info.task_state.unwrap(),
                            task_info
                                .messages
                                .last()
                                .map_or("".to_string(), |m| m.message.clone())
                        );

                        // Wait for site explorer to refresh it then try again after that.
                        // Someday, we should generate metrics for visiblity if something fails multiple times.
                        DbExploredEndpoint::set_preingestion_recheck_versions(
                            endpoint.address,
                            txn,
                        )
                        .await?;

                        // We need site explorer to requery the version
                        DbExploredEndpoint::set_waiting_for_explorer_refresh(endpoint.address, txn)
                            .await?;
                    }
                    _ => {
                        // Unexpected state
                        tracing::error!(
                            "Unrecognized task state for {}: {:?}",
                            endpoint.address,
                            task_info.task_state
                        );
                    }
                };
            }
            Err(e) => {
                tracing::error!("Getting Redfish task from {} failed: {e}", endpoint.address);
            }
        };
        Ok(())
    }
}

/// find_version will locate a version number within an ExploredEndpoint
fn find_version(
    endpoint: &ExploredEndpoint,
    fw_info: &FirmwareHost,
    firmware_type: FirmwareHostComponentType,
) -> Option<String> {
    for service in endpoint.report.service.iter() {
        if let Some(matching_inventory) = service
            .inventories
            .iter()
            .find(|&x| fw_info.matching_version_id(&x.id, firmware_type))
        {
            return matching_inventory.version.clone();
        };
    }
    None
}

/// need_upgrade determines if the given endpoint needs a firmware upgrade based on the description in fw_info, and if so returns the FirmwareEntry matching the desired upgrade.
fn need_upgrade(
    endpoint: &ExploredEndpoint,
    fw_info: &FirmwareHost,
    firmware_type: FirmwareHostComponentType,
) -> Option<FirmwareEntry> {
    // First, find the BMC version.
    let mut current_version = None;
    for service in endpoint.report.service.iter() {
        if let Some(matching_inventory) = service
            .inventories
            .iter()
            .find(|&x| fw_info.matching_version_id(&x.id, firmware_type))
        {
            current_version = matching_inventory.version.as_ref();
            break;
        };
    }
    let current_version = current_version?.to_owned();

    // Now find the desired version, if it's not the version that is currently installed.
    fw_info
        .components
        .get(&firmware_type)?
        .known_firmware
        .iter()
        .find(|x| x.default && x.version != current_version)
        .cloned()
}

/// initiate_update will start a Redfish connection to the given address and start an update
/// by doing an upload.  It may be unable to start it if the firmware has not been previously
/// downloaded; if that happens it also returns success, but has not modified the state.  On Redfish
///  errors, we return Ok but leave the state as it was, with the intention that we will retry
///  on the next go.
async fn initiate_update(
    txn: &mut Transaction<'_, Postgres>,
    endpoint_clone: &ExploredEndpoint,
    redfish_client_pool: &Arc<dyn RedfishClientPool>,
    to_install: &FirmwareEntry,
    downloader: &FirmwareDownloader,
) -> Result<(), DatabaseError> {
    if !downloader
        .available(
            &to_install.get_filename(),
            &to_install.get_url(),
            &to_install.get_checksum(),
        )
        .await
    {
        tracing::info!(
            "{} is being downloaded from {}, update deferred",
            to_install.get_filename().display(),
            to_install.get_url()
        );

        return Ok(());
    }

    // Setup the Redfish connection
    let redfish_client = match redfish_client_pool
        .create_client(
            &endpoint_clone.address.to_string(),
            None,
            RedfishAuth::Key(CredentialKey::HostRedfish {
                credential_type: CredentialType::SiteDefault,
            }),
            true,
        )
        .await
    {
        Ok(redfish_client) => redfish_client,
        Err(e) => {
            tracing::info!(
                "Failed to open redfish to {}: {e}",
                endpoint_clone.address.to_string()
            );
            return Ok(());
        }
    };
    let task = match redfish_client
        .update_firmware_multipart(to_install.get_filename().as_path(), true)
        .await
    {
        Ok(task) => task,
        Err(e) => {
            tracing::error!(
                "Failed uploading firmware to {}: {e}",
                endpoint_clone.address.to_string()
            );
            return Ok(());
        }
    };

    DbExploredEndpoint::set_preingestion_waittask(endpoint_clone.address, task, txn).await?;

    Ok(())
}
