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

use std::collections::HashMap;
use std::default::Default;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use db::work_lock_manager::WorkLockManagerHandle;
use db::{DatabaseError, WithTransaction};
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialProvider, Credentials,
};
use futures_util::FutureExt;
use libredfish::model::task::TaskState;
use libredfish::model::update_service::TransferProtocolType;
use libredfish::{PowerState, RedfishError, SystemPowerControl};
use model::firmware::{Firmware, FirmwareComponentType, FirmwareEntry};
use model::site_explorer::{
    ExploredEndpoint, InitialResetPhase, PowerDrainState, PreingestionState, TimeSyncResetPhase,
};
use opentelemetry::metrics::Meter;
use sqlx::PgPool;
use tokio::fs::File;
use tokio::io::AsyncBufReadExt;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinSet;

use crate::cfg::file::{CarbideConfig, FirmwareConfig, FirmwareGlobal};
use crate::firmware_downloader::FirmwareDownloader;
use crate::preingestion_manager::metrics::PreingestionMetrics;
use crate::redfish::{RedfishClientCreationError, RedfishClientPool};
use crate::{CarbideError, CarbideResult};

mod metrics;

const NOT_FOUND: u16 = 404;

pub struct PreingestionManager {
    static_info: Arc<PreingestionManagerStatic>,
    metric_holder: Arc<metrics::MetricHolder>,
    database_connection: PgPool,
}

#[derive(Clone)]
struct PreingestionManagerStatic {
    run_interval: Duration,
    firmware_global: FirmwareGlobal,
    host_info: FirmwareConfig,
    redfish_client_pool: Arc<dyn RedfishClientPool>,
    downloader: FirmwareDownloader,
    upload_limiter: Arc<Semaphore>,
    concurrency_limit: usize,
    hgx_bmc_gpu_reboot_delay: Duration,
    upgrade_script_state: Arc<UpdateScriptManager>,
    credential_provider: Option<Arc<dyn CredentialProvider>>,
    work_lock_manager_handle: WorkLockManagerHandle,
}

impl PreingestionManager {
    const ITERATION_WORK_KEY: &'static str = "PreingestionManager::run_single_iteration";

    // Note on allow(too_many_arguments): It's normal for long-running services like this, which
    // integrate a lot of other services together (redfish, credentialss, config, work manager,
    // etc.) to require a lot of arguments. We can't really avoid this.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database_connection: sqlx::PgPool,
        config: Arc<CarbideConfig>,
        redfish_client_pool: Arc<dyn RedfishClientPool>,
        meter: Meter,
        downloader: Option<FirmwareDownloader>,
        upload_limiter: Option<Arc<Semaphore>>,
        credential_provider: Option<Arc<dyn CredentialProvider>>,
        work_lock_manager_handle: WorkLockManagerHandle,
    ) -> PreingestionManager {
        let hold_period = config
            .firmware_global
            .run_interval
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30))
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(meter, hold_period));

        PreingestionManager {
            static_info: Arc::new(PreingestionManagerStatic {
                run_interval: config
                    .firmware_global
                    .run_interval
                    .to_std()
                    .unwrap_or(Duration::from_secs(30)),
                firmware_global: config.firmware_global.clone(),
                host_info: config.get_firmware_config(),
                redfish_client_pool,
                downloader: downloader.unwrap_or_default(),
                upload_limiter: upload_limiter.unwrap_or(Arc::new(Semaphore::new(5))),
                concurrency_limit: config.firmware_global.concurrency_limit,
                upgrade_script_state: Default::default(),
                credential_provider,
                hgx_bmc_gpu_reboot_delay: config
                    .firmware_global
                    .hgx_bmc_gpu_reboot_delay
                    .to_std()
                    .unwrap_or(Duration::from_secs(30)),
                work_lock_manager_handle,
            }),
            metric_holder,
            database_connection,
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
    pub async fn run_single_iteration(&self) -> CarbideResult<()> {
        let mut metrics = PreingestionMetrics::new();
        let db = self.database_connection.clone();

        let _work_lock = match self
            .static_info
            .work_lock_manager_handle
            .try_acquire_lock(Self::ITERATION_WORK_KEY.into())
            .await
        {
            Ok(lock) => lock,
            Err(e) => {
                // Unable to obtain the lock, we'll sleep and try again later.  There must be another instance of carbide-api running.
                tracing::warn!(
                    "Unable to acquire lock for {}. Will try again on next iteration: {}",
                    Self::ITERATION_WORK_KEY,
                    e
                );
                return Ok(());
            }
        };

        let items = db
            .with_txn(|txn| {
                db::explored_endpoints::find_preingest_not_waiting_not_error(txn).boxed()
            })
            .await??;

        if !items.is_empty() && items.len() < 3 {
            // Show states if a modest amount, just count otherwise
            tracing::debug!(
                "PreingestionManager: Working on {} items {:?}",
                items.len(),
                items
                    .iter()
                    .map(|x| format!("({}: {:?})", x.address, x.preingestion_state))
                    .collect::<Vec<String>>()
            );
        } else {
            tracing::debug!("PreingestionManager: Working on {} items", items.len())
        }

        // Limit the number of concurrent preingestion tasks.
        // This does not affect how many endpoints are done in a single iteration, it just avoids opening
        // too many simultaneous postgres transactions, which can cause things to deadlock.
        let limit_sem = Arc::new(Semaphore::new(self.static_info.concurrency_limit));
        let mut task_set = JoinSet::new();

        for endpoint in items.into_iter() {
            let permit = limit_sem.clone().acquire_owned().await.unwrap();
            let static_info = self.static_info.clone();
            let db = db.clone();
            let _abort_handle = task_set
                .build_task()
                .name(&format!("preingestion {}", endpoint.address))
                .spawn(async move {
                    let _permit = permit; // retain semaphore until we're done
                    one_endpoint(&db, &endpoint, static_info).await
                });
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
                        tracing::warn!("Error handling preingestion update: {e}");
                    }
                },
                Err(e) => {
                    tracing::warn!("Error handling preingestion update: {e}");
                }
            }
        }

        let mut conn = db.acquire().await.map_err(DatabaseError::acquire)?;

        metrics.machines_in_preingestion =
            db::explored_endpoints::find_preingest_not_waiting_not_error(&mut conn)
                .await?
                .len();
        metrics.waiting_for_installation =
            db::explored_endpoints::find_preingest_installing(&mut conn)
                .await?
                .len();

        tracing::debug!(
            "Preingestion metrics: in_preingestion {} waiting {} delayed {}",
            metrics.machines_in_preingestion,
            metrics.waiting_for_installation,
            metrics.delayed_uploading,
        );
        self.metric_holder.update_metrics(metrics);

        Ok(())
    }
}

struct EndpointResult {
    delayed_upgrade: bool,
}

async fn one_endpoint(
    db: &PgPool,
    endpoint: &ExploredEndpoint,
    static_info: Arc<PreingestionManagerStatic>,
) -> CarbideResult<EndpointResult> {
    tracing::debug!("Preingestion on endpoint {:?}", endpoint);

    // Main state machine match.
    let delayed_upgrade = match &endpoint.preingestion_state {
        PreingestionState::Initial => {
            // Check BMC time sync first before proceeding with firmware checks
            match static_info.check_bmc_time_sync(db, endpoint).await {
                Ok(true) => {
                    // Time is in sync, proceed with firmware version check
                    static_info
                        .check_firmware_versions_below_preingestion(db, endpoint)
                        .await?
                }
                Ok(false) => {
                    // Time is not in sync, initiate reset sequence
                    tracing::warn!(
                        "{} BMC time is out of sync, initiating reset to fix time synchronization",
                        endpoint.address
                    );
                    static_info
                        .time_sync_resets(db, endpoint, &TimeSyncResetPhase::Start, None)
                        .await?
                }
                Err(e) => {
                    if let CarbideError::Internal { message } = e {
                        tracing::error!(
                            "{} internal error checking BMC time sync: {message}, failing preingestion",
                            endpoint.address
                        );
                        db.with_txn(|txn| {
                            db::explored_endpoints::set_preingestion_failed(
                                endpoint.address,
                                format!("Failed to check BMC time sync: {message}"),
                                txn,
                            )
                            .boxed()
                        })
                        .await??;
                    } else {
                        tracing::warn!(
                            "{} retryable error checking BMC time sync: {e}, will retry later",
                            endpoint.address
                        );
                    }
                    false
                }
            }
        }
        PreingestionState::RecheckVersionsAfterFailure { .. } => {
            static_info
                .start_firmware_uploads_or_continue(db, endpoint, true)
                .await?
        }
        PreingestionState::RecheckVersions => {
            static_info
                .start_firmware_uploads_or_continue(db, endpoint, true)
                .await?
        }
        PreingestionState::InitialReset { phase, last_time } => {
            static_info
                .pre_update_resets(db, endpoint, Some(phase), Some(last_time))
                .await?;
            false
        }
        PreingestionState::TimeSyncReset { phase, last_time } => {
            static_info
                .time_sync_resets(db, endpoint, phase, Some(last_time))
                .await?;
            false
        }
        PreingestionState::UpgradeFirmwareWait {
            task_id,
            final_version,
            upgrade_type,
            power_drains_needed,
            firmware_number,
        } => {
            static_info
                .in_upgrade_firmware_wait(
                    db,
                    &InUpgradeFirmwareWaitArgs {
                        endpoint,
                        task_id,
                        final_version,
                        upgrade_type,
                        power_drains_needed,
                        firmware_number: firmware_number.unwrap_or(0),
                    },
                )
                .await?;
            false
        }
        details @ PreingestionState::ResetForNewFirmware { .. } => {
            static_info
                .in_reset_for_new_firmware(db, endpoint, details)
                .await?;
            false
        }
        PreingestionState::NewFirmwareReportedWait {
            final_version,
            upgrade_type,
            previous_reset_time,
        } => {
            static_info
                .in_new_firmware_reported_wait(
                    db,
                    endpoint,
                    final_version,
                    upgrade_type,
                    previous_reset_time,
                )
                .await?;
            false
        }
        PreingestionState::ScriptRunning => {
            static_info.waiting_for_script(db, endpoint).await?;
            false
        }
        PreingestionState::Complete => {
            // This should have been filtered out by the query that got us this list.
            tracing::warn!(
                "Endpoint showed complete preingestion and should not have been here: {endpoint:?}"
            );
            false
        }
        PreingestionState::Failed { .. } => {
            // There was a serious failure, we never automatically leave this state and wait for a force delete
            false
        }
    };

    Ok(EndpointResult { delayed_upgrade })
}

impl PreingestionManagerStatic {
    /// find_fw_info_for_host looks up the firmware config for the given endpoint
    fn find_fw_info_for_host(&self, endpoint: &ExploredEndpoint) -> Option<Firmware> {
        let vendor = match &endpoint.report.vendor {
            Some(vendor) => vendor.to_owned(),
            None => {
                // No vendor found for the endpoint, we can't match firmware
                tracing::debug!("find_fw_info_for_host: {} No vendor", endpoint.address);
                return None;
            }
        };
        let model = endpoint.report.model()?;
        self.host_info.find(vendor, &model)
    }

    /// check_firmware_versions_below_preingestion will check if we actually need to do firmware upgrades before
    /// ingestion can happen, and either kick them off if so otherwise move on.
    async fn check_firmware_versions_below_preingestion(
        &self,
        db: &PgPool,
        endpoint: &ExploredEndpoint,
    ) -> CarbideResult<bool> {
        // First, we need to check if it's appropriate to upgrade at this point or wait until later.
        let fw_info = match self.find_fw_info_for_host(endpoint) {
            None => {
                tracing::debug!(
                    "check_firmware_versions_below_preingestion {}: No matching firmware info found",
                    endpoint.address
                );
                // No desired firmware description found for this host, nothing to do.
                // This is the expected path for DPUs.
                db.with_txn(|txn| {
                    db::explored_endpoints::set_preingestion_complete(endpoint.address, txn).boxed()
                })
                .await??;
                return Ok(false);
            }
            Some(fw_info) => fw_info,
        };
        for (fwtype, desc) in &fw_info.components {
            if let Some(min_preingestion) = &desc.preingest_upgrade_when_below
                && let Some(current) = endpoint.find_version(&fw_info, *fwtype)
            {
                tracing::info!(
                    "check_firmware_versions_below_preingestion {}: {fwtype:?} min preingestion {min_preingestion:?} current {current:?}",
                    endpoint.address
                );

                if version_compare::compare(current, min_preingestion)
                    .is_ok_and(|c| c == version_compare::Cmp::Lt)
                {
                    tracing::info!(
                        "check_firmware_versions_below_preingestion {}: Start upload of {fwtype:?}",
                        endpoint.address
                    );
                    // One or both of the versions are low enough to absolutely need upgrades first - do them both while we're at it.
                    let delayed_upgrade = self
                        .start_firmware_uploads_or_continue(db, endpoint, false)
                        .await?;
                    return Ok(delayed_upgrade);
                } else {
                    tracing::info!(
                        "check_firmware_versions_below_preingestion {}: {fwtype:?} is good",
                        endpoint.address
                    );
                }
            }
        }

        tracing::debug!(
            "check_firmware_versions_below_preingestion {}: Satisfied and marking complete",
            endpoint.address
        );
        // Good enough for now at least, proceed with ingestion.
        db.with_txn(|txn| {
            db::explored_endpoints::set_preingestion_complete(endpoint.address, txn).boxed()
        })
        .await??;
        Ok(false)
    }

    /// start_firmware_uploads_or_continue will start a firmware upgrade if any of the endpoint's versions
    /// do not match the desired version.  If they all match, it will continue on.  The upload must complete
    /// before we return; this means only one upload happens at a time, but we don't expect that doing multiples
    /// would make a significant difference, as we're limited by our own upload bandwidth.
    async fn start_firmware_uploads_or_continue(
        &self,
        db: &PgPool,
        endpoint: &ExploredEndpoint,
        repeat: bool,
    ) -> CarbideResult<bool> {
        if endpoint.waiting_for_explorer_refresh {
            tracing::debug!(
                "start_firmware_uploads_or_continue {}: Waiting for explorer refresh",
                endpoint.address
            );
            // We've updated something and are waiting for site explorer to get back around to it
            return Ok(false);
        }

        // Determine if auto updates should be enabled.
        // We can't check machine IDs here as they may not be available yet, so use the global value only.
        if !self.firmware_global.autoupdate {
            tracing::debug!(
                "start_firmware_uploads_or_continue {}: Auto updates disabled",
                endpoint.address
            );
            db.with_txn(|txn| {
                db::explored_endpoints::set_preingestion_complete(endpoint.address, txn).boxed()
            })
            .await??;
            return Ok(false);
        }

        let fw_info = match self.find_fw_info_for_host(endpoint) {
            None => {
                // No desired firmware description found for this host
                tracing::debug!(
                    "start_firmware_uploads_or_continue {}: No firmware info found",
                    endpoint.address
                );

                return Ok(false);
            }
            Some(fw_info) => fw_info,
        };

        // Specifying ordering is optional, and defaults to first BMC then UEFI.
        let mut ordering = fw_info.ordering().clone();
        if ordering.is_empty() {
            ordering.push(FirmwareComponentType::Bmc);
            ordering.push(FirmwareComponentType::Uefi);
        }
        for upgrade_type in ordering {
            let (done, delayed_upgrade) = self
                .start_upgrade_if_needed(db, endpoint, &fw_info, upgrade_type, repeat)
                .await?;

            if done {
                // We started something and need to wait now, or we had a valid reason not to start and will retry later.
                // In the former case only, the state has been updated.
                return Ok(delayed_upgrade);
            }
        }

        tracing::debug!(
            "start_firmware_uploads_or_continue {}: No further updates needed",
            endpoint.address
        );

        // Nothing needed to be updated, we're complete.
        db.with_txn(|txn| {
            db::explored_endpoints::set_preingestion_complete(endpoint.address, txn).boxed()
        })
        .await??;

        Ok(false)
    }

    /// First bool is true if started an upgrade, or for some other reason shouldn't check for updating other firmwares.  Second is if we delayed the update.
    async fn start_upgrade_if_needed(
        &self,
        db: &PgPool,
        endpoint: &ExploredEndpoint,
        fw_info: &Firmware,
        fw_type: FirmwareComponentType,
        repeat: bool,
    ) -> Result<(bool, bool), DatabaseError> {
        {
            match need_upgrade(endpoint, fw_info, fw_type) {
                None => {
                    tracing::debug!(
                        "start_upgrade_if_needed {}: Upgrade of {fw_type:?} not needed",
                        endpoint.address
                    );
                    Ok((false, false))
                }
                Some(to_install) => {
                    if to_install.script.is_some() {
                        self.by_script(db, endpoint.address, &to_install).await?;
                        return Ok((true, false));
                    }
                    let Ok(_active) = self.upload_limiter.try_acquire() else {
                        tracing::debug!(
                            "Deferring installation of {:?} on {}, too many uploads already active",
                            to_install,
                            endpoint.address
                        );
                        return Ok((true, true)); // Don't check others
                    };

                    if !repeat && to_install.pre_update_resets {
                        self.pre_update_resets(db, endpoint, None, None).await?;
                        return Ok((true, false));
                    }

                    tracing::info!("Installing {:?} on {}", to_install, endpoint.address);

                    initiate_update(
                        endpoint,
                        &self.redfish_client_pool,
                        &to_install,
                        &fw_type,
                        &self.downloader,
                        0,
                        db,
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
        db: &PgPool,
        args: &InUpgradeFirmwareWaitArgs<'_>,
    ) -> CarbideResult<()> {
        let (endpoint, task_id, final_version, upgrade_type, power_drains_needed, firmware_number) = (
            args.endpoint,
            args.task_id,
            args.final_version,
            args.upgrade_type,
            args.power_drains_needed,
            args.firmware_number,
        );

        let redfish_client = match self
            .redfish_client_pool
            .create_client_for_ingested_host(endpoint.address, None, db)
            .await
            .map_err(|e| match e {
                RedfishClientCreationError::RedfishError(e) => CarbideError::RedfishError(e),
                _ => CarbideError::internal(format!("{e}")),
            }) {
            Ok(redfish_client) => redfish_client,
            Err(e) => {
                tracing::warn!("Redfish connection to {} failed: {e}", endpoint.address);
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
                        tracing::debug!(
                            "Upgrade task for {} not yet complete, current state {:?} message {:?}",
                            endpoint.address,
                            task_info.task_state,
                            task_info.messages,
                        );
                    }
                    Some(TaskState::Completed) => {
                        // Task has completed, update is done and we can clean up.  Site explorer will ingest this next time it runs on this endpoint.

                        // If we have multiple firmware files to be uploaded, do the next one.
                        if let Some(fw_info) = self.find_fw_info_for_host(endpoint)
                            && let Some(component_info) = fw_info.components.get(upgrade_type)
                            && let Some(selected_firmware) =
                                component_info.known_firmware.iter().find(|&x| x.default)
                        {
                            let firmware_number = firmware_number + 1;
                            if firmware_number
                                < selected_firmware.filenames.len().try_into().unwrap_or(0)
                            {
                                tracing::info!(
                                    "Installing {:?} chain step {} on {}",
                                    selected_firmware,
                                    firmware_number,
                                    endpoint.address
                                );

                                initiate_update(
                                    endpoint,
                                    &self.redfish_client_pool,
                                    selected_firmware,
                                    upgrade_type,
                                    &self.downloader,
                                    firmware_number,
                                    db,
                                )
                                .await?;
                                return Ok(());
                            }
                        }
                        tracing::info!(
                            "Marking completion of Redfish task of firmware upgrade for {}",
                            &endpoint.address
                        );
                        db.with_txn(|txn| {
                            db::explored_endpoints::set_preingestion_reset_for_new_firmware(
                                endpoint.address,
                                final_version,
                                upgrade_type,
                                *power_drains_needed,
                                None,
                                None,
                                txn,
                            )
                            .boxed()
                        })
                        .await??;
                        // Can immediately process as that new state
                        return self
                            .in_reset_for_new_firmware(
                                db,
                                endpoint,
                                &PreingestionState::ResetForNewFirmware {
                                    final_version: final_version.to_string(),
                                    upgrade_type: *upgrade_type,
                                    power_drains_needed: *power_drains_needed,
                                    delay_until: None,
                                    last_power_drain_operation: None,
                                },
                            )
                            .await;
                    }
                    Some(TaskState::Exception)
                    | Some(TaskState::Interrupted)
                    | Some(TaskState::Killed)
                    | Some(TaskState::Cancelled) => {
                        let msg = format!(
                            "Failure in firmware upgrade for {}: {} {:?}",
                            &endpoint.address,
                            task_info.task_state.unwrap_or(TaskState::Killed),
                            task_info
                                .messages
                                .last()
                                .map_or(String::new(), |m| m.message.clone())
                        );
                        tracing::warn!(msg);

                        db.with_txn(|txn| {
                            async move {
                                // Wait for site explorer to refresh it then try again after that.
                                // Someday, we should generate metrics for visiblity if something fails multiple times.
                                db::explored_endpoints::set_preingestion_recheck_versions_reason(
                                    endpoint.address,
                                    msg,
                                    txn,
                                )
                                .await?;
                                db::explored_endpoints::re_explore_if_version_matches(
                                    endpoint.address,
                                    endpoint.report_version,
                                    txn,
                                )
                                .await?;

                                // We need site explorer to requery the version
                                db::explored_endpoints::set_waiting_for_explorer_refresh(
                                    endpoint.address,
                                    txn,
                                )
                                .await?;
                                Ok::<_, DatabaseError>(())
                            }
                            .boxed()
                        })
                        .await??;
                    }
                    _ => {
                        // Unexpected state
                        tracing::warn!(
                            "Unrecognized task state for {}: {:?}",
                            endpoint.address,
                            task_info.task_state
                        );
                    }
                };
            }
            Err(e) => match e {
                RedfishError::HTTPErrorCode { status_code, .. } => {
                    if status_code == NOT_FOUND {
                        // Dells (maybe others) have been observed to not have report the job any more after completing a host reboot for a UEFI upgrade.  If we get a 404 but see that we're at the right version, we're done with that upgrade.
                        if let Some(fw_info) = self.find_fw_info_for_host(endpoint)
                            && let Some(current_version) =
                                endpoint.find_version(&fw_info, *upgrade_type)
                            && current_version == final_version
                        {
                            tracing::debug!(
                                "Marking completion of Redfish task of firmware upgrade for {} with missing task",
                                &endpoint.address
                            );
                            db.with_txn(|txn| {
                                db::explored_endpoints::set_preingestion_recheck_versions(
                                    endpoint.address,
                                    txn,
                                )
                                .boxed()
                            })
                            .await??;
                        }
                    }
                }
                _ => {
                    tracing::warn!("Getting Redfish task from {} failed: {e}", endpoint.address);
                }
            },
        };
        Ok(())
    }

    async fn in_reset_for_new_firmware(
        &self,
        db: &PgPool,
        endpoint: &ExploredEndpoint,
        state: &PreingestionState,
    ) -> CarbideResult<()> {
        let (
            final_version,
            upgrade_type,
            power_drains_needed,
            delay_until,
            last_power_drain_operation,
        ) = match state {
            PreingestionState::ResetForNewFirmware {
                final_version,
                upgrade_type,
                power_drains_needed,
                delay_until,
                last_power_drain_operation,
            } => (
                final_version,
                upgrade_type,
                power_drains_needed,
                delay_until,
                last_power_drain_operation,
            ),
            _ => {
                return Err(CarbideError::InvalidArgument(
                    "Wrong enum in_reset_for_new_firmware".to_string(),
                ));
            }
        };

        let redfish_client = match self
            .redfish_client_pool
            .create_client_for_ingested_host(endpoint.address, None, db)
            .await
            .map_err(|e| match e {
                RedfishClientCreationError::RedfishError(e) => CarbideError::RedfishError(e),
                _ => CarbideError::internal(format!("{e}")),
            }) {
            Ok(redfish_client) => redfish_client,
            Err(e) => {
                tracing::error!("Redfish connection to {} failed: {e}", endpoint.address);
                return Ok(());
            }
        };

        let mut need_wait = false;
        // Still not reporting the new version.
        // If this is the UEFI, we need to request a reboot.  Otherwise, we just need to keep waiting.
        // The version reported doesn't update until the end of the UEFI portion of the boot, which can be quite a long wait.

        if let Some(power_drains_needed) = power_drains_needed {
            if let Some(delay_until) = delay_until
                && *delay_until > chrono::Utc::now().timestamp()
            {
                tracing::info!(
                    "Waiting after {last_power_drain_operation:?} of {}",
                    &endpoint.address
                );
                return Ok(());
            }

            match last_power_drain_operation {
                None | Some(PowerDrainState::On) => {
                    // The 1000 is for unit tests; values above this will skip delays.
                    if *power_drains_needed == 0 || *power_drains_needed == 1000 {
                        tracing::info!("Power drains for {} done", &endpoint.address);
                        // This path, and only this path of the match, exits the match and lets us proceed.  All others should return after updating state.
                        need_wait = false; // We've reset multiple times already and should be reporting the new version
                    } else {
                        tracing::info!(
                            "Upgrade task has completed for {} but needs {} power drain(s), initiating one",
                            &endpoint.address,
                            *power_drains_needed
                        );
                        if let Err(e) = redfish_client.power(SystemPowerControl::ForceOff).await {
                            tracing::error!("Failed to power off {}: {e}", &endpoint.address);
                            return Ok(());
                        }

                        // Wait 60 seconds after powering off to do AC powercycle
                        let delay = if *power_drains_needed < 1000 {
                            time::Duration::seconds(60)
                        } else {
                            time::Duration::seconds(0)
                        };
                        db.with_txn(|txn| {
                            db::explored_endpoints::set_preingestion_reset_for_new_firmware(
                                endpoint.address,
                                final_version,
                                upgrade_type,
                                Some(*power_drains_needed),
                                Some(delay),
                                Some(PowerDrainState::Off),
                                txn,
                            )
                            .boxed()
                        })
                        .await??;
                        return Ok(());
                    }
                }
                Some(PowerDrainState::Off) => {
                    if endpoint.report.vendor.unwrap_or_default().is_lenovo() {
                        tracing::info!("Doing powercycle now for {}", &endpoint.address);
                        if let Err(e) = redfish_client.power(SystemPowerControl::ACPowercycle).await
                        {
                            tracing::error!("Failed to power cycle {}: {e}", &endpoint.address);
                            return Ok(());
                        }
                    }
                    let delay = if *power_drains_needed < 1000 {
                        time::Duration::seconds(90)
                    } else {
                        time::Duration::seconds(0)
                    };
                    db.with_txn(|txn| {
                        db::explored_endpoints::set_preingestion_reset_for_new_firmware(
                            endpoint.address,
                            final_version,
                            upgrade_type,
                            Some(*power_drains_needed),
                            Some(delay),
                            Some(PowerDrainState::Powercycle),
                            txn,
                        )
                        .boxed()
                    })
                    .await??;
                    return Ok(());
                }
                Some(PowerDrainState::Powercycle) => {
                    tracing::info!("Turning back on {}", &endpoint.address);
                    if let Err(e) = redfish_client.power(SystemPowerControl::On).await {
                        tracing::error!("Failed to power on {}: {e}", &endpoint.address);
                        return Ok(());
                    }
                    let delay = if *power_drains_needed < 1000 {
                        time::Duration::seconds(5)
                    } else {
                        time::Duration::seconds(0)
                    };
                    db.with_txn(|txn| {
                        db::explored_endpoints::set_preingestion_reset_for_new_firmware(
                            endpoint.address,
                            final_version,
                            upgrade_type,
                            Some(*power_drains_needed - 1),
                            Some(delay),
                            Some(PowerDrainState::On),
                            txn,
                        )
                        .boxed()
                    })
                    .await??;
                    return Ok(());
                }
            };
        } else if upgrade_type.is_uefi() {
            tracing::info!(
                "Upgrade task has completed for {} but needs reboot, initiating one",
                &endpoint.address
            );
            if let Err(e) = redfish_client.power(SystemPowerControl::ForceRestart).await {
                tracing::error!("Failed to reboot {}: {e}", &endpoint.address);
                return Ok(());
            }
            db.with_txn(|txn| {
                db::explored_endpoints::set_preingestion_new_reported_wait(
                    endpoint.address,
                    final_version,
                    upgrade_type,
                    txn,
                )
                .boxed()
            })
            .await??;

            need_wait = true;
        }
        // Lenovo and Nvidia DPU BMC needs to be manually reset after the update
        let bmc_vendor = endpoint
            .report
            .vendor
            .unwrap_or(bmc_vendor::BMCVendor::Unknown);
        if upgrade_type.is_bmc() && (bmc_vendor.is_lenovo() || bmc_vendor.is_nvidia()) {
            tracing::info!(
                "Upgrade task has completed for {} but needs BMC reboot, initiating one",
                &endpoint.address
            );
            if let Err(e) = redfish_client.bmc_reset().await {
                tracing::error!("Failed to reboot {}: {e}", &endpoint.address);
                return Ok(());
            }
            db.with_txn(|txn| {
                db::explored_endpoints::set_preingestion_new_reported_wait(
                    endpoint.address,
                    final_version,
                    upgrade_type,
                    txn,
                )
                .boxed()
            })
            .await??;
            // Will not be reporting the new version yet, we need to wait.
            need_wait = true;
        }
        if *upgrade_type == FirmwareComponentType::HGXBmc
            || *upgrade_type == FirmwareComponentType::Gpu
        {
            // Needs a host power reset
            // DGX models only had an "off", GB200 (and presumably later ones) has an actual AC powercycle.
            let poweroff_style = if redfish_client.ac_powercycle_supported_by_power() {
                SystemPowerControl::ACPowercycle
            } else {
                SystemPowerControl::ForceOff
            };
            if let Err(e) = redfish_client.power(poweroff_style).await {
                tracing::error!("Failed to power off {}: {e}", &endpoint.address);
                return Ok(());
            }
            tokio::time::sleep(self.hgx_bmc_gpu_reboot_delay).await;
            if let Err(e) = redfish_client.power(SystemPowerControl::On).await {
                tracing::error!("Failed to power on {}: {e}", &endpoint.address);
                return Ok(());
            }
            // Does not need a wait
        }

        if need_wait {
            db.with_txn(|txn| {
                db::explored_endpoints::set_waiting_for_explorer_refresh(endpoint.address, txn)
                    .boxed()
            })
            .await??;
            return Ok(());
        } else if *upgrade_type == FirmwareComponentType::Cec {
            match redfish_client
                .chassis_reset("Bluefield_ERoT", SystemPowerControl::GracefulRestart)
                .await
            {
                Ok(()) => {}
                Err(e) if e.to_string().contains("is not supported") => {
                    tracing::error!(
                        "Chassis reset is not supported by current CEC FW. Need to do host power cycle! BMC IP: {}",
                        endpoint.address
                    );
                }
                Err(e) => {
                    tracing::error!("Failed to call chassis_reset: {e}");
                }
            }
        }
        // No need for resets or reboots, go right to waiting for the new version to show up, and we might as well check right away.
        db.with_txn(|txn| {
            db::explored_endpoints::set_preingestion_new_reported_wait(
                endpoint.address,
                final_version,
                upgrade_type,
                txn,
            )
            .boxed()
        })
        .await??;

        self.in_new_firmware_reported_wait(db, endpoint, final_version, upgrade_type, &None)
            .await
    }

    async fn in_new_firmware_reported_wait(
        &self,
        db: &PgPool,
        endpoint: &ExploredEndpoint,
        final_version: &str,
        upgrade_type: &FirmwareComponentType,
        previous_reset_time: &Option<i64>,
    ) -> CarbideResult<()> {
        if let Some(fw_info) = self.find_fw_info_for_host(endpoint) {
            if let Some(current_version) = endpoint.find_version(&fw_info, *upgrade_type) {
                if current_version != final_version {
                    // Still not reporting the new version.
                    if !self.firmware_global.no_reset_retries
                        && let Some(previous_reset_time) = previous_reset_time
                        && previous_reset_time + 30 * 60 <= Utc::now().timestamp()
                    {
                        tracing::info!(
                            "Upgrade for {} {:?} has taken more than 30 minutes to report new version; resetting again.",
                            &endpoint.address,
                            upgrade_type
                        );
                        let state = &PreingestionState::ResetForNewFirmware {
                            final_version: final_version.to_string(),
                            upgrade_type: *upgrade_type,
                            power_drains_needed: None,
                            delay_until: None,
                            last_power_drain_operation: None,
                        };
                        return Box::pin(self.in_reset_for_new_firmware(db, endpoint, state)).await;
                    }
                    db.with_txn(|txn| {
                        db::explored_endpoints::set_waiting_for_explorer_refresh(
                            endpoint.address,
                            txn,
                        )
                        .boxed()
                    })
                    .await??;
                    tracing::info!(
                        "Upgrade {} task has completed for {} but still reports version {current_version} (expected version: {final_version})",
                        upgrade_type,
                        &endpoint.address
                    );
                    return Ok(());
                }
                tracing::info!(
                    "Upgrade for {} now reports version {current_version}",
                    &endpoint.address
                );
            } else {
                // This path should only happen if something strange happened with the version definitions
                tracing::error!(
                    "in_upgrade_firmware_wait: Could not find current version {} {:?} {:?}",
                    &endpoint.address,
                    fw_info,
                    *upgrade_type
                );
                // Make sure we wait for the new version
                db.with_txn(|txn| {
                    db::explored_endpoints::set_waiting_for_explorer_refresh(endpoint.address, txn)
                        .boxed()
                })
                .await??;
            }
        } else {
            // This path should only happen if something strange happened with the version definitions
            tracing::error!(
                "in_upgrade_firmware_wait: Could not find fw_info {} {:?} {:?}",
                &endpoint.address,
                endpoint.report.vendor,
                endpoint.report.systems
            );
            // Make sure we wait for the new version
            db.with_txn(|txn| {
                db::explored_endpoints::set_waiting_for_explorer_refresh(endpoint.address, txn)
                    .boxed()
            })
            .await??;
        }

        // Go back to checking versions as there may be other things that need upgrading
        db.with_txn(|txn| {
            db::explored_endpoints::set_preingestion_recheck_versions(endpoint.address, txn).boxed()
        })
        .await??;

        Ok(())
    }

    /// Helper: Execute power off and BMC reset sequence
    /// Returns true if successful, false if any step failed
    async fn execute_power_off_and_bmc_reset(
        &self,
        redfish_client: &dyn libredfish::Redfish,
        endpoint: &ExploredEndpoint,
    ) -> bool {
        match redfish_client.power(SystemPowerControl::ForceOff).await {
            Ok(()) => {}
            Err(e) if matches!(e, RedfishError::UnnecessaryOperation) => {
                // ignore because it is already off
                tracing::debug!("Power off not needed on {}: {e}", endpoint.address);
            }
            Err(e) => {
                tracing::warn!("Could not turn off power on {}: {e}", endpoint.address);
                return false;
            }
        }

        let status = match redfish_client.get_power_state().await {
            Ok(status) => status,
            Err(e) => {
                tracing::warn!("Could not get power of {}: {e}", endpoint.address);
                return false;
            }
        };
        if status != PowerState::Off {
            tracing::warn!("Host {} did not turn off when requested", endpoint.address);
            return false;
        }
        if let Err(e) = redfish_client.bmc_reset().await {
            tracing::warn!("Could not reset BMC on {}: {e}", endpoint.address);
            return false;
        }
        true
    }

    /// Helper: Wait for BMC reset and power on the host
    /// Returns true if successful, false if any step failed
    async fn execute_wait_bmc_and_power_on(
        &self,
        redfish_client: &dyn libredfish::Redfish,
        endpoint: &ExploredEndpoint,
    ) -> bool {
        if let Err(e) = redfish_client.get_tasks().await {
            tracing::info!(
                "Waiting for {} BMC reset to complete: {e}",
                endpoint.address
            );
            return false;
        }

        match redfish_client.power(SystemPowerControl::On).await {
            Ok(()) => {}
            Err(e) if matches!(e, RedfishError::UnnecessaryOperation) => {
                // ignore because it is already on
                tracing::debug!("Power on not needed on {}: {e}", endpoint.address);
            }
            Err(e) => {
                tracing::warn!("Could not turn on power on {}: {e}", endpoint.address);
                return false;
            }
        }

        let status = match redfish_client.get_power_state().await {
            Ok(status) => status,
            Err(e) => {
                tracing::warn!("Could not get power of {}: {e}", endpoint.address);
                return false;
            }
        };
        if status != PowerState::On {
            tracing::warn!("Host {} did not turn on when requested", endpoint.address);
            return false;
        }
        true
    }

    /// Helper: Check if we should proceed after the boot wait period
    /// Returns true if 20 minutes have elapsed, false otherwise
    fn should_proceed_after_boot_wait(
        &self,
        last_time: Option<&DateTime<Utc>>,
        endpoint: &ExploredEndpoint,
    ) -> bool {
        if Utc::now().signed_duration_since(last_time.unwrap_or(&Utc::now()))
            < chrono::TimeDelta::minutes(20)
        {
            tracing::trace!("Waiting for {} to complete boot sequence", endpoint.address);
            return false;
        }
        true
    }

    async fn pre_update_resets(
        &self,
        db: &PgPool,
        endpoint: &ExploredEndpoint,
        phase: Option<&InitialResetPhase>,
        last_time: Option<&DateTime<Utc>>,
    ) -> Result<(), DatabaseError> {
        let redfish_client = match self
            .redfish_client_pool
            .create_client_for_ingested_host(endpoint.address, None, db)
            .await
        {
            Ok(redfish_client) => redfish_client,
            Err(e) => {
                tracing::warn!("Redfish connection to {} failed: {e}", endpoint.address);
                return Ok(());
            }
        };

        match phase.unwrap_or(&InitialResetPhase::Start) {
            InitialResetPhase::Start => {
                if !self
                    .execute_power_off_and_bmc_reset(redfish_client.as_ref(), endpoint)
                    .await
                {
                    return Ok(());
                }
                tracing::info!("{} initial reset BMC reset intiated", endpoint.address);
                db.with_txn(|txn| {
                    db::explored_endpoints::set_preingestion_initial_reset(
                        endpoint.address,
                        InitialResetPhase::BMCWasReset,
                        txn,
                    )
                    .boxed()
                })
                .await??;
                Ok(())
            }
            InitialResetPhase::BMCWasReset => {
                if !self
                    .execute_wait_bmc_and_power_on(redfish_client.as_ref(), endpoint)
                    .await
                {
                    return Ok(());
                }
                tracing::info!(
                    "{} initial reset BMC reset complete, started host reset",
                    endpoint.address
                );
                db.with_txn(|txn| {
                    db::explored_endpoints::set_preingestion_initial_reset(
                        endpoint.address,
                        InitialResetPhase::WaitHostBoot,
                        txn,
                    )
                    .boxed()
                })
                .await??;
                Ok(())
            }
            InitialResetPhase::WaitHostBoot => {
                if !self.should_proceed_after_boot_wait(last_time, endpoint) {
                    return Ok(());
                }
                // Now we can actually proceed with the upgrade.  Go back to checking firmware so we don't have to store all of that info.
                tracing::info!("{} initial reset complete", endpoint.address);
                db.with_txn(|txn| {
                    db::explored_endpoints::set_preingestion_recheck_versions(endpoint.address, txn)
                        .boxed()
                })
                .await??;
                Ok(())
            }
        }
    }

    async fn time_sync_resets(
        &self,
        db: &PgPool,
        endpoint: &ExploredEndpoint,
        phase: &TimeSyncResetPhase,
        last_time: Option<&DateTime<Utc>>,
    ) -> CarbideResult<bool> {
        let redfish_client = match self
            .redfish_client_pool
            .create_client_for_ingested_host(endpoint.address, None, db)
            .await
        {
            Ok(redfish_client) => redfish_client,
            Err(e) => {
                tracing::warn!("Redfish connection to {} failed: {e}", endpoint.address);
                return Ok(false);
            }
        };

        match phase {
            TimeSyncResetPhase::Start => {
                if let Err(e) = redfish_client.set_utc_timezone().await {
                    tracing::error!("Could not set UTC timezone on {}: {e}", endpoint.address);
                    return Err(CarbideError::RedfishError(e));
                }
                if !self
                    .execute_power_off_and_bmc_reset(redfish_client.as_ref(), endpoint)
                    .await
                {
                    return Ok(false);
                }
                tracing::info!("{} time sync reset BMC reset initiated", endpoint.address);
                db.with_txn(|txn| {
                    db::explored_endpoints::set_preingestion_time_sync_reset(
                        endpoint.address,
                        TimeSyncResetPhase::BMCWasReset,
                        txn,
                    )
                    .boxed()
                })
                .await??;
                Ok(false)
            }
            TimeSyncResetPhase::BMCWasReset => {
                if !self
                    .execute_wait_bmc_and_power_on(redfish_client.as_ref(), endpoint)
                    .await
                {
                    return Ok(false);
                }
                tracing::info!(
                    "{} time sync reset BMC reset complete, started host reset",
                    endpoint.address
                );
                db.with_txn(|txn| {
                    db::explored_endpoints::set_preingestion_time_sync_reset(
                        endpoint.address,
                        TimeSyncResetPhase::WaitHostBoot,
                        txn,
                    )
                    .boxed()
                })
                .await??;
                Ok(false)
            }
            TimeSyncResetPhase::WaitHostBoot => {
                if !self.should_proceed_after_boot_wait(last_time, endpoint) {
                    return Ok(false);
                }

                // Host has booted, now check time sync again
                tracing::info!(
                    "{} time sync reset complete, checking time sync",
                    endpoint.address
                );

                match self.check_bmc_time_sync(db, endpoint).await {
                    Ok(true) => {
                        // Time is now in sync, proceed with firmware check
                        tracing::info!("{} BMC time is now in sync after reset", endpoint.address);
                        let delayed_upgrade = self
                            .check_firmware_versions_below_preingestion(db, endpoint)
                            .await?;
                        Ok(delayed_upgrade)
                    }
                    Ok(false) => {
                        // Time is still not in sync after reset, fail now
                        tracing::error!(
                            "{} BMC time is still out of sync after reset attempt, failing preingestion",
                            endpoint.address
                        );
                        db.with_txn(|txn| {
                            db::explored_endpoints::set_preingestion_failed(
                                endpoint.address,
                                "BMC time synchronization failed after reset attempt. Time difference exceeds 5 minutes threshold.".to_string(),
                                txn,
                            )
                            .boxed()
                        })
                        .await??;
                        Ok(false)
                    }
                    Err(e) => {
                        if let CarbideError::Internal { message } = e {
                            // Error checking time sync after reset, fail now
                            tracing::error!(
                                "{} internal error checking BMC time sync after reset: {message}, failing preingestion",
                                endpoint.address
                            );
                            db.with_txn(|txn| {
                                db::explored_endpoints::set_preingestion_failed(
                                    endpoint.address,
                                    format!("Failed to check BMC time sync after reset: {message}"),
                                    txn,
                                )
                                .boxed()
                            })
                            .await??;
                        } else {
                            tracing::warn!(
                                "{} retryable error checking BMC time sync after reset: {e}, will retry later",
                                endpoint.address
                            );
                        }
                        Ok(false)
                    }
                }
            }
        }
    }

    async fn by_script(
        &self,
        db: &PgPool,
        endpoint_address: std::net::IpAddr,
        to_install: &FirmwareEntry,
    ) -> Result<(), DatabaseError> {
        self.upgrade_script_state
            .started(endpoint_address.to_string());

        let address = endpoint_address.to_string();
        let script = to_install.script.clone().unwrap_or("/bin/false".into()); // Should always be Some at this point
        let upgrade_script_state = self.upgrade_script_state.clone();
        let (username, password) = if let Some(credential_provider) = &self.credential_provider {
            // We need to backtrack from the IP address to get the MAC address, which is what the credentials database is keyed on
            let interface = db
                .with_txn(|txn| db::machine_interface::find_by_ip(txn, endpoint_address).boxed())
                .await??;
            let Some(interface) = interface else {
                tracing::warn!(
                    "Unable to run update script for {address}: MAC address not retrievable"
                );
                return Ok(());
            };

            let key = CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcRoot {
                    bmc_mac_address: interface.mac_address,
                },
            };
            match credential_provider.get_credentials(&key).await {
                Ok(Some(credentials)) => match credentials {
                    Credentials::UsernamePassword { username, password } => (username, password),
                },
                Ok(None) => {
                    tracing::warn!(
                        "Unable to run update script for {address}: No credentials exists"
                    );
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        "Unable to run update script for {address}: Unable to retrieve credentials due to error: {e}"
                    );
                    return Ok(());
                }
            }
        } else {
            ("Unknown".to_string(), "Unknown".to_string())
        };
        tokio::spawn(async move {
            let mut cmd = match tokio::process::Command::new(script)
                .env("BMC_IP", address.clone())
                .env("BMC_USERNAME", username)
                .env("BMC_PASSWORD", password)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(cmd) => cmd,
                Err(e) => {
                    tracing::error!("Upgrade script {address} command creation failed: {e}");
                    upgrade_script_state.completed(address, false);
                    return;
                }
            };

            let Some(stdout) = cmd.stdout.take() else {
                tracing::error!("Upgrade script {address} STDOUT creation failed");
                let _ = cmd.kill().await;
                let _ = cmd.wait().await;
                upgrade_script_state.completed(address, false);
                return;
            };
            let stdout = tokio::io::BufReader::new(stdout);

            let Some(stderr) = cmd.stderr.take() else {
                tracing::error!("Upgrade script {address} STDERR creation failed");
                let _ = cmd.kill().await;
                let _ = cmd.wait().await;
                upgrade_script_state.completed(address, false);
                return;
            };
            let stderr = tokio::io::BufReader::new(stderr);

            // Take the stdout and stderr from the script and write them to a log with a searchable prefix
            let address2 = address.clone();
            let thread = tokio::spawn(async move {
                let mut lines = stderr.lines();
                while let Some(line) = lines.next_line().await.unwrap_or(None) {
                    tracing::info!("Upgrade script {address2} STDERR {line}");
                }
            });
            let mut lines = stdout.lines();
            while let Some(line) = lines.next_line().await.unwrap_or(None) {
                tracing::info!("Upgrade script {address} {line}");
            }
            let _ = tokio::join!(thread);

            match cmd.wait().await {
                Err(e) => {
                    tracing::info!("Upgrade script {address} FAILED: Wait failure {e}");
                    upgrade_script_state.completed(address, false);
                }
                Ok(errorcode) => {
                    if errorcode.success() {
                        tracing::info!("Upgrade script {address} completed successfully");
                        upgrade_script_state.completed(address, true);
                    } else {
                        tracing::warn!("Upgrade script {address} FAILED: Exited with {errorcode}");
                        upgrade_script_state.completed(address, false);
                    }
                }
            }
        });

        db.with_txn(|txn| {
            db::explored_endpoints::set_preingestion_script_running(endpoint_address, txn).boxed()
        })
        .await??;
        Ok(())
    }

    async fn waiting_for_script(
        &self,
        db: &PgPool,
        endpoint: &ExploredEndpoint,
    ) -> Result<(), DatabaseError> {
        db.with_txn(|txn| async move {
            let address = endpoint.address.to_string();
            let Some(success) = self.upgrade_script_state.state(&address) else {
                // Not yet completed, or we restarted (which specifically needs a manual restart of interrupted scripts)
                return Ok(());
            };

            self.upgrade_script_state.clear(&address);

            if success {
                db::explored_endpoints::set_preingestion_recheck_versions(endpoint.address, txn)
                    .await?;
                Ok(())
            } else {
                db::explored_endpoints::set_preingestion_failed(endpoint.address,format!(
                    "The upgrade script failed.  Search the log for \"Upgrade script {}\" for script output.  Force delete the explored endpoint to retry.",
                    endpoint.address
                ), txn).await?;
                Ok(())
            }
        }.boxed()).await?
    }

    /// check_bmc_time_sync checks if the BMC's system time is synchronized with the local system time.
    /// Returns true if the time difference is within the acceptable NTP drift threshold (5 minutes),
    /// false otherwise.
    async fn check_bmc_time_sync(
        &self,
        db: &PgPool,
        endpoint: &ExploredEndpoint,
    ) -> CarbideResult<bool> {
        tracing::debug!("Checking BMC time sync for {:?}", endpoint);
        let redfish_client = match self
            .redfish_client_pool
            .create_client_for_ingested_host(endpoint.address, None, db)
            .await
            .map_err(|e| match e {
                RedfishClientCreationError::RedfishError(e) => CarbideError::RedfishError(e),
                _ => CarbideError::internal(format!("{e}")),
            }) {
            Ok(redfish_client) => redfish_client,
            Err(e) => {
                return Err(e);
            }
        };

        // Get the manager's DateTime from Redfish
        let bmc_time = match redfish_client
            .get_manager()
            .await
            .map_err(CarbideError::RedfishError)?
            .date_time
        {
            Some(time) => time,
            None => {
                return Err(CarbideError::internal("Failed to get BMC time".to_string()));
            }
        };

        let system_time = Utc::now();
        let time_diff = (system_time - bmc_time).num_seconds().abs();

        // Reasonable NTP drift threshold: 5 minutes (300 seconds)
        const NTP_DRIFT_THRESHOLD_SECONDS: i64 = 300;

        if time_diff > NTP_DRIFT_THRESHOLD_SECONDS {
            tracing::warn!(
                "BMC time for {} is out of sync: BMC time: {}, System time: {}, Difference: {} seconds",
                endpoint.address,
                bmc_time,
                system_time,
                time_diff
            );
            Ok(false)
        } else {
            tracing::debug!(
                "BMC time for {} is in sync: difference {} seconds",
                endpoint.address,
                time_diff
            );
            Ok(true)
        }
    }
}

#[derive(Debug, Default)]
struct UpdateScriptManager {
    active: std::sync::Mutex<HashMap<String, Option<bool>>>,
}

impl UpdateScriptManager {
    fn started(&self, id: String) {
        let mut hashmap = self.active.lock().expect("lock poisoned");
        hashmap.insert(id, None);
    }

    fn completed(&self, id: String, success: bool) {
        let mut hashmap = self.active.lock().expect("lock poisoned");
        hashmap.insert(id, Some(success));
    }

    fn clear(&self, id: &String) {
        let mut hashmap = self.active.lock().expect("lock poisoned");
        hashmap.remove(id);
    }

    fn state(&self, id: &String) -> Option<bool> {
        let hashmap = self.active.lock().expect("lock poisoned");
        *hashmap.get(id).unwrap_or(&None)
    }
}

struct InUpgradeFirmwareWaitArgs<'a> {
    endpoint: &'a ExploredEndpoint,
    task_id: &'a str,
    final_version: &'a str,
    upgrade_type: &'a FirmwareComponentType,
    power_drains_needed: &'a Option<u32>,
    firmware_number: u32,
}

/// need_upgrade determines if the given endpoint needs a firmware upgrade based on the description in fw_info, and if
/// so returns the FirmwareEntry matching the desired upgrade along with the ID that Redfish uses to specify its version.
fn need_upgrade(
    endpoint: &ExploredEndpoint,
    fw_info: &Firmware,
    firmware_type: FirmwareComponentType,
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
        .find(|x| (x.default || x.preingestion_exclusive_config) && x.version != current_version)
        .cloned()
}

/// initiate_update will start a Redfish connection to the given address and start an update
/// by doing an upload.  It may be unable to start it if the firmware has not been previously
/// downloaded; if that happens it also returns success, but has not modified the state.  On Redfish
///  errors, we return Ok but leave the state as it was, with the intention that we will retry
///  on the next go.
async fn initiate_update(
    endpoint_clone: &ExploredEndpoint,
    redfish_client_pool: &Arc<dyn RedfishClientPool>,
    to_install: &FirmwareEntry,
    firmware_type: &FirmwareComponentType,
    downloader: &FirmwareDownloader,
    firmware_number: u32,
    db_pool: &PgPool,
) -> Result<(), DatabaseError> {
    if !to_install.get_filename(firmware_number).ends_with("bfb")
        && !downloader.available(
            &to_install.get_filename(firmware_number),
            &to_install.get_url(),
            &to_install.get_checksum(),
        )
    {
        tracing::debug!(
            "{} is being downloaded from {}, update deferred",
            to_install.get_filename(firmware_number).display(),
            to_install.get_url()
        );

        return Ok(());
    }

    // Setup the Redfish connection
    let redfish_client = match redfish_client_pool
        .create_client_for_ingested_host(endpoint_clone.address, None, db_pool)
        .await
    {
        Ok(redfish_client) => redfish_client,
        Err(e) => {
            tracing::debug!(
                "Failed to open redfish to {}: {e}",
                endpoint_clone.address.to_string()
            );
            return Ok(());
        }
    };

    tracing::debug!(
        "initiate_update: Started upload of firmware to {}",
        endpoint_clone.address
    );
    let redfish_component_type: libredfish::model::update_service::ComponentType =
        match to_install.install_only_specified {
            false => libredfish::model::update_service::ComponentType::Unknown,
            true => (*firmware_type).into(),
        };
    let task = if to_install.get_filename(firmware_number).ends_with("bfb") {
        let _ = redfish_client
            .enable_rshim_bmc()
            .await
            .map_err(|e| tracing::error!("initiate_update: Failed to call enable_rshim_bmc: {e}"));
        let image_uri = format!(
            "{}/{}",
            to_install.get_url(),
            to_install.get_filename(firmware_number).display()
        );
        tracing::debug!(
            "initiate_update: Using simple_update with image URI: {}",
            image_uri
        );
        match redfish_client
            .update_firmware_simple_update(
                image_uri.as_str(),
                vec!["redfish/v1/UpdateService/FirmwareInventory/DPU_OS".to_string()],
                TransferProtocolType::HTTP,
            )
            .await
        {
            Ok(task) => task.id,
            Err(e) => {
                tracing::error!(
                    "initiate_update: Failed to call update_firmware_simple_update {}: {e}",
                    endpoint_clone.address
                );
                return Ok(());
            }
        }
    } else {
        match redfish_client
            .update_firmware_multipart(
                to_install.get_filename(firmware_number).as_path(),
                true,
                Duration::from_secs(120),
                redfish_component_type,
            )
            .await
        {
            Ok(task) => task,
            Err(RedfishError::NotSupported(err)) => {
                tracing::warn!(
                    "Multipart update is not supported: {err}. Trying to use HttpPushUri"
                );
                let file =
                    match File::open(to_install.get_filename(firmware_number).as_path()).await {
                        Ok(f) => f,
                        Err(e) => {
                            tracing::error!("Failed to open a file: {e}");
                            return Ok(());
                        }
                    };
                match redfish_client.update_firmware(file).await {
                    Ok(task) => task.id,
                    Err(e) => {
                        tracing::error!(
                            "initiate_update: Failed uploading firmware to {}: {e}",
                            endpoint_clone.address
                        );
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "initiate_update: Failed uploading firmware to {}: {e}",
                    endpoint_clone.address
                );
                return Ok(());
            }
        }
    };

    tracing::debug!(
        "initiate_update: Completed upload of firmware to {}",
        endpoint_clone.address
    );

    db_pool
        .with_txn(|txn| {
            Box::pin(db::explored_endpoints::set_preingestion_waittask(
                endpoint_clone.address,
                task,
                &to_install.version,
                firmware_type,
                to_install.power_drains_needed,
                firmware_number,
                txn,
            ))
        })
        .await??;

    Ok(())
}
