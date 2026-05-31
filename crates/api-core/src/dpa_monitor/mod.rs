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
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use carbide_dpa::DpaInfo;
use carbide_utils::periodic_timer::PeriodicTimer;
use carbide_uuid::machine::MachineId;
use carbide_uuid::spx::NULL_SPX_PARTITION_ID;
use chrono::TimeDelta;
use db::db_read::PgPoolReader;
use db::work_lock_manager::WorkLockManagerHandle;
use db::{self, ObjectColumnFilter, TransactionVending};
use metrics::DpaMonitorMetrics;
use model::dpa_interface::DpaLockMode::{Locked, Unlocked};
use model::dpa_interface::{DpaInterface, DpaInterfaceControllerState};
use model::instance::snapshot::InstanceSnapshot;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{HostHealthConfig, LoadSnapshotOptions, Machine, ManagedHostStateSnapshot};
use mqttea::client::MqtteaClient;
use sqlx::{PgConnection, PgPool, PgTransaction};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::cfg::file::DpaConfig;
use crate::{CarbideError, CarbideResult};

mod metrics;

pub struct DpaMonitor {
    db_services: DbServices,
    dpa_info: Option<Arc<DpaInfo>>,
    config: DpaConfig,
    host_health: HostHealthConfig,
    metric_holder: Arc<metrics::MetricHolder>,
    work_lock_manager_handle: WorkLockManagerHandle,
}

pub struct DbServices {
    db_pool: PgPool,
}

// This carries the result running the handler for a single dpa interface.
// If the dpa interface needs to a new state, the new state is returned.
// If we started a transaction in the handler, the transaction is returned.
pub struct HandlerResult {
    new_state: Option<DpaInterfaceControllerState>,
    txn: Option<PgTransaction<'static>>,
}

impl DpaMonitor {
    const ITERATION_WORK_KEY: &'static str = "DpaMonitor::run_single_iteration";

    pub fn new(
        db_pool: PgPool,
        _db_reader: PgPoolReader,
        dpa_info: Option<Arc<DpaInfo>>,
        _meter: opentelemetry::metrics::Meter,
        config: DpaConfig,
        host_health: HostHealthConfig,
        work_lock_manager_handle: WorkLockManagerHandle,
    ) -> Self {
        let hold_period = config
            .monitor_run_interval
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(_meter, hold_period));

        Self {
            db_services: DbServices { db_pool },
            dpa_info,
            config,
            host_health,
            work_lock_manager_handle,
            metric_holder,
        }
    }

    pub fn start(
        mut self,
        join_set: &mut JoinSet<()>,
        cancel_token: CancellationToken,
    ) -> io::Result<()> {
        join_set
            .build_task()
            .name("dpa-monitor")
            .spawn(async move { self.run(cancel_token).await })?;

        Ok(())
    }

    pub async fn run(&mut self, cancel_token: CancellationToken) {
        let timer = PeriodicTimer::new(self.config.monitor_run_interval);
        loop {
            let mut tick = timer.tick();
            match self.run_single_iteration().await {
                Ok(num_changes) => {
                    if num_changes > 0 {
                        // Decrease the interval if changes have been made.
                        tick.set_interval(Duration::from_millis(1000));
                    }
                }
                Err(e) => {
                    tracing::warn!("DpaMonitor error: {}", e);
                }
            }

            tokio::select! {
                _ = tick.sleep() => {},
                _ = cancel_token.cancelled() => {
                    tracing::info!("DpaMonitor stop was requested");
                    return;
                }
            }
        }
    }

    pub async fn run_single_iteration(&mut self) -> CarbideResult<usize> {
        let mut metrics = DpaMonitorMetrics::new();
        let span_id: String = format!("{:#x}", u64::from_le_bytes(rand::random::<[u8; 8]>()));
        let check_dpa_span = tracing::span!(
            parent: None,
            tracing::Level::INFO,
            "dpa-monitor",
            span_id,
        );
        let result = self
            .run_single_iteration_inner(&mut metrics)
            .instrument(check_dpa_span.clone())
            .await;
        check_dpa_span.record("metrics", metrics.to_string());
        self.metric_holder.update_metrics(metrics);
        result
    }

    async fn run_single_iteration_inner(
        &mut self,
        metrics: &mut DpaMonitorMetrics,
    ) -> CarbideResult<usize> {
        let _lock = match self
            .work_lock_manager_handle
            .try_acquire_lock(Self::ITERATION_WORK_KEY.into())
            .await
        {
            Ok(lock) => lock,
            Err(e) => {
                tracing::warn!(
                    "DpaMonitor failed to acquire work lock: Another instance of carbide running? {e}"
                );
                return Ok(0);
            }
        };
        tracing::info!(
            lock = Self::ITERATION_WORK_KEY,
            "DpaMonitor acquired the lock",
        );

        let mut txn = self.db_services.db_pool.txn_begin().await?;

        let mut snapshots = match self.get_all_snapshots(&mut txn).await {
            Ok(snapshots) => snapshots,
            Err(e) => {
                tracing::error!(error = %e, "run_single_iteration_inner: Failed to load ManagedHost snapshots in IbFabricMonitor");
                // Record the same error for all fabrics, so that the problem is at least visible on dashboards
                return Err(e);
            }
        };

        txn.commit().await?;

        for mh in snapshots.values_mut() {
            metrics.num_machines_scanned += 1;

            // If the machine does not have any dpa interfaces, we can skip it.
            if mh.dpa_interface_snapshots.is_empty() {
                tracing::info!("run_single_iteration_inner: skipping, no dpa interfaces");
                continue;
            }

            // If the machine is an instance, increment the number of instances scanned.
            if mh.instance.is_some() {
                metrics.num_instances_scanned += 1;
            }

            for idx in 0..mh.dpa_interface_snapshots.len() {
                metrics.num_dpa_interfaces_scanned += 1;

                let controller_state = mh.dpa_interface_snapshots[idx].controller_state.clone();

                // Look at this DPA interface and see if we need to transition it to a new state.
                // This will return a new state if we need to transition to a new state, or None if we can stay in the current state.
                // We build an array of dpa interfaces and new state.
                // After examining all the dpa interfaces in all the machines, we will update the DB with the new states in another loop
                let handler_result = self.handle_dpa_interface(mh, idx, metrics).await?;

                let new_state = handler_result.new_state;
                let txn = handler_result.txn;

                if let Some(new_state) = new_state {
                    let new_version = controller_state.version.increment();

                    let mut txn =
                        match txn {
                            Some(t) => t,
                            None => self.db_services.db_pool.begin().await.map_err(|e| {
                                db::AnnotatedSqlxError::new("dpa_monitor begin txn", e)
                            })?,
                        };

                    db::dpa_interface::try_update_controller_state(
                        &mut txn,
                        mh.dpa_interface_snapshots[idx].id,
                        controller_state.version,
                        new_version,
                        &new_state,
                    )
                    .await?;

                    txn.commit()
                        .await
                        .map_err(|e| db::AnnotatedSqlxError::new("dpa_monitor commit txn", e))?;
                } else if let Some(txn) = txn {
                    txn.commit()
                        .await
                        .map_err(|e| db::AnnotatedSqlxError::new("dpa_monitor commit txn", e))?;
                }
            }
        }

        Ok(0)
    }

    // This function will be called when the DPA object is in Assigned state.
    // We need to make sure that the partitioning configuration of the NIC is in sync with
    // the desired state. It's possible we are moving from Ready state to Assigned state.
    // In this case, we need to send SetVNI command to move the NIC into the desired partition.
    // If we were already in Assigned state, and the user changed the SpxConfig using the
    // UpdateInstanceConfig API, we need to send SetVNI command to move the NIC into the new partition.
    // or remove the NIC from any partition.
    // The desired state will be in instance.spx_config field. The observed state will be in the
    // NIC's network_status_observation field.
    // Currently, we only support one attachment per NIC. This routine will have to be changed
    // when we start supporting multiple attachments per NIC.
    #[allow(clippy::too_many_arguments)]
    async fn reconcile_assigned_state<'a>(
        &mut self,
        dpa_interface: &mut DpaInterface,
        machine: &Machine,
        instance: &InstanceSnapshot,
        client: Arc<MqtteaClient>,
        dpa_info: &Arc<DpaInfo>,
        hb_interval: TimeDelta,
        metrics: &mut DpaMonitorMetrics,
    ) -> CarbideResult<Option<PgTransaction<'a>>> {
        let db_services = &self.db_services;

        let this_mac = dpa_interface.mac_address;

        let spx_config = instance.config.spxconfig.clone();

        let instance_version = instance.spx_config_version;
        let nic_version = dpa_interface.network_config.version.to_string();

        let mut need_creation = false;
        let mut need_deletion = false;
        let mut need_heartbeat = false;

        let mut vni = 0_u32;

        let mut this_nic_configured_attachments = spx_config
            .spx_attachments
            .iter()
            .filter(|a| a.mac_address == Some(this_mac.to_string()))
            .collect::<Vec<_>>();

        if this_nic_configured_attachments.len() > 1 {
            tracing::error!(
                "reconcile_assigned_state: this_nic_configured_attachments length is greater than 1"
            );
            return Err(CarbideError::InvalidArgument(
                "reconcile_assigned_state this_nic_configured_attachments length is greater than 1"
                    .to_string(),
            ));
        }

        let mut this_nic_observed_attachments = Vec::new();

        let observed = machine.spx_status_observation.clone();
        if let Some(observed) = observed {
            this_nic_observed_attachments = observed
                .spx_attachments
                .into_iter()
                .filter(|a| a.mac_address == this_mac)
                .collect::<Vec<_>>();
        }

        if this_nic_observed_attachments.len() > 1 {
            tracing::error!(
                "reconcile_assigned_state this_nic_observed_attachments length is greater than 1"
            );
            return Err(CarbideError::InvalidArgument(
                "reconcile_assigned_state this_nic_observed_attachments length is greater than 1"
                    .to_string(),
            ));
        }

        if this_nic_configured_attachments.is_empty() {
            if !this_nic_observed_attachments.is_empty() {
                need_deletion = true;
            }
        } else {
            let mut txn = db_services.db_pool.begin().await.map_err(|e| {
                db::AnnotatedSqlxError::new("reconcile_assigned_state begin txn", e)
            })?;
            let partition_id = this_nic_configured_attachments.remove(0).spx_partition_id;
            let partition = db::spx_partition::find_by(
                txn.as_mut(),
                ObjectColumnFilter::List(db::spx_partition::IdColumn, &[partition_id]),
            )
            .await?;

            txn.commit().await.map_err(|e| {
                db::AnnotatedSqlxError::new("reconcile_assigned_state commit txn", e)
            })?;

            if partition.len() != 1 {
                tracing::error!(
                    "reconcile_assigned_state SPX partition {partition_id} is not found"
                );
                return Err(CarbideError::InvalidArgument(format!(
                    "SPX partition {partition_id} is not found",
                )));
            }

            vni = partition[0].vni.unwrap_or(0) as u32;
            debug_assert_ne!(vni, 0, "VNI in SPX partition {partition_id} is 0");

            if !this_nic_observed_attachments.is_empty() {
                let observed_attachment = this_nic_observed_attachments.remove(0);

                if (observed_attachment.partition_id != Some(partition_id))
                    || (observed_attachment.config_version != Some(instance_version))
                {
                    need_creation = true;
                } else {
                    need_heartbeat = true;
                }
            } else {
                need_creation = true;
            }
        }

        if !need_creation && !need_deletion && !need_heartbeat {
            return Ok(None);
        }

        debug_assert_eq!(
            (need_creation as u8) + (need_deletion as u8) + (need_heartbeat as u8),
            1,
            "reconcile_assigned_state: at most one of need_creation, need_deletion, need_heartbeat should be set"
        );

        tracing::debug!(
            "[{}] reconcile_assigned_state: need_creation {need_creation}, need_deletion {need_deletion}, need_heartbeat {need_heartbeat}",
            chrono::Utc::now()
        );

        if need_creation {
            let txn = self
                .send_set_vni_command(
                    dpa_interface,
                    client,
                    dpa_info,
                    vni,
                    false,
                    instance_version.to_string(),
                )
                .await?;
            return Ok(txn);
        } else if need_deletion {
            let txn = self
                .send_set_vni_command(dpa_interface, client, dpa_info, 0_u32, false, nic_version)
                .await?;
            return Ok(txn);
        } else if need_heartbeat {
            let txn = self
                .do_heartbeat(dpa_interface, client, dpa_info, hb_interval, vni, metrics)
                .await?;
            return Ok(txn);
        }

        Ok(None)
    }

    // This function will be called when the DPA object is in Ready state.
    // We need to make sure that the partitioning configuration of the NIC is in sync with
    // the desired state.
    // Currently, we only support one attachment per NIC. This routine will have to be changed
    // when we start supporting multiple attachments per NIC.
    async fn reconcile_ready_state<'a>(
        &mut self,
        machine: &Machine,
        dpa_interface: &mut DpaInterface,
        client: Arc<MqtteaClient>,
        dpa_info: &Arc<DpaInfo>,
        hb_interval: TimeDelta,
        metrics: &mut DpaMonitorMetrics,
    ) -> CarbideResult<Option<PgTransaction<'a>>> {
        let nic_version = dpa_interface.network_config.version;
        let nic_version_str = nic_version.to_string();

        let mut need_deletion = false;
        let mut need_heartbeat = false;

        let this_mac = dpa_interface.mac_address;

        let observed = machine.spx_status_observation.clone();

        let mut this_nic_observed_attachments = Vec::new();

        if let Some(observed) = observed {
            this_nic_observed_attachments = observed
                .spx_attachments
                .into_iter()
                .filter(|a| a.mac_address == this_mac)
                .collect::<Vec<_>>();
        }

        if this_nic_observed_attachments.len() > 1 {
            tracing::error!(
                "reconcile_assigned_state this_nic_observed_attachments length is greater than 1"
            );
            return Err(CarbideError::InvalidArgument(
                "reconcile_assigned_state this_nic_observed_attachments length is greater than 1"
                    .to_string(),
            ));
        }

        if this_nic_observed_attachments.is_empty() {
            return Ok(None);
        }

        let observed_attachment = this_nic_observed_attachments.remove(0).clone();

        if (observed_attachment.partition_id != Some(NULL_SPX_PARTITION_ID))
            || (observed_attachment.config_version != Some(nic_version))
        {
            need_deletion = true;
        } else {
            need_heartbeat = true;
        }

        tracing::debug!(
            "[{}] reconcile_ready_state: need_deletion {need_deletion}, need_heartbeat {need_heartbeat}",
            chrono::Utc::now()
        );

        if need_deletion {
            let txn = self
                .send_set_vni_command(
                    dpa_interface,
                    client,
                    dpa_info,
                    0_u32,
                    false,
                    nic_version_str,
                )
                .await?;
            return Ok(txn);
        } else if need_heartbeat {
            let txn = self
                .do_heartbeat(dpa_interface, client, dpa_info, hb_interval, 0_u32, metrics)
                .await?;
            return Ok(txn);
        }

        Ok(None)
    }

    // This should return a txn if we started one, an indication of whether state is changing,
    // and if so, the new state.
    // We should:
    //    1. Go through the state transitions for the card.
    //    2. Send heartbeats in Ready and Assigned states if necessary.
    //    3. If the DPA is in ASSIGNED state, go through the attachments.
    //    4.    If we are not an instance, then, we need to do ResetVNI.
    //    5.    If we are an instance, then, we need to do SetVNI.
    //    6. We need a way for machine statehandler to determine if congig is done.
    async fn handle_dpa_interface(
        &mut self,
        mh: &mut ManagedHostStateSnapshot,
        idx: usize,
        metrics: &mut DpaMonitorMetrics,
    ) -> CarbideResult<HandlerResult> {
        let dpa_interface = &mut mh.dpa_interface_snapshots[idx];

        let hb_interval = self.config.hb_interval;

        let dpa_info = self.dpa_info.clone().unwrap();

        let host_use_admin_network = dpa_interface.use_admin_network();

        let controller_state = dpa_interface.controller_state.value.clone();
        match controller_state {
            DpaInterfaceControllerState::Provisioning => {
                if host_use_admin_network {
                    return Ok(HandlerResult {
                        new_state: None,
                        txn: None,
                    });
                }

                let new_state = DpaInterfaceControllerState::Ready;
                tracing::info!(state = ?new_state, "Dpa Interface state transition");
                Ok(HandlerResult {
                    new_state: Some(new_state),
                    txn: None,
                })
            }

            DpaInterfaceControllerState::Ready => {
                // We will stay in Ready state as long use_admin_network is true.
                // When an instance is created from this host, use_admin_network
                // will be turned off. We then need to SetVNI, and wait for the
                // SetVNI to take effect.

                let client = dpa_info
                    .mqtt_client
                    .clone()
                    .ok_or_else(|| eyre::eyre!("Missing mqtt_client"))?;

                if !host_use_admin_network {
                    // We are in the process of transitioning to an instance.
                    // So go through the unlock/apply firmware/lock sequence
                    let new_state = DpaInterfaceControllerState::Unlocking;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");

                    Ok(HandlerResult {
                        new_state: Some(new_state),
                        txn: None,
                    })
                } else {
                    // When we are in the Ready state, we need to make sure that there are no VNIs configured on the NICs.
                    // If an instance has just been released and we transition to Ready state, we need to reset the VNIs on the NICs to 0.
                    // The reconciliation routine will send SetVNI command with VNI being 0, as long as the observed state is different from the desired state.
                    // If the observed state is the same as the desired state, we can stay in the Assigned state and we
                    // will send heartbeat commands to keep the states in sync.

                    let txn = self
                        .reconcile_ready_state(
                            &mh.host_snapshot,
                            dpa_interface,
                            client,
                            &dpa_info,
                            hb_interval,
                            metrics,
                        )
                        .await?;

                    Ok(HandlerResult {
                        new_state: None,
                        txn,
                    })
                }
            }

            DpaInterfaceControllerState::Unlocking => {
                // Once we reach Unlocking state, we would have replied to
                // ForgeAgentControl requests from scout with a reply indicating
                // that it should unlock the card. The scout does the action, and
                // publishes an observation indicating the lock status. That causes
                // us to update the card state in the DB. If card_state is none, that
                // means this sequence has not yet taken place. So we just wait.
                if dpa_interface.card_state.is_none() {
                    tracing::info!("card_state none for dpa: {:#?}", dpa_interface.id);
                    return Ok(HandlerResult {
                        new_state: None,
                        txn: None,
                    });
                }
                if let Some(ref mut cs) = dpa_interface.card_state
                    && cs.lockmode == Some(Unlocked)
                {
                    let new_state = DpaInterfaceControllerState::ApplyFirmware;
                    tracing::info!(state = ?new_state, "Interface unlocked. Transitioning to next state");
                    return Ok(HandlerResult {
                        new_state: Some(new_state),
                        txn: None,
                    });
                }
                Ok(HandlerResult {
                    new_state: None,
                    txn: None,
                })
            }

            DpaInterfaceControllerState::ApplyFirmware => {
                // At this point, we're in the ApplyFirmware state, which means we
                // have sent a firmware flash instruction to scout (via a configured
                // FirmwareFlasherProfile). Now, we wait for an observation report
                // from scout indicating firmware has been applied (or skipped if no
                // config was available).
                let Some(ref card_state) = dpa_interface.card_state else {
                    tracing::info!(
                        "no firmware report, because card_state none for dpa: {:#?}, waiting for retry",
                        dpa_interface.id
                    );
                    return Ok(HandlerResult {
                        new_state: None,
                        txn: None,
                    });
                };
                if let Some(ref firmware_report) = card_state.firmware_report {
                    // Transition on to the next state if the flash succeeded and reset
                    // either wasn't requested (None) or succeeded (Some(true)).
                    //
                    // To explain this a bit better, if no reset was requested, then
                    // we'll get None back here. Since no reset was requested at all,
                    // then we can continue, so we just "default" to true, to let
                    // things continue. If a reset WAS requested, then we'll unwrap
                    // whatever the result was (either success/true, or failed/false).
                    let reset_ok = firmware_report.reset.unwrap_or(true);
                    if firmware_report.flashed && reset_ok {
                        let new_state = DpaInterfaceControllerState::ApplyProfile;
                        tracing::info!(
                            state = ?new_state,
                            observed_version = firmware_report.observed_version.as_deref().unwrap_or("none"),
                            "firmware report received and successfully applied, transitioning"
                        );
                        return Ok(HandlerResult {
                            new_state: Some(new_state),
                            txn: None,
                        });
                    }
                    tracing::warn!(
                        flashed = firmware_report.flashed,
                        reset = ?firmware_report.reset,
                        observed_version = firmware_report.observed_version.as_deref().unwrap_or("none"),
                        "firmware report received but not successful, waiting for retry"
                    );
                }

                // ..if we get here, it's because the firmware_report in the CardState
                // wasn't set yet. ...or it was, and this round wasn't successful, so we're
                // just going to keep hanging out in this state until it is (letting the
                // apply workflow happen again).
                Ok(HandlerResult {
                    new_state: None,
                    txn: None,
                })
            }

            DpaInterfaceControllerState::ApplyProfile => handle_apply_profile(dpa_interface),

            DpaInterfaceControllerState::Locking => {
                let Some(ref cs) = dpa_interface.card_state else {
                    tracing::error!(
                        "Unexpected - card_state none for dpa: {:#?}",
                        dpa_interface.id
                    );
                    return Ok(HandlerResult {
                        new_state: None,
                        txn: None,
                    });
                };
                if cs.lockmode == Some(Locked) {
                    let new_state = DpaInterfaceControllerState::Assigned;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");
                    return Ok(HandlerResult {
                        new_state: Some(new_state),
                        txn: None,
                    });
                }
                Ok(HandlerResult {
                    new_state: None,
                    txn: None,
                })
            }

            DpaInterfaceControllerState::Assigned => {
                // We will stay in the Assigned state as long as use_admin_network is off, which
                // means we are in the tenant network. Once use_admin_network is turned on, we
                // will send a SetVNI command to the DPA Interface card to set the VNI to 0
                // and will transition to WaitingForResetVNI state.

                let client = dpa_info
                    .mqtt_client
                    .clone()
                    .ok_or_else(|| eyre::eyre!("Missing mqtt_client"))?;

                if host_use_admin_network {
                    let new_state = DpaInterfaceControllerState::Ready;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");
                    Ok(HandlerResult {
                        new_state: Some(new_state),
                        txn: None,
                    })
                } else {
                    // When we are in the Assigned state, we need to make sure the NICs are configured
                    // with the correct VNI. We have to reconcile the desired state (as specified in the
                    // spx_config field of the instance) with the observed state of the NIC in the
                    // network_status_observation field of the DpaInterface. Send SetVNI command to the NIC
                    // to set the VNI to the desired value if the observed state is different from the desired state.
                    // If the observed state is the same as the desired state, we can stay in the Assigned state and we
                    // will send heartbeat commands to keep the states in sync.

                    let instance = mh.instance.as_ref().ok_or_else(|| {
                        tracing::error!("reconcile_assigned_state instance is missing");
                        eyre::eyre!("reconcile_assigned_state instance is missing")
                    })?;
                    let txn = self
                        .reconcile_assigned_state(
                            dpa_interface,
                            &mh.host_snapshot,
                            instance,
                            client,
                            &dpa_info,
                            hb_interval,
                            metrics,
                        )
                        .await?;

                    Ok(HandlerResult {
                        new_state: None,
                        txn,
                    })
                }
            }
        }
    }

    async fn get_all_snapshots(
        &self,
        txn: &mut PgConnection,
    ) -> CarbideResult<HashMap<MachineId, ManagedHostStateSnapshot>> {
        let machine_ids = db::machine::find_machine_ids(
            &mut *txn,
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?;

        let mut res = db::managed_host::load_by_machine_ids(
            txn,
            &machine_ids,
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: true,
                host_health_config: self.host_health,
            },
        )
        .await
        .map_err(Into::<CarbideError>::into)?;

        for mh in res.values_mut() {
            let machine_id = mh.host_snapshot.id;
            let dpa_snapshots = db::dpa_interface::find_by_machine_id(&mut *txn, machine_id)
                .await
                .map_err(Into::<CarbideError>::into)?;
            mh.dpa_interface_snapshots = dpa_snapshots;
        }

        Ok(res)
    }

    // Determine if we need to do a heartbeat or if we need to
    // send a SetVni command because the DPA and Carbide are out of sync.
    // If so, call send_set_vni_command to send the heart beat or set vni
    async fn do_heartbeat<'a>(
        &mut self,
        state: &mut DpaInterface,
        client: Arc<MqtteaClient>,
        dpa_info: &Arc<DpaInfo>,
        hb_interval: TimeDelta,
        vni: u32,
        metrics: &mut DpaMonitorMetrics,
    ) -> CarbideResult<Option<PgTransaction<'a>>> {
        // We are in the Ready or Assigned state and we continue to be in the same state.
        // In this state, we will send SetVni command to the DPA if
        //    (1) if the heartbeat interval has elapsed since the heartbeat
        //    (2) The DPA sent us an ack and it looks like the DPA lost its config (due to powercycle potentially)
        // Heartbeat is identified by the revision being se to the sentinel value "NIL"
        // When we send a heartbeat below, we update the last_hb_time for the interface entry.

        // XXX TODO XXX
        // Verify with the FW team how the card behaves if it loses its config after a powercyle.
        // If we send it a heartbeat with NIL as the revision, but with a valid VNI (since its a part
        // of a tenancy), will it echo back the VNI? Or does the reply alway carry whatever VNI it is using?
        // If it just echoes back the VNI, we have to send it a SetVni command with the VNI to use.
        // XXX TODO XXX

        let Some(next_hb_time) = state.last_hb_time.checked_add_signed(hb_interval) else {
            // checked_add_signed returns None if the addition overflows
            return Ok(None);
        };

        if chrono::Utc::now() < next_hb_time {
            return Ok(None);
        }

        let txn = self
            .send_set_vni_command(state, client, dpa_info, vni, true, "NIL".to_string())
            .await?;

        metrics.num_heartbeats_sent += 1;

        Ok(txn)
    }

    // Send a SetVni command to the DPA. The SetVni command could be a heart beat (identified by
    // revision being "NIL"). If needs_vni is true, get the VNI to use from the DB. Otherwise, vni
    // sent is 0.
    async fn send_set_vni_command<'a>(
        &mut self,
        state: &mut DpaInterface,
        client: Arc<MqtteaClient>,
        dpa_info: &Arc<DpaInfo>, // dpa_info contains the subnet_ip and subnet_mask to use for the SetVni command
        vni: u32,
        heart_beat: bool,
        revision_str: String,
    ) -> CarbideResult<Option<PgTransaction<'a>>> {
        let services = &self.db_services;

        // Send a heartbeat command, indicated by the revision string being "NIL".
        match carbide_dpa::send_dpa_command(
            client,
            dpa_info,
            state.mac_address.to_string(),
            revision_str,
            vni as i32,
        )
        .await
        {
            Ok(()) => {
                if heart_beat {
                    let mut txn =
                        services.db_pool.begin().await.map_err(|e| {
                            db::AnnotatedSqlxError::new("dpa_monitor hb begin txn", e)
                        })?;
                    let res = db::dpa_interface::update_last_hb_time(state, &mut txn).await;
                    if res.is_err() {
                        tracing::error!(
                            "Error updating last_hb_time for dpa id: {} res: {:#?}",
                            state.id,
                            res
                        );
                    }
                    Ok(Some(txn))
                } else {
                    Ok(None)
                }
            }
            Err(_e) => Ok(None),
        }
    }
}

/// handle_apply_profile handles the ApplyProfile state for a
/// SuperNIC/DPA interface, which means we sent an mlxconfig
/// profile config down to scout (which takes care of resetting
/// mlxconfig parameters back to defaults, and then potentially
/// overlaying a profile of parameters over top of it).
///
/// And just so it's clear, there are two "success" cases that
/// we check for here.
/// 1. A profile was configured and successfully synced — scout
///    reports a profile_name and profile_synced is true.
/// 2. NO profile was configured (indicating reset only) — scout
///    reports profile_name=None and profile_synced true. This is
///    successful because the reset itself succeeded and there was
///    nothing else to apply.
///
/// In both cases, profile_synced=Some(true) is the signal that
/// the workflow completed successfully, and it's safe to transition
/// to the next state.
fn handle_apply_profile(state: &DpaInterface) -> CarbideResult<HandlerResult> {
    let Some(ref cs) = state.card_state else {
        tracing::info!(
            "no profile report, because card_state none for dpa: {:#?}, waiting for retry",
            state.id
        );
        return Ok(HandlerResult {
            new_state: None,
            txn: None,
        });
    };
    if cs.profile_synced == Some(true) {
        let new_state = DpaInterfaceControllerState::Locking;
        tracing::info!(
            state = ?new_state,
            profile = cs.profile.as_deref().unwrap_or("none"),
            "profile applied successfully, transitioning"
        );
        return Ok(HandlerResult {
            new_state: Some(new_state),
            txn: None,
        });
    }
    Ok(HandlerResult {
        new_state: None,
        txn: None,
    })
}
