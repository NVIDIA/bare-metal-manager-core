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

//! State Handler implementation for Machines

use std::{net::IpAddr, sync::Arc};

use crate::db::machine_validation::{MachineValidationState, MachineValidationStatus};
use crate::db::network_segment::NetworkSegment;
use crate::model::instance::config::network::NetworkDetails;
use crate::model::machine::DisableSecureBootState;
use crate::redfish;
use crate::state_controller::machine::{
    get_measuring_prerequisites, handle_measuring_state, MeasuringOutcome,
};
use chrono::{DateTime, Duration, Utc};
use config_version::ConfigVersion;
use eyre::eyre;
use forge_secrets::credentials::{BmcCredentialType, CredentialKey};
use forge_uuid::machine::MachineId;
use futures::TryFutureExt;
use itertools::Itertools;
use libredfish::{
    model::task::{Task, TaskState},
    Boot, Redfish, RedfishError, SystemPowerControl,
};
use std::mem::discriminant as enum_discr;
use tokio::{fs::File, sync::Semaphore};

use crate::{
    cfg::file::{
        DpuModel, Firmware, FirmwareComponentType, FirmwareConfig, FirmwareEntry,
        MachineValidationConfig,
    },
    db::{
        explored_endpoints::DbExploredEndpoint, instance::DeleteInstance, machine::Machine,
        machine_topology::MachineTopology, machine_validation::MachineValidation,
    },
    firmware_downloader::FirmwareDownloader,
    model::{
        machine::{
            all_equal, get_display_ids, BmcFirmwareUpgradeSubstate, CleanupState,
            DpuDiscoveringState, DpuInitState, FailureCause, FailureDetails, FailureSource,
            HostReprovisionState, InstanceNextStateResolver, InstanceState, LockdownInfo,
            LockdownMode::{self, Enable},
            LockdownState, MachineLastRebootRequestedMode, MachineNextStateResolver,
            MachineSnapshot, MachineState, MachineValidationFilter, ManagedHostState,
            ManagedHostStateSnapshot, MeasuringState, NextReprovisionState, PerformPowerOperation,
            ReprovisionState, RetryInfo, StateMachineArea, UefiSetupInfo, UefiSetupState,
        },
        site_explorer::ExploredEndpoint,
    },
    redfish::{
        build_redfish_client_from_bmc_ip, host_power_control, poll_redfish_job,
        set_host_uefi_password,
    },
    state_controller::{
        machine::context::MachineStateHandlerContextObjects,
        state_handler::{
            StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
            StateHandlerServices,
        },
    },
};
use measured_boot::records::MeasurementMachineState;

mod ib;
mod storage;

// We can't use http::StatusCode because libredfish has a newer version
const NOT_FOUND: u16 = 404;

/// Reachability params to check if DPU is up or not.
#[derive(Copy, Clone, Debug)]
pub struct ReachabilityParams {
    pub dpu_wait_time: chrono::Duration,
    pub power_down_wait: chrono::Duration,
    pub failure_retry_time: chrono::Duration,
}

/// Parameters used by the HostStateMachineHandler.
#[derive(Copy, Clone, Debug)]
pub struct HostHandlerParams {
    pub attestation_enabled: bool,
    pub reachability_params: ReachabilityParams,
    pub machine_validation_config: MachineValidationConfig,
}

/// The actual Machine State handler
#[derive(Debug, Clone)]
pub struct MachineStateHandler {
    host_handler: HostMachineStateHandler,
    pub dpu_handler: DpuMachineStateHandler,
    instance_handler: InstanceStateHandler,
    dpu_up_threshold: chrono::Duration,
    /// Reachability params to check if DPU is up or not
    reachability_params: ReachabilityParams,
    parsed_hosts: Arc<FirmwareConfig>,
    downloader: FirmwareDownloader,
    upload_limiter: Arc<Semaphore>,
}

pub struct MachineStateHandlerBuilder {
    dpu_up_threshold: chrono::Duration,
    dpu_nic_firmware_initial_update_enabled: bool,
    dpu_nic_firmware_reprovision_update_enabled: bool,
    hardware_models: Option<FirmwareConfig>,
    reachability_params: ReachabilityParams,
    firmware_downloader: Option<FirmwareDownloader>,
    attestation_enabled: bool,
    upload_limiter: Option<Arc<Semaphore>>,
    machine_validation_config: MachineValidationConfig,
}

impl MachineStateHandlerBuilder {
    pub fn builder() -> Self {
        Self {
            dpu_up_threshold: chrono::Duration::minutes(5),
            dpu_nic_firmware_initial_update_enabled: true,
            dpu_nic_firmware_reprovision_update_enabled: true,
            hardware_models: None,
            reachability_params: ReachabilityParams {
                dpu_wait_time: chrono::Duration::zero(),
                power_down_wait: chrono::Duration::zero(),
                failure_retry_time: chrono::Duration::zero(),
            },
            firmware_downloader: None,
            attestation_enabled: false,
            upload_limiter: None,
            machine_validation_config: MachineValidationConfig { enabled: true },
        }
    }

    pub fn dpu_up_threshold(mut self, dpu_up_threshold: chrono::Duration) -> Self {
        self.dpu_up_threshold = dpu_up_threshold;
        self
    }

    #[cfg(test)] // currently only used in tests
    pub fn dpu_nic_firmware_initial_update_enabled(
        mut self,
        dpu_nic_firmware_initial_update_enabled: bool,
    ) -> Self {
        self.dpu_nic_firmware_initial_update_enabled = dpu_nic_firmware_initial_update_enabled;
        self
    }

    pub fn dpu_nic_firmware_reprovision_update_enabled(
        mut self,
        dpu_nic_firmware_reprovision_update_enabled: bool,
    ) -> Self {
        self.dpu_nic_firmware_reprovision_update_enabled =
            dpu_nic_firmware_reprovision_update_enabled;
        self
    }

    #[cfg(test)] // currently only used in tests
    pub fn reachability_params(mut self, reachability_params: ReachabilityParams) -> Self {
        self.reachability_params = reachability_params;
        self
    }

    pub fn dpu_wait_time(mut self, dpu_wait_time: chrono::Duration) -> Self {
        self.reachability_params.dpu_wait_time = dpu_wait_time;
        self
    }

    pub fn power_down_wait(mut self, power_down_wait: chrono::Duration) -> Self {
        self.reachability_params.power_down_wait = power_down_wait;
        self
    }

    pub fn failure_retry_time(mut self, failure_retry_time: chrono::Duration) -> Self {
        self.reachability_params.failure_retry_time = failure_retry_time;
        self
    }

    pub fn hardware_models(mut self, hardware_models: FirmwareConfig) -> Self {
        self.hardware_models = Some(hardware_models);
        self
    }

    pub fn firmware_downloader(mut self, firmware_downloader: &FirmwareDownloader) -> Self {
        self.firmware_downloader = Some(firmware_downloader.clone());
        self
    }

    pub fn attestation_enabled(mut self, attestation_enabled: bool) -> Self {
        self.attestation_enabled = attestation_enabled;
        self
    }

    pub fn upload_limiter(mut self, upload_limiter: Arc<Semaphore>) -> Self {
        self.upload_limiter = Some(upload_limiter);
        self
    }

    pub fn machine_validation_config(
        mut self,
        machine_validation_config: MachineValidationConfig,
    ) -> Self {
        self.machine_validation_config = machine_validation_config;
        self
    }

    pub fn build(self) -> MachineStateHandler {
        MachineStateHandler::new(self)
    }
}

impl MachineStateHandler {
    fn new(builder: MachineStateHandlerBuilder) -> Self {
        MachineStateHandler {
            dpu_up_threshold: builder.dpu_up_threshold,
            host_handler: HostMachineStateHandler::new(HostHandlerParams {
                attestation_enabled: builder.attestation_enabled,
                reachability_params: builder.reachability_params,
                machine_validation_config: builder.machine_validation_config,
            }),
            dpu_handler: DpuMachineStateHandler::new(
                builder.dpu_nic_firmware_initial_update_enabled,
                builder.reachability_params,
            ),
            instance_handler: InstanceStateHandler::new(
                builder.dpu_nic_firmware_reprovision_update_enabled,
                builder.attestation_enabled,
                builder.reachability_params,
                builder.hardware_models.clone().unwrap_or_default(),
            ),
            reachability_params: builder.reachability_params,
            parsed_hosts: Arc::new(builder.hardware_models.unwrap_or_default()),
            downloader: builder.firmware_downloader.unwrap_or_default(),
            upload_limiter: builder
                .upload_limiter
                .unwrap_or(Arc::new(Semaphore::new(5))),
        }
    }

    fn record_metrics(
        &self,
        state: &mut ManagedHostStateSnapshot,
        ctx: &mut StateHandlerContext<MachineStateHandlerContextObjects>,
    ) {
        for dpu_snapshot in state.dpu_snapshots.iter() {
            let fw_version = dpu_snapshot
                .hardware_info
                .as_ref()
                .and_then(|hi| hi.dpu_info.as_ref().map(|di| di.firmware_version.clone()));
            if let Some(fw_version) = fw_version {
                *ctx.metrics
                    .dpu_firmware_versions
                    .entry(fw_version)
                    .or_default() += 1;
            }

            for component in &dpu_snapshot.agent_reported_inventory.components {
                let mut component = component.clone();
                // Remove the URL field for metrics purposes. We don't want to report different metrics
                // just because the URL field in components differ. Only name and version are important
                component.url = String::new();
                *ctx.metrics
                    .machine_inventory_component_versions
                    .entry(component)
                    .or_default() += 1;
            }

            // Update DPU network health Prometheus metrics
            // TODO: This needs to be fixed for multi-dpu
            ctx.metrics.dpus_healthy += if dpu_snapshot
                .dpu_agent_health_report
                .as_ref()
                .map(|health| health.alerts.is_empty())
                .unwrap_or(false)
            {
                1
            } else {
                0
            };
            if let Some(report) = dpu_snapshot.dpu_agent_health_report.as_ref() {
                for alert in report.alerts.iter() {
                    *ctx.metrics
                        .dpu_health_probe_alerts
                        .entry((alert.id.clone(), alert.target.clone()))
                        .or_default() += 1;
                }
            }
            if let Some(observation) = dpu_snapshot.network_status_observation.as_ref() {
                if let Some(agent_version) = observation.agent_version.as_ref() {
                    *ctx.metrics
                        .agent_versions
                        .entry(agent_version.clone())
                        .or_default() += 1;
                }
                if Utc::now().signed_duration_since(observation.observed_at)
                    <= self.dpu_up_threshold
                {
                    ctx.metrics.dpus_up += 1;
                }

                *ctx.metrics
                    .client_certificate_expiry
                    .entry(observation.machine_id.clone())
                    .or_default() = observation.client_certificate_expiry;
            }
        }

        ctx.metrics.is_usable_as_instance = state.is_usable_as_instance().is_ok();
        ctx.metrics.num_gpus = state
            .host_snapshot
            .hardware_info
            .as_ref()
            .map(|info| info.gpus.len())
            .unwrap_or_default();
        ctx.metrics.assigned_to_tenant = state
            .instance
            .as_ref()
            .map(|instance| instance.config.tenant.tenant_organization_id.clone());
        ctx.metrics.is_host_bios_password_set =
            state.host_snapshot.bios_password_set_time.is_some();

        for alert in state.aggregate_health.alerts.iter() {
            ctx.metrics
                .health_probe_alerts
                .insert((alert.id.clone(), alert.target.clone()));
            for c in alert.classifications.iter() {
                ctx.metrics.health_alert_classifications.insert(c.clone());
            }
        }

        ctx.metrics.num_merge_overrides = state.host_snapshot.health_report_overrides.merges.len();
        ctx.metrics.replace_override_enabled = state
            .host_snapshot
            .health_report_overrides
            .replace
            .is_some();
    }

    async fn attempt_state_transition(
        &self,
        host_machine_id: &MachineId,
        mh_snapshot: &mut ManagedHostStateSnapshot,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        let mh_state = mh_snapshot.managed_state.clone();

        // If it's been more than 5 minutes since DPU reported status, consider it unhealthy
        for dpu_snapshot in &mh_snapshot.dpu_snapshots {
            if let Some(dpu_health) = dpu_snapshot.dpu_agent_health_report.as_ref() {
                if !dpu_health.alerts.is_empty() {
                    continue;
                }
                if let Some(observation) = &dpu_snapshot.network_status_observation {
                    let observed_at = observation.observed_at;
                    let since_last_seen = Utc::now().signed_duration_since(observed_at);
                    if since_last_seen > self.dpu_up_threshold {
                        let message = format!("Last seen over {} ago", self.dpu_up_threshold);
                        let dpu_machine_id = &dpu_snapshot.machine_id;
                        let health_report = health_report::HealthReport::heartbeat_timeout(
                            "forge-dpu-agent".to_string(),
                            "forge-dpu-agent".to_string(),
                            message,
                        );
                        Machine::update_dpu_agent_health_report(
                            txn,
                            dpu_machine_id,
                            &health_report,
                        )
                        .await?;

                        tracing::warn!(
                        host_machine_id = %host_machine_id,
                        dpu_machine_id = %dpu_machine_id,
                        last_seen = %observed_at,
                        "DPU is not sending network status observations, marking unhealthy");
                        // The next iteration will run with the now unhealthy network
                        return Ok(StateHandlerOutcome::DoNothing);
                    }
                }
            }
        }

        if dpu_reprovisioning_needed(&mh_snapshot.dpu_snapshots) {
            // Reprovision is started and user requested for restart of reprovision.
            let (restart_reprov, firmware_upgrade_needed) = can_restart_reprovision(
                &mh_snapshot.dpu_snapshots,
                mh_snapshot.host_snapshot.current.version,
            );
            if restart_reprov {
                if let Some(next_state) = self
                    .restart_dpu_reprovision(
                        &mh_state,
                        mh_snapshot,
                        ctx,
                        txn,
                        host_machine_id,
                        firmware_upgrade_needed,
                    )
                    .await?
                {
                    return Ok(StateHandlerOutcome::Transition(next_state));
                }
            }
        }

        // Don't update failed state failure cause everytime. Record first failure cause only,
        // otherwise first failure cause will be overwritten.
        if !matches!(mh_state, ManagedHostState::Failed { .. }) {
            if let Some((machine_id, details)) = get_failed_state(mh_snapshot) {
                tracing::error!(
                    %machine_id,
                    "ManagedHost {}/{} (failed machine: {}) is moved to Failed state with cause: {:?}",
                    mh_snapshot.host_snapshot.machine_id,
                    get_display_ids(&mh_snapshot.dpu_snapshots),
                    machine_id,
                    details
                );
                let next_state = match mh_state {
                    ManagedHostState::Assigned { .. } => ManagedHostState::Assigned {
                        instance_state: InstanceState::Failed {
                            details,
                            machine_id,
                        },
                    },
                    _ => ManagedHostState::Failed {
                        details,
                        machine_id,
                        retry_count: 0,
                    },
                };
                return Ok(StateHandlerOutcome::Transition(next_state));
            }
        }

        match &mh_state {
            ManagedHostState::DpuDiscoveringState { .. } => {
                if mh_snapshot
                    .host_snapshot
                    .associated_dpu_machine_ids()
                    .is_empty()
                {
                    tracing::info!(
                        machine_id = %host_machine_id,
                        "Skipping to HostInit because machine has no DPUs"
                    );
                    Ok(StateHandlerOutcome::Transition(
                        ManagedHostState::HostInit {
                            machine_state: MachineState::WaitingForPlatformConfiguration,
                        },
                    ))
                } else {
                    let mut state_handler_outcome = StateHandlerOutcome::DoNothing;
                    for dpu_snapshot in &mh_snapshot.dpu_snapshots.clone() {
                        state_handler_outcome = self
                            .dpu_handler
                            .handle_dpu_discovering_state(
                                mh_snapshot,
                                dpu_snapshot,
                                &mh_state,
                                txn,
                                ctx,
                            )
                            .await?;

                        if let StateHandlerOutcome::Transition(..) = state_handler_outcome {
                            return Ok(state_handler_outcome);
                        }
                    }

                    Ok(state_handler_outcome)
                }
            }
            ManagedHostState::DPUInit { .. } => {
                self.dpu_handler
                    .handle_object_state(host_machine_id, mh_snapshot, &mh_state, txn, ctx)
                    .await
            }

            ManagedHostState::HostInit { .. } => {
                self.host_handler
                    .handle_object_state(host_machine_id, mh_snapshot, &mh_state, txn, ctx)
                    .await
            }

            ManagedHostState::Ready => {
                if host_reprovisioning_requested(mh_snapshot).await {
                    if let Some(next_state) = self
                        .handle_host_reprovision(mh_snapshot, ctx.services, host_machine_id, txn)
                        .await?
                    {
                        return Ok(StateHandlerOutcome::Transition(next_state));
                    } else {
                        return Ok(StateHandlerOutcome::DoNothing);
                    }
                }
                if is_machine_validation_requested(mh_snapshot).await {
                    //reboot the machine with new scout image
                    handler_host_power_control(
                        mh_snapshot,
                        ctx.services,
                        SystemPowerControl::ForceRestart,
                        txn,
                    )
                    .await?;
                    let machine_validation =
                        match MachineValidation::find_active_machine_validation_by_machine_id(
                            txn,
                            host_machine_id,
                        )
                        .await
                        {
                            Ok(data) => data,
                            Err(e) => {
                                tracing::info!(
                                    error = %e,
                                    "find_active_machine_validation_by_machine_id"
                                );
                                Machine::set_machine_validation_request(txn, host_machine_id, true)
                                    .await
                                    .map_err(StateHandlerError::from)?;
                                // Health Alert ?
                                // Rare screnario, if something googfed up in DB
                                return Ok(StateHandlerOutcome::DoNothing);
                            }
                        };

                    let next_state = ManagedHostState::HostInit {
                        machine_state: MachineState::MachineValidating {
                            context: "OnDemand".to_string(),
                            id: machine_validation.id,
                            completed: 1,
                            total: 1,
                            is_enabled: self
                                .host_handler
                                .host_handler_params
                                .machine_validation_config
                                .enabled,
                        },
                    };
                    return Ok(StateHandlerOutcome::Transition(next_state));
                }
                // Check if DPU reprovisioning is requested
                if dpu_reprovisioning_needed(&mh_snapshot.dpu_snapshots) {
                    let mut dpus_for_reprov = vec![];
                    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                        if dpu_snapshot.reprovision_requested.is_some() {
                            handler_restart_dpu(dpu_snapshot, ctx.services, txn).await?;
                            Machine::update_dpu_reprovision_start_time(
                                &dpu_snapshot.machine_id,
                                txn,
                            )
                            .await?;
                            dpus_for_reprov.push(dpu_snapshot);
                        }
                    }
                    // All DPUs must have same value for this parameter. All DPUs are updated
                    // together grpc API or automatic updater. Still we are using `any` to avoid
                    // blocking state machine.
                    // TODO: multidpu: Keep it at some common place to avoid duplicates.
                    let is_firmware_upgrade_needed = dpus_for_reprov.iter().any(|x| {
                        x.reprovision_requested
                            .as_ref()
                            .map(|x| x.update_firmware)
                            .unwrap_or_default()
                    });

                    let reprov_state = if is_firmware_upgrade_needed {
                        ReprovisionState::BmcFirmwareUpgrade {
                            substate: BmcFirmwareUpgradeSubstate::CheckFwVersion,
                        }
                    } else {
                        set_managed_host_topology_update_needed(
                            txn,
                            &mh_snapshot.host_snapshot,
                            &dpus_for_reprov,
                        )
                        .await?;
                        ReprovisionState::WaitingForNetworkInstall
                    };
                    let next_state = reprov_state.next_state_with_all_dpus_updated(
                        &mh_state,
                        &mh_snapshot.dpu_snapshots,
                        dpus_for_reprov.iter().map(|x| &x.machine_id).collect_vec(),
                    )?;
                    return Ok(StateHandlerOutcome::Transition(next_state));
                }

                // Check to see if measurement machine (i.e. attestation) state has changed
                // if so, just place it into the measuring state and let it be handled inside
                // the measurement state
                if self.host_handler.host_handler_params.attestation_enabled
                    && check_if_should_redo_measurements(&mh_snapshot.host_snapshot.machine_id, txn)
                        .await?
                {
                    return Ok(StateHandlerOutcome::Transition(
                        ManagedHostState::Measuring {
                            measuring_state: MeasuringState::WaitingForMeasurements, // let's just start from the beginning
                        },
                    ));
                }

                // Check if instance to be created.
                if mh_snapshot.instance.is_some() {
                    // Instance is requested by user. Let's configure it.

                    // Switch to using the network we just created for the tenant
                    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                        let (mut netconf, version) = dpu_snapshot.network_config.clone().take();
                        netconf.use_admin_network = Some(false);
                        Machine::try_update_network_config(
                            txn,
                            &dpu_snapshot.machine_id,
                            version,
                            &netconf,
                        )
                        .await?;
                    }

                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkSegmentToBeReady,
                    };
                    Ok(StateHandlerOutcome::Transition(next_state))
                } else {
                    // This feature has only been tested thoroughly on Dells and Lenovos
                    if (mh_snapshot.host_snapshot.bmc_vendor.is_dell()
                        || mh_snapshot.host_snapshot.bmc_vendor.is_lenovo())
                        && mh_snapshot.host_snapshot.bios_password_set_time.is_none()
                    {
                        tracing::info!("transitioning legacy {} host {} to UefiSetupState::UnlockHost while it is in ManagedHostState::Ready so that the BIOS password can be configured",mh_snapshot.host_snapshot.bmc_vendor, mh_snapshot.host_snapshot.machine_id);
                        return Ok(StateHandlerOutcome::Transition(
                            ManagedHostState::HostInit {
                                machine_state: MachineState::UefiSetup {
                                    uefi_setup_info: UefiSetupInfo {
                                        uefi_password_jid: None,
                                        uefi_setup_state: UefiSetupState::UnlockHost,
                                    },
                                },
                            },
                        ));
                    }

                    Ok(StateHandlerOutcome::DoNothing)
                }
            }

            ManagedHostState::Assigned { instance_state: _ } => {
                // Process changes needed for instance.
                self.instance_handler
                    .handle_object_state(host_machine_id, mh_snapshot, &mh_state, txn, ctx)
                    .await
            }

            ManagedHostState::WaitingForCleanup { cleanup_state } => {
                match cleanup_state {
                    CleanupState::HostCleanup => {
                        if !cleanedup_after_state_transition(
                            mh_snapshot.host_snapshot.current.version,
                            mh_snapshot.host_snapshot.last_cleanup_time,
                        ) {
                            let status = trigger_reboot_if_needed(
                                &mh_snapshot.host_snapshot,
                                mh_snapshot,
                                None,
                                &self.reachability_params,
                                ctx.services,
                                txn,
                            )
                            .await?;
                            return Ok(StateHandlerOutcome::Wait(status.status));
                        }

                        // Reboot host
                        handler_host_power_control(
                            mh_snapshot,
                            ctx.services,
                            SystemPowerControl::ForceRestart,
                            txn,
                        )
                        .await?;

                        let validation_id = MachineValidation::create_new_run(
                            txn,
                            &mh_snapshot.host_snapshot.machine_id,
                            "Cleanup".to_string(),
                            MachineValidationFilter::default(),
                        )
                        .await?;
                        // Link to machine
                        let next_state = ManagedHostState::HostInit {
                            machine_state: MachineState::MachineValidating {
                                context: "Cleanup".to_string(),
                                id: validation_id,
                                completed: 1,
                                total: 1,
                                is_enabled: self
                                    .host_handler
                                    .host_handler_params
                                    .machine_validation_config
                                    .enabled,
                            },
                        };
                        Ok(StateHandlerOutcome::Transition(next_state))
                    }
                    CleanupState::DisableBIOSBMCLockdown => {
                        tracing::error!(
                            machine_id = %host_machine_id,
                            "DisableBIOSBMCLockdown state is not implemented. Machine stuck in unimplemented state.",
                        );
                        Err(StateHandlerError::InvalidHostState(
                            host_machine_id.clone(),
                            Box::new(mh_state.clone()),
                        ))
                    }
                }
            }
            ManagedHostState::Created => {
                tracing::error!("Machine just created. We should not be here.");
                Err(StateHandlerError::InvalidHostState(
                    host_machine_id.clone(),
                    Box::new(mh_state.clone()),
                ))
            }
            ManagedHostState::ForceDeletion => {
                // Just ignore. Delete is done directly in api.rs::admin_force_delete_machine.
                tracing::info!(
                    machine_id = %host_machine_id,
                    "Machine is marked for forced deletion. Ignoring.",
                );
                Ok(StateHandlerOutcome::Deleted)
            }
            ManagedHostState::Failed {
                details,
                machine_id,
                retry_count,
            } => {
                match details.cause {
                    // DPU discovery failed needs more logic to handle.
                    // DPU discovery can failed from multiple states init,
                    // waitingfornetworkinstall, reprov(waitingforfirmwareupgrade),
                    // reprov(waitingfornetworkinstall). Error handler must be aware of it and
                    // handle based on it.
                    // Another bigger problem is every discovery will need a
                    // fresh os install as scout is executed by cloud-init and it runs only
                    // once after os install. This has to be changed.
                    FailureCause::Discovery { .. } if machine_id.machine_type().is_host() => {
                        // If user manually reboots host, and discovery is successful then also it will come out
                        // of failed state.
                        if discovered_after_state_transition(
                            mh_snapshot.host_snapshot.current.version,
                            mh_snapshot.host_snapshot.last_discovery_time,
                        ) {
                            ctx.metrics
                                .machine_reboot_attempts_in_failed_during_discovery =
                                Some(*retry_count as u64);
                            // Anytime host discovery is successful, move to next state.
                            Machine::clear_failure_details(machine_id, txn).await?;
                            let next_state = handler_host_lockdown(txn, ctx, mh_snapshot).await?;
                            return Ok(StateHandlerOutcome::Transition(next_state));
                        }

                        // Wait till failure_retry_time is over except first time.
                        // First time, host is already up and reported that discovery is failed.
                        // Let's reboot now immediately.
                        if *retry_count == 0 {
                            handler_host_power_control(
                                mh_snapshot,
                                ctx.services,
                                SystemPowerControl::ForceRestart,
                                txn,
                            )
                            .await?;
                            let next_state = ManagedHostState::Failed {
                                retry_count: retry_count + 1,
                                details: details.clone(),
                                machine_id: machine_id.clone(),
                            };
                            return Ok(StateHandlerOutcome::Transition(next_state));
                        }

                        if trigger_reboot_if_needed(
                            &mh_snapshot.host_snapshot,
                            mh_snapshot,
                            Some(*retry_count as i64),
                            &self.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?
                        .increase_retry_count
                        {
                            let next_state = ManagedHostState::Failed {
                                retry_count: retry_count + 1,
                                details: details.clone(),
                                machine_id: machine_id.clone(),
                            };
                            Ok(StateHandlerOutcome::Transition(next_state))
                        } else {
                            Ok(StateHandlerOutcome::DoNothing)
                        }
                    }
                    FailureCause::NVMECleanFailed { .. } if machine_id.machine_type().is_host() => {
                        if cleanedup_after_state_transition(
                            mh_snapshot.host_snapshot.current.version,
                            mh_snapshot.host_snapshot.last_cleanup_time,
                        ) && mh_snapshot.host_snapshot.failure_details.failed_at
                            < mh_snapshot
                                .host_snapshot
                                .last_cleanup_time
                                .unwrap_or_default()
                        {
                            // Cleaned up successfully after a failure.
                            let next_state = ManagedHostState::WaitingForCleanup {
                                cleanup_state: CleanupState::HostCleanup,
                            };
                            Machine::clear_failure_details(machine_id, txn)
                                .await
                                .map_err(StateHandlerError::from)?;
                            return Ok(StateHandlerOutcome::Transition(next_state));
                        }

                        if trigger_reboot_if_needed(
                            &mh_snapshot.host_snapshot,
                            mh_snapshot,
                            Some(*retry_count as i64),
                            &self.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?
                        .increase_retry_count
                        {
                            let next_state = ManagedHostState::Failed {
                                retry_count: retry_count + 1,
                                details: details.clone(),
                                machine_id: machine_id.clone(),
                            };
                            Ok(StateHandlerOutcome::Transition(next_state))
                        } else {
                            Ok(StateHandlerOutcome::DoNothing)
                        }
                    }
                    FailureCause::MeasurementsRetired { .. }
                    | FailureCause::MeasurementsRevoked { .. }
                    | FailureCause::MeasurementsCAValidationFailed { .. } => {
                        if check_if_not_in_original_failure_cause_anymore(
                            &mh_snapshot.host_snapshot.machine_id,
                            txn,
                            &details.cause,
                        )
                        .await?
                        {
                            // depending on the source of the failure, move it to the correct measuring state
                            match &details.source {
                                    FailureSource::StateMachineArea(area) => {
                                        match area{
                                            StateMachineArea::MainFlow => Ok(StateHandlerOutcome::Transition(
                                                ManagedHostState::Measuring {
                                                    measuring_state: MeasuringState::WaitingForMeasurements
                                                }
                                            )),
                                            StateMachineArea::HostInit => Ok(StateHandlerOutcome::Transition(
                                                ManagedHostState::HostInit {
                                                    machine_state: MachineState::Measuring{
                                                        measuring_state: MeasuringState::WaitingForMeasurements
                                                    }
                                                }
                                            )),
                                            StateMachineArea::AssignedInstance => Ok(StateHandlerOutcome::Transition(
                                                ManagedHostState::PostAssignedMeasuring {
                                                        measuring_state: MeasuringState::WaitingForMeasurements
                                                }
                                            )),
                                            _ => Err(StateHandlerError::InvalidState(
                                                "Unimplemented StateMachineArea for FailureSource of  MeasurementsRetired, MeasurementsRevoked, MeasurementsCAValidationFailed"
                                                    .to_string(),
                                            ))
                                        }
                                    },
                                    _ => Err(StateHandlerError::InvalidState(
                                        "The source of MeasurementsRetired, MeasurementsRevoked, MeasurementsCAValidationFailed can only be StateMachine"
                                            .to_string(),
                                    ))
                                }
                        } else {
                            Ok(StateHandlerOutcome::DoNothing)
                        }
                    }
                    FailureCause::MachineValidation { .. }
                        if machine_id.machine_type().is_host() =>
                    {
                        if is_machine_validation_requested(mh_snapshot).await {
                            //reboot the machine with new scout image
                            handler_host_power_control(
                                mh_snapshot,
                                ctx.services,
                                SystemPowerControl::ForceRestart,
                                txn,
                            )
                            .await?;
                            // Clear the error so that state machine doesnt get into loop
                            Machine::clear_failure_details(machine_id, txn)
                                .await
                                .map_err(StateHandlerError::from)?;
                            let machine_validation =
                            match MachineValidation::find_active_machine_validation_by_machine_id(
                                txn,
                                host_machine_id,
                            )
                            .await
                            {
                                Ok(data) => data,
                                Err(e) => {
                                    tracing::info!(
                                        error = %e,
                                        "find_active_machine_validation_by_machine_id"
                                    );
                                    Machine::set_machine_validation_request(txn, host_machine_id, true)
                                        .await
                                        .map_err(StateHandlerError::from)?;
                                    // Health Alert ?
                                    // Rare screnario, if something googfed up in DB
                                    return Ok(StateHandlerOutcome::DoNothing);
                                }
                            };

                            let next_state = ManagedHostState::HostInit {
                                machine_state: MachineState::MachineValidating {
                                    context: "OnDemand".to_string(),
                                    id: machine_validation.id,
                                    completed: 1,
                                    total: 1,
                                    is_enabled: self
                                        .host_handler
                                        .host_handler_params
                                        .machine_validation_config
                                        .enabled,
                                },
                            };
                            Ok(StateHandlerOutcome::Transition(next_state))
                        } else {
                            Ok(StateHandlerOutcome::DoNothing)
                        }
                    }
                    _ => {
                        // Do nothing.
                        // Handle error cause and decide how to recover if possible.
                        tracing::error!(
                            %machine_id,
                            "ManagedHost {} is in Failed state with machine/cause {}/{}. Failed at: {}, Ignoring.",
                            host_machine_id,
                            machine_id,
                            details.cause,
                            details.failed_at,
                        );
                        // TODO: Should this be StateHandlerError::ManualInterventionRequired ?
                        Ok(StateHandlerOutcome::DoNothing)
                    }
                }
            }
            ManagedHostState::DPUReprovision { .. } => {
                for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                    if let StateHandlerOutcome::Transition(next_state) = handle_dpu_reprovision(
                        mh_snapshot,
                        &self.reachability_params,
                        ctx.services,
                        txn,
                        &MachineNextStateResolver,
                        dpu_snapshot,
                        self.parsed_hosts.clone().as_ref(),
                    )
                    .await?
                    {
                        return Ok(StateHandlerOutcome::Transition(next_state));
                    }
                }
                Ok(StateHandlerOutcome::DoNothing)
            }

            ManagedHostState::HostReprovision { .. } => {
                if let Some(next_state) = self
                    .handle_host_reprovision(mh_snapshot, ctx.services, host_machine_id, txn)
                    .await?
                {
                    Ok(StateHandlerOutcome::Transition(next_state))
                } else {
                    Ok(StateHandlerOutcome::DoNothing)
                }
            }

            // ManagedHostState::Measuring is introduced into the flow when
            // attestation_enabled is set to true (defaults to false), and
            // is triggered when a machine being in Ready state suddently
            // ceases being attested
            ManagedHostState::Measuring { measuring_state } => {
                handle_measuring_state(measuring_state, &mh_snapshot.host_snapshot.machine_id, txn)
                    .await
                    .map(|v| map_measuring_outcome_to_state_handler_outcome(&v, measuring_state))?
            }
            ManagedHostState::PostAssignedMeasuring { measuring_state } => {
                handle_measuring_state(measuring_state, &mh_snapshot.host_snapshot.machine_id, txn)
                    .await
                    .map(|v| {
                        map_post_assigned_measuring_outcome_to_state_handler_outcome(
                            &v,
                            measuring_state,
                        )
                    })?
            }
        }
    }

    async fn handle_restart_dpu_reprovision_assigned_state(
        &self,
        state: &ManagedHostStateSnapshot,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        host_machine_id: &MachineId,
        dpus_for_reprov: &[&MachineSnapshot],
        upgrade_firmware: bool,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        // User approval must have received, otherwise reprovision has not
        // started.
        if let Err(err) =
            handler_host_power_control(state, ctx.services, SystemPowerControl::ForceRestart, txn)
                .await
        {
            tracing::error!(%host_machine_id, "Host reboot failed with error: {err}");
        }
        let next_reprov_state = if upgrade_firmware
            && self
                .instance_handler
                .dpu_nic_firmware_reprovision_update_enabled
        {
            ReprovisionState::BmcFirmwareUpgrade {
                substate: BmcFirmwareUpgradeSubstate::CheckFwVersion,
            }
        } else {
            set_managed_host_topology_update_needed(txn, &state.host_snapshot, dpus_for_reprov)
                .await?;
            ReprovisionState::WaitingForNetworkInstall
        };
        Ok(Some(next_reprov_state.next_state_with_all_dpus_updated(
            &state.managed_state,
            &state.dpu_snapshots,
            dpus_for_reprov.iter().map(|x| &x.machine_id).collect_vec(),
        )?))
    }

    async fn restart_dpu_reprovision(
        &self,
        managed_state: &ManagedHostState,
        state: &ManagedHostStateSnapshot,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        host_machine_id: &MachineId,
        upgrade_firmware: bool,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let mut next_state = None;

        let dpus_for_reprov = state
            .dpu_snapshots
            .iter()
            .filter(|x| x.reprovision_requested.is_some())
            .collect_vec();

        match managed_state {
            ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision { .. } | InstanceState::Failed { .. },
            } => {
                // If we are here means already reprovision is going on, as validated by
                // can_restart_reprovision fucntion.
                next_state = self
                    .handle_restart_dpu_reprovision_assigned_state(
                        state,
                        ctx,
                        txn,
                        host_machine_id,
                        &dpus_for_reprov,
                        upgrade_firmware,
                    )
                    .await?;

                for dpu in &dpus_for_reprov {
                    Machine::clear_failure_details(&dpu.machine_id, txn).await?;
                }
            }
            ManagedHostState::DPUReprovision { .. } => {
                let next_reprov_state = if upgrade_firmware {
                    ReprovisionState::BmcFirmwareUpgrade {
                        substate: BmcFirmwareUpgradeSubstate::CheckFwVersion,
                    }
                } else {
                    set_managed_host_topology_update_needed(
                        txn,
                        &state.host_snapshot,
                        &dpus_for_reprov,
                    )
                    .await?;
                    ReprovisionState::WaitingForNetworkInstall
                };

                next_state = Some(next_reprov_state.next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    dpus_for_reprov.iter().map(|x| &x.machine_id).collect_vec(),
                )?);
            }
            _ => {}
        };

        if next_state.is_some() {
            // Restart all DPUs, sit back and relax.
            for dpu in dpus_for_reprov {
                Machine::update_dpu_reprovision_start_time(&dpu.machine_id, txn).await?;
                handler_restart_dpu(dpu, ctx.services, txn).await?;
            }
            return Ok(next_state);
        }

        Ok(None)
    }

    // Handles when in HostReprovisioning or when entering it
    async fn handle_host_reprovision(
        &self,
        state: &ManagedHostStateSnapshot,
        services: &StateHandlerServices,
        machine_id: &MachineId,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        // Treat Ready (but flagged to do updates) the same as HostReprovisionState/CheckingFirmware
        let original_state = &state.managed_state;
        let managed_host_state = match &state.managed_state {
            ManagedHostState::HostReprovision { reprovision_state } => reprovision_state,
            ManagedHostState::Ready => &HostReprovisionState::CheckingFirmware,
            _ => {
                return Err(StateHandlerError::InvalidState(format!(
                    "Invalid state for calling handle_host_reprovision {:?}",
                    state.managed_state
                )))
            }
        };
        match managed_host_state {
            HostReprovisionState::CheckingFirmware => {
                self.host_checking_fw(state, services, machine_id, original_state, txn)
                    .await
            }
            HostReprovisionState::WaitingForFirmwareUpgrade {
                task_id,
                final_version,
                firmware_type,
            } => {
                self.host_waiting_fw(
                    HostWaitingFWArgs {
                        task_id: task_id.to_string(),
                        firmware_type: *firmware_type,
                        final_version: final_version.to_string(),
                    },
                    state,
                    services,
                    machine_id,
                    txn,
                )
                .await
            }
            HostReprovisionState::ResetForNewFirmware {
                final_version,
                firmware_type,
            } => {
                self.host_reset_for_new_firmware(
                    state,
                    services,
                    final_version,
                    firmware_type,
                    machine_id,
                    txn,
                )
                .await
            }
            HostReprovisionState::NewFirmwareReportedWait {
                final_version,
                firmware_type,
            } => {
                self.host_new_firmware_reported_wait(
                    state,
                    final_version,
                    firmware_type,
                    machine_id,
                    txn,
                )
                .await
            }
            HostReprovisionState::FailedFirmwareUpgrade { .. } => Ok(None),
        }
    }

    async fn host_checking_fw(
        &self,
        state: &ManagedHostStateSnapshot,
        services: &StateHandlerServices,
        machine_id: &MachineId,
        original_state: &ManagedHostState,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let mut ret = self
            .host_checking_fw_noclear(state, services, machine_id, txn)
            .await?;

        if ret == Some(original_state.clone()) {
            // host_checking_fw_noclear can return Ready to indicate that we're moving out of CheckingFirmware,
            // but we also take this path when we're actually in Ready - for that case, return Ok(None) so that
            // we don't keep retransitioning to the same state.
            ret = None;
        }

        // Check if we are returning to the ready state, and clear the host reprovisioning request if so.
        if let Some(ret) = &ret {
            match ret {
                ManagedHostState::HostReprovision { .. } => {}
                _ => {
                    Machine::clear_host_reprovisioning_request(txn, machine_id).await?;
                }
            };
        }

        Ok(ret)
    }
    async fn host_checking_fw_noclear(
        &self,
        state: &ManagedHostStateSnapshot,
        services: &StateHandlerServices,
        machine_id: &MachineId,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let Some(explored_endpoint) =
            find_explored_refreshed_endpoint(state, machine_id, txn).await?
        else {
            // find_explored_refreshed_endpoint's behavior is to return None to indicate we're waiting for an update, not to indicate there isn't anything.

            tracing::debug!("Managed host {machine_id} waiting for site explorer to revisit");
            return Ok(Some(ManagedHostState::HostReprovision {
                reprovision_state: HostReprovisionState::CheckingFirmware,
            }));
        };

        let Some(fw_info) = self.parsed_hosts.find_fw_info_for_host(&explored_endpoint) else {
            return Ok(Some(ManagedHostState::Ready));
        };

        for firmware_type in fw_info.ordering() {
            if let Some(to_install) =
                need_host_fw_upgrade(&explored_endpoint, &fw_info, firmware_type)
            {
                tracing::debug!(
                    "Installing {:?} on {}",
                    to_install,
                    explored_endpoint.address
                );

                match self
                    .initiate_host_fw_update(
                        explored_endpoint.address,
                        services,
                        &to_install,
                        &state.host_snapshot,
                        &firmware_type,
                        txn,
                    )
                    .await?
                {
                    Some(task_id) => {
                        // Upload complete and updated started, will monitor task in future iterations
                        return Ok(Some(ManagedHostState::HostReprovision {
                            reprovision_state: HostReprovisionState::WaitingForFirmwareUpgrade {
                                task_id,
                                firmware_type,
                                final_version: to_install.version,
                            },
                        }));
                    }
                    None => {
                        // Deferred upload due to download or other reason, recheck later
                        return Ok(Some(ManagedHostState::HostReprovision {
                            reprovision_state: HostReprovisionState::CheckingFirmware,
                        }));
                    }
                };
            }
        }

        // Nothing needs updates, return to ready.  But first, we may need to reenable lockdown.

        let redfish_client = services
            .redfish_client_pool
            .create_client_from_machine_snapshot(&state.host_snapshot, txn)
            .await?;

        match redfish_client.lockdown_status().await {
            Err(RedfishError::NotSupported(_)) => Ok(Some(ManagedHostState::Ready)),
            Err(e) => {
                tracing::warn!("Could not get lockdown status for {machine_id}: {e}",);
                Ok(None)
            }
            Ok(status) if status.is_fully_disabled() => {
                tracing::debug!("host firmware update: Reenabling lockdown");
                // Already disabled, we need to reenable.
                if let Err(e) = redfish_client
                    .lockdown(libredfish::EnabledDisabled::Enabled)
                    .await
                {
                    tracing::error!("Could not set lockdown for {machine_id}: {e}");
                    return Ok(None);
                }
                // Reenabling lockdown can require us to wait for the DPU to become available again due to resets, we cannot go directly to Ready.
                Ok(Some(ManagedHostState::HostInit {
                    machine_state: MachineState::WaitingForLockdown {
                        lockdown_info: LockdownInfo {
                            state: LockdownState::TimeWaitForDPUDown,
                            mode: Enable,
                        },
                    },
                }))
            }
            _ => {
                tracing::debug!("host firmware update: Don't need to reenable lockdown");
                Ok(Some(ManagedHostState::Ready))
            }
        }
    }

    /// Uploads a firmware update via multipart, returning the task ID, or None if upload was deferred
    async fn initiate_host_fw_update(
        &self,
        address: IpAddr,
        services: &StateHandlerServices,
        to_install: &FirmwareEntry,
        snapshot: &MachineSnapshot,
        component_type: &FirmwareComponentType,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<Option<String>, StateHandlerError> {
        if !self
            .downloader
            .available(
                &to_install.get_filename(),
                &to_install.get_url(),
                &to_install.get_checksum(),
            )
            .await
        {
            tracing::debug!(
                "{} is being downloaded from {}, update deferred",
                to_install.get_filename().display(),
                to_install.get_url()
            );

            return Ok(None);
        }

        let Ok(_active) = self.upload_limiter.try_acquire() else {
            tracing::debug!(
                "Deferring installation of {:?} on {}, too many uploads already active",
                to_install,
                snapshot.machine_id,
            );
            return Ok(None);
        };

        // Setup the Redfish connection
        let redfish_client = services
            .redfish_client_pool
            .create_client_from_machine_snapshot(snapshot, txn)
            .await?;

        match redfish_client.lockdown_status().await {
            Err(e) => {
                tracing::warn!(
                    "Could not get lockdown status for {}: {e}",
                    address.to_string()
                );
                return Ok(None);
            }
            Ok(status) if status.is_fully_disabled() => {
                // Already disabled, we can go ahead
                tracing::debug!("Host fw update: No need for disabling lockdown");
            }
            _ => {
                tracing::debug!("Host fw update: Disabling lockdown");
                if let Err(e) = redfish_client
                    .lockdown(libredfish::EnabledDisabled::Disabled)
                    .await
                {
                    tracing::warn!("Could not set lockdown for {}: {e}", address.to_string());
                    return Ok(None);
                }
            }
        };

        let redfish_component_type: libredfish::model::update_service::ComponentType =
            match to_install.install_only_specified {
                false => libredfish::model::update_service::ComponentType::Unknown,
                true => (*component_type).into(),
            };
        let task = match redfish_client
            .update_firmware_multipart(
                to_install.get_filename().as_path(),
                true,
                std::time::Duration::from_secs(120),
                redfish_component_type,
            )
            .await
        {
            Ok(task) => task,
            Err(e) => {
                tracing::warn!("Failed uploading firmware to {}: {e}", address.to_string());
                return Ok(None);
            }
        };

        Ok(Some(task))
    }

    async fn host_waiting_fw(
        &self,
        args: HostWaitingFWArgs,
        state: &ManagedHostStateSnapshot,
        services: &StateHandlerServices,
        machine_id: &MachineId,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let address = state
            .host_snapshot
            .bmc_info
            .ip_addr()
            .map_err(StateHandlerError::GenericError)?;
        // Setup the Redfish connection
        let redfish_client = services
            .redfish_client_pool
            .create_client_from_machine_snapshot(&state.host_snapshot, txn)
            .await?;

        match redfish_client.get_task(args.task_id.as_str()).await {
            Ok(task_info) => {
                match task_info.task_state {
                    Some(TaskState::New)
                    | Some(TaskState::Starting)
                    | Some(TaskState::Running)
                    | Some(TaskState::Pending) => {
                        tracing::debug!(
                            "Upgrade task for {} not yet complete, current state {:?} message {:?}",
                            machine_id,
                            task_info.task_state,
                            task_info.messages,
                        );
                        Ok(None)
                    }
                    Some(TaskState::Completed) => {
                        // Task has completed, update is done and we can clean up.  Site explorer will ingest this next time it runs on this endpoint.
                        tracing::debug!(
                            "Saw completion of host firmware upgrade task for {}",
                            machine_id
                        );

                        Ok(Some(ManagedHostState::HostReprovision {
                            reprovision_state: HostReprovisionState::ResetForNewFirmware {
                                final_version: args.final_version.to_string(),
                                firmware_type: args.firmware_type,
                            },
                        }))
                    }
                    Some(TaskState::Exception)
                    | Some(TaskState::Interrupted)
                    | Some(TaskState::Killed)
                    | Some(TaskState::Cancelled) => {
                        tracing::debug!(
                            "Failure in firmware upgrade for {}: {} {:?}",
                            machine_id,
                            task_info.task_state.unwrap(),
                            task_info
                                .messages
                                .last()
                                .map_or("".to_string(), |m| m.message.clone())
                        );

                        // We need site explorer to requery the version, just in case it actually did get done
                        DbExploredEndpoint::set_waiting_for_explorer_refresh(address, txn).await?;
                        Ok(Some(ManagedHostState::HostReprovision {
                            reprovision_state: HostReprovisionState::CheckingFirmware,
                        }))
                    }
                    _ => {
                        // Unexpected state
                        tracing::warn!(
                            "Unrecognized task state for {}: {:?}",
                            machine_id,
                            task_info.task_state
                        );
                        // For now, a force delete will be needed to recover from this state
                        Ok(Some(ManagedHostState::HostReprovision {
                            reprovision_state: HostReprovisionState::FailedFirmwareUpgrade {
                                firmware_type: args.firmware_type,
                            },
                        }))
                    }
                }
            }
            Err(e) => match e {
                RedfishError::HTTPErrorCode { status_code, .. } => {
                    if status_code == NOT_FOUND {
                        // Dells (maybe others) have been observed to not have report the job any more after completing a host reboot for a UEFI upgrade.  If we get a 404 but see that we're at the right version, we're done with that upgrade.
                        let Some(endpoint) =
                            find_explored_refreshed_endpoint(state, machine_id, txn).await?
                        else {
                            return Ok(None);
                        };

                        if let Some(fw_info) = self.parsed_hosts.find_fw_info_for_host(&endpoint) {
                            if let Some(current_version) =
                                endpoint.find_version(&fw_info, args.firmware_type)
                            {
                                if current_version == args.final_version {
                                    tracing::info!(
                                    "Marking completion of Redfish task of firmware upgrade for {} with missing task",
                                    &endpoint.address
                                );
                                    return Ok(Some(ManagedHostState::HostReprovision {
                                        reprovision_state: HostReprovisionState::CheckingFirmware,
                                    }));
                                }
                            }
                        }
                    }
                    Err(StateHandlerError::RedfishError {
                        operation: "get_task",
                        error: e,
                    })
                }
                _ => Err(StateHandlerError::RedfishError {
                    operation: "get_task",
                    error: e,
                }),
            },
        }
    }

    async fn host_reset_for_new_firmware(
        &self,
        state: &ManagedHostStateSnapshot,
        services: &StateHandlerServices,
        final_version: &str,
        firmware_type: &FirmwareComponentType,
        machine_id: &MachineId,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let Some(endpoint) = find_explored_refreshed_endpoint(state, machine_id, txn).await? else {
            tracing::debug!("Waiting for site explorer to revisit {machine_id}");
            return Ok(None);
        };

        if firmware_type.is_uefi() {
            tracing::debug!(
                "Upgrade task has completed for {} but needs reboot, initiating one",
                &endpoint.address
            );
            handler_host_power_control(state, services, SystemPowerControl::ForceRestart, txn)
                .await?;

            // Same state but with the rebooted flag set, it can take a long time to reboot in some cases so we do not retry.
        }

        if firmware_type.is_bmc()
            && !endpoint
                .report
                .vendor
                .unwrap_or(bmc_vendor::BMCVendor::Unknown)
                .is_dell()
        {
            tracing::debug!(
                "Upgrade task has completed for {} but needs BMC reboot, initiating one",
                &endpoint.address
            );
            let redfish_client = build_redfish_client_from_bmc_ip(
                state.host_snapshot.bmc_addr(),
                &services.redfish_client_pool,
                txn,
            )
            .await?;

            if let Err(e) = redfish_client.bmc_reset().await {
                tracing::warn!("Failed to reboot {}: {e}", &endpoint.address);
                return Ok(None);
            }
        }

        if *firmware_type == FirmwareComponentType::HGXBmc {
            // Needs a host power reset
            let redfish_client = build_redfish_client_from_bmc_ip(
                state.host_snapshot.bmc_addr(),
                &services.redfish_client_pool,
                txn,
            )
            .await?;
            if let Err(e) = redfish_client.power(SystemPowerControl::ForceOff).await {
                tracing::error!("Failed to power off {}: {e}", &endpoint.address);
                return Ok(None);
            }
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            if let Err(e) = redfish_client.power(SystemPowerControl::On).await {
                tracing::error!("Failed to power on {}: {e}", &endpoint.address);
                return Ok(None);
            }
            // Okay to proceed
        }

        // Now we can go on to waiting for the correct version to be reported
        Ok(Some(ManagedHostState::HostReprovision {
            reprovision_state: HostReprovisionState::NewFirmwareReportedWait {
                firmware_type: *firmware_type,
                final_version: final_version.to_string(),
            },
        }))
    }

    async fn host_new_firmware_reported_wait(
        &self,
        state: &ManagedHostStateSnapshot,
        final_version: &str,
        firmware_type: &FirmwareComponentType,
        machine_id: &MachineId,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let Some(endpoint) = find_explored_refreshed_endpoint(state, machine_id, txn).await? else {
            tracing::debug!("Waiting for site explorer to revisit {machine_id}");
            return Ok(None);
        };

        let Some(fw_info) = self.parsed_hosts.find_fw_info_for_host(&endpoint) else {
            tracing::error!("Could no longer find firmware info for {machine_id}");
            return Ok(Some(ManagedHostState::HostReprovision {
                reprovision_state: HostReprovisionState::CheckingFirmware,
            }));
        };
        let Some(current_version) = endpoint.find_version(&fw_info, *firmware_type) else {
            tracing::error!("Could no longer find current version for {machine_id}");
            return Ok(Some(ManagedHostState::HostReprovision {
                reprovision_state: HostReprovisionState::CheckingFirmware,
            }));
        };

        if current_version == final_version {
            // Done waiting, go back to overall checking of versions
            tracing::debug!("Done waiting for {machine_id} to reach version");
            Ok(Some(ManagedHostState::HostReprovision {
                reprovision_state: HostReprovisionState::CheckingFirmware,
            }))
        } else {
            tracing::debug!("Waiting for {machine_id} to reach version {final_version} currently {current_version}");
            DbExploredEndpoint::re_explore_if_version_matches(
                endpoint.address,
                endpoint.report_version,
                txn,
            )
            .await?;
            Ok(None)
        }
    }
}

/// need_host_fw_upgrade determines if the given endpoint needs a firmware upgrade based on the description in fw_info, and if so returns the FirmwareEntry matching the desired upgrade.
fn need_host_fw_upgrade(
    endpoint: &ExploredEndpoint,
    fw_info: &Firmware,
    firmware_type: FirmwareComponentType,
) -> Option<FirmwareEntry> {
    // Determining if we've disabled upgrades for this host is determined in machine_update_manager, not here; if it was disabled, nothing kicks it out of Ready.

    // First, find the current version.
    let Some(current_version) = endpoint.report.versions.get(&firmware_type) else {
        // Not listed, so we couldn't do an upgrade
        return None;
    };

    // Now find the desired version, if it's not the version that is currently installed.
    fw_info
        .components
        .get(&firmware_type)?
        .known_firmware
        .iter()
        .find(|x| x.default && x.version != *current_version)
        .cloned()
}

/// This function checks if reprovisioning is requested of a given DPU or not.
fn dpu_reprovisioning_needed(dpu_snapshots: &[MachineSnapshot]) -> bool {
    dpu_snapshots
        .iter()
        .any(|x| x.reprovision_requested.is_some())
}

// Function to wait for some time in state machine.
fn wait(basetime: &DateTime<Utc>, wait_time: Duration) -> bool {
    let expected_time = *basetime + wait_time;
    let current_time = Utc::now();

    current_time < expected_time
}

fn is_dpu_up(state: &ManagedHostStateSnapshot, dpu_snapshot: &MachineSnapshot) -> bool {
    let observation_time = dpu_snapshot
        .network_status_observation
        .as_ref()
        .map(|o| o.observed_at)
        .unwrap_or(DateTime::<Utc>::MIN_UTC);
    let state_change_time = state.host_snapshot.current.version.timestamp();

    if observation_time < state_change_time {
        return false;
    }

    true
}

/// are_dpus_up_trigger_reboot_if_needed returns true if the dpu_agent indicates that the DPU has rebooted and is healthy.
/// otherwise returns false. triggers a reboot in case the DPU is down/bricked.
async fn are_dpus_up_trigger_reboot_if_needed(
    state: &ManagedHostStateSnapshot,
    reachability_params: &ReachabilityParams,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> bool {
    for dpu_snapshot in &state.dpu_snapshots {
        if !is_dpu_up(state, dpu_snapshot) {
            match reboot_if_needed(state, dpu_snapshot, reachability_params, services, txn).await {
                Ok(_) => {}
                Err(e) => tracing::warn!("could not reboot dpu {}: {e}", dpu_snapshot.machine_id),
            }
            return false;
        }
    }

    true
}

#[async_trait::async_trait]
impl StateHandler for MachineStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ContextObjects = MachineStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        mh_snapshot: &mut ManagedHostStateSnapshot,
        _mh_state: &Self::ControllerState, // mh_snapshot above already contains it
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        if !mh_snapshot
            .host_snapshot
            .associated_dpu_machine_ids()
            .is_empty()
            && mh_snapshot.dpu_snapshots.is_empty()
        {
            return Err(StateHandlerError::GenericError(eyre!(
                "No DPU snapshot found."
            )));
        }
        self.record_metrics(mh_snapshot, ctx);
        self.attempt_state_transition(host_machine_id, mh_snapshot, txn, ctx)
            .await
    }
}

fn map_measuring_outcome_to_state_handler_outcome(
    measuring_outcome: &MeasuringOutcome,
    measuring_state: &MeasuringState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    match measuring_outcome {
        MeasuringOutcome::NoChange => Ok(StateHandlerOutcome::Wait(
            match measuring_state {
                MeasuringState::WaitingForMeasurements => {
                    "Waiting for machine to send measurement report"
                }
                MeasuringState::PendingBundle => {
                    "Waiting for matching measurement bundle for machine profile"
                }
            }
            .to_string(),
        )),
        MeasuringOutcome::WaitForGoldenValues => Ok(StateHandlerOutcome::Transition(
            ManagedHostState::Measuring {
                measuring_state: MeasuringState::PendingBundle,
            },
        )),
        MeasuringOutcome::WaitForScoutToSendMeasurements => Ok(StateHandlerOutcome::Transition(
            ManagedHostState::Measuring {
                measuring_state: MeasuringState::WaitingForMeasurements,
            },
        )),
        MeasuringOutcome::Unsuccessful((failure_details, machine_id)) => {
            Ok(StateHandlerOutcome::Transition(ManagedHostState::Failed {
                details: FailureDetails {
                    cause: failure_details.cause.clone(),
                    failed_at: failure_details.failed_at,
                    source: FailureSource::StateMachineArea(StateMachineArea::MainFlow),
                },
                machine_id: machine_id.clone(),
                retry_count: 0,
            }))
        }
        MeasuringOutcome::PassedOk => Ok(StateHandlerOutcome::Transition(ManagedHostState::Ready)),
    }
}

fn map_host_init_measuring_outcome_to_state_handler_outcome(
    measuring_outcome: &MeasuringOutcome,
    measuring_state: &MeasuringState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    match measuring_outcome {
        MeasuringOutcome::NoChange => Ok(StateHandlerOutcome::Wait(
            match measuring_state {
                MeasuringState::WaitingForMeasurements => {
                    "Waiting for machine to send measurement report"
                }
                MeasuringState::PendingBundle => {
                    "Waiting for matching measurement bundle for machine profile"
                }
            }
            .to_string(),
        )),
        MeasuringOutcome::WaitForGoldenValues => Ok(StateHandlerOutcome::Transition(
            ManagedHostState::HostInit {
                machine_state: MachineState::Measuring {
                    measuring_state: MeasuringState::PendingBundle,
                },
            },
        )),
        MeasuringOutcome::WaitForScoutToSendMeasurements => Ok(StateHandlerOutcome::Transition(
            ManagedHostState::HostInit {
                machine_state: MachineState::Measuring {
                    measuring_state: MeasuringState::WaitingForMeasurements,
                },
            },
        )),
        MeasuringOutcome::Unsuccessful((failure_details, machine_id)) => {
            Ok(StateHandlerOutcome::Transition(ManagedHostState::Failed {
                details: FailureDetails {
                    cause: failure_details.cause.clone(),
                    failed_at: failure_details.failed_at,
                    source: FailureSource::StateMachineArea(StateMachineArea::HostInit),
                },
                machine_id: machine_id.clone(),
                retry_count: 0,
            }))
        }
        MeasuringOutcome::PassedOk => Ok(StateHandlerOutcome::Transition(
            ManagedHostState::HostInit {
                machine_state: MachineState::WaitingForDiscovery,
            },
        )),
    }
}

fn map_post_assigned_measuring_outcome_to_state_handler_outcome(
    measuring_outcome: &MeasuringOutcome,
    measuring_state: &MeasuringState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    match measuring_outcome {
        MeasuringOutcome::NoChange => Ok(StateHandlerOutcome::Wait(
            match measuring_state {
                MeasuringState::WaitingForMeasurements => {
                    "Waiting for machine to send measurement report"
                }
                MeasuringState::PendingBundle => {
                    "Waiting for matching measurement bundle for machine profile"
                }
            }
            .to_string(),
        )),
        MeasuringOutcome::WaitForGoldenValues => Ok(StateHandlerOutcome::Transition(
            ManagedHostState::PostAssignedMeasuring {
                measuring_state: MeasuringState::PendingBundle,
            },
        )),
        MeasuringOutcome::WaitForScoutToSendMeasurements => Ok(StateHandlerOutcome::Transition(
            ManagedHostState::PostAssignedMeasuring {
                measuring_state: MeasuringState::WaitingForMeasurements,
            },
        )),
        MeasuringOutcome::Unsuccessful((failure_details, machine_id)) => {
            Ok(StateHandlerOutcome::Transition(ManagedHostState::Failed {
                details: FailureDetails {
                    cause: failure_details.cause.clone(),
                    failed_at: failure_details.failed_at,
                    source: FailureSource::StateMachineArea(StateMachineArea::AssignedInstance),
                },
                machine_id: machine_id.clone(),
                retry_count: 0,
            }))
        }
        MeasuringOutcome::PassedOk => Ok(StateHandlerOutcome::Transition(
            ManagedHostState::WaitingForCleanup {
                cleanup_state: CleanupState::HostCleanup,
            },
        )),
    }
}

// this is called when we are in the Ready state and checking
// if everything is ok in general
async fn check_if_should_redo_measurements(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<bool, StateHandlerError> {
    let (machine_state, ek_cert_verification_status) =
        get_measuring_prerequisites(machine_id, txn).await?;

    if !ek_cert_verification_status.signing_ca_found {
        return Ok(true);
    }
    match machine_state {
        MeasurementMachineState::Measured => Ok(false),
        _ => Ok(true),
    }
}

async fn check_if_not_in_original_failure_cause_anymore(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    original_failure_cause: &FailureCause,
) -> Result<bool, StateHandlerError> {
    let (_, ek_cert_verification_status) = get_measuring_prerequisites(machine_id, txn).await?;

    // if the failure cause was ca validation and it no longer is, then we can try
    // transitioning to the Measuring state to see where that takes us further
    if enum_discr(original_failure_cause)
        == enum_discr(&FailureCause::MeasurementsCAValidationFailed {
            err: "Dummy error".to_string(),
        })
        && ek_cert_verification_status.signing_ca_found
    {
        return Ok(true);
    }

    let current_failure_cause = super::get_measurement_failure_cause(txn, machine_id).await;

    if let Ok(current_failure_cause) = current_failure_cause {
        match original_failure_cause {
            FailureCause::MeasurementsRetired { .. } => {
                // if current/latest failure cause is the same
                // do nothing
                if enum_discr(&current_failure_cause)
                    == enum_discr(&FailureCause::MeasurementsRetired {
                        err: "Dummy error".to_string(),
                    })
                {
                    Ok(false) // nothing has changed
                } else {
                    Ok(true) // the state has changed
                }
            }
            FailureCause::MeasurementsRevoked { .. } => {
                // if current/latest failure cause is the same
                // do nothing
                if enum_discr(&current_failure_cause)
                    == enum_discr(&FailureCause::MeasurementsRevoked {
                        err: "Dummy error".to_string(),
                    })
                {
                    Ok(false) // nothing has changed
                } else {
                    Ok(true) // the state has changed
                }
            }
            FailureCause::MeasurementsCAValidationFailed { .. } => {
                if ek_cert_verification_status.signing_ca_found {
                    Ok(true) // it has changed
                } else {
                    Ok(false) // nothing has changed
                }
            }
            _ => Ok(true), // it has definitely changed (although we shouldn't be here)
        }
    } else {
        Ok(true) // something has definitely changed
    }
}

/// Return `DpuModel` if the explored endpoint is a DPU
pub fn identify_dpu(dpu_snapshot: &MachineSnapshot) -> DpuModel {
    let model = dpu_snapshot
        .hardware_info
        .as_ref()
        .and_then(|hi| {
            hi.dpu_info
                .as_ref()
                .map(|di| di.part_description.to_string())
        })
        .unwrap_or("".to_string());
    model.into()
}

async fn component_update(
    redfish: &dyn Redfish,
    component: FirmwareComponentType,
    component_value: &FirmwareEntry,
) -> Result<Option<Task>, StateHandlerError> {
    let redfish_component_name = match component {
        // Note: DPU uses different name for BMC Firmware as
        // BF2: 6d53cf4d_BMC_Firmware
        // BF3: BMC_Firmware
        FirmwareComponentType::Bfb => "DPU_OS",
        FirmwareComponentType::Bmc => "BMC_Firmware",
        FirmwareComponentType::Uefi => "DPU_UEFI",
        FirmwareComponentType::Cec => "Bluefield_FW_ERoT",
        _ => "Unknown",
    };
    let inventories =
        redfish
            .get_software_inventories()
            .await
            .map_err(|e| StateHandlerError::RedfishError {
                operation: "get_software_inventories",
                error: e,
            })?;

    let inventory_id = inventories
        .iter()
        .find(|i| i.contains(redfish_component_name))
        .ok_or(StateHandlerError::FirmwareUpdateError(eyre!(
            "No inventory found that matches: {}",
            redfish_component_name
        )))?;

    let inventory = match redfish.get_firmware(inventory_id).await {
        Ok(inventory) => inventory,
        Err(e) => {
            tracing::error!("redfish command get_firmware error {}", e.to_string());
            return Err(StateHandlerError::RedfishError {
                operation: "get_firmware",
                error: e,
            });
        }
    };

    if inventory.version.is_none() {
        let msg = format!("Unknown {:?} version", component);
        tracing::error!(msg);
        return Err(StateHandlerError::FirmwareUpdateError(eyre!(msg)));
    };

    let cur_version = inventory.version.unwrap_or("0".to_string());
    let update_version = &component_value.version;

    match version_compare::compare_to(
        cur_version.clone(),
        update_version,
        version_compare::Cmp::Ge,
    ) {
        Ok(update_is_not_needed) => {
            if update_is_not_needed {
                return Ok(None);
            }
        }
        Err(e) => {
            return Err(StateHandlerError::FirmwareUpdateError(eyre!(
                    "Could not compare firmware versions (cur_version: {cur_version}, update_version: {update_version}): {e:#?}",
                )));
        }
    };

    let update_path = component_value.filename.as_ref().unwrap();
    let update_file = File::open(update_path).await.map_err(|e| {
        StateHandlerError::FirmwareUpdateError(eyre!(
            "Failed to open {:?} path {} with error {}",
            component,
            update_path,
            e.to_string()
        ))
    })?;

    tracing::info!("Updating {redfish_component_name} from {cur_version} to {update_version}");
    match redfish.update_firmware(update_file).await {
        Ok(task) => Ok(Some(task)),
        Err(e) => {
            tracing::error!("redfish command update_firmware error {}", e.to_string());
            Err(StateHandlerError::RedfishError {
                operation: "update_firmware",
                error: e,
            })
        }
    }
}

async fn handle_dpu_reprovision_bmc_firmware_upgrade(
    state: &ManagedHostStateSnapshot,
    substate: &BmcFirmwareUpgradeSubstate,
    dpu_snapshot: &MachineSnapshot,
    hardware_models: &FirmwareConfig,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    match substate {
        BmcFirmwareUpgradeSubstate::Failed { .. } => Ok(StateHandlerOutcome::DoNothing),
        BmcFirmwareUpgradeSubstate::CheckFwVersion => {
            let dpu_redfish_client_result = build_redfish_client_from_bmc_ip(
                dpu_snapshot.bmc_addr(),
                &services.redfish_client_pool,
                txn,
            )
            .await;

            let dpu_redfish_client = match dpu_redfish_client_result {
                Ok(redfish_client) => redfish_client,
                Err(e) => {
                    return Ok(StateHandlerOutcome::Wait(format!(
                        "Waiting for RedFish to become available: {:?}",
                        e
                    )))
                }
            };

            let model = identify_dpu(dpu_snapshot);
            if let Some(dpu_desc) =
                hardware_models.find(bmc_vendor::BMCVendor::Nvidia, model.to_string())
            {
                let mut ordering = dpu_desc.ordering.clone();
                if ordering.is_empty() {
                    ordering.push(FirmwareComponentType::Bmc);
                    ordering.push(FirmwareComponentType::Cec);
                }

                for dpu_component in ordering {
                    if let Some(dpu_component_value) = dpu_desc.components.get(&dpu_component) {
                        if !dpu_component_value.known_firmware.is_empty() {
                            let task = component_update(
                                &*dpu_redfish_client,
                                dpu_component,
                                &dpu_component_value.known_firmware[0],
                            )
                            .await?;
                            if task.is_some() {
                                let next_state = ReprovisionState::BmcFirmwareUpgrade {
                                    substate: BmcFirmwareUpgradeSubstate::WaitForUpdateCompletion {
                                        firmware_type: dpu_component,
                                        task_id: task.unwrap().id,
                                    },
                                }
                                .next_bmc_updrade_step(state, dpu_snapshot)?;
                                return Ok(StateHandlerOutcome::Transition(next_state));
                            };
                        }
                    }
                }
            }

            Ok(StateHandlerOutcome::Transition(
                ReprovisionState::BmcFirmwareUpgrade {
                    substate: BmcFirmwareUpgradeSubstate::FwUpdateCompleted,
                }
                .next_bmc_updrade_step(state, dpu_snapshot)?,
            ))
        }
        BmcFirmwareUpgradeSubstate::FwUpdateCompleted => {
            // Sync all DPUs before transition to the next state
            let mut dpus_for_reprov = vec![];
            let dpus_states_for_reprov = &state
                .dpu_snapshots
                .iter()
                .filter_map(|x| {
                    if x.reprovision_requested.is_some() {
                        dpus_for_reprov.push(x);
                        state
                            .managed_state
                            .as_reprovision_state(&dpu_snapshot.machine_id)
                    } else {
                        None
                    }
                })
                .collect_vec();

            if !all_equal(dpus_states_for_reprov)? {
                return Ok(StateHandlerOutcome::Wait(
                    "Waiting for DPUs to come in BmcFirmwareUpgradeSubstate::FwUpdateCompleted"
                        .to_string(),
                ));
            }

            for dpu_snapshot in &dpus_for_reprov {
                handler_restart_dpu(dpu_snapshot, services, txn).await?;
            }

            Ok(StateHandlerOutcome::Transition(
                ReprovisionState::FirmwareUpgrade.next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    dpus_for_reprov.iter().map(|x| &x.machine_id).collect_vec(),
                )?,
            ))
        }
        BmcFirmwareUpgradeSubstate::WaitForUpdateCompletion {
            firmware_type,
            task_id,
        } => {
            let dpu_redfish_client = build_redfish_client_from_bmc_ip(
                dpu_snapshot.bmc_addr(),
                &services.redfish_client_pool,
                txn,
            )
            .await?;

            let task = dpu_redfish_client.get_task(task_id).await.map_err(|e| {
                StateHandlerError::RedfishError {
                    operation: "get_task",
                    error: e,
                }
            })?;

            tracing::info!("{:?} FW update task: {:#?}", firmware_type, task);

            match task.task_state {
                Some(TaskState::Completed) => {
                    let next_state = ReprovisionState::BmcFirmwareUpgrade {
                        substate: BmcFirmwareUpgradeSubstate::Reboot { count: 0 },
                    }
                    .next_bmc_updrade_step(state, dpu_snapshot)?;

                    if *firmware_type == FirmwareComponentType::Cec {
                        match dpu_redfish_client
                            .chassis_reset("Bluefield_ERoT", SystemPowerControl::GracefulRestart)
                            .await
                        {
                            Ok(()) => Ok(StateHandlerOutcome::Transition(next_state)),
                            Err(e) if e.to_string().contains("is not supported") => {
                                tracing::warn!("Chassis reset is not supported by current CEC FW, triggering host power cycle");
                                Ok(StateHandlerOutcome::Transition(
                                    ReprovisionState::BmcFirmwareUpgrade {
                                        substate: BmcFirmwareUpgradeSubstate::HostPowerCycle,
                                    }
                                    .next_bmc_updrade_step(state, dpu_snapshot)?,
                                ))
                            }
                            Err(e) => Err(StateHandlerError::RedfishError {
                                operation: "chassis_reset",
                                error: e,
                            }),
                        }
                    } else {
                        dpu_redfish_client.bmc_reset().await.map_err(|e| {
                            StateHandlerError::RedfishError {
                                operation: "bmc_reset",
                                error: e,
                            }
                        })?;

                        Ok(StateHandlerOutcome::Transition(next_state))
                    }
                }
                Some(TaskState::Exception) => {
                    let msg = format!(
                        "Failed to update FW:  {:#?}",
                        task.messages
                            .last()
                            .map_or("".to_string(), |m| m.message.clone())
                    );

                    tracing::error!(msg);
                    let next_state = ReprovisionState::BmcFirmwareUpgrade {
                        substate: BmcFirmwareUpgradeSubstate::Failed {
                            failure_details: msg,
                        },
                    }
                    .next_bmc_updrade_step(state, dpu_snapshot)?;

                    Ok(StateHandlerOutcome::Transition(next_state))
                }
                Some(_) => {
                    // TODO: Are any of these states an error? Or we're waiting for something
                    Ok(StateHandlerOutcome::DoNothing)
                }
                None => Err(StateHandlerError::GenericError(eyre!(
                    "No task state field in task: {:#?}",
                    task
                ))),
            }
        }
        BmcFirmwareUpgradeSubstate::HostPowerCycle => {
            let mut dpu_ids_for_reprovisioning = Vec::new();
            let dpus_states_for_reprov = &state
                .dpu_snapshots
                .iter()
                .filter_map(|x| {
                    if x.reprovision_requested.is_some() {
                        dpu_ids_for_reprovisioning.push(dpu_snapshot.machine_id.clone());
                        state
                            .managed_state
                            .as_reprovision_state(&dpu_snapshot.machine_id)
                    } else {
                        None
                    }
                })
                .collect_vec();

            // Wait for all DPUs to be in sync in whether HostPowerCycle state (if it did CEC FW update)
            // or in the FwUpdateCompleted susbstate.
            let dpus_not_in_sync_state = dpus_states_for_reprov
                .iter()
                .enumerate()
                .filter(|(_i, s)| {
                    !matches!(
                        s,
                        ReprovisionState::BmcFirmwareUpgrade {
                            substate: BmcFirmwareUpgradeSubstate::HostPowerCycle,
                        } | ReprovisionState::BmcFirmwareUpgrade {
                            substate: BmcFirmwareUpgradeSubstate::FwUpdateCompleted,
                        }
                    )
                })
                .collect_vec();
            if !dpus_not_in_sync_state.is_empty() {
                let msg = format!("Waiting for DPUs to come in HostPowerCycle or FwUpdateCompleted state. DPUs not in sync state: {:#?}",
                dpus_not_in_sync_state.iter().map(|(i, s)| {(dpu_ids_for_reprovisioning[*i].clone(), s)}).collect_vec());

                return Ok(StateHandlerOutcome::Wait(msg));
            }

            handler_host_power_control(state, services, SystemPowerControl::ForceOff, txn).await?;
            let redfish_client = build_redfish_client_from_bmc_ip(
                state.host_snapshot.bmc_addr(),
                &services.redfish_client_pool,
                txn,
            )
            .await?;
            let power_state = host_power_state(redfish_client.as_ref()).await?;
            // Host is not powered-off yet. Try again.
            if power_state != libredfish::PowerState::Off {
                tracing::error!(
                    "Machine {} is still not power-off state. Turning off for host again.",
                    state.host_snapshot.machine_id
                );
                return Ok(StateHandlerOutcome::Wait(format!(
                    "Host {} is not still powered off. Trying again.",
                    state.host_snapshot.machine_id
                )));
            }
            handler_host_power_control(state, services, SystemPowerControl::On, txn).await?;

            let next_state = ReprovisionState::BmcFirmwareUpgrade {
                substate: BmcFirmwareUpgradeSubstate::CheckFwVersion,
            }
            .next_bmc_updrade_step(state, dpu_snapshot)?;

            Ok(StateHandlerOutcome::Transition(next_state))
        }
        BmcFirmwareUpgradeSubstate::Reboot { count: _ } => {
            // This is a No-OP. The reboot will be done in the CheckFwVersion before transitioning to the NIC FW update (Reprovisioning/FirmwareUpgrade)
            // Go again to CheckFvVersion- if all BMC FW is up to date - it'll transition to NicFwUpdate
            let next_state = ReprovisionState::BmcFirmwareUpgrade {
                substate: BmcFirmwareUpgradeSubstate::CheckFwVersion,
            }
            .next_bmc_updrade_step(state, dpu_snapshot)?;

            Ok(StateHandlerOutcome::Transition(next_state))
        }
    }
}

/// Handle workflow of DPU reprovision
async fn handle_dpu_reprovision(
    state: &ManagedHostStateSnapshot,
    reachability_params: &ReachabilityParams,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    next_state_resolver: &impl NextReprovisionState,
    dpu_snapshot: &MachineSnapshot,
    hardware_models: &FirmwareConfig,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let dpu_machine_id = &dpu_snapshot.machine_id;
    let reprovision_state = state
        .managed_state
        .as_reprovision_state(dpu_machine_id)
        .ok_or_else(|| StateHandlerError::MissingDpuFromState(dpu_machine_id.clone()))?;

    match reprovision_state {
        ReprovisionState::BmcFirmwareUpgrade { substate } => {
            handle_dpu_reprovision_bmc_firmware_upgrade(
                state,
                substate,
                dpu_snapshot,
                hardware_models,
                services,
                txn,
            )
            .await
        }
        ReprovisionState::FirmwareUpgrade => {
            // Firmware upgrade is going on. Lets wait for it to over.
            let dpus_snapshots_for_reprov = &state
                .dpu_snapshots
                .iter()
                .filter(|x| x.reprovision_requested.is_some())
                .collect_vec();

            for dpu_snapshot in dpus_snapshots_for_reprov {
                if !rebooted(dpu_snapshot) {
                    return Ok(StateHandlerOutcome::Wait(format!(
                        "Waiting for DPU {} to come up.",
                        dpu_snapshot.machine_id
                    )));
                }
            }

            // All DPUs have responded now.
            set_managed_host_topology_update_needed(
                txn,
                &state.host_snapshot,
                dpus_snapshots_for_reprov,
            )
            .await?;

            Ok(StateHandlerOutcome::Transition(
                next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
            ))
        }
        ReprovisionState::PoweringOffHost => {
            let dpus_states_for_reprov = &state
                .dpu_snapshots
                .iter()
                .filter_map(|x| {
                    if x.reprovision_requested.is_some() {
                        state.managed_state.as_reprovision_state(dpu_machine_id)
                    } else {
                        None
                    }
                })
                .collect_vec();

            if !all_equal(dpus_states_for_reprov)? {
                return Ok(StateHandlerOutcome::Wait(
                    "Waiting for DPUs to come in PoweringOffHost state.".to_string(),
                ));
            }

            handler_host_power_control(state, services, SystemPowerControl::ForceOff, txn).await?;
            Ok(StateHandlerOutcome::Transition(
                next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
            ))
        }
        ReprovisionState::PowerDown => {
            let basetime = state
                .host_snapshot
                .last_reboot_requested
                .as_ref()
                .map(|x| x.time)
                .unwrap_or(state.host_snapshot.current.version.timestamp());

            if wait(&basetime, reachability_params.power_down_wait) {
                return Ok(StateHandlerOutcome::DoNothing);
            }

            let redfish_client = build_redfish_client_from_bmc_ip(
                state.host_snapshot.bmc_addr(),
                &services.redfish_client_pool,
                txn,
            )
            .await?;
            let power_state = host_power_state(redfish_client.as_ref()).await?;

            // Host is not powered-off yet. Try again.
            if power_state != libredfish::PowerState::Off {
                tracing::error!(
                    "Machine {} is still not power-off state. Turning off for host again.",
                    state.host_snapshot.machine_id
                );
                handler_host_power_control(state, services, SystemPowerControl::ForceOff, txn)
                    .await?;

                return Ok(StateHandlerOutcome::Wait(format!(
                    "Host {} is not still powered off. Trying again.",
                    state.host_snapshot.machine_id
                )));
            }
            handler_host_power_control(state, services, SystemPowerControl::On, txn).await?;
            Ok(StateHandlerOutcome::Transition(
                next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
            ))
        }
        ReprovisionState::WaitingForNetworkInstall => {
            if let Some(dpu_id) =
                try_wait_for_dpu_discovery(state, reachability_params, services, true, txn).await?
            {
                // Return Wait.
                return Ok(StateHandlerOutcome::Wait(format!(
                    "DPU discovery for {dpu_id} is still not completed."
                )));
            }

            for dpu_snapshot in &state.dpu_snapshots {
                handler_restart_dpu(dpu_snapshot, services, txn).await?;
            }
            Ok(StateHandlerOutcome::Transition(
                next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
            ))
        }
        ReprovisionState::BufferTime => {
            // This state just waits for some time to avoid race condition where
            // dpu_agent sends heartbeat just before DPU goes down. A few microseconds
            // gap can cause host to restart before DPU comes up. This will fail Host
            // DHCP.
            if wait(
                &state.host_snapshot.current.version.timestamp(),
                reachability_params.dpu_wait_time,
            ) {
                return Ok(StateHandlerOutcome::DoNothing);
            }
            Ok(StateHandlerOutcome::Transition(
                next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
            ))
        }
        ReprovisionState::WaitingForNetworkConfig => {
            for dpu_snapshot in &state.dpu_snapshots {
                if !is_dpu_up(state, dpu_snapshot) {
                    let msg = format!("Waiting for DPU {} to come up", dpu_snapshot.machine_id);
                    tracing::warn!("{msg}");

                    let reboot_status =
                        reboot_if_needed(state, dpu_snapshot, reachability_params, services, txn)
                            .await?;

                    return Ok(StateHandlerOutcome::Wait(format!(
                        "{msg};\nreboot_status: {reboot_status:#?}"
                    )));
                }

                if !managed_host_network_config_version_synced_and_dpu_healthy(dpu_snapshot) {
                    tracing::warn!(
                        "Waiting for network to be ready for DPU {}",
                        dpu_snapshot.machine_id
                    );

                    // we requested a DPU reboot in ReprovisionState::WaitingForNetworkInstall
                    // let the trigger_reboot_if_needed determine if we are stuck here
                    // (based on how long it has been since the last requested reboot)
                    let reboot_status =
                        reboot_if_needed(state, dpu_snapshot, reachability_params, services, txn)
                            .await?;

                    // TODO: Make is_network_ready give us more details as a string
                    return Ok(StateHandlerOutcome::Wait(format!(
                        "Waiting for DPU {} to sync network config/become healthy;\nreboot status: {reboot_status:#?}",
                        dpu_snapshot.machine_id
                    )));
                }
            }

            // Clear reprovisioning state.
            for dpu_snapshot in &state.dpu_snapshots {
                Machine::clear_dpu_reprovisioning_request(txn, &dpu_snapshot.machine_id, false)
                    .await
                    .map_err(StateHandlerError::from)?;
            }

            Ok(StateHandlerOutcome::Transition(
                next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
            ))
        }
        ReprovisionState::RebootHostBmc => {
            // Work around for FORGE-3864
            // A NIC FW update from 24.39.2048 to 24.41.1000 can cause the Redfish service to become unavailable on Lenovos.
            // Forge initiates a NIC FW update in ReprovisionState::FirmwareUpgrade
            // At this point, all of the host's DPU have finished the NIC FW Update, been power cycled, and the ARM has come up on the DPU.
            if state.host_snapshot.bmc_vendor.is_lenovo() {
                tracing::info!(
                    "Initiating BMC cold reset of lenovo machine {}",
                    state.host_snapshot.machine_id
                );

                let bmc_mac_address = state.host_snapshot.bmc_info.mac.ok_or_else(|| {
                    StateHandlerError::MissingData {
                        object_id: state.host_snapshot.machine_id.to_string(),
                        missing: "bmc_mac",
                    }
                })?;

                let bmc_ip_address = state
                    .host_snapshot
                    .bmc_info
                    .ip
                    .clone()
                    .ok_or_else(|| StateHandlerError::MissingData {
                        object_id: state.host_snapshot.machine_id.to_string(),
                        missing: "bmc_ip",
                    })?
                    .parse()
                    .map_err(|e| {
                        StateHandlerError::GenericError(eyre!(
                            "parsing the host's BMC IP address failed: {}",
                            e
                        ))
                    })?;

                services
                    .ipmi_tool
                    .bmc_cold_reset(
                        bmc_ip_address,
                        CredentialKey::BmcCredentials {
                            credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
                        },
                    )
                    .await
                    .map_err(StateHandlerError::GenericError)?;
            }

            Ok(StateHandlerOutcome::Transition(
                next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
            ))
        }
        ReprovisionState::RebootHost => {
            // We can expect transient issues here in case we just rebooted the host's BMC and it has not come up yet
            handler_host_power_control(state, services, SystemPowerControl::ForceRestart, txn)
                .await?;

            // We need to wait for the host to reboot and submit its new Hardware information in
            // case of Ready.
            Ok(StateHandlerOutcome::Transition(
                next_state_resolver.next_state(&state.managed_state, dpu_machine_id)?,
            ))
        }
        ReprovisionState::NotUnderReprovision => Ok(StateHandlerOutcome::DoNothing),
    }
}

// Returns true if update_manager flagged this managed host as needing its firmware examined
async fn host_reprovisioning_requested(state: &ManagedHostStateSnapshot) -> bool {
    state.host_snapshot.host_reprovision_requested.is_some()
}

/// This function waits for DPU to finish discovery and reboots it.
async fn try_wait_for_dpu_discovery(
    state: &ManagedHostStateSnapshot,
    reachability_params: &ReachabilityParams,
    services: &StateHandlerServices,
    is_reprovision_case: bool,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Option<MachineId>, StateHandlerError> {
    // We are waiting for the `DiscoveryCompleted` RPC call to update the
    // `last_discovery_time` timestamp.
    // This indicates that all forge-scout actions have succeeded.
    for dpu_snapshot in &state.dpu_snapshots {
        if is_reprovision_case && dpu_snapshot.reprovision_requested.is_none() {
            // This is reprovision handling and this DPU is not under reprovisioning.
            continue;
        }
        if !discovered_after_state_transition(
            dpu_snapshot.current.version,
            dpu_snapshot.last_discovery_time,
        ) {
            let _status = trigger_reboot_if_needed(
                dpu_snapshot,
                state,
                None,
                reachability_params,
                services,
                txn,
            )
            .await?;
            // TODO propagate the status.status message to a StateHandlerOutcome::Wait
            return Ok(Some(dpu_snapshot.machine_id.clone()));
        }
    }

    Ok(None)
}

async fn set_managed_host_topology_update_needed(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    host_snapshot: &MachineSnapshot,
    dpus: &[&MachineSnapshot],
) -> Result<(), StateHandlerError> {
    //Update it for host and DPU both.
    for dpu_snapshot in dpus {
        MachineTopology::set_topology_update_needed(txn, &dpu_snapshot.machine_id, true).await?;
    }
    MachineTopology::set_topology_update_needed(txn, &host_snapshot.machine_id, true).await?;
    Ok(())
}

/// This function returns failure cause for both host and dpu.
fn get_failed_state(state: &ManagedHostStateSnapshot) -> Option<(MachineId, FailureDetails)> {
    // Return updated state only for errors which should cause machine to move into failed
    // state.
    if state.host_snapshot.failure_details.cause != FailureCause::NoError {
        return Some((
            state.host_snapshot.machine_id.clone(),
            state.host_snapshot.failure_details.clone(),
        ));
    } else {
        for dpu_snapshot in &state.dpu_snapshots {
            // In case of the DPU, use first failed DPU and recover it before moving forward.
            if dpu_snapshot.failure_details.cause != FailureCause::NoError {
                return Some((
                    dpu_snapshot.machine_id.clone(),
                    dpu_snapshot.failure_details.clone(),
                ));
            }
        }
    }

    None
}

/// A `StateHandler` implementation for DPU machines
#[derive(Debug, Clone)]
pub struct DpuMachineStateHandler {
    dpu_nic_firmware_initial_update_enabled: bool,
    reachability_params: ReachabilityParams,
}

impl DpuMachineStateHandler {
    pub fn new(
        dpu_nic_firmware_initial_update_enabled: bool,
        reachability_params: ReachabilityParams,
    ) -> Self {
        DpuMachineStateHandler {
            dpu_nic_firmware_initial_update_enabled,
            reachability_params,
        }
    }

    async fn is_secure_boot_disabled(
        &self,
        // passing in dpu_machine_id only for testing
        dpu_machine_id: &MachineId,
        dpu_redfish_client: &dyn Redfish,
    ) -> Result<bool, StateHandlerError> {
        let secure_boot_status = dpu_redfish_client.get_secure_boot().await.map_err(|e| {
            StateHandlerError::RedfishError {
                operation: "disable_secure_boot",
                error: e,
            }
        })?;

        let secure_boot_enable =
            secure_boot_status
                .secure_boot_enable
                .ok_or(StateHandlerError::MissingData {
                    object_id: dpu_machine_id.to_string(),
                    missing: "expected secure_boot_enable_field set in secure boot response",
                })?;

        let secure_boot_current_boot =
            secure_boot_status
                .secure_boot_current_boot
                .ok_or(StateHandlerError::MissingData {
                    object_id: dpu_machine_id.to_string(),
                    missing: "expected secure_boot_enable_field set in secure boot response",
                })?;

        Ok(!secure_boot_enable && !secure_boot_current_boot.is_enabled())
    }
}

impl DpuMachineStateHandler {
    async fn handle_dpu_discovering_state(
        &self,
        state: &mut ManagedHostStateSnapshot,
        dpu_snapshot: &MachineSnapshot,
        _controller_state: &ManagedHostState,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        let dpu_machine_id = &dpu_snapshot.machine_id.clone();
        let current_dpu_state = match &state.managed_state {
            ManagedHostState::DpuDiscoveringState { dpu_states } => dpu_states
                .states
                .get(dpu_machine_id)
                .ok_or_else(|| StateHandlerError::MissingDpuFromState(dpu_machine_id.clone()))?,
            _ => {
                return Err(StateHandlerError::InvalidState(
                    "Unexpected state.".to_string(),
                ));
            }
        };

        match current_dpu_state {
            DpuDiscoveringState::Initializing => {
                let next_state = DpuDiscoveringState::Configuring
                    .next_state(&state.managed_state, dpu_machine_id)?;
                Ok(StateHandlerOutcome::Transition(next_state))
            }
            DpuDiscoveringState::Configuring => {
                let next_state = DpuDiscoveringState::EnableRshim
                    .next_state(&state.managed_state, dpu_machine_id)?;
                Ok(StateHandlerOutcome::Transition(next_state))
            }
            DpuDiscoveringState::EnableRshim => {
                let dpu_redfish_client_result = build_redfish_client_from_bmc_ip(
                    dpu_snapshot.bmc_addr(),
                    &ctx.services.redfish_client_pool,
                    txn,
                )
                .await;

                let dpu_redfish_client = match dpu_redfish_client_result {
                    Ok(redfish_client) => redfish_client,
                    Err(e) => {
                        return Ok(StateHandlerOutcome::Wait(format!(
                            "Waiting for RedFish to become available: {:?}",
                            e
                        )))
                    }
                };

                let _ = dpu_redfish_client
                    .enable_rshim_bmc()
                    .await
                    .map_err(|e| tracing::info!("failed to enable rshim on DPU {e}"));

                let next_state = DpuDiscoveringState::DisableSecureBoot {
                    count: 0,
                    disable_secure_boot_state: Some(DisableSecureBootState::CheckSecureBootStatus),
                }
                .next_state(&state.managed_state, dpu_machine_id)?;
                Ok(StateHandlerOutcome::Transition(next_state))
            }
            // The proceure to disable secure boot is documented on page 58-59 here: https://docs.nvidia.com/networking/display/nvidia-bluefield-management-and-initial-provisioning.pdf
            DpuDiscoveringState::DisableSecureBoot {
                disable_secure_boot_state,
                count,
            } => {
                let next_state: ManagedHostState;

                // Use the host snapshot instead of the DPU snapshot because
                // the state.host_snapshot.current.version might be a bit more correct:
                // the state machine is driven by the host state
                let time_since_state_change =
                    state.host_snapshot.current.version.since_state_change();

                let dpu_redfish_client_result = build_redfish_client_from_bmc_ip(
                    dpu_snapshot.bmc_addr(),
                    &ctx.services.redfish_client_pool,
                    txn,
                )
                .await;

                let dpu_redfish_client = match dpu_redfish_client_result {
                    Ok(redfish_client) => redfish_client,
                    Err(e) => {
                        return Ok(StateHandlerOutcome::Wait(format!(
                            "Waiting for RedFish to become available: {:?}",
                            e
                        )))
                    }
                };

                let wait_for_dpu_to_come_up = if time_since_state_change.num_minutes() > 5 {
                    false
                } else {
                    let (has_dpu_finished_booting, dpu_boot_progress) =
                        redfish::did_dpu_finish_booting(dpu_redfish_client.as_ref())
                            .await
                            .map_err(|e| StateHandlerError::RedfishError {
                                operation: "did_dpu_finish_booting",
                                error: e,
                            })?;

                    if *count > 0 && !has_dpu_finished_booting {
                        tracing::info!("Waiting for DPU {} to finish booting; boot progress: {dpu_boot_progress:#?}; DisableSecureBoot cycle: {count}", dpu_snapshot.machine_id)
                    }

                    !has_dpu_finished_booting
                };

                match disable_secure_boot_state {
                    Some(disable_secure_boot_state) => match disable_secure_boot_state {
                        DisableSecureBootState::CheckSecureBootStatus => {
                            // This is the logic:
                            // CheckSecureBootStatus -> DisableSecureBoot -> DisableSecureBootState::RebootDPU{0} -> DisableSecureBootState::RebootDPU{1}
                            // The first time we check to see if secure boot is disabled, we do not need to wait. The DPU should already be up.
                            // However, we need to give time in between the second reboot and checking the status again.
                            if *count > 0 && wait_for_dpu_to_come_up {
                                return Ok(StateHandlerOutcome::Wait(format!(
                                    "Waiting for DPU {dpu_machine_id} to come back up from last reboot; time since last reboot: {time_since_state_change}; DisableSecureBoot cycle: {count}",
                                )));
                            }

                            match self
                                .is_secure_boot_disabled(
                                    dpu_machine_id,
                                    dpu_redfish_client.as_ref(),
                                )
                                .await
                            {
                                Ok(is_secure_boot_disabled) => {
                                    if is_secure_boot_disabled {
                                        next_state = DpuDiscoveringState::SetUefiHttpBoot
                                            .next_state(&state.managed_state, dpu_machine_id)?;
                                    } else {
                                        next_state = DpuDiscoveringState::DisableSecureBoot {
                                            disable_secure_boot_state: Some(
                                                DisableSecureBootState::DisableSecureBoot,
                                            ),
                                            count: *count,
                                        }
                                        .next_state(&state.managed_state, dpu_machine_id)?;
                                    }
                                }
                                Err(StateHandlerError::MissingData { object_id, missing }) => {
                                    tracing::info!(
                                        "Missing data in secure boot status response for DPU {}: {}; rebooting DPU as a work-around",
                                        object_id, missing
                                    );

                                    /***
                                     * If the DPU's BMC comes up after UEFI client was run on an ARM
                                     * there is a known issue where the redfish query for the secure boot
                                     * status comes back incomplete.
                                     * Example:
                                     * {
                                            "@odata.id": "/redfish/v1/Systems/Bluefield/SecureBoot",
                                            "@odata.type": "#SecureBoot.v1_1_0.SecureBoot",
                                            "Description": "The UEFI Secure Boot associated with this system.",
                                            "Id": "SecureBoot",
                                            "Name": "UEFI Secure Boot",
                                            "SecureBootDatabases": {
                                                "@odata.id": "/redfish/v1/Systems/Bluefield/SecureBoot/SecureBootDatabases"
                                        }

                                    (missing the SecureBootEnable and SecureBootCurrentBoot fields)
                                    The known work around for this issue is to reboot the DPU's ARM. There is a pending FR
                                    to fix this on the hardware level.
                                    ***/

                                    dpu_redfish_client
                                        .power(SystemPowerControl::ForceRestart)
                                        .await
                                        .map_err(|e| StateHandlerError::RedfishError {
                                            operation: "force_restart",
                                            error: e,
                                        })?;

                                    next_state = DpuDiscoveringState::DisableSecureBoot {
                                        disable_secure_boot_state: Some(
                                            DisableSecureBootState::CheckSecureBootStatus,
                                        ),
                                        count: *count + 1,
                                    }
                                    .next_state(&state.managed_state, dpu_machine_id)?;
                                }
                                Err(e) => {
                                    return Err(e);
                                }
                            }
                        }
                        DisableSecureBootState::DisableSecureBoot => {
                            dpu_redfish_client
                                .disable_secure_boot()
                                .await
                                .map_err(|e| StateHandlerError::RedfishError {
                                    operation: "disable_secure_boot",
                                    error: e,
                                })?;

                            next_state = DpuDiscoveringState::DisableSecureBoot {
                                disable_secure_boot_state: Some(
                                    DisableSecureBootState::RebootDPU { reboot_count: 0 },
                                ),
                                count: *count,
                            }
                            .next_state(&state.managed_state, dpu_machine_id)?;
                        }
                        // DPUs requires two reboots after the previous step in order to disable secure boot.
                        // From the doc linked above: "the BlueField Arm OS must be rebooted twice. The first
                        // reboot is for the UEFI redfish client to read the request from the BMC and apply it; the
                        // second reboot is for the setting to take effect."
                        // We do not need to wait between disabling secure boot and the first reboot.
                        // But, we need to give the DPU time to come up after the initial reboot,
                        // before we reboot it again.
                        DisableSecureBootState::RebootDPU { reboot_count } => {
                            if *reboot_count == 0 {
                                next_state = DpuDiscoveringState::DisableSecureBoot {
                                    disable_secure_boot_state: Some(
                                        DisableSecureBootState::RebootDPU {
                                            reboot_count: *reboot_count + 1,
                                        },
                                    ),
                                    count: *count,
                                }
                                .next_state(&state.managed_state, dpu_machine_id)?;
                            } else {
                                if wait_for_dpu_to_come_up {
                                    return Ok(StateHandlerOutcome::Wait(format!(
                                        "Waiting for DPU {dpu_machine_id} to come back up from last reboot; time since last reboot: {time_since_state_change}",
                                    )));
                                }

                                next_state = DpuDiscoveringState::DisableSecureBoot {
                                    disable_secure_boot_state: Some(
                                        DisableSecureBootState::CheckSecureBootStatus,
                                    ),
                                    count: *count + 1,
                                }
                                .next_state(&state.managed_state, dpu_machine_id)?;
                            }

                            //
                            // Next just do a ForceRestart to netboot without secureboot.
                            //
                            // This will kick off the ARM OS install since we move to DPU/Init next.
                            //
                            dpu_redfish_client
                                .power(SystemPowerControl::ForceRestart)
                                .await
                                .map_err(|e| StateHandlerError::RedfishError {
                                    operation: "force_restart",
                                    error: e,
                                })?;
                        }
                    },
                    None => {
                        // Add the new sub-state to DpuDiscoveringState::DisableSecureBoot if we have a machine with the older version of the state
                        next_state = DpuDiscoveringState::DisableSecureBoot {
                            disable_secure_boot_state: Some(
                                DisableSecureBootState::CheckSecureBootStatus,
                            ),
                            count: 0,
                        }
                        .next_state(&state.managed_state, dpu_machine_id)?;
                    }
                }

                Ok(StateHandlerOutcome::Transition(next_state))
            }

            DpuDiscoveringState::SetUefiHttpBoot => {
                let dpu_redfish_client_result = build_redfish_client_from_bmc_ip(
                    dpu_snapshot.bmc_addr(),
                    &ctx.services.redfish_client_pool,
                    txn,
                )
                .await;

                let dpu_redfish_client = match dpu_redfish_client_result {
                    Ok(redfish_client) => redfish_client,
                    Err(e) => {
                        return Ok(StateHandlerOutcome::Wait(format!(
                            "Waiting for RedFish to become available: {:?}",
                            e
                        )))
                    }
                };

                // This configures the DPU to boot once from UEFI HTTP.
                //
                // NOTE: since we don't have interface names yet (see comment about UEFI not
                // guaranteed to have POSTed), it will loop through all the interfaces between
                // IPv4, IPv6 so it may take a while.
                //
                dpu_redfish_client
                    .boot_once(Boot::UefiHttp)
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "boot_once",
                        error: e,
                    })
                    .await?;

                let next_state = DpuDiscoveringState::RebootAllDPUS
                    .next_state(&state.managed_state, dpu_machine_id)?;
                Ok(StateHandlerOutcome::Transition(next_state))
            }
            DpuDiscoveringState::RebootAllDPUS => {
                if !state.managed_state.all_dpu_states_in_sync()? {
                    return Ok(StateHandlerOutcome::Wait(
                        "Waiting for all dpus to finish configuring.".to_string(),
                    ));
                }

                //
                // Next just do a ForceRestart to netboot without secureboot.
                //
                // This will kick off the ARM OS install since we move to DPU/Init next.
                //
                for dpu_snapshot in &state.dpu_snapshots {
                    handler_restart_dpu(dpu_snapshot, ctx.services, txn).await?;
                }

                let next_state =
                    DpuInitState::Init.next_state_with_all_dpus_updated(&state.managed_state)?;
                Ok(StateHandlerOutcome::Transition(next_state))
            }
        }
    }

    async fn handle_dpuinit_state(
        &self,
        state: &mut ManagedHostStateSnapshot,
        dpu_snapshot: &MachineSnapshot,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        let dpu_machine_id = &dpu_snapshot.machine_id;
        let dpu_state = match &state.managed_state {
            ManagedHostState::DPUInit { dpu_states } => dpu_states
                .states
                .get(dpu_machine_id)
                .ok_or_else(|| StateHandlerError::MissingDpuFromState(dpu_machine_id.clone()))?,
            _ => {
                return Err(StateHandlerError::InvalidState(
                    "Unexpected state.".to_string(),
                ));
            }
        };
        match &dpu_state {
            DpuInitState::Init => {
                // initial restart, firmware update and scout is run, first reboot of dpu discovery
                let dpu_discovery_result = try_wait_for_dpu_discovery(
                    state,
                    &self.reachability_params,
                    ctx.services,
                    false,
                    txn,
                )
                .await?;

                if let Some(dpu_id) = dpu_discovery_result {
                    return Ok(StateHandlerOutcome::Wait(format!(
                        "Waiting for DPU {dpu_id} discovery and reboot"
                    )));
                }

                tracing::debug!(
                    "ManagedHostState::DPUNotReady::Init: firmware update enabled = {}",
                    self.dpu_nic_firmware_initial_update_enabled
                );

                // All DPUs are discovered. Reboot them to proceed.
                for dpu_snapshot in &state.dpu_snapshots {
                    handler_restart_dpu(dpu_snapshot, ctx.services, txn).await?;
                }

                let machine_state = DpuInitState::WaitingForPlatformPowercycle {
                    substate: PerformPowerOperation::Off,
                };
                let next_state =
                    machine_state.next_state_with_all_dpus_updated(&state.managed_state)?;
                Ok(StateHandlerOutcome::Transition(next_state))
            }

            DpuInitState::WaitingForPlatformPowercycle {
                substate: PerformPowerOperation::Off,
            } => {
                // Wait until all DPUs arrive in Off state.
                if !state.managed_state.all_dpu_states_in_sync()? {
                    return Ok(StateHandlerOutcome::Wait(
                        "Waiting for all dpus to move to off state.".to_string(),
                    ));
                }

                // All DPUs are in Off state, turn off the host.
                let host_redfish_client = ctx
                    .services
                    .redfish_client_pool
                    .create_client_from_machine_snapshot(&state.host_snapshot, txn)
                    .await?;

                host_redfish_client
                    .power(SystemPowerControl::ForceOff)
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "host_power_off",
                        error: e,
                    })?;

                let next_state = DpuInitState::WaitingForPlatformPowercycle {
                    substate: PerformPowerOperation::On,
                }
                .next_state_with_all_dpus_updated(&state.managed_state)?;

                Ok(StateHandlerOutcome::Transition(next_state))
            }
            DpuInitState::WaitingForPlatformPowercycle {
                substate: PerformPowerOperation::On,
            } => {
                let host_redfish_client = ctx
                    .services
                    .redfish_client_pool
                    .create_client_from_machine_snapshot(&state.host_snapshot, txn)
                    .await?;

                host_redfish_client
                    .power(SystemPowerControl::On)
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "host_power_off",
                        error: e,
                    })?;

                let next_state = DpuInitState::WaitingForPlatformConfiguration
                    .next_state_with_all_dpus_updated(&state.managed_state)?;

                Ok(StateHandlerOutcome::Transition(next_state))
            }
            DpuInitState::WaitingForPlatformConfiguration => {
                let dpu_redfish_client = match build_redfish_client_from_bmc_ip(
                    dpu_snapshot.bmc_addr(),
                    &ctx.services.redfish_client_pool,
                    txn,
                )
                .await
                {
                    Ok(client) => client,
                    Err(e) => {
                        let msg = format!("failed to create redfish client for DPU {}, potentially because we turned the host off as part of error handling in this state. err: {}", dpu_snapshot.machine_id, e);
                        tracing::warn!(msg);
                        // If we cannot create a redfish client for the DPU, this function call will never result in an actual DPU reboot.
                        // The only side effect is turning the DPU's host back on if we turned it off earlier.
                        let reboot_status = reboot_if_needed(
                            state,
                            dpu_snapshot,
                            &self.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?;

                        return Ok(StateHandlerOutcome::Wait(format!(
                            "{msg};\nDPU reboot status: {reboot_status:#?}",
                        )));
                    }
                };

                let boot_interface_mac = None; // libredfish will choose the DPU
                if let Err(e) = call_forge_setup_and_handle_no_dpu_error(
                    dpu_redfish_client.as_ref(),
                    boot_interface_mac,
                    state.host_snapshot.associated_dpu_machine_ids().len(),
                    ctx.services.site_config.site_explorer.allow_zero_dpu_hosts,
                )
                .await
                {
                    let msg = format!("redfish forge_setup failed for DPU {}, potentially due to known race condition between UEFI POST and BMC. issuing a force-restart. err: {}", dpu_snapshot.machine_id, e);
                    tracing::warn!(msg);
                    let reboot_status = reboot_if_needed(
                        state,
                        dpu_snapshot,
                        &self.reachability_params,
                        ctx.services,
                        txn,
                    )
                    .await?;

                    return Ok(StateHandlerOutcome::Wait(format!(
                        "{msg};\nWaiting for DPU {} to reboot: {reboot_status:#?}",
                        dpu_snapshot.machine_id
                    )));
                }

                if let Err(e) = ctx
                    .services
                    .redfish_client_pool
                    .uefi_setup(dpu_redfish_client.as_ref(), true)
                    .await
                {
                    let msg = format!(
                        "Failed to run uefi_setup call failed for DPU {}: {}",
                        dpu_snapshot.machine_id, e
                    );
                    tracing::warn!(msg);
                    let reboot_status = reboot_if_needed(
                        state,
                        dpu_snapshot,
                        &self.reachability_params,
                        ctx.services,
                        txn,
                    )
                    .await?;

                    return Ok(StateHandlerOutcome::Wait(format!(
                        "{msg};\nWaiting for DPU {} to reboot: {reboot_status:#?}",
                        dpu_snapshot.machine_id
                    )));
                }

                // We need to reboot the DPU after configuring the BIOS settings appropriately
                // so that they are applied
                handler_restart_dpu(dpu_snapshot, ctx.services, txn).await?;

                let next_state = DpuInitState::WaitingForNetworkConfig
                    .next_state(&state.managed_state, dpu_machine_id)?;

                Ok(StateHandlerOutcome::Transition(next_state))
            }

            DpuInitState::WaitingForNetworkConfig => {
                // is_network_ready is syncing over all DPUs.
                // The code will move only when all DPUs returns network_ready signal.
                for dpu_snapshot in &state.dpu_snapshots {
                    if !managed_host_network_config_version_synced_and_dpu_healthy(dpu_snapshot) {
                        // we requested a DPU reboot in DpuInitState::Init
                        // let the trigger_reboot_if_needed determine if we are stuck here
                        // (based on how long it has been since the last requested reboot)
                        let reboot_status = reboot_if_needed(
                            state,
                            dpu_snapshot,
                            &self.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?;

                        // TODO: Make is_network_ready give us more details as a string
                        return Ok(StateHandlerOutcome::Wait(
                            format!("Waiting for DPU agent to apply network config and report healthy network for DPU {}\nreboot status: {reboot_status:#?}",
                        dpu_snapshot.machine_id),
                        ));
                    }
                }

                let next_state = ManagedHostState::HostInit {
                    machine_state: MachineState::EnableIpmiOverLan,
                };
                Ok(StateHandlerOutcome::Transition(next_state))
            }
            DpuInitState::WaitingForNetworkInstall => {
                tracing::warn!(
                    "Invalid State WaitingForNetworkInstall for dpu Machine {}",
                    dpu_machine_id
                );
                Err(StateHandlerError::InvalidHostState(
                    dpu_machine_id.clone(),
                    Box::new(state.managed_state.clone()),
                ))
            }
        }
    }
}

#[async_trait::async_trait]
impl StateHandler for DpuMachineStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ContextObjects = MachineStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        _host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        _controller_state: &Self::ControllerState,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        let mut state_handler_outcome = StateHandlerOutcome::DoNothing;

        if state.host_snapshot.associated_dpu_machine_ids().is_empty() {
            let next_state = ManagedHostState::HostInit {
                machine_state: MachineState::WaitingForPlatformConfiguration,
            };
            Ok(StateHandlerOutcome::Transition(next_state))
        } else {
            for dpu_snapshot in &state.dpu_snapshots.clone() {
                state_handler_outcome = self
                    .handle_dpuinit_state(state, dpu_snapshot, txn, ctx)
                    .await?;

                if let StateHandlerOutcome::Transition(..) = state_handler_outcome {
                    return Ok(state_handler_outcome);
                }
            }

            Ok(state_handler_outcome)
        }
    }
}

fn get_reboot_cycle(
    next_potential_reboot_time: DateTime<Utc>,
    entered_state_at: DateTime<Utc>,
    wait_period: Duration,
) -> Result<i64, StateHandlerError> {
    if next_potential_reboot_time <= entered_state_at {
        return Err(
            StateHandlerError::GenericError(
                eyre::eyre!("Poorly configured paramters: next_potential_reboot_time: {}, entered_state_at: {}, wait_period: {}",
                    next_potential_reboot_time,
                    entered_state_at,
                    wait_period.num_minutes()
                )
            )
        );
    }

    let cycle = next_potential_reboot_time - entered_state_at;

    // Although trigger_reboot_if_needed makes sure to not send wait_period as 0, but still if some other
    // function calls get_reboot_cycle, this function must not panic, so setting it min 1 minute
    // here as well.
    Ok(cycle.num_minutes() / wait_period.num_minutes().max(1))
}

#[derive(Debug)]
struct RebootStatus {
    increase_retry_count: bool, // the vague previous return value
    status: String,             // what we did or are waiting for
}

/// In case machine does not come up until a specified duration, this function tries to reboot
/// it again. The reboot continues till 6 hours only. After that this function gives up.
async fn trigger_reboot_if_needed(
    target: &MachineSnapshot,
    state: &ManagedHostStateSnapshot,
    retry_count: Option<i64>,
    reachability_params: &ReachabilityParams,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<RebootStatus, StateHandlerError> {
    let Some(last_reboot_requested) = &target.last_reboot_requested else {
        return Ok(RebootStatus {
            increase_retry_count: false,
            status: "No pending reboot. Will keep waiting.".to_string(),
        });
    };
    let host = &state.host_snapshot;
    if let MachineLastRebootRequestedMode::PowerOff = last_reboot_requested.mode {
        // PowerOn the host.
        tracing::info!(
            "Machine {} is in power-off state. Turning on for host: {}",
            target.machine_id,
            host.machine_id,
        );
        let basetime = host
            .last_reboot_requested
            .as_ref()
            .map(|x| x.time)
            .unwrap_or(host.current.version.timestamp());

        if wait(&basetime, reachability_params.power_down_wait) {
            return Ok(RebootStatus {
                increase_retry_count: false,
                status: format!(
                    "Waiting for host to power off. Next check at {}",
                    basetime + reachability_params.power_down_wait
                ),
            });
        }

        let redfish_client =
            build_redfish_client_from_bmc_ip(host.bmc_addr(), &services.redfish_client_pool, txn)
                .await?;

        let power_state = host_power_state(redfish_client.as_ref()).await?;

        // If power-off done, power-on now.
        // If host is not powered-off yet, try again.
        let action = if power_state == libredfish::PowerState::Off {
            SystemPowerControl::On
        } else {
            tracing::error!(
                "Machine {} is still not power-off state. Turning off again for host: {}",
                target.machine_id,
                host.machine_id,
            );
            SystemPowerControl::ForceOff
        };

        tracing::trace!(machine_id=%target.machine_id, "Redfish setting host power state to {action}");
        handler_host_power_control(state, services, action, txn).await?;
        return Ok(RebootStatus {
            increase_retry_count: false,
            status: format!("Set power state to {action} using Redfish API"),
        });
    }

    let wait_period = reachability_params
        .failure_retry_time
        .max(Duration::minutes(1));

    let current_time = Utc::now();
    let entered_state_at = target.current.version.timestamp();
    let next_potential_reboot_time: DateTime<Utc> =
        if last_reboot_requested.time + wait_period > entered_state_at {
            last_reboot_requested.time + wait_period
        } else {
            // Handles this case:
            // T0: State A
            //      DPU was hung--Reboot DPU
            //      DPU last requested reboot requested time: T0
            // T1 (T0 + 1 hour): State B
            //      DPU was hung; DPU wait period is 45 mins
            //      If we only calculate the next reboot time from the last requested reboot time
            //      the DPU's next potential reboot time = T0 + 45 < T1
            // Our logic to detect the reboot cycle will return an error here,
            // because the next reboot time is before the time the DPU entered State B.
            // Update the DPU's next reboot time to be 5 minutes after it entered State B to handle
            // this edge case.
            entered_state_at + Duration::minutes(5)
        };

    let time_elapsed_since_state_change = (current_time - entered_state_at).num_minutes();
    // Let's stop at 15 cycles of reboot.
    let max_retry_duration = Duration::minutes(wait_period.num_minutes() * 15);

    let should_try = if let Some(retry_count) = retry_count {
        retry_count < 15
    } else {
        entered_state_at + max_retry_duration > current_time
    };

    // We can try reboot only upto 15 cycles from state change.
    if should_try {
        // A cycle is done but host has not responded yet. Let's try a reboot.
        if next_potential_reboot_time < current_time {
            // Find the cycle.
            // We are trying to reboot 3 times and power down/up on 4th cycle.
            let cycle = match retry_count {
                Some(x) => x,
                None => {
                    get_reboot_cycle(next_potential_reboot_time, entered_state_at, wait_period)?
                }
            };

            // Dont power down the host on the first cycle
            let power_down_host = cycle != 0 && cycle % 4 == 0;

            let status = if power_down_host {
                // PowerDown
                // DPU or host, in both cases power down is triggered from host.
                let action = SystemPowerControl::ForceOff;
                handler_host_power_control(state, services, action, txn).await?;
                format!(
                    "Has not come up after {} minutes, trying ForceOff, cycle: {cycle}",
                    time_elapsed_since_state_change,
                )
            } else {
                // Reboot
                if target.machine_id.machine_type().is_dpu() {
                    handler_restart_dpu(target, services, txn).await?;
                } else {
                    handler_host_power_control(
                        state,
                        services,
                        SystemPowerControl::ForceRestart,
                        txn,
                    )
                    .await?;
                }
                format!(
                    "Has not come up after {} minutes. Rebooting again, cycle: {cycle}.",
                    time_elapsed_since_state_change
                )
            };

            tracing::info!("Machine {}: {status}", target.machine_id,);

            Ok(RebootStatus {
                increase_retry_count: true,
                status,
            })
        } else {
            Ok(RebootStatus {
                increase_retry_count: false,
                status: format!("Will attempt next reboot at {next_potential_reboot_time}"),
            })
        }
    } else {
        let h = (current_time - entered_state_at).num_hours();
        Err(StateHandlerError::ManualInterventionRequired(format!(
            "Machine has not responded after {h} hours."
        )))
    }
}

/// This function waits until target machine is up or not. It relies on scout to identify if
/// machine has come up or not after reboot.
// True if machine is rebooted after state change.
fn rebooted(target: &MachineSnapshot) -> bool {
    target.last_reboot_time.unwrap_or_default() > target.current.version.timestamp()
}

fn machine_validation_completed(target: &MachineSnapshot) -> bool {
    target.last_machine_validation_time.unwrap_or_default() > target.current.version.timestamp()
}
// Was machine rebooted after state change?
fn discovered_after_state_transition(
    version: ConfigVersion,
    last_discovery_time: Option<DateTime<Utc>>,
) -> bool {
    last_discovery_time.unwrap_or_default() > version.timestamp()
}

// Was DPU reprov restart requested after state change
fn dpu_reprovision_restart_requested_after_state_transition(
    version: ConfigVersion,
    reprov_restart_requested_at: DateTime<Utc>,
) -> bool {
    reprov_restart_requested_at > version.timestamp()
}

fn cleanedup_after_state_transition(
    version: ConfigVersion,
    last_cleanup_time: Option<DateTime<Utc>>,
) -> bool {
    last_cleanup_time.unwrap_or_default() > version.timestamp()
}

/// A `StateHandler` implementation for host machines
#[derive(Debug, Clone)]
pub struct HostMachineStateHandler {
    host_handler_params: HostHandlerParams,
}

impl HostMachineStateHandler {
    pub fn new(host_handler_params: HostHandlerParams) -> Self {
        Self {
            host_handler_params,
        }
    }
}

fn managed_host_network_config_version_synced_and_dpu_healthy(
    dpu_snapshot: &MachineSnapshot,
) -> bool {
    if !dpu_snapshot.managed_host_network_config_version_synced() {
        return false;
    }

    let Some(dpu_health) = &dpu_snapshot.dpu_agent_health_report else {
        return false;
    };

    !dpu_health
        .has_classification(&health_report::HealthAlertClassification::prevent_host_state_changes())
}

fn check_host_health_for_alerts(state: &ManagedHostStateSnapshot) -> Result<(), StateHandlerError> {
    match state
        .aggregate_health
        .has_classification(&health_report::HealthAlertClassification::prevent_host_state_changes())
    {
        true => Err(StateHandlerError::HealthProbeAlert),
        false => Ok(()),
    }
}

async fn reboot_if_needed(
    state: &ManagedHostStateSnapshot,
    machine_snapshot: &MachineSnapshot,
    reachability_params: &ReachabilityParams,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<RebootStatus, StateHandlerError> {
    let reboot_status = trigger_reboot_if_needed(
        machine_snapshot,
        &state.clone(),
        None,
        reachability_params,
        services,
        txn,
    )
    .await
    .map_err(|e| {
        StateHandlerError::GenericError(eyre!(
            "failed to trigger reboot for DPU {}: {e}",
            machine_snapshot.machine_id
        ))
    })?;

    if reboot_status.increase_retry_count {
        tracing::info!(%machine_snapshot.machine_id,
            "triggered reboot for machine in managed-host state {}: {}",
            state.managed_state,
            reboot_status.status
        );
    }

    Ok(reboot_status)
}

async fn handler_host_lockdown(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    state: &mut ManagedHostStateSnapshot,
) -> Result<ManagedHostState, StateHandlerError> {
    // Enable Bios/BMC lockdown now.
    lockdown_host(txn, state, ctx.services).await?;

    Ok(ManagedHostState::HostInit {
        machine_state: MachineState::WaitingForLockdown {
            lockdown_info: LockdownInfo {
                state: LockdownState::TimeWaitForDPUDown,
                mode: Enable,
            },
        },
    })
}

/// TODO: we need to handle the case where the job is deleted for some reason
async fn handle_host_uefi_setup(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    state: &mut ManagedHostStateSnapshot,
    uefi_setup_info: UefiSetupInfo,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let redfish_client = build_redfish_client_from_bmc_ip(
        state.host_snapshot.bmc_addr(),
        &ctx.services.redfish_client_pool,
        txn,
    )
    .await?;

    match uefi_setup_info.uefi_setup_state.clone() {
        UefiSetupState::UnlockHost => {
            if state.host_snapshot.bmc_vendor.is_dell() {
                redfish_client
                    .lockdown_bmc(libredfish::EnabledDisabled::Disabled)
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "lockdown",
                        error: e,
                    })?;
            }

            Ok(StateHandlerOutcome::Transition(
                ManagedHostState::HostInit {
                    machine_state: MachineState::UefiSetup {
                        uefi_setup_info: UefiSetupInfo {
                            uefi_password_jid: None,
                            uefi_setup_state: UefiSetupState::SetUefiPassword,
                        },
                    },
                },
            ))
        }
        UefiSetupState::SetUefiPassword => {
            match set_host_uefi_password(
                redfish_client.as_ref(),
                ctx.services.redfish_client_pool.clone(),
            )
            .await
            {
                Ok(job_id) => Ok(StateHandlerOutcome::Transition(
                    ManagedHostState::HostInit {
                        machine_state: MachineState::UefiSetup {
                            uefi_setup_info: UefiSetupInfo {
                                uefi_password_jid: job_id,
                                uefi_setup_state: UefiSetupState::WaitForPasswordJobScheduled,
                            },
                        },
                    },
                )),
                Err(e) => {
                    let msg = format!(
                        "failed to set the BIOS password on {} ({}): {}",
                        state.host_snapshot.machine_id, state.host_snapshot.bmc_vendor, e
                    );

                    // This feature has only been tested thoroughly on Dells and Lenovos
                    if state.host_snapshot.bmc_vendor.is_dell()
                        || state.host_snapshot.bmc_vendor.is_lenovo()
                    {
                        return Err(StateHandlerError::GenericError(eyre::eyre!("{}", msg)));
                    }

                    // For all other vendors, allow ingestion even though we couldnt set the bios password
                    // An operator will have to set the bios password manually
                    tracing::info!(msg);

                    Ok(StateHandlerOutcome::Transition(
                        ManagedHostState::HostInit {
                            machine_state: MachineState::UefiSetup {
                                uefi_setup_info: UefiSetupInfo {
                                    uefi_password_jid: uefi_setup_info.uefi_password_jid.clone(),
                                    uefi_setup_state: UefiSetupState::LockdownHost,
                                },
                            },
                        },
                    ))
                }
            }
        }
        UefiSetupState::WaitForPasswordJobScheduled => {
            if let Some(job_id) = uefi_setup_info.uefi_password_jid.clone() {
                if !poll_redfish_job(
                    redfish_client.as_ref(),
                    job_id.clone(),
                    libredfish::JobState::Scheduled,
                )
                .await
                .map_err(|e| StateHandlerError::GenericError(eyre::eyre!("{}", e)))?
                {
                    return Ok(StateHandlerOutcome::Wait(format!(
                        "waiting for job {:#?} to complete",
                        job_id
                    )));
                }
            }

            Ok(StateHandlerOutcome::Transition(
                ManagedHostState::HostInit {
                    machine_state: MachineState::UefiSetup {
                        uefi_setup_info: UefiSetupInfo {
                            uefi_password_jid: uefi_setup_info.uefi_password_jid.clone(),
                            uefi_setup_state: UefiSetupState::PowercycleHost,
                        },
                    },
                },
            ))
        }
        UefiSetupState::PowercycleHost => {
            host_power_control(
                redfish_client.as_ref(),
                &state.host_snapshot,
                SystemPowerControl::ForceRestart,
                ctx.services.ipmi_tool.clone(),
                txn,
            )
            .await
            .map_err(|e| {
                StateHandlerError::GenericError(eyre!("handler_host_power_control failed: {}", e))
            })?;
            Ok(StateHandlerOutcome::Transition(
                ManagedHostState::HostInit {
                    machine_state: MachineState::UefiSetup {
                        uefi_setup_info: UefiSetupInfo {
                            uefi_password_jid: uefi_setup_info.uefi_password_jid.clone(),
                            uefi_setup_state: UefiSetupState::WaitForPasswordJobCompletion,
                        },
                    },
                },
            ))
        }
        UefiSetupState::WaitForPasswordJobCompletion => {
            if let Some(job_id) = uefi_setup_info.uefi_password_jid.clone() {
                let redfish_client = build_redfish_client_from_bmc_ip(
                    state.host_snapshot.bmc_addr(),
                    &ctx.services.redfish_client_pool,
                    txn,
                )
                .await?;
                if !poll_redfish_job(
                    redfish_client.as_ref(),
                    job_id.clone(),
                    libredfish::JobState::Completed,
                )
                .await
                .map_err(|e| StateHandlerError::GenericError(eyre::eyre!("{}", e)))?
                {
                    return Ok(StateHandlerOutcome::Wait(format!(
                        "waiting for job {:#?} to complete",
                        job_id
                    )));
                }
            }

            state.host_snapshot.bios_password_set_time = Some(chrono::offset::Utc::now());
            Machine::update_bios_password_set(&state.host_snapshot.machine_id, txn)
                .await
                .map_err(|e| {
                    StateHandlerError::GenericError(eyre!(
                        "update_host_bios_password_set failed: {}",
                        e
                    ))
                })?;

            Ok(StateHandlerOutcome::Transition(
                ManagedHostState::HostInit {
                    machine_state: MachineState::UefiSetup {
                        uefi_setup_info: UefiSetupInfo {
                            uefi_password_jid: uefi_setup_info.uefi_password_jid.clone(),
                            uefi_setup_state: UefiSetupState::LockdownHost,
                        },
                    },
                },
            ))
        }
        UefiSetupState::LockdownHost => Ok(StateHandlerOutcome::Transition(
            handler_host_lockdown(txn, ctx, state).await.map_err(|e| {
                StateHandlerError::GenericError(eyre!("handle_host_lockdown failed: {}", e))
            })?,
        )),
    }
}

#[async_trait::async_trait]
impl StateHandler for HostMachineStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ContextObjects = MachineStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        mh_snapshot: &mut ManagedHostStateSnapshot,
        _controller_state: &Self::ControllerState,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        if let ManagedHostState::HostInit { machine_state } = &mh_snapshot.managed_state {
            match machine_state {
                MachineState::Init => Err(StateHandlerError::InvalidHostState(
                    host_machine_id.clone(),
                    Box::new(mh_snapshot.managed_state.clone()),
                )),
                MachineState::EnableIpmiOverLan => {
                    let host_redfish_client = build_redfish_client_from_bmc_ip(
                        mh_snapshot.host_snapshot.bmc_addr(),
                        &ctx.services.redfish_client_pool,
                        txn,
                    )
                    .await?;

                    if !host_redfish_client
                        .is_ipmi_over_lan_enabled()
                        .await
                        .map_err(|e| StateHandlerError::RedfishError {
                            operation: "enable_ipmi_over_lan",
                            error: e,
                        })?
                    {
                        tracing::info!(
                            machine_id = %host_machine_id,
                            "IPMI over LAN is currently disabled on this host--enabling IPMI over LAN");

                        host_redfish_client
                            .enable_ipmi_over_lan(libredfish::EnabledDisabled::Enabled)
                            .await
                            .map_err(|e| StateHandlerError::RedfishError {
                                operation: "enable_ipmi_over_lan",
                                error: e,
                            })?;
                    }

                    let next_state = ManagedHostState::HostInit {
                        machine_state: MachineState::WaitingForPlatformConfiguration,
                    };

                    Ok(StateHandlerOutcome::Transition(next_state))
                }
                MachineState::WaitingForPlatformConfiguration => {
                    let next_state = if self.host_handler_params.attestation_enabled {
                        ManagedHostState::HostInit {
                            machine_state: MachineState::Measuring {
                                measuring_state: MeasuringState::WaitingForMeasurements,
                            },
                        }
                    } else {
                        ManagedHostState::HostInit {
                            machine_state: MachineState::WaitingForDiscovery,
                        }
                    };

                    tracing::info!(
                        machine_id = %host_machine_id,
                        "Starting UEFI / BMC setup");

                    let redfish_client = build_redfish_client_from_bmc_ip(
                        mh_snapshot.host_snapshot.bmc_addr(),
                        &ctx.services.redfish_client_pool,
                        txn,
                    )
                    .await?;

                    let boot_interface_mac = if mh_snapshot.dpu_snapshots.len() > 1 {
                        // Multi DPU case. Reason it is kept separate is that forge_setup/setting
                        // booting device based on MAC is not tested yet. Soon when it is tested,
                        // and confirmed to work with all hardware, this `if` condition can be removed.
                        let primary_interface = mh_snapshot
                            .host_snapshot
                            .interfaces
                            .iter()
                            .find(|x| x.is_primary)
                            .ok_or_else(|| {
                                StateHandlerError::GenericError(eyre::eyre!(
                                    "Missing primary interface from host: {}",
                                    mh_snapshot.host_snapshot.machine_id
                                ))
                            })?;
                        Some(primary_interface.mac_address.to_string())
                    } else {
                        // libredfish will choose the DPU
                        None
                    };

                    match call_forge_setup_and_handle_no_dpu_error(
                        redfish_client.as_ref(),
                        boot_interface_mac.as_deref(),
                        mh_snapshot.host_snapshot.associated_dpu_machine_ids().len(),
                        ctx.services.site_config.site_explorer.allow_zero_dpu_hosts,
                    )
                    .await
                    {
                        Ok(_) => {
                            // Host needs to be rebooted to pick up the changes after calling forge_setup
                            handler_host_power_control(
                                mh_snapshot,
                                ctx.services,
                                SystemPowerControl::ForceRestart,
                                txn,
                            )
                            .await?;

                            Ok(StateHandlerOutcome::Transition(next_state))
                        }
                        Err(e) => {
                            tracing::warn!("redfish forge_setup failed for {host_machine_id}, potentially due to known race condition between UEFI POST and BMC. triggering force-restart if needed. err: {}", e);

                            // if forge_setup failed, rebooted to potentially work around
                            // a known race between the DPU UEFI and the BMC, where if
                            // the BMC is not up when DPU UEFI runs, then Attributes might
                            // not come through. The fix is to force-restart the DPU to
                            // re-POST.
                            //
                            // As of July 2024, Josh Price said there's an NBU FR to fix
                            // this, but it wasn't target to a release yet.
                            let status = trigger_reboot_if_needed(
                                &mh_snapshot.host_snapshot,
                                mh_snapshot,
                                None,
                                &self.host_handler_params.reachability_params,
                                ctx.services,
                                txn,
                            )
                            .await?;

                            Ok(StateHandlerOutcome::Wait(
                                        format!("redfish forge_setup failed: {e}; triggered host reboot?: {status:#?}"),
                                    ))
                        }
                    }
                }
                MachineState::Measuring { measuring_state } => handle_measuring_state(
                    measuring_state,
                    &mh_snapshot.host_snapshot.machine_id,
                    txn,
                )
                .await
                .map(|v| {
                    map_host_init_measuring_outcome_to_state_handler_outcome(&v, measuring_state)
                })?,
                MachineState::WaitingForDiscovery => {
                    if !discovered_after_state_transition(
                        mh_snapshot.host_snapshot.current.version,
                        mh_snapshot.host_snapshot.last_discovery_time,
                    ) {
                        tracing::trace!(
                            machine_id = %host_machine_id,
                            "Waiting for forge-scout to report host online. \
                                         Host last seen {:?}, must come after DPU's {}",
                            mh_snapshot.host_snapshot.last_discovery_time,
                            mh_snapshot.host_snapshot.current.version.timestamp()
                        );
                        let status = trigger_reboot_if_needed(
                            &mh_snapshot.host_snapshot,
                            mh_snapshot,
                            None,
                            &self.host_handler_params.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?;
                        return Ok(StateHandlerOutcome::Wait(status.status));
                    }

                    Ok(StateHandlerOutcome::Transition(
                        ManagedHostState::HostInit {
                            machine_state: MachineState::UefiSetup {
                                uefi_setup_info: UefiSetupInfo {
                                    uefi_password_jid: None,
                                    uefi_setup_state: UefiSetupState::SetUefiPassword,
                                },
                            },
                        },
                    ))
                }
                MachineState::UefiSetup { uefi_setup_info } => {
                    Ok(
                        handle_host_uefi_setup(txn, ctx, mh_snapshot, uefi_setup_info.clone())
                            .await?,
                    )
                }
                MachineState::WaitingForLockdown { lockdown_info } => {
                    match lockdown_info.state {
                        LockdownState::TimeWaitForDPUDown => {
                            // Lets wait for some time before checking if DPU is up or not.
                            // Waiting is needed because DPU takes some time to go down. If we check DPU
                            // reachability before it goes down, it will give us wrong result.
                            if wait(
                                &mh_snapshot.host_snapshot.current.version.timestamp(),
                                self.host_handler_params.reachability_params.dpu_wait_time,
                            ) {
                                Ok(StateHandlerOutcome::Wait(format!(
                                    "Forced wait of {} for DPU to power down",
                                    self.host_handler_params.reachability_params.dpu_wait_time
                                )))
                            } else {
                                let next_state = ManagedHostState::HostInit {
                                    machine_state: MachineState::WaitingForLockdown {
                                        lockdown_info: LockdownInfo {
                                            state: LockdownState::WaitForDPUUp,
                                            mode: lockdown_info.mode.clone(),
                                        },
                                    },
                                };
                                Ok(StateHandlerOutcome::Transition(next_state))
                            }
                        }
                        LockdownState::WaitForDPUUp => {
                            // Has forge-dpu-agent reported state? That means DPU is up.
                            if are_dpus_up_trigger_reboot_if_needed(
                                mh_snapshot,
                                &self.host_handler_params.reachability_params,
                                ctx.services,
                                txn,
                            )
                            .await
                            {
                                // reboot host
                                // When forge changes BIOS params (for lockdown enable/disable both), host does a power cycle.
                                // During power cycle, DPU also reboots. Now DPU and Host are coming up together. Since DPU is not ready yet,
                                // it does not forward DHCP discover from host and host goes into failure mode and stops sending further
                                // DHCP Discover. A second reboot starts DHCP cycle again when DPU is already up.

                                handler_host_power_control(
                                    mh_snapshot,
                                    ctx.services,
                                    SystemPowerControl::ForceRestart,
                                    txn,
                                )
                                .await?;
                                if LockdownMode::Enable == lockdown_info.mode {
                                    let validation_id = MachineValidation::create_new_run(
                                        txn,
                                        &mh_snapshot.host_snapshot.machine_id,
                                        "Discovery".to_string(),
                                        MachineValidationFilter::default(),
                                    )
                                    .await?;
                                    let next_state = ManagedHostState::HostInit {
                                        machine_state: MachineState::MachineValidating {
                                            context: "Discovery".to_string(),
                                            id: validation_id,
                                            completed: 1,
                                            total: 1,
                                            is_enabled: self
                                                .host_handler_params
                                                .machine_validation_config
                                                .enabled,
                                        },
                                    };
                                    Ok(StateHandlerOutcome::Transition(next_state))
                                } else {
                                    // We have not implemented LockdownMode::Disabled. This is a kind of placeholder for it, but we never needed it.
                                    Ok(StateHandlerOutcome::DoNothing)
                                }
                            } else {
                                Ok(StateHandlerOutcome::Wait("Waiting for DPU to report UP by sending a network status observation".to_string()))
                            }
                        }
                    }
                }
                MachineState::Discovered {
                    skip_reboot_wait: skip_reboot,
                } => {
                    // Check if machine is rebooted. If yes, move to Ready state
                    // or Measuring state, depending on if machine attestation
                    // is enabled or not.
                    if rebooted(&mh_snapshot.host_snapshot) || *skip_reboot {
                        Ok(StateHandlerOutcome::Transition(ManagedHostState::Ready))
                    } else {
                        let status = trigger_reboot_if_needed(
                            &mh_snapshot.host_snapshot,
                            mh_snapshot,
                            None,
                            &self.host_handler_params.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?;
                        Ok(StateHandlerOutcome::Wait(format!(
                            "Waiting for scout to call RebootCompleted grpc. {}",
                            status.status
                        )))
                    }
                }
                MachineState::MachineValidating {
                    context,
                    id,
                    completed,
                    total,
                    is_enabled,
                } => {
                    tracing::trace!(
                        "context = {} id = {} completed = {} total = {}, is_enabled = {} ",
                        context,
                        id,
                        completed,
                        total,
                        is_enabled,
                    );
                    if !rebooted(&mh_snapshot.host_snapshot) {
                        let status = trigger_reboot_if_needed(
                            &mh_snapshot.host_snapshot,
                            mh_snapshot,
                            None,
                            &self.host_handler_params.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?;
                        return Ok(StateHandlerOutcome::Wait(status.status));
                    }
                    if !*is_enabled {
                        tracing::info!("Skipping Machine Validation");
                        let _ = MachineValidation::mark_machine_validation_complete(
                            txn,
                            host_machine_id,
                            id,
                            MachineValidationStatus {
                                state: MachineValidationState::Skipped,
                                ..MachineValidationStatus::default()
                            },
                        )
                        .await;
                        return Ok(StateHandlerOutcome::Transition(
                            ManagedHostState::HostInit {
                                machine_state: MachineState::Discovered {
                                    // Since we're skipping machine validation, we don't need to
                                    // wait on *another* reboot. We already waited for the prior
                                    // reboot to complete above, so tell the Discovered state to
                                    // skip it.
                                    skip_reboot_wait: true,
                                },
                            },
                        ));
                    }
                    // Host validation completed
                    if machine_validation_completed(&mh_snapshot.host_snapshot) {
                        if mh_snapshot.host_snapshot.failure_details.cause == FailureCause::NoError
                        {
                            tracing::info!(
                                "{} machine validation completed",
                                mh_snapshot.host_snapshot.machine_id
                            );

                            handler_host_power_control(
                                mh_snapshot,
                                ctx.services,
                                SystemPowerControl::ForceRestart,
                                txn,
                            )
                            .await?;
                            return Ok(StateHandlerOutcome::Transition(
                                ManagedHostState::HostInit {
                                    machine_state: MachineState::Discovered {
                                        skip_reboot_wait: false,
                                    },
                                },
                            ));
                        } else {
                            tracing::info!(
                                "{} machine validation failed",
                                mh_snapshot.host_snapshot.machine_id
                            );
                            return Ok(StateHandlerOutcome::Transition(ManagedHostState::Failed {
                                details: mh_snapshot.host_snapshot.failure_details.clone(),
                                machine_id: mh_snapshot.host_snapshot.machine_id.clone(),
                                retry_count: 0,
                            }));
                        }
                    }
                    Ok(StateHandlerOutcome::DoNothing)
                }
            }
        } else {
            Err(StateHandlerError::InvalidHostState(
                host_machine_id.clone(),
                Box::new(mh_snapshot.managed_state.clone()),
            ))
        }
    }
}

/// A `StateHandler` implementation for instances
#[derive(Debug, Clone)]
pub struct InstanceStateHandler {
    dpu_nic_firmware_reprovision_update_enabled: bool,
    attestation_enabled: bool,
    reachability_params: ReachabilityParams,
    hardware_models: FirmwareConfig,
}

impl InstanceStateHandler {
    pub fn new(
        dpu_nic_firmware_reprovision_update_enabled: bool,
        attestation_enabled: bool,
        reachability_params: ReachabilityParams,
        hardware_models: FirmwareConfig,
    ) -> Self {
        InstanceStateHandler {
            dpu_nic_firmware_reprovision_update_enabled,
            attestation_enabled,
            reachability_params,
            hardware_models,
        }
    }
}

#[async_trait::async_trait]
impl StateHandler for InstanceStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ContextObjects = MachineStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        mh_snapshot: &mut ManagedHostStateSnapshot,
        _controller_state: &Self::ControllerState,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        let Some(ref instance) = mh_snapshot.instance else {
            return Err(StateHandlerError::GenericError(eyre!(
                "Instance is empty at this point. Cleanup is needed for host: {}.",
                host_machine_id
            )));
        };

        if let ManagedHostState::Assigned { instance_state } = &mh_snapshot.managed_state {
            match instance_state {
                InstanceState::Init => {
                    // we should not be here. This state to be used if state machine has not
                    // picked instance creation and user asked for status.
                    Err(StateHandlerError::InvalidHostState(
                        host_machine_id.clone(),
                        Box::new(mh_snapshot.managed_state.clone()),
                    ))
                }
                InstanceState::WaitingForNetworkSegmentToBeReady => {
                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkConfig,
                    };
                    let network_segment_ids_with_vpc = instance
                        .config
                        .network
                        .interfaces
                        .iter()
                        .filter_map(|x| match x.network_details {
                            Some(NetworkDetails::VpcPrefixId(_)) => x.network_segment_id,
                            _ => None,
                        })
                        .collect_vec();

                    // No network segment is configured with vpc_prefix_id.
                    if network_segment_ids_with_vpc.is_empty() {
                        return Ok(StateHandlerOutcome::Transition(next_state));
                    }

                    let network_segments_are_ready = NetworkSegment::are_network_segments_ready(
                        txn,
                        &network_segment_ids_with_vpc,
                    )
                    .await?;
                    if !network_segments_are_ready {
                        return Ok(StateHandlerOutcome::Wait(
                            "Waiting for all segments to come in ready state.".to_string(),
                        ));
                    }
                    Ok(StateHandlerOutcome::Transition(next_state))
                }
                InstanceState::WaitingForNetworkConfig => {
                    // It should be first state to process here.
                    // Wait for instance network config to be applied
                    // Reboot host and moved to Ready.

                    // TODO GK if delete_requested skip this whole step,
                    // reboot and jump to BootingWithDiscoveryImage

                    // Check DPU network config has been applied
                    if !mh_snapshot.managed_host_network_config_version_synced() {
                        return Ok(StateHandlerOutcome::Wait(
                            "Waiting for DPU agent(s) to apply network config and report healthy network"
                                .to_string(),
                        ));
                    }

                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForStorageConfig,
                    };

                    // Check instance network config has been applied
                    // TODO: This would need to be checked per DPU
                    let expected = &instance.network_config_version;
                    let actual = match &instance.observations.network {
                        None => {
                            if mh_snapshot
                                .host_snapshot
                                .associated_dpu_machine_ids()
                                .is_empty()
                            {
                                tracing::info!(
                                    machine_id = %host_machine_id,
                                    "Skipping network config because machine has no DPUs"
                                );
                                return Ok(StateHandlerOutcome::Transition(next_state));
                            }
                            return Ok(StateHandlerOutcome::Wait(
                                "Waiting for DPU agent to apply initial network config".to_string(),
                            ));
                        }
                        Some(network_status) => &network_status.config_version,
                    };
                    if expected != actual {
                        return Ok(StateHandlerOutcome::Wait(
                            "Waiting for DPU agent to apply most recent network config".to_string(),
                        ));
                    }

                    check_host_health_for_alerts(mh_snapshot)?;

                    ib::bind_ib_ports(
                        ctx.services,
                        txn,
                        instance.id,
                        instance.config.infiniband.ib_interfaces.clone(),
                    )
                    .await?;

                    ib::record_infiniband_status_observation(
                        ctx.services,
                        txn,
                        instance,
                        instance.config.infiniband.ib_interfaces.clone(),
                    )
                    .await?;

                    Ok(StateHandlerOutcome::Transition(next_state))
                }
                InstanceState::WaitingForStorageConfig => {
                    if let Some(dpu_snapshot) = &mh_snapshot.dpu_snapshots.first() {
                        let dpu_machine_id = &dpu_snapshot.machine_id;
                        // attach volumes to instance
                        storage::attach_storage_volumes(
                            ctx.services,
                            txn,
                            instance.id,
                            dpu_machine_id,
                            instance.config.storage.clone(),
                            false,
                        )
                        .await?;

                        storage::record_storage_status_observation(
                            ctx.services,
                            txn,
                            instance,
                            instance.config.storage.clone(),
                        )
                        .await?;
                    }
                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForRebootToReady,
                    };
                    Ok(StateHandlerOutcome::Transition(next_state))
                }
                InstanceState::WaitingForRebootToReady => {
                    // Reboot host
                    handler_host_power_control(
                        mh_snapshot,
                        ctx.services,
                        SystemPowerControl::ForceRestart,
                        txn,
                    )
                    .await?;

                    // Instance is ready.
                    // We can not determine if machine is rebooted successfully or not. Just leave
                    // it like this and declare Instance Ready.
                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::Ready,
                    };
                    Ok(StateHandlerOutcome::Transition(next_state))
                }
                InstanceState::Ready => {
                    // Machine is up after reboot. Hurray. Instance is up.

                    // Wait for user's approval. Once user approves for dpu
                    // reprovision/update firmware, trigger it.
                    let reprov_can_be_started =
                        if dpu_reprovisioning_needed(&mh_snapshot.dpu_snapshots) {
                            // Usually all DPUs are updated with user_approval_received field as true
                            // if `invoke_instance_power` is called.
                            // TODO: multidpu: Move this field to `instances` table and unset on
                            // reprovision is completed.
                            mh_snapshot
                                .dpu_snapshots
                                .iter()
                                .filter(|x| x.reprovision_requested.is_some())
                                .all(|x| {
                                    x.reprovision_requested
                                        .as_ref()
                                        .map(|x| x.user_approval_received)
                                        .unwrap_or_default()
                                })
                        } else {
                            false
                        };

                    if instance.deleted.is_some() || reprov_can_be_started {
                        for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                            if dpu_snapshot.reprovision_requested.is_some() {
                                // User won't be allowed to clear reprovisioning flag after this.
                                Machine::update_dpu_reprovision_start_time(
                                    &dpu_snapshot.machine_id,
                                    txn,
                                )
                                .await?;
                            }
                        }

                        // Reboot host. Host will boot with carbide discovery image now. Changes
                        // are done in get_pxe_instructions api.
                        // User will loose all access to instance now.
                        if let Err(err) = handler_host_power_control(
                            mh_snapshot,
                            ctx.services,
                            SystemPowerControl::ForceRestart,
                            txn,
                        )
                        .await
                        {
                            // Fix: 4647451
                            // No need to return if reboot fails. The managedhost will move to next
                            // state (BootingWithDiscoveryImage) and recovery code will try to
                            // reboot after certain time, if machine does not respond.
                            tracing::error!(%host_machine_id, "Host reboot failed with error: {err}");
                        }

                        let next_state = ManagedHostState::Assigned {
                            instance_state: InstanceState::BootingWithDiscoveryImage {
                                retry: RetryInfo { count: 0 },
                            },
                        };
                        Ok(StateHandlerOutcome::Transition(next_state))
                    } else {
                        ib::record_infiniband_status_observation(
                            ctx.services,
                            txn,
                            instance,
                            instance.config.infiniband.ib_interfaces.clone(),
                        )
                        .await?;
                        Ok(StateHandlerOutcome::DoNothing)
                    }
                }
                InstanceState::BootingWithDiscoveryImage { retry } => {
                    if !rebooted(&mh_snapshot.host_snapshot) {
                        let status = trigger_reboot_if_needed(
                            &mh_snapshot.host_snapshot,
                            mh_snapshot,
                            // can't send 0. 0 will force power-off as cycle calculator.
                            Some(retry.count as i64 + 1),
                            &self.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?;

                        let st = if status.increase_retry_count {
                            let next_state = ManagedHostState::Assigned {
                                instance_state: InstanceState::BootingWithDiscoveryImage {
                                    retry: RetryInfo {
                                        count: retry.count + 1,
                                    },
                                },
                            };
                            StateHandlerOutcome::Transition(next_state)
                        } else {
                            StateHandlerOutcome::Wait(status.status)
                        };
                        return Ok(st);
                    }

                    // Now retry_count won't exceed a limit. Function trigger_reboot_if_needed does
                    // not reboot a machine after 6 hrs, so this counter won't increase at all
                    // after 6 hours.
                    ctx.metrics
                        .machine_reboot_attempts_in_booting_with_discovery_image =
                        Some(retry.count + 1);

                    // In case state is triggered for delete instance handling, follow that path.
                    if instance.deleted.is_some() {
                        let next_state = ManagedHostState::Assigned {
                            instance_state: InstanceState::SwitchToAdminNetwork,
                        };
                        return Ok(StateHandlerOutcome::Transition(next_state));
                    }

                    // If we are here, DPU reprov MUST have been be requested.
                    if dpu_reprovisioning_needed(&mh_snapshot.dpu_snapshots) {
                        // All DPUs must have same value for this parameter. All DPUs are updated
                        // together grpc API or automatic updater.
                        // TODO: multidpu: Keep it at some common place to avoid duplicates.
                        let mut dpus_for_reprov = vec![];
                        for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                            if dpu_snapshot.reprovision_requested.is_some() {
                                handler_restart_dpu(dpu_snapshot, ctx.services, txn).await?;
                                dpus_for_reprov.push(dpu_snapshot);
                            }
                        }

                        let is_firmware_upgrade_needed = dpus_for_reprov.iter().any(|x| {
                            x.reprovision_requested
                                .as_ref()
                                .map(|x| x.update_firmware)
                                .unwrap_or_default()
                        });

                        let reprovision_state = if is_firmware_upgrade_needed
                            && self.dpu_nic_firmware_reprovision_update_enabled
                        {
                            ReprovisionState::BmcFirmwareUpgrade {
                                substate: BmcFirmwareUpgradeSubstate::CheckFwVersion,
                            }
                        } else {
                            set_managed_host_topology_update_needed(
                                txn,
                                &mh_snapshot.host_snapshot,
                                &dpus_for_reprov,
                            )
                            .await?;
                            ReprovisionState::WaitingForNetworkInstall
                        };
                        let next_state = reprovision_state.next_state_with_all_dpus_updated(
                            &mh_snapshot.managed_state,
                            &mh_snapshot.dpu_snapshots,
                            dpus_for_reprov.iter().map(|x| &x.machine_id).collect_vec(),
                        )?;
                        Ok(StateHandlerOutcome::Transition(next_state))
                    } else {
                        Ok(StateHandlerOutcome::Wait(
                            "Don't know how did we reach here.".to_string(),
                        ))
                    }
                }

                InstanceState::SwitchToAdminNetwork => {
                    // Tenant is gone and so is their network, switch back to admin network
                    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                        let (mut netconf, version) = dpu_snapshot.network_config.clone().take();
                        netconf.use_admin_network = Some(true);
                        Machine::try_update_network_config(
                            txn,
                            &dpu_snapshot.machine_id,
                            version,
                            &netconf,
                        )
                        .await?;
                    }

                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkReconfig,
                    };
                    Ok(StateHandlerOutcome::Transition(next_state))
                }
                InstanceState::WaitingForNetworkReconfig => {
                    // Has forge-dpu-agent applied the new network config so that
                    // we are back on the admin network?
                    if !mh_snapshot.managed_host_network_config_version_synced() {
                        return Ok(StateHandlerOutcome::Wait(
                            "Waiting for DPU agent(s) to apply network config and report healthy network"
                                .to_string(),
                        ));
                    }
                    check_host_health_for_alerts(mh_snapshot)?;

                    ib::unbind_ib_ports(
                        ctx.services,
                        txn,
                        instance.id,
                        instance.config.infiniband.ib_interfaces.clone(),
                    )
                    .await?;

                    // TODO: TPM cleanup
                    // Reboot host
                    handler_host_power_control(
                        mh_snapshot,
                        ctx.services,
                        SystemPowerControl::ForceRestart,
                        txn,
                    )
                    .await?;

                    // Deleting an instance and marking vpc segments deleted must be done together.
                    // If segments are marked deleted and instance is not deleted (may be due to redfish failure),
                    // network segment handler will delete those segments forcefully.
                    // if instance is deleted before, we won't get network segment details as these
                    // details are stored in instance's network config which is deleted.

                    // Delete from database now. Once done, reboot and move to next state.
                    DeleteInstance {
                        instance_id: instance.id,
                    }
                    .delete(txn)
                    .await
                    .map_err(|err| StateHandlerError::GenericError(err.into()))?;

                    let network_segment_ids_with_vpc = instance
                        .config
                        .network
                        .interfaces
                        .iter()
                        .filter_map(|x| match x.network_details {
                            Some(NetworkDetails::VpcPrefixId(_)) => x.network_segment_id,
                            _ => None,
                        })
                        .collect_vec();

                    // Mark all network ready for delete which were created for vpc_prefixes.
                    if !network_segment_ids_with_vpc.is_empty() {
                        NetworkSegment::mark_as_deleted_no_validation(
                            txn,
                            &network_segment_ids_with_vpc,
                        )
                        .await
                        .map_err(|err| StateHandlerError::GenericError(err.into()))?;
                    }

                    let next_state = if self.attestation_enabled {
                        ManagedHostState::PostAssignedMeasuring {
                            measuring_state: MeasuringState::WaitingForMeasurements,
                        }
                    } else {
                        ManagedHostState::WaitingForCleanup {
                            cleanup_state: CleanupState::HostCleanup,
                        }
                    };
                    Ok(StateHandlerOutcome::Transition(next_state))
                }
                InstanceState::DPUReprovision { .. } => {
                    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                        if let StateHandlerOutcome::Transition(next_state) = handle_dpu_reprovision(
                            mh_snapshot,
                            &self.reachability_params,
                            ctx.services,
                            txn,
                            &InstanceNextStateResolver,
                            dpu_snapshot,
                            &self.hardware_models,
                        )
                        .await?
                        {
                            return Ok(StateHandlerOutcome::Transition(next_state));
                        }
                    }
                    Ok(StateHandlerOutcome::DoNothing)
                }
                InstanceState::Failed {
                    details,
                    machine_id,
                } => {
                    // Only way to proceed is to
                    // 1. Force-delete the machine.
                    // 2. If failed during reprovision, fix the config/hw issue and
                    //    retrigger DPU reprovision.
                    tracing::warn!(
                        "Instance id {}/machine: {} stuck in failed state. details: {:?}, failed machine: {}",
                        instance.id,
                        host_machine_id,
                        details,
                        machine_id
                    );
                    return Ok(StateHandlerOutcome::DoNothing);
                }
            }
        } else {
            // We are not in Assigned state. Should this be Err(StateHandlerError::InvalidHostState)?
            Ok(StateHandlerOutcome::DoNothing)
        }
    }
}

/// Issues a reboot request command to a host or DPU
async fn handler_restart_dpu(
    machine_snapshot: &MachineSnapshot,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), StateHandlerError> {
    restart_dpu(machine_snapshot, services, txn).await?;

    Machine::update_reboot_requested_time(
        &machine_snapshot.machine_id,
        txn,
        crate::model::machine::MachineLastRebootRequestedMode::Reboot,
    )
    .await
    .map_err(|err| err.into())
    //handler_host_power_control(state, services, SystemPowerControl::ForceRestart, txn).await
}

async fn host_power_state(
    redfish_client: &dyn Redfish,
) -> Result<libredfish::PowerState, StateHandlerError> {
    redfish_client
        .get_power_state()
        .await
        .map_err(|e| StateHandlerError::RedfishError {
            operation: "get_power_state",
            error: e,
        })
}

pub async fn handler_host_power_control(
    managedhost_snapshot: &ManagedHostStateSnapshot,
    services: &StateHandlerServices,
    action: SystemPowerControl,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), StateHandlerError> {
    let redfish_client = build_redfish_client_from_bmc_ip(
        managedhost_snapshot.host_snapshot.bmc_addr(),
        &services.redfish_client_pool,
        txn,
    )
    .await?;

    let power_state = host_power_state(redfish_client.as_ref()).await?;

    if (power_state == libredfish::PowerState::Off
        && (action == SystemPowerControl::ForceOff
            || action == SystemPowerControl::GracefulShutdown))
        || (power_state == libredfish::PowerState::On && action == SystemPowerControl::On)
    {
        let machine_id = &managedhost_snapshot.host_snapshot.machine_id;
        tracing::warn!(%machine_id, %power_state, %action, "Target power state is already reached. Skipping power control action");
    } else {
        host_power_control(
            redfish_client.as_ref(),
            &managedhost_snapshot.host_snapshot,
            action,
            services.ipmi_tool.clone(),
            txn,
        )
        .await
        .map_err(|e| {
            StateHandlerError::GenericError(eyre!("handler_host_power_control failed: {}", e))
        })?;
    }
    // If host is forcedOff/On, it will impact DPU also. So DPU timestamp should also be updated
    // here.
    if action == SystemPowerControl::ForceOff || action == SystemPowerControl::On {
        for dpu_snapshot in &managedhost_snapshot.dpu_snapshots {
            Machine::update_reboot_requested_time(&dpu_snapshot.machine_id, txn, action.into())
                .await?;
        }
    }

    Ok(())
}

async fn restart_dpu(
    machine_snapshot: &MachineSnapshot,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), StateHandlerError> {
    let dpu_redfish_client = build_redfish_client_from_bmc_ip(
        machine_snapshot.bmc_addr(),
        &services.redfish_client_pool,
        txn,
    )
    .await?;

    if let Err(e) = dpu_redfish_client
        .power(SystemPowerControl::ForceRestart)
        .await
    {
        tracing::error!(%e, "Failed to reboot a DPU");
        return Err(StateHandlerError::RedfishError {
            operation: "reboot dpu",
            error: e,
        });
    }

    Ok(())
}

/// Issues a lockdown and reboot request command to a host.
async fn lockdown_host(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &ManagedHostStateSnapshot,
    services: &StateHandlerServices,
) -> Result<(), StateHandlerError> {
    let host_snapshot = &state.host_snapshot;
    let redfish_client = build_redfish_client_from_bmc_ip(
        host_snapshot.bmc_addr(),
        &services.redfish_client_pool,
        txn,
    )
    .await?;

    // the forge_setup call includes the equivalent of these calls internally in libredfish
    // - serial setup (bios, bmc)
    // - tpm clear (bios)
    // - boot once to pxe
    let boot_interface_mac = if state.dpu_snapshots.len() > 1 {
        // Multi DPU case
        let primary_interface = state
            .host_snapshot
            .interfaces
            .iter()
            .find(|x| x.is_primary)
            .ok_or_else(|| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "Missing primary interface from host: {}",
                    state.host_snapshot.machine_id
                ))
            })?;
        Some(primary_interface.mac_address.to_string())
    } else {
        // libredfish will choose the DPU
        None
    };

    call_forge_setup_and_handle_no_dpu_error(
        redfish_client.as_ref(),
        boot_interface_mac.as_deref(),
        state.host_snapshot.associated_dpu_machine_ids().len(),
        services.site_config.site_explorer.allow_zero_dpu_hosts,
    )
    .await
    .map_err(|e| StateHandlerError::RedfishError {
        operation: "forge_setup",
        error: e,
    })?;

    redfish_client
        .lockdown(libredfish::EnabledDisabled::Enabled)
        .await
        .map_err(|e| StateHandlerError::RedfishError {
            operation: "lockdown",
            error: e,
        })?;

    tracing::info!("Forcing restart");

    handler_host_power_control(state, services, SystemPowerControl::ForceRestart, txn).await?;

    Ok(())
}

/// find_explored_refreshed_endpoint will locate the explored endpoint for the given state.
/// It will return an error for not finding any endpoint, and Ok(None) when we're still waiting
/// on explorer to have a chance to run again.
pub async fn find_explored_refreshed_endpoint(
    state: &ManagedHostStateSnapshot,
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Option<ExploredEndpoint>, StateHandlerError> {
    let addr: IpAddr = state
        .host_snapshot
        .bmc_info
        .ip_addr()
        .map_err(StateHandlerError::GenericError)?;

    let endpoint = DbExploredEndpoint::find_by_ips(txn, vec![addr]).await?;
    let endpoint = endpoint.first().ok_or(StateHandlerError::GenericError(
        eyre! {"Unable to find explored_endpoint for {machine_id}"},
    ))?;

    if endpoint.waiting_for_explorer_refresh {
        // In the cases where this was called, we care about prompt updates, so poke site explorer to revisit this endpoint next time it runs
        DbExploredEndpoint::re_explore_if_version_matches(
            endpoint.address,
            endpoint.report_version,
            txn,
        )
        .await?;
        return Ok(None);
    }
    Ok(Some(endpoint.clone()))
}

struct HostWaitingFWArgs {
    task_id: String,
    firmware_type: FirmwareComponentType,
    final_version: String,
}

// If already reprovisioning is started, we can restart.
// Also check that this is not some old request. The restart requested time must be greater than
// last state change.
fn can_restart_reprovision(
    dpu_snapshots: &[MachineSnapshot],
    version: ConfigVersion,
) -> (bool, bool) {
    let mut reprov_started = false;
    let mut requested_at = vec![];
    let mut firmware_upgrade_needed = false;
    for dpu_snapshot in dpu_snapshots {
        if let Some(reprov_req) = &dpu_snapshot.reprovision_requested {
            if reprov_req.started_at.is_some() {
                reprov_started = true;
            }
            firmware_upgrade_needed |= reprov_req.update_firmware;
            requested_at.push(reprov_req.restart_reprovision_requested_at);
        }
    }

    if !reprov_started {
        return (false, false);
    }

    // Get the latest time of restart requested.
    requested_at.sort();

    let Some(latest_requested_at) = requested_at.last() else {
        return (false, false);
    };

    (
        dpu_reprovision_restart_requested_after_state_transition(version, *latest_requested_at),
        firmware_upgrade_needed,
    )
}

/// Call [`Redfish::forge_setup`], but ignore any [`RedfishError::NoDpu`] if we expect there to be no DPUs.
///
/// TODO(ken): This is a temporary workaround for work-in-progress on zero-DPU support (August 2024)
/// The way we should do this going forward is to plumb the actual non-DPU MAC address we want to
/// boot from, but that information is not in scope at this time. Once it is, and we pass it to
/// forge_setup, we should no longer expect a NoDpu error and can thus call vanilla forge_setup again.
async fn call_forge_setup_and_handle_no_dpu_error(
    redfish_client: &dyn Redfish,
    boot_interface_mac: Option<&str>,
    expected_dpu_count: usize,
    allow_zero_dpus: bool,
) -> Result<(), RedfishError> {
    let setup_result = redfish_client.forge_setup(boot_interface_mac).await;
    match (setup_result, expected_dpu_count, allow_zero_dpus) {
        (Err(RedfishError::NoDpu), 0, true) => {
            tracing::info!("redfish forge_setup failed due to there being no DPUs on the host. This is expected as the host has no DPUs, and we are configured to allow this.");
            Ok(())
        }
        (Ok(()), _, _) => Ok(()),
        (Err(e), _, _) => Err(e),
    }
}

// Returns true if update_manager flagged this managed host as needing its firmware examined
async fn is_machine_validation_requested(state: &ManagedHostStateSnapshot) -> bool {
    let Some(on_demand_machine_validation_request) =
        state.host_snapshot.on_demand_machine_validation_request
    else {
        return false;
    };

    if on_demand_machine_validation_request {
        tracing::info!(machine_id = %state.host_snapshot.machine_id, "Machine Validation is requested");
    }

    on_demand_machine_validation_request
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_cycle_1() {
        let state_change_time =
            chrono::DateTime::<Utc>::from_str("2024-01-30T11:26:18.261228950+00:00").unwrap();

        let expected_time = state_change_time + Duration::minutes(30);
        let wait_period = Duration::minutes(30);

        let cycle = get_reboot_cycle(expected_time, state_change_time, wait_period).unwrap();
        assert_eq!(cycle, 1);
    }

    #[test]
    fn test_cycle_2() {
        let state_change_time =
            chrono::DateTime::<Utc>::from_str("2024-01-30T11:26:18.261228950+00:00").unwrap();

        let expected_time = state_change_time + Duration::minutes(70);
        let wait_period = Duration::minutes(30);

        let cycle = get_reboot_cycle(expected_time, state_change_time, wait_period).unwrap();
        assert_eq!(cycle, 2);
    }

    #[test]
    fn test_cycle_3() {
        let state_change_time =
            chrono::DateTime::<Utc>::from_str("2024-01-30T11:26:18.261228950+00:00").unwrap();

        let expected_time = state_change_time + Duration::minutes(121);
        let wait_period = Duration::minutes(30);

        let cycle = get_reboot_cycle(expected_time, state_change_time, wait_period).unwrap();
        assert_eq!(cycle, 4);
    }

    #[test]
    fn test_cycle_4() {
        let state_change_time =
            chrono::DateTime::<Utc>::from_str("2024-01-30T11:26:18.261228950+00:00").unwrap();

        let expected_time = state_change_time + Duration::minutes(30);
        let wait_period = Duration::minutes(0);

        let cycle = get_reboot_cycle(expected_time, state_change_time, wait_period).unwrap();
        assert_eq!(cycle, 30);
    }
}
