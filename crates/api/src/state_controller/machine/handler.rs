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

//! State Handler implementation for Machines

use std::collections::{HashMap, HashSet};
use std::mem::discriminant as enum_discr;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use carbide_dpf::KubeImpl;
use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Duration, Utc};
use config_version::{ConfigVersion, Versioned};
use db::host_machine_update::clear_host_reprovisioning_request;
use db::machine::{mark_machine_ingestion_done_with_dpf, update_restart_verification_status};
use db::{self};
use eyre::eyre;
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialProvider, Credentials,
};
use futures::TryFutureExt;
use health_report::{
    HealthAlertClassification, HealthProbeAlert, HealthProbeId, HealthReport, OverrideMode,
};
use itertools::Itertools;
use libredfish::model::oem::nvidia_dpu::HostPrivilegeLevel;
use libredfish::model::task::TaskState;
use libredfish::model::update_service::TransferProtocolType;
use libredfish::{Boot, EnabledDisabled, PowerState, Redfish, RedfishError, SystemPowerControl};
use machine_validation::{handle_machine_validation_requested, handle_machine_validation_state};
use measured_boot::records::MeasurementMachineState;
use model::DpuModel;
use model::firmware::{Firmware, FirmwareComponentType, FirmwareEntry};
use model::instance::InstanceNetworkSyncStatus;
use model::instance::config::network::{
    DeviceLocator, InstanceInterfaceConfig, InterfaceFunctionId, NetworkDetails,
};
use model::instance::snapshot::InstanceSnapshot;
use model::instance::status::SyncState;
use model::instance::status::extension_service::{
    self, ExtensionServiceDeploymentStatus, ExtensionServicesReadiness,
    InstanceExtensionServicesStatus,
};
use model::machine::LockdownMode::{self, Enable};
use model::machine::infiniband::{IbConfigNotSyncedReason, ib_config_synced};
use model::machine::nvlink::nvlink_config_synced;
use model::machine::{
    BomValidating, BomValidatingContext, CleanupState, CreateBossVolumeContext,
    CreateBossVolumeState, DpuDiscoveringState, DpuInitNextStateResolver, DpuInitState,
    FailureCause, FailureDetails, FailureSource, HostPlatformConfigurationState,
    HostReprovisionState, InitialResetPhase, InstallDpuOsState, InstanceNextStateResolver,
    InstanceState, LockdownInfo, LockdownState, Machine, MachineLastRebootRequested,
    MachineLastRebootRequestedMode, MachineNextStateResolver, MachineState, ManagedHostState,
    ManagedHostStateSnapshot, MeasuringState, NetworkConfigUpdateState, NextStateBFBSupport,
    PerformPowerOperation, PowerDrainState, ReprovisionState, RetryInfo, SecureEraseBossContext,
    SecureEraseBossState, SetBootOrderInfo, SetBootOrderState, SetSecureBootState,
    StateMachineArea, UefiSetupInfo, UefiSetupState, ValidationState,
    dpf_based_dpu_provisioning_possible, get_display_ids,
};
use model::power_manager::PowerHandlingOutcome;
use model::resource_pool::common::CommonPools;
use model::site_explorer::ExploredEndpoint;
use sku::{handle_bom_validation_requested, handle_bom_validation_state};
use sqlx::PgConnection;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tokio::sync::Semaphore;
use tracing::instrument;
use version_compare::Cmp;

use crate::cfg::file::{
    BomValidationConfig, CarbideConfig, FirmwareConfig, MachineValidationConfig,
    PowerManagerOptions, TimePeriod,
};
use crate::firmware_downloader::FirmwareDownloader;
use crate::redfish::{
    self, host_power_control, host_power_control_with_location, set_host_uefi_password,
};
use crate::state_controller::common_services::CommonStateHandlerServices;
use crate::state_controller::machine::context::MachineStateHandlerContextObjects;
use crate::state_controller::machine::{
    MeasuringOutcome, get_measuring_prerequisites, handle_measuring_state,
};
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
    StateHandlerOutcomeWithTransaction,
};

mod dpf;
mod helpers;
mod machine_validation;
mod power;
mod sku;
use helpers::{
    DpuDiscoveringStateHelper, DpuInitStateHelper, ManagedHostStateHelper, NextState,
    ReprovisionStateHelper, all_equal,
};

// We can't use http::StatusCode because libredfish has a newer version
const NOT_FOUND: u16 = 404;

#[cfg(not(test))]
pub const MAX_FIRMWARE_UPGRADE_RETRIES: u32 = 5;

#[cfg(test)]
pub const MAX_FIRMWARE_UPGRADE_RETRIES: u32 = 2; // Faster for tests

/// Reachability params to check if DPU is up or not.
#[derive(Copy, Clone, Debug)]
pub struct ReachabilityParams {
    pub dpu_wait_time: chrono::Duration,
    pub power_down_wait: chrono::Duration,
    pub failure_retry_time: chrono::Duration,
    pub scout_reporting_timeout: chrono::Duration,
}

/// Parameters used by the HostStateMachineHandler.
#[derive(Clone, Debug)]
pub struct HostHandlerParams {
    pub attestation_enabled: bool,
    pub reachability_params: ReachabilityParams,
    pub machine_validation_config: MachineValidationConfig,
    pub bom_validation: BomValidationConfig,
}

/// Parameters used by the Power config.
#[derive(Clone, Debug)]
pub struct PowerOptionConfig {
    pub enabled: bool,
    pub next_try_duration_on_success: chrono::TimeDelta,
    pub next_try_duration_on_failure: chrono::TimeDelta,
    pub wait_duration_until_host_reboot: chrono::TimeDelta,
}

impl From<PowerManagerOptions> for PowerOptionConfig {
    fn from(options: PowerManagerOptions) -> Self {
        Self {
            enabled: options.enabled,
            next_try_duration_on_success: options.next_try_duration_on_success,
            next_try_duration_on_failure: options.next_try_duration_on_failure,
            wait_duration_until_host_reboot: options.wait_duration_until_host_reboot,
        }
    }
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
    host_upgrade: Arc<HostUpgradeState>,
    power_options_config: PowerOptionConfig,
    enable_secure_boot: bool,
}

#[derive(Debug, Clone)]
pub struct DpfConfig {
    enabled: bool,
    pub kube_client_provider: Arc<dyn KubeImpl>,
}

impl DpfConfig {
    pub fn from(
        config: crate::cfg::file::DpfConfig,
        kube_client_provider: Arc<dyn KubeImpl>,
    ) -> Self {
        Self {
            enabled: config.enabled,
            kube_client_provider,
        }
    }
}

pub struct MachineStateHandlerBuilder {
    dpu_up_threshold: chrono::Duration,
    dpu_nic_firmware_initial_update_enabled: bool,
    // TODO: Cleanup needed for this flag.
    dpu_nic_firmware_reprovision_update_enabled: bool,
    hardware_models: Option<FirmwareConfig>,
    no_firmware_update_reset_retries: bool,
    reachability_params: ReachabilityParams,
    firmware_downloader: Option<FirmwareDownloader>,
    attestation_enabled: bool,
    upload_limiter: Option<Arc<Semaphore>>,
    machine_validation_config: MachineValidationConfig,
    common_pools: Option<Arc<CommonPools>>,
    bom_validation: BomValidationConfig,
    instance_autoreboot_period: Option<TimePeriod>,
    credential_provider: Option<Arc<dyn CredentialProvider>>,
    power_options_config: PowerOptionConfig,
    enable_secure_boot: bool,
    hgx_bmc_gpu_reboot_delay: chrono::Duration,
    dpf_config: DpfConfig,
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
                scout_reporting_timeout: chrono::Duration::zero(),
            },
            firmware_downloader: None,
            no_firmware_update_reset_retries: false,
            attestation_enabled: false,
            upload_limiter: None,
            machine_validation_config: MachineValidationConfig {
                enabled: true,
                ..MachineValidationConfig::default()
            },
            common_pools: None,
            bom_validation: BomValidationConfig::default(),
            instance_autoreboot_period: None,
            credential_provider: None,
            power_options_config: PowerOptionConfig {
                enabled: true,
                next_try_duration_on_success: chrono::Duration::minutes(0),
                next_try_duration_on_failure: chrono::Duration::minutes(0),
                wait_duration_until_host_reboot: chrono::Duration::minutes(0),
            },
            enable_secure_boot: false,
            hgx_bmc_gpu_reboot_delay: chrono::Duration::seconds(30),
            dpf_config: DpfConfig {
                enabled: false,
                kube_client_provider: Arc::new(carbide_dpf::Production {}),
            },
        }
    }

    pub fn dpf_config(mut self, dpf_config: DpfConfig) -> Self {
        self.dpf_config = dpf_config;
        self
    }

    pub fn credential_provider(mut self, credential_provider: Arc<dyn CredentialProvider>) -> Self {
        self.credential_provider = Some(credential_provider);
        self
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

    pub fn dpu_enable_secure_boot(mut self, dpu_enable_secure_boot: bool) -> Self {
        self.enable_secure_boot = dpu_enable_secure_boot;
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

    pub fn scout_reporting_timeout(mut self, scout_reporting_timeout: chrono::Duration) -> Self {
        self.reachability_params.scout_reporting_timeout = scout_reporting_timeout;
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

    pub fn common_pools(mut self, common_pools: Arc<CommonPools>) -> Self {
        self.common_pools = Some(common_pools);
        self
    }

    pub fn bom_validation(mut self, bom_validation: BomValidationConfig) -> Self {
        self.bom_validation = bom_validation;
        self
    }

    pub fn no_firmware_update_reset_retries(
        mut self,
        no_firmware_update_reset_retries: bool,
    ) -> Self {
        self.no_firmware_update_reset_retries = no_firmware_update_reset_retries;
        self
    }

    pub fn instance_autoreboot_period(mut self, period: Option<TimePeriod>) -> Self {
        self.instance_autoreboot_period = period;
        self
    }

    pub fn power_options_config(mut self, config: PowerOptionConfig) -> Self {
        self.power_options_config = config;
        self
    }

    pub fn build(self) -> MachineStateHandler {
        MachineStateHandler::new(self)
    }
}

impl MachineStateHandler {
    fn new(builder: MachineStateHandlerBuilder) -> Self {
        let host_upgrade = Arc::new(HostUpgradeState {
            parsed_hosts: Arc::new(builder.hardware_models.clone().unwrap_or_default()),
            downloader: builder.firmware_downloader.unwrap_or_default(),
            upload_limiter: builder
                .upload_limiter
                .unwrap_or(Arc::new(Semaphore::new(5))),
            no_firmware_update_reset_retries: builder.no_firmware_update_reset_retries,
            instance_autoreboot_period: builder.instance_autoreboot_period,
            upgrade_script_state: Default::default(),
            credential_provider: builder.credential_provider,
            async_firmware_uploader: Arc::new(Default::default()),
            hgx_bmc_gpu_reboot_delay: builder
                .hgx_bmc_gpu_reboot_delay
                .to_std()
                .unwrap_or(tokio::time::Duration::from_secs(30)),
        });
        MachineStateHandler {
            dpu_up_threshold: builder.dpu_up_threshold,
            host_handler: HostMachineStateHandler::new(HostHandlerParams {
                attestation_enabled: builder.attestation_enabled,
                reachability_params: builder.reachability_params,
                machine_validation_config: builder.machine_validation_config,
                bom_validation: builder.bom_validation,
            }),
            dpu_handler: DpuMachineStateHandler::new(
                builder.dpu_nic_firmware_initial_update_enabled,
                builder.hardware_models.clone().unwrap_or_default(),
                builder.reachability_params,
                builder.enable_secure_boot,
                builder.dpf_config.clone(),
            ),
            instance_handler: InstanceStateHandler::new(
                builder.attestation_enabled,
                builder.reachability_params,
                builder.common_pools,
                host_upgrade.clone(),
                builder.hardware_models.clone().unwrap_or_default(),
                builder.enable_secure_boot,
                builder.dpf_config.clone(),
            ),
            reachability_params: builder.reachability_params,
            host_upgrade,
            power_options_config: builder.power_options_config,
            enable_secure_boot: builder.enable_secure_boot,
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

            for mut component in dpu_snapshot
                .inventory
                .as_ref()
                .map(|i| i.components.clone())
                .unwrap_or_default()
            {
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
                    .entry(observation.machine_id.to_string())
                    .or_default() = observation.client_certificate_expiry;
            }
        }

        ctx.metrics.machine_id = state.host_snapshot.id.to_string();
        ctx.metrics.is_usable_as_instance = state.is_usable_as_instance(false).is_ok();
        ctx.metrics.num_gpus = state
            .host_snapshot
            .hardware_info
            .as_ref()
            .map(|info| info.gpus.len())
            .unwrap_or_default();
        ctx.metrics.in_use_by_tenant = state
            .instance
            .as_ref()
            .map(|instance| instance.config.tenant.tenant_organization_id.clone());
        ctx.metrics.is_host_bios_password_set =
            state.host_snapshot.bios_password_set_time.is_some();
        ctx.metrics.sku = state.host_snapshot.hw_sku.clone();
        ctx.metrics.sku_device_type = state.host_snapshot.hw_sku_device_type.clone();

        // Note that DPU alerts may be suppressed (classifications removed) in the aggregate health report.
        let suppress_alerts =
            health_report::HealthAlertClassification::suppress_external_alerting();
        for alert in state.aggregate_health.alerts.iter() {
            ctx.metrics
                .health_probe_alerts
                .insert((alert.id.clone(), alert.target.clone()));
            for c in alert.classifications.iter() {
                ctx.metrics.health_alert_classifications.insert(c.clone());
                if *c == suppress_alerts {
                    ctx.metrics.alerts_suppressed = true;
                }
            }
        }

        ctx.metrics.num_merge_overrides = state.host_snapshot.health_report_overrides.merges.len();
        ctx.metrics.replace_override_enabled = state
            .host_snapshot
            .health_report_overrides
            .replace
            .is_some();
    }

    async fn record_health_history(
        &self,
        mh_snapshot: &mut ManagedHostStateSnapshot,
        txn: &mut PgConnection,
    ) -> Result<(), StateHandlerError> {
        db::machine_health_history::persist(
            txn,
            &mh_snapshot.host_snapshot.id,
            &mh_snapshot.aggregate_health,
        )
        .await?;

        Ok(())
    }

    async fn clear_dpu_reprovision(
        mh_snaphost: &ManagedHostStateSnapshot,
        txn: &mut PgConnection,
    ) -> Result<(), StateHandlerError> {
        db::machine::remove_health_report_override(
            txn,
            &mh_snaphost.host_snapshot.id,
            health_report::OverrideMode::Merge,
            model::machine_update_module::HOST_UPDATE_HEALTH_REPORT_SOURCE,
        )
        .await?;

        for dpu_snapshot in &mh_snaphost.dpu_snapshots {
            db::machine::clear_dpu_reprovisioning_request(txn, &dpu_snapshot.id, false)
                .await
                .map_err(StateHandlerError::from)?;
        }

        Ok(())
    }

    async fn clear_host_reprovision(
        mh_snaphost: &ManagedHostStateSnapshot,
        txn: &mut PgConnection,
    ) -> Result<(), StateHandlerError> {
        // Host fw update health override is not set yet. It is done when host re-provisioning is
        // started in state handler.
        clear_host_reprovisioning_request(txn, &mh_snaphost.host_snapshot.id)
            .await
            .map_err(StateHandlerError::from)?;

        Ok(())
    }

    async fn clear_host_update_alert_and_reprov(
        mh_snaphost: &ManagedHostStateSnapshot,
        txn: &mut PgConnection,
    ) -> Result<(), StateHandlerError> {
        // Clear DPU reprovision
        Self::clear_dpu_reprovision(mh_snaphost, txn).await?;

        // Clear host reprovision
        Self::clear_host_reprovision(mh_snaphost, txn).await
    }

    #[allow(txn_held_across_await)]
    async fn attempt_state_transition(
        &self,
        host_machine_id: &MachineId,
        mh_snapshot: &mut ManagedHostStateSnapshot,
        txn: &mut PgConnection,
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
                        let dpu_machine_id = &dpu_snapshot.id;
                        let health_report = health_report::HealthReport::heartbeat_timeout(
                            "forge-dpu-agent".to_string(),
                            "forge-dpu-agent".to_string(),
                            message,
                        );
                        db::machine::update_dpu_agent_health_report(
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
                        return Ok(StateHandlerOutcome::do_nothing());
                    }
                }
            }
        }

        if let Some(outcome) = handle_restart_verification(mh_snapshot, txn, ctx).await? {
            return Ok(outcome);
        }

        if dpu_reprovisioning_needed(&mh_snapshot.dpu_snapshots) {
            // Reprovision is started and user requested for restart of reprovision.
            let restart_reprov = can_restart_reprovision(
                &mh_snapshot.dpu_snapshots,
                mh_snapshot.host_snapshot.state.version,
            );
            if restart_reprov
                && let Some(next_state) = self
                    .start_dpu_reprovision(&mh_state, mh_snapshot, ctx, txn, host_machine_id)
                    .await?
            {
                return Ok(StateHandlerOutcome::transition(next_state));
            }
        }

        // Don't update failed state failure cause everytime. Record first failure cause only,
        // otherwise first failure cause will be overwritten.
        if !matches!(mh_state, ManagedHostState::Failed { .. })
            && let Some((machine_id, details)) = get_failed_state(mh_snapshot)
        {
            tracing::error!(
                %machine_id,
                "ManagedHost {}/{} (failed machine: {}) is moved to Failed state with cause: {:?}",
                mh_snapshot.host_snapshot.id,
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
            return Ok(StateHandlerOutcome::transition(next_state));
        }

        match &mh_state {
            ManagedHostState::DpuDiscoveringState { .. } => {
                if mh_snapshot
                    .host_snapshot
                    .associated_dpu_machine_ids()
                    .is_empty()
                {
                    // GB200/300 dpu info not populated in expected machines and dpu not cabled up will go through here.
                    tracing::info!(
                        machine_id = %host_machine_id,
                        "Skipping to HostInit because machine has no DPUs"
                    );
                    Ok(StateHandlerOutcome::transition(
                        ManagedHostState::HostInit {
                            machine_state: MachineState::WaitingForPlatformConfiguration,
                        },
                    ))
                } else {
                    let mut state_handler_outcome = StateHandlerOutcome::do_nothing();
                    if ctx.services.site_config.force_dpu_nic_mode {
                        // skip dpu discovery and init entirely, treat it as a nic
                        return Ok(StateHandlerOutcome::transition(
                            ManagedHostState::HostInit {
                                machine_state: MachineState::WaitingForPlatformConfiguration,
                            },
                        ));
                        /*
                        // todo: check for machine type before skipping? not sure site explorer is setting this
                        if let Some(hwinfo) = mh_snapshot.host_snapshot.hardware_info.clone() {
                            if let Some(dmi_data) = hwinfo.dmi_data {
                                if dmi_data.product_name.contains("GB200 NVL") {

                                }
                            }
                        }
                         */
                    }
                    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
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

                        if let outcome @ StateHandlerOutcome::Transition { .. } =
                            state_handler_outcome
                        {
                            return Ok(outcome);
                        }
                    }

                    Ok(state_handler_outcome)
                }
            }
            ManagedHostState::DPUInit { .. } => {
                self.dpu_handler
                    .handle_object_state_inner(mh_snapshot, txn, ctx)
                    .await
            }

            ManagedHostState::HostInit { .. } => {
                self.host_handler
                    .handle_object_state_inner(host_machine_id, mh_snapshot, txn, ctx)
                    .await
            }

            ManagedHostState::Ready => {
                // Check if scout is running. If not, emit metric.
                if let Some(last_scout_contact) = mh_snapshot.host_snapshot.last_scout_contact_time
                {
                    let since_last_contact = Utc::now().signed_duration_since(last_scout_contact);
                    let timeout_threshold = self.reachability_params.scout_reporting_timeout;

                    if since_last_contact > timeout_threshold {
                        ctx.metrics.host_with_scout_heartbeat_timeout =
                            Some(host_machine_id.to_string());
                    }
                }

                // Check if instance to be created.
                if mh_snapshot.instance.is_some() {
                    // Instance is requested by user. Let's configure it.

                    // Clear if any reprovision (dpu or host) is set due to race scenario.
                    Self::clear_host_update_alert_and_reprov(mh_snapshot, txn).await?;

                    let mut next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::DpaProvisioning,
                    };

                    if !ctx.services.site_config.is_dpa_enabled() {
                        // If DPA is not enabled, we don't need to do any DPA provisioning.
                        // So go directly to WaitingForDpaToBeReady state, where we will change
                        // the network status of our DPUs.
                        next_state = ManagedHostState::Assigned {
                            instance_state: InstanceState::WaitingForDpaToBeReady,
                        };
                    }

                    return Ok(StateHandlerOutcome::transition(next_state));
                }

                if let Some(outcome) = handle_bom_validation_requested(
                    txn,
                    &self.host_handler.host_handler_params,
                    mh_snapshot,
                )
                .await?
                {
                    return Ok(outcome);
                }

                if host_reprovisioning_requested(mh_snapshot) {
                    if let Some(next_state) = self
                        .host_upgrade
                        .handle_host_reprovision(
                            mh_snapshot,
                            ctx.services,
                            host_machine_id,
                            HostFirmwareScenario::Ready,
                            txn,
                        )
                        .await?
                    {
                        let health_override =
                        crate::machine_update_manager::machine_update_module::create_host_update_health_report_hostfw();
                        // The health report alert gets generated here, the machine update manager retains responsibilty for clearing it when we're done.
                        db::machine::insert_health_report_override(
                            txn,
                            host_machine_id,
                            health_report::OverrideMode::Merge,
                            &health_override,
                            false,
                        )
                        .await?;

                        return Ok(StateHandlerOutcome::transition(next_state));
                    } else {
                        return Ok(StateHandlerOutcome::do_nothing());
                    }
                }
                if let Some(outcome) =
                    handle_machine_validation_requested(txn, mh_snapshot, false).await?
                {
                    return Ok(outcome);
                }

                // Check if DPU reprovisioning is requested
                if dpu_reprovisioning_needed(&mh_snapshot.dpu_snapshots) {
                    let mut dpus_for_reprov = vec![];
                    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                        if dpu_snapshot.reprovision_requested.is_some() {
                            handler_restart_dpu(dpu_snapshot, ctx.services, txn).await?;
                            db::machine::update_dpu_reprovision_start_time(&dpu_snapshot.id, txn)
                                .await?;
                            dpus_for_reprov.push(dpu_snapshot);
                        }
                    }

                    set_managed_host_topology_update_needed(
                        txn,
                        &mh_snapshot.host_snapshot,
                        &dpus_for_reprov,
                    )
                    .await?;

                    let reprov_state = ReprovisionState::next_substate_based_on_bfb_support(
                        self.enable_secure_boot,
                        mh_snapshot,
                        ctx.services.site_config.dpf.enabled,
                    );

                    let next_state = reprov_state.next_state_with_all_dpus_updated(
                        &mh_state,
                        &mh_snapshot.dpu_snapshots,
                        dpus_for_reprov.iter().map(|x| &x.id).collect_vec(),
                    )?;

                    let health_override = crate::machine_update_manager::machine_update_module::create_host_update_health_report_dpufw();
                    // Mark the Host as in update.
                    db::machine::insert_health_report_override(
                        txn,
                        host_machine_id,
                        health_report::OverrideMode::Merge,
                        &health_override,
                        false,
                    )
                    .await?;
                    return Ok(StateHandlerOutcome::transition(next_state));
                }

                // Check to see if measurement machine (i.e. attestation) state has changed
                // if so, just place it into the measuring state and let it be handled inside
                // the measurement state
                if self.host_handler.host_handler_params.attestation_enabled
                    && check_if_should_redo_measurements(&mh_snapshot.host_snapshot.id, txn).await?
                {
                    return Ok(StateHandlerOutcome::transition(
                        ManagedHostState::Measuring {
                            measuring_state: MeasuringState::WaitingForMeasurements, // let's just start from the beginning
                        },
                    ));
                }

                // This feature has only been tested thoroughly on Dells and Lenovos
                if (mh_snapshot.host_snapshot.bmc_vendor().is_dell()
                    || mh_snapshot.host_snapshot.bmc_vendor().is_lenovo())
                    && mh_snapshot.host_snapshot.bios_password_set_time.is_none()
                {
                    tracing::info!(
                        "transitioning legacy {} host {} to UefiSetupState::UnlockHost while it is in ManagedHostState::Ready so that the BIOS password can be configured",
                        mh_snapshot.host_snapshot.bmc_vendor(),
                        mh_snapshot.host_snapshot.id
                    );
                    return Ok(StateHandlerOutcome::transition(
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

                Ok(StateHandlerOutcome::do_nothing())
            }

            ManagedHostState::Assigned { instance_state: _ } => {
                // Process changes needed for instance.
                self.instance_handler
                    .handle_object_state_inner(host_machine_id, mh_snapshot, txn, ctx)
                    .await
            }

            ManagedHostState::WaitingForCleanup { cleanup_state } => {
                let redfish_client = ctx
                    .services
                    .redfish_client_pool
                    .create_client_from_machine(&mh_snapshot.host_snapshot, txn)
                    .await?;

                match cleanup_state {
                    CleanupState::Init => {
                        if mh_snapshot.host_snapshot.bmc_vendor().is_dell()
                            && let Some(boss_controller_id) = redfish_client
                                .get_boss_controller()
                                .await
                                .map_err(|e| StateHandlerError::RedfishError {
                                    operation: "get_boss_controller",
                                    error: e,
                                })?
                        {
                            let next_state: ManagedHostState =
                                ManagedHostState::WaitingForCleanup {
                                    cleanup_state: CleanupState::SecureEraseBoss {
                                        secure_erase_boss_context: SecureEraseBossContext {
                                            boss_controller_id,
                                            secure_erase_jid: None,
                                            secure_erase_boss_state:
                                                SecureEraseBossState::UnlockHost,
                                            iteration: Some(0),
                                        },
                                    },
                                };

                            return Ok(StateHandlerOutcome::transition(next_state));
                        }

                        let next_state: ManagedHostState = ManagedHostState::WaitingForCleanup {
                            cleanup_state: CleanupState::HostCleanup {
                                boss_controller_id: None,
                            },
                        };

                        Ok(StateHandlerOutcome::transition(next_state))
                    }
                    CleanupState::SecureEraseBoss {
                        secure_erase_boss_context,
                    } => {
                        let boss_controller_id =
                            secure_erase_boss_context.boss_controller_id.clone();

                        match secure_erase_boss_context.secure_erase_boss_state {
                            SecureEraseBossState::UnlockHost => {
                                redfish_client
                                    .set_idrac_lockdown(EnabledDisabled::Disabled)
                                    .await
                                    .map_err(|e| StateHandlerError::RedfishError {
                                        operation: "set_idrac_lockdown",
                                        error: e,
                                    })?;

                                let next_state: ManagedHostState =
                                    ManagedHostState::WaitingForCleanup {
                                        cleanup_state: CleanupState::SecureEraseBoss {
                                            secure_erase_boss_context: SecureEraseBossContext {
                                                boss_controller_id,
                                                secure_erase_jid: None,
                                                secure_erase_boss_state:
                                                    SecureEraseBossState::SecureEraseBoss,
                                                iteration: secure_erase_boss_context.iteration,
                                            },
                                        },
                                    };

                                Ok(StateHandlerOutcome::transition(next_state))
                            }
                            SecureEraseBossState::SecureEraseBoss => {
                                let jid = redfish_client
                                    .decommission_storage_controller(
                                        &secure_erase_boss_context.boss_controller_id,
                                    )
                                    .await
                                    .map_err(|e| StateHandlerError::RedfishError {
                                        operation: "decommission_storage_controller",
                                        error: e,
                                    })?;

                                let next_state: ManagedHostState =
                                    ManagedHostState::WaitingForCleanup {
                                        cleanup_state: CleanupState::SecureEraseBoss {
                                            secure_erase_boss_context: SecureEraseBossContext {
                                                boss_controller_id,
                                                secure_erase_jid: jid,
                                                secure_erase_boss_state:
                                                    SecureEraseBossState::WaitForJobCompletion,
                                                iteration: secure_erase_boss_context.iteration,
                                            },
                                        },
                                    };

                                Ok(StateHandlerOutcome::transition(next_state))
                            }
                            SecureEraseBossState::WaitForJobCompletion => {
                                wait_for_boss_controller_job_to_complete(
                                    redfish_client.as_ref(),
                                    mh_snapshot,
                                )
                                .await
                            }
                            SecureEraseBossState::HandleJobFailure {
                                failure: _,
                                power_state: _,
                            } => {
                                handle_boss_job_failure(
                                    redfish_client.as_ref(),
                                    mh_snapshot,
                                    ctx.services,
                                    txn,
                                )
                                .await
                            }
                        }
                    }
                    CleanupState::HostCleanup { boss_controller_id } => {
                        if !cleanedup_after_state_transition(
                            mh_snapshot.host_snapshot.state.version,
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
                            return Ok(StateHandlerOutcome::wait(status.status));
                        }

                        // Reboot host
                        handler_host_power_control(
                            mh_snapshot,
                            ctx.services,
                            SystemPowerControl::ForceRestart,
                            txn,
                        )
                        .await?;

                        let next_state = match boss_controller_id {
                            Some(boss_controller_id) => ManagedHostState::WaitingForCleanup {
                                cleanup_state: CleanupState::CreateBossVolume {
                                    create_boss_volume_context: CreateBossVolumeContext {
                                        boss_controller_id: boss_controller_id.to_string(),
                                        create_boss_volume_jid: None,
                                        create_boss_volume_state:
                                            CreateBossVolumeState::CreateBossVolume,
                                        iteration: Some(0),
                                    },
                                },
                            },
                            None => ManagedHostState::BomValidating {
                                bom_validating_state: BomValidating::UpdatingInventory(
                                    BomValidatingContext {
                                        machine_validation_context: Some("Cleanup".to_string()),
                                        ..BomValidatingContext::default()
                                    },
                                ),
                            },
                        };

                        Ok(StateHandlerOutcome::transition(next_state))
                    }
                    CleanupState::CreateBossVolume {
                        create_boss_volume_context,
                    } => {
                        let boss_controller_id =
                            create_boss_volume_context.boss_controller_id.clone();
                        match create_boss_volume_context.create_boss_volume_state {
                            CreateBossVolumeState::CreateBossVolume => {
                                let jid = redfish_client
                                    .create_storage_volume(
                                        &create_boss_volume_context.boss_controller_id,
                                        "VD_0",
                                        "RAID1",
                                    )
                                    .await
                                    .map_err(|e| StateHandlerError::RedfishError {
                                        operation: "create_storage_volume",
                                        error: e,
                                    })?;

                                let next_state: ManagedHostState =
                                    ManagedHostState::WaitingForCleanup {
                                        cleanup_state: CleanupState::CreateBossVolume {
                                            create_boss_volume_context: CreateBossVolumeContext {
                                                boss_controller_id,
                                                create_boss_volume_jid: jid,
                                                create_boss_volume_state:
                                                    CreateBossVolumeState::WaitForJobScheduled,
                                                iteration: create_boss_volume_context.iteration,
                                            },
                                        },
                                    };

                                Ok(StateHandlerOutcome::transition(next_state))
                            }
                            CreateBossVolumeState::WaitForJobScheduled => {
                                let job_id = match &create_boss_volume_context
                                    .create_boss_volume_jid
                                {
                                    Some(jid) => Ok(jid),
                                    None => Err(StateHandlerError::GenericError(eyre::eyre!(
                                        "could not find job ID in the Create BOSS Volume Context"
                                    ))),
                                }?;

                                let job_state = redfish_client
                                    .get_job_state(job_id)
                                    .await
                                    .map_err(|e| StateHandlerError::RedfishError {
                                        operation: "get_job_state",
                                        error: e,
                                    })?;

                                if !matches!(job_state, libredfish::JobState::Scheduled) {
                                    return Ok(StateHandlerOutcome::wait(format!(
                                        "waiting for job {:#?} to be scheduled; current state: {job_state:#?}",
                                        job_id
                                    )));
                                }

                                let next_state: ManagedHostState =
                                    ManagedHostState::WaitingForCleanup {
                                        cleanup_state: CleanupState::CreateBossVolume {
                                            create_boss_volume_context: CreateBossVolumeContext {
                                                boss_controller_id,
                                                create_boss_volume_jid: create_boss_volume_context
                                                    .create_boss_volume_jid
                                                    .clone(),
                                                create_boss_volume_state:
                                                    CreateBossVolumeState::RebootHost,
                                                iteration: create_boss_volume_context.iteration,
                                            },
                                        },
                                    };

                                Ok(StateHandlerOutcome::transition(next_state))
                            }
                            CreateBossVolumeState::RebootHost => {
                                redfish_client
                                    .power(SystemPowerControl::ForceRestart)
                                    .await
                                    .map_err(|e| StateHandlerError::RedfishError {
                                        operation: "ForceRestart",
                                        error: e,
                                    })?;

                                let next_state: ManagedHostState =
                                    ManagedHostState::WaitingForCleanup {
                                        cleanup_state: CleanupState::CreateBossVolume {
                                            create_boss_volume_context: CreateBossVolumeContext {
                                                boss_controller_id,
                                                create_boss_volume_jid: create_boss_volume_context
                                                    .create_boss_volume_jid
                                                    .clone(),
                                                create_boss_volume_state:
                                                    CreateBossVolumeState::WaitForJobCompletion,
                                                iteration: create_boss_volume_context.iteration,
                                            },
                                        },
                                    };

                                Ok(StateHandlerOutcome::transition(next_state))
                            }
                            CreateBossVolumeState::WaitForJobCompletion => {
                                wait_for_boss_controller_job_to_complete(
                                    redfish_client.as_ref(),
                                    mh_snapshot,
                                )
                                .await
                            }
                            CreateBossVolumeState::LockHost => {
                                redfish_client
                                    .set_idrac_lockdown(EnabledDisabled::Enabled)
                                    .await
                                    .map_err(|e| StateHandlerError::RedfishError {
                                        operation: "set_idrac_lockdown",
                                        error: e,
                                    })?;

                                let next_state: ManagedHostState =
                                    ManagedHostState::BomValidating {
                                        bom_validating_state: BomValidating::UpdatingInventory(
                                            BomValidatingContext {
                                                machine_validation_context: Some(
                                                    "Cleanup".to_string(),
                                                ),
                                                ..BomValidatingContext::default()
                                            },
                                        ),
                                    };

                                Ok(StateHandlerOutcome::transition(next_state))
                            }
                            CreateBossVolumeState::HandleJobFailure {
                                failure: _,
                                power_state: _,
                            } => {
                                handle_boss_job_failure(
                                    redfish_client.as_ref(),
                                    mh_snapshot,
                                    ctx.services,
                                    txn,
                                )
                                .await
                            }
                        }
                    }
                    CleanupState::DisableBIOSBMCLockdown => {
                        tracing::error!(
                            machine_id = %host_machine_id,
                            "DisableBIOSBMCLockdown state is not implemented. Machine stuck in unimplemented state.",
                        );
                        Err(StateHandlerError::InvalidHostState(
                            *host_machine_id,
                            Box::new(mh_state.clone()),
                        ))
                    }
                }
            }
            ManagedHostState::Created => {
                tracing::error!("Machine just created. We should not be here.");
                Err(StateHandlerError::InvalidHostState(
                    *host_machine_id,
                    Box::new(mh_state.clone()),
                ))
            }
            ManagedHostState::ForceDeletion => {
                // Just ignore. Delete is done directly in api.rs::admin_force_delete_machine.
                tracing::info!(
                    machine_id = %host_machine_id,
                    "Machine is marked for forced deletion. Ignoring.",
                );
                Ok(StateHandlerOutcome::deleted())
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
                            mh_snapshot.host_snapshot.state.version,
                            mh_snapshot.host_snapshot.last_discovery_time,
                        ) {
                            ctx.metrics
                                .machine_reboot_attempts_in_failed_during_discovery =
                                Some(*retry_count as u64);
                            // Anytime host discovery is successful, move to next state.
                            db::machine::clear_failure_details(machine_id, txn).await?;
                            let next_state = ManagedHostState::HostInit {
                                machine_state: MachineState::WaitingForLockdown {
                                    lockdown_info: LockdownInfo {
                                        state: LockdownState::SetLockdown,
                                        mode: LockdownMode::Enable,
                                    },
                                },
                            };
                            return Ok(StateHandlerOutcome::transition(next_state));
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
                                machine_id: *machine_id,
                            };
                            return Ok(StateHandlerOutcome::transition(next_state));
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
                                machine_id: *machine_id,
                            };
                            Ok(StateHandlerOutcome::transition(next_state))
                        } else {
                            Ok(StateHandlerOutcome::do_nothing())
                        }
                    }
                    FailureCause::NVMECleanFailed { .. } if machine_id.machine_type().is_host() => {
                        if cleanedup_after_state_transition(
                            mh_snapshot.host_snapshot.state.version,
                            mh_snapshot.host_snapshot.last_cleanup_time,
                        ) && mh_snapshot.host_snapshot.failure_details.failed_at
                            < mh_snapshot
                                .host_snapshot
                                .last_cleanup_time
                                .unwrap_or_default()
                        {
                            // Cleaned up successfully after a failure.
                            let next_state = ManagedHostState::WaitingForCleanup {
                                cleanup_state: CleanupState::Init,
                            };
                            db::machine::clear_failure_details(machine_id, txn)
                                .await
                                .map_err(StateHandlerError::from)?;
                            return Ok(StateHandlerOutcome::transition(next_state));
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
                                machine_id: *machine_id,
                            };
                            Ok(StateHandlerOutcome::transition(next_state))
                        } else {
                            Ok(StateHandlerOutcome::do_nothing())
                        }
                    }
                    FailureCause::MeasurementsRetired { .. }
                    | FailureCause::MeasurementsRevoked { .. }
                    | FailureCause::MeasurementsCAValidationFailed { .. } => {
                        if check_if_not_in_original_failure_cause_anymore(
                            &mh_snapshot.host_snapshot.id,
                            txn,
                            &details.cause,
                            self.host_handler.host_handler_params.attestation_enabled,
                        )
                        .await?
                        {
                            // depending on the source of the failure, move it to the correct measuring state
                            match &details.source {
                                    FailureSource::StateMachineArea(area) => {
                                        match area{
                                            StateMachineArea::MainFlow => Ok(StateHandlerOutcome::transition(
                                                ManagedHostState::Measuring {
                                                    measuring_state: MeasuringState::WaitingForMeasurements
                                                }
                                            )),
                                            StateMachineArea::HostInit => Ok(StateHandlerOutcome::transition(
                                                ManagedHostState::HostInit {
                                                    machine_state: MachineState::Measuring{
                                                        measuring_state: MeasuringState::WaitingForMeasurements
                                                    }
                                                }
                                            )),
                                            StateMachineArea::AssignedInstance => Ok(StateHandlerOutcome::transition(
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
                            Ok(StateHandlerOutcome::do_nothing())
                        }
                    }
                    FailureCause::MachineValidation { .. }
                        if machine_id.machine_type().is_host() =>
                    {
                        match handle_machine_validation_requested(txn, mh_snapshot, true).await? {
                            Some(outcome) => Ok(outcome),
                            None => Ok(StateHandlerOutcome::do_nothing()),
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
                        Ok(StateHandlerOutcome::do_nothing())
                    }
                }
            }
            ManagedHostState::DPUReprovision { .. } => {
                for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                    // TODO: Optimization Possible: We can have another outcome something like
                    // TransitionNotPossible. This will be valid for the sync states (States where
                    // we wait for all DPUs to come in same state). If return value is
                    // TransitionNotPossible, means at least one DPU is not in ready to move into
                    // next state, thus no point of checking for next DPU. In this case, just break
                    // the loop.
                    if let outcome @ StateHandlerOutcome::Transition { .. } =
                        handle_dpu_reprovision(
                            mh_snapshot,
                            &self.reachability_params,
                            txn,
                            &MachineNextStateResolver,
                            dpu_snapshot,
                            ctx,
                            &self.dpu_handler.hardware_models,
                            &self.dpu_handler.dpf_config,
                        )
                        .await?
                    {
                        return Ok(outcome);
                    }
                }
                Ok(StateHandlerOutcome::do_nothing())
            }

            ManagedHostState::HostReprovision { .. } => {
                if let Some(next_state) = self
                    .host_upgrade
                    .handle_host_reprovision(
                        mh_snapshot,
                        ctx.services,
                        host_machine_id,
                        HostFirmwareScenario::Ready,
                        txn,
                    )
                    .await?
                {
                    Ok(StateHandlerOutcome::transition(next_state))
                } else {
                    Ok(StateHandlerOutcome::do_nothing())
                }
            }

            // ManagedHostState::Measuring is introduced into the flow when
            // attestation_enabled is set to true (defaults to false), and
            // is triggered when a machine being in Ready state suddently
            // ceases being attested
            ManagedHostState::Measuring { measuring_state } => handle_measuring_state(
                measuring_state,
                &mh_snapshot.host_snapshot.id,
                txn,
                self.host_handler.host_handler_params.attestation_enabled,
            )
            .await
            .map(|v| map_measuring_outcome_to_state_handler_outcome(&v, measuring_state))?,
            ManagedHostState::PostAssignedMeasuring { measuring_state } => handle_measuring_state(
                measuring_state,
                &mh_snapshot.host_snapshot.id,
                txn,
                self.host_handler.host_handler_params.attestation_enabled,
            )
            .await
            .map(|v| {
                map_post_assigned_measuring_outcome_to_state_handler_outcome(&v, measuring_state)
            })?,
            ManagedHostState::BomValidating {
                bom_validating_state,
            } => {
                handle_bom_validation_state(
                    txn,
                    &self.host_handler.host_handler_params,
                    ctx.services,
                    mh_snapshot,
                    bom_validating_state,
                )
                .await
            }
            ManagedHostState::Validation { validation_state } => match validation_state {
                ValidationState::MachineValidation { machine_validation } => {
                    handle_machine_validation_state(
                        txn,
                        ctx,
                        machine_validation,
                        &self.host_handler.host_handler_params,
                        mh_snapshot,
                    )
                    .await
                }
            },
        }
    }

    async fn handle_restart_dpu_reprovision_assigned_state(
        &self,
        state: &ManagedHostStateSnapshot,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
        txn: &mut PgConnection,
        host_machine_id: &MachineId,
        dpus_for_reprov: &[&Machine],
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        // User approval must have received, otherwise reprovision has not
        // started.
        if let Err(err) =
            handler_host_power_control(state, ctx.services, SystemPowerControl::ForceRestart, txn)
                .await
        {
            tracing::error!(%host_machine_id, "Host reboot failed with error: {err}");
        }
        set_managed_host_topology_update_needed(txn, &state.host_snapshot, dpus_for_reprov).await?;

        let reprov_state = ReprovisionState::next_substate_based_on_bfb_support(
            self.enable_secure_boot,
            state,
            ctx.services.site_config.dpf.enabled,
        );
        Ok(Some(reprov_state.next_state_with_all_dpus_updated(
            &state.managed_state,
            &state.dpu_snapshots,
            dpus_for_reprov.iter().map(|x| &x.id).collect_vec(),
        )?))
    }

    // If current BMC FW allows to install bfb via redfish - performs redfish install,
    // otherwise reboots a DPU for iPXE install.
    async fn start_dpu_reprovision(
        &self,
        managed_state: &ManagedHostState,
        state: &ManagedHostStateSnapshot,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
        txn: &mut PgConnection,
        host_machine_id: &MachineId,
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
                    )
                    .await?;

                for dpu in &dpus_for_reprov {
                    db::machine::clear_failure_details(&dpu.id, txn).await?;
                }
            }
            ManagedHostState::DPUReprovision { .. } => {
                set_managed_host_topology_update_needed(
                    txn,
                    &state.host_snapshot,
                    &dpus_for_reprov,
                )
                .await?;

                next_state = Some(
                    ReprovisionState::next_substate_based_on_bfb_support(
                        self.enable_secure_boot,
                        state,
                        ctx.services.site_config.dpf.enabled,
                    )
                    .next_state_with_all_dpus_updated(
                        &state.managed_state,
                        &state.dpu_snapshots,
                        dpus_for_reprov.iter().map(|x| &x.id).collect_vec(),
                    )?,
                );
            }
            _ => {}
        };

        if next_state.is_some() {
            // Restart all DPUs, sit back and relax.
            for dpu in dpus_for_reprov {
                db::machine::update_dpu_reprovision_start_time(&dpu.id, txn).await?;
                handler_restart_dpu(dpu, ctx.services, txn).await?;
            }
            return Ok(next_state);
        }

        Ok(None)
    }
}

#[derive(Clone)]
struct FullFirmwareInfo<'a> {
    model: &'a str,
    to_install: &'a FirmwareEntry,
    component_type: &'a FirmwareComponentType,
    firmware_number: &'a u32,
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

    // Now find the desired version, if it's not the version that is currently installed
    fw_info
        .components
        .get(&firmware_type)?
        .known_firmware
        .iter()
        .find(|x| x.default && x.version != *current_version)
        .cloned()
}

/// This function checks if reprovisioning is requested of a given DPU or not.
fn dpu_reprovisioning_needed(dpu_snapshots: &[Machine]) -> bool {
    dpu_snapshots
        .iter()
        .any(|x| x.reprovision_requested.is_some())
}

#[allow(txn_held_across_await)]
async fn handle_restart_verification(
    mh_snapshot: &ManagedHostStateSnapshot,
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<Option<StateHandlerOutcome<ManagedHostState>>, StateHandlerError> {
    const MAX_VERIFICATION_ATTEMPTS: i32 = 2;

    // Check host first
    if let Some(last_reboot) = &mh_snapshot.host_snapshot.last_reboot_requested
        && last_reboot.restart_verified == Some(false)
    {
        let verification_attempts = last_reboot.verification_attempts.unwrap_or(0);

        let host_redfish_client = match ctx
            .services
            .redfish_client_pool
            .create_client_from_machine(&mh_snapshot.host_snapshot, txn)
            .await
        {
            Ok(client) => client,
            Err(err) => {
                tracing::warn!(
                    "Failed to create Redfish client for host {} during force-restart verification: {}",
                    mh_snapshot.host_snapshot.id,
                    err
                );
                update_restart_verification_status(
                    &mh_snapshot.host_snapshot.id,
                    last_reboot.clone(),
                    None,
                    0,
                    txn,
                )
                .await?;
                return Ok(None); // Skip verification, continue with state transition
            }
        };

        let restart_found = match check_restart_in_logs(
            host_redfish_client.as_ref(),
            last_reboot.time,
        )
        .await
        {
            Ok(found) => found,
            Err(err) => {
                tracing::warn!(
                    "Failed to fetch BMC logs for host {} during force-restart verification: {}",
                    mh_snapshot.host_snapshot.id,
                    err
                );
                update_restart_verification_status(
                    &mh_snapshot.host_snapshot.id,
                    last_reboot.clone(),
                    None,
                    0,
                    txn,
                )
                .await?;
                return Ok(None); // Skip verification, continue with state transition
            }
        };

        if restart_found {
            update_restart_verification_status(
                &mh_snapshot.host_snapshot.id,
                last_reboot.clone(),
                Some(true),
                0,
                txn,
            )
            .await?;
            tracing::info!("Restart verified for host {}", mh_snapshot.host_snapshot.id);
            return Ok(None);
        }

        if verification_attempts >= MAX_VERIFICATION_ATTEMPTS {
            host_redfish_client
                .power(SystemPowerControl::ForceRestart)
                .await
                .map_err(|e| StateHandlerError::RedfishError {
                    operation: "restart host",
                    error: e,
                })?;

            update_restart_verification_status(
                &mh_snapshot.host_snapshot.id,
                last_reboot.clone(),
                None,
                0,
                txn,
            )
            .await?;

            tracing::info!(
                "Issued force-restart for host {} after {} failed verifications",
                mh_snapshot.host_snapshot.id,
                verification_attempts
            );
            return Ok(None);
        }

        update_restart_verification_status(
            &mh_snapshot.host_snapshot.id,
            last_reboot.clone(),
            Some(false),
            verification_attempts + 1,
            txn,
        )
        .await?;

        return Ok(Some(StateHandlerOutcome::wait(format!(
            "Waiting for {} force-restart verification - attempt {}/{}",
            mh_snapshot.host_snapshot.id,
            verification_attempts + 1,
            MAX_VERIFICATION_ATTEMPTS
        ))));
    }

    // Check DPUs
    let mut pending_message = Vec::new();

    for dpu in &mh_snapshot.dpu_snapshots {
        if let Some(last_reboot) = &dpu.last_reboot_requested
            && last_reboot.restart_verified == Some(false)
        {
            let verification_attempts = last_reboot.verification_attempts.unwrap_or(0);

            let dpu_redfish_client = match ctx
                .services
                .redfish_client_pool
                .create_client_from_machine(dpu, txn)
                .await
            {
                Ok(client) => client,
                Err(err) => {
                    tracing::warn!(
                        "Failed to create Redfish client for DPU {} during force-restart verification: {}",
                        dpu.id,
                        err
                    );
                    update_restart_verification_status(&dpu.id, last_reboot.clone(), None, 0, txn)
                        .await?;
                    continue; // Skip verification, continue with state transition
                }
            };

            let restart_found = match check_restart_in_logs(
                dpu_redfish_client.as_ref(),
                last_reboot.time,
            )
            .await
            {
                Ok(found) => found,
                Err(err) => {
                    tracing::warn!(
                        "Failed to fetch BMC logs for DPU {} during force-restart verification: {}",
                        dpu.id,
                        err
                    );
                    update_restart_verification_status(&dpu.id, last_reboot.clone(), None, 0, txn)
                        .await?;
                    continue; // Skip verification, continue with state transition
                }
            };

            if restart_found {
                update_restart_verification_status(
                    &dpu.id,
                    last_reboot.clone(),
                    Some(true),
                    0,
                    txn,
                )
                .await?;
                tracing::info!("Restart verified for DPU {}", dpu.id);
            } else if verification_attempts >= MAX_VERIFICATION_ATTEMPTS {
                dpu_redfish_client
                    .power(SystemPowerControl::ForceRestart)
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "reboot dpu",
                        error: e,
                    })?;

                update_restart_verification_status(&dpu.id, last_reboot.clone(), None, 0, txn)
                    .await?;

                tracing::info!(
                    "Issued force-restart for DPU {} after {} failed verifications",
                    dpu.id,
                    verification_attempts
                );
            } else {
                update_restart_verification_status(
                    &dpu.id,
                    last_reboot.clone(),
                    Some(false),
                    verification_attempts + 1,
                    txn,
                )
                .await?;
                pending_message.push(format!(
                    "DPU {} force-restart verification - attempt {}/{}",
                    dpu.id,
                    verification_attempts + 1,
                    MAX_VERIFICATION_ATTEMPTS
                ));
            }
        }
    }

    if !pending_message.is_empty() {
        Ok(Some(StateHandlerOutcome::wait(pending_message.join(", "))))
    } else {
        Ok(None)
    }
}

pub async fn check_restart_in_logs(
    redfish_client: &dyn Redfish,
    restart_time: DateTime<Utc>,
) -> Result<bool, RedfishError> {
    lazy_static::lazy_static! {
        // Vendor specific messages
        static ref SPECIFIC_RESET_KEYWORDS: HashSet<&'static str> = HashSet::from([
            "Server reset.",                                       // HPE
            "Server power restored.",                              // HPE
            "The server is restarted by chassis control command.", // Lenovo
            "DPU Warm Reset",                                      // Bluefield
            "BMC IP Address Deleted",                              // Bluefield
        ]);

        // Generic reset keywords
        static ref GENERIC_RESET_KEYWORDS: Vec<&'static str> =
            vec!["reset", "reboot", "restart", "power", "start"];
    }

    let logs = redfish_client.get_bmc_event_log(Some(restart_time)).await?;

    for log in &logs {
        tracing::debug!("BMC log message: {}", log.message);
    }

    let restart_found = logs.iter().any(|log| {
        // First check exact matches
        if SPECIFIC_RESET_KEYWORDS.contains(log.message.as_str()) {
            return true;
        }
        // Then generic keywords
        let lowercase_message = log.message.to_lowercase();
        GENERIC_RESET_KEYWORDS
            .iter()
            .any(|keyword| lowercase_message.contains(keyword))
    });

    Ok(restart_found)
}

// Function to wait for some time in state machine.
fn wait(basetime: &DateTime<Utc>, wait_time: Duration) -> bool {
    let expected_time = *basetime + wait_time;
    let current_time = Utc::now();

    current_time < expected_time
}

fn is_dpu_up(state: &ManagedHostStateSnapshot, dpu_snapshot: &Machine) -> bool {
    let observation_time = dpu_snapshot
        .network_status_observation
        .as_ref()
        .map(|o| o.observed_at)
        .unwrap_or(DateTime::<Utc>::MIN_UTC);
    let state_change_time = state.host_snapshot.state.version.timestamp();

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
    services: &CommonStateHandlerServices,
    txn: &mut PgConnection,
) -> bool {
    for dpu_snapshot in &state.dpu_snapshots {
        if !is_dpu_up(state, dpu_snapshot) {
            match trigger_reboot_if_needed(
                dpu_snapshot,
                state,
                None,
                reachability_params,
                services,
                txn,
            )
            .await
            {
                Ok(_) => {}
                Err(e) => tracing::warn!("could not reboot dpu {}: {e}", dpu_snapshot.id),
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

    // Note: extra_logfmt_logging_fields function to add additional
    // parameters that should be logged for each event inside span
    // crated by tracing instrumentation of handle_object_state.
    #[instrument(skip_all, fields(object_id=%host_machine_id, state=%_mh_state))]
    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        mh_snapshot: &mut ManagedHostStateSnapshot,
        _mh_state: &Self::ControllerState, // mh_snapshot above already contains it
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<ManagedHostState>, StateHandlerError> {
        let mut txn = ctx.services.db_pool.begin().await?;
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
        self.record_health_history(mh_snapshot, &mut txn).await?;

        // Handles power options based on the host's state and configuration settings.
        let PowerHandlingOutcome {
            power_options,
            continue_state_machine,
            msg,
        } = match mh_snapshot.host_snapshot.state.value {
            ManagedHostState::Assigned {
                instance_state: InstanceState::Ready,
            } => {
                // We can't touch a machine which is in Assigned/Ready state. A tenant owns it.
                PowerHandlingOutcome::new(None, true, None)
            }
            _ => {
                if self.power_options_config.enabled {
                    power::handle_power(mh_snapshot, &mut txn, ctx, &self.power_options_config)
                        .await?
                } else {
                    PowerHandlingOutcome::new(None, true, None)
                }
            }
        };

        let result = if continue_state_machine {
            self.attempt_state_transition(host_machine_id, mh_snapshot, &mut txn, ctx)
                .await
                .map(|o| o.with_txn(Some(txn)))
        } else {
            Ok(StateHandlerOutcome::wait(format!(
                "State machine can't proceed due to power manager. {}",
                msg.unwrap_or_default()
            ))
            .with_txn(Some(txn)))
        };

        // Persist power options before returning
        // They are persisted in an individual DB transaction in order to be unaffected
        // by the main state handling outcome
        if let Some(power_options) = power_options {
            let mut txn = ctx.services.db_pool.begin().await?;
            db::power_options::persist(&power_options, &mut txn).await?;
            txn.commit().await?;
        }

        result
    }
}

fn map_measuring_outcome_to_state_handler_outcome(
    measuring_outcome: &MeasuringOutcome,
    measuring_state: &MeasuringState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    match measuring_outcome {
        MeasuringOutcome::NoChange => Ok(StateHandlerOutcome::wait(
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
        MeasuringOutcome::WaitForGoldenValues => Ok(StateHandlerOutcome::transition(
            ManagedHostState::Measuring {
                measuring_state: MeasuringState::PendingBundle,
            },
        )),
        MeasuringOutcome::WaitForScoutToSendMeasurements => Ok(StateHandlerOutcome::transition(
            ManagedHostState::Measuring {
                measuring_state: MeasuringState::WaitingForMeasurements,
            },
        )),
        MeasuringOutcome::Unsuccessful((failure_details, machine_id)) => {
            Ok(StateHandlerOutcome::transition(ManagedHostState::Failed {
                details: FailureDetails {
                    cause: failure_details.cause.clone(),
                    failed_at: failure_details.failed_at,
                    source: FailureSource::StateMachineArea(StateMachineArea::MainFlow),
                },
                machine_id: *machine_id,
                retry_count: 0,
            }))
        }
        MeasuringOutcome::PassedOk => Ok(StateHandlerOutcome::transition(ManagedHostState::Ready)),
    }
}

fn map_host_init_measuring_outcome_to_state_handler_outcome(
    measuring_outcome: &MeasuringOutcome,
    measuring_state: &MeasuringState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    match measuring_outcome {
        MeasuringOutcome::NoChange => Ok(StateHandlerOutcome::wait(
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
        MeasuringOutcome::WaitForGoldenValues => Ok(StateHandlerOutcome::transition(
            ManagedHostState::HostInit {
                machine_state: MachineState::Measuring {
                    measuring_state: MeasuringState::PendingBundle,
                },
            },
        )),
        MeasuringOutcome::WaitForScoutToSendMeasurements => Ok(StateHandlerOutcome::transition(
            ManagedHostState::HostInit {
                machine_state: MachineState::Measuring {
                    measuring_state: MeasuringState::WaitingForMeasurements,
                },
            },
        )),
        MeasuringOutcome::Unsuccessful((failure_details, machine_id)) => {
            Ok(StateHandlerOutcome::transition(ManagedHostState::Failed {
                details: FailureDetails {
                    cause: failure_details.cause.clone(),
                    failed_at: failure_details.failed_at,
                    source: FailureSource::StateMachineArea(StateMachineArea::HostInit),
                },
                machine_id: *machine_id,
                retry_count: 0,
            }))
        }
        MeasuringOutcome::PassedOk => Ok(StateHandlerOutcome::transition(
            ManagedHostState::HostInit {
                machine_state: MachineState::WaitingForDiscovery,
            },
        )),
    }
}

#[allow(txn_held_across_await)]
async fn handle_bfb_install_state(
    state: &ManagedHostStateSnapshot,
    substate: InstallDpuOsState,
    dpu_snapshot: &Machine,
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    next_state_resolver: &impl NextState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let dpu_machine_id = &dpu_snapshot.id.clone();
    let dpu_redfish_client_result = ctx
        .services
        .redfish_client_pool
        .create_client_from_machine(dpu_snapshot, txn)
        .await;

    let dpu_redfish_client = match dpu_redfish_client_result {
        Ok(redfish_client) => redfish_client,
        Err(e) => {
            return Ok(StateHandlerOutcome::wait(format!(
                "Waiting for RedFish to become available: {:?}",
                e
            )));
        }
    };
    match substate {
        InstallDpuOsState::Completed => Ok(StateHandlerOutcome::transition(
            next_state_resolver.next_bfb_install_state(
                &state.managed_state,
                &InstallDpuOsState::Completed,
                dpu_machine_id,
            )?,
        )),
        InstallDpuOsState::InstallationError { .. } => Ok(StateHandlerOutcome::do_nothing()),

        InstallDpuOsState::InstallingBFB => {
            let task = dpu_redfish_client
                .update_firmware_simple_update(
                    "carbide-pxe.forge//public/blobs/internal/aarch64/forge.bfb",
                    vec!["redfish/v1/UpdateService/FirmwareInventory/DPU_OS".to_string()],
                    TransferProtocolType::HTTP,
                )
                .await
                .map_err(|e| StateHandlerError::RedfishError {
                    operation: "update_firmware_simple_update",
                    error: e,
                })?;
            tracing::info!(
                "DPU {} OS install task {} submitted.",
                dpu_snapshot.id,
                task.id
            );
            Ok(StateHandlerOutcome::transition(
                next_state_resolver.next_bfb_install_state(
                    &state.managed_state,
                    &InstallDpuOsState::WaitForInstallComplete {
                        task_id: task.id,
                        progress: "0".to_string(),
                    },
                    dpu_machine_id,
                )?,
            ))
        }

        InstallDpuOsState::WaitForInstallComplete { task_id, .. } => {
            let task = dpu_redfish_client
                .get_task(task_id.as_str())
                .await
                .map_err(|e| StateHandlerError::RedfishError {
                    operation: "get_task",
                    error: e,
                })?;

            tracing::info!(
                "DPU {} OS install task {}: {:#?}",
                dpu_snapshot.id,
                task.id,
                task.task_state
            );

            match task.task_state {
                Some(TaskState::Completed) => {
                    tracing::info!("Install BFB on {:#?} completed", dpu_snapshot.bmc_addr());
                    let next_state = next_state_resolver.next_bfb_install_state(
                        &state.managed_state,
                        &InstallDpuOsState::Completed,
                        dpu_machine_id,
                    )?;
                    Ok(StateHandlerOutcome::transition(next_state))
                }
                Some(TaskState::Exception) => {
                    let msg = format!(
                        "BFB install task {} on {:#?} failed: {}.",
                        task_id,
                        dpu_snapshot.bmc_addr(),
                        task.messages.iter().map(|t| t.message.clone()).join("\n")
                    );
                    tracing::error!(msg);
                    let next_state = next_state_resolver.next_bfb_install_state(
                        &state.managed_state,
                        &InstallDpuOsState::InstallationError { msg },
                        dpu_machine_id,
                    )?;
                    Ok(StateHandlerOutcome::transition(next_state))
                }
                Some(TaskState::Running) | Some(TaskState::New) | Some(TaskState::Starting) => {
                    let percent_complete = task
                        .percent_complete
                        .map_or("0".to_string(), |p| p.to_string());
                    Ok(StateHandlerOutcome::wait(format!(
                        "Waiting for BFB install to complete: {}%",
                        percent_complete
                    )))
                }
                task_state => {
                    let msg = format!(
                        "BFB install task {} on {:#?} failed ({:#?}): {}",
                        task_id,
                        dpu_snapshot.bmc_addr(),
                        task_state,
                        task.messages.iter().map(|t| t.message.clone()).join("\n")
                    );
                    tracing::error!(msg);
                    let next_state = next_state_resolver.next_bfb_install_state(
                        &state.managed_state,
                        &InstallDpuOsState::InstallationError { msg },
                        dpu_machine_id,
                    )?;
                    Ok(StateHandlerOutcome::transition(next_state))
                }
            }
        }
    }
}

fn map_post_assigned_measuring_outcome_to_state_handler_outcome(
    measuring_outcome: &MeasuringOutcome,
    measuring_state: &MeasuringState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    match measuring_outcome {
        MeasuringOutcome::NoChange => Ok(StateHandlerOutcome::wait(
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
        MeasuringOutcome::WaitForGoldenValues => Ok(StateHandlerOutcome::transition(
            ManagedHostState::PostAssignedMeasuring {
                measuring_state: MeasuringState::PendingBundle,
            },
        )),
        MeasuringOutcome::WaitForScoutToSendMeasurements => Ok(StateHandlerOutcome::transition(
            ManagedHostState::PostAssignedMeasuring {
                measuring_state: MeasuringState::WaitingForMeasurements,
            },
        )),
        MeasuringOutcome::Unsuccessful((failure_details, machine_id)) => {
            Ok(StateHandlerOutcome::transition(ManagedHostState::Failed {
                details: FailureDetails {
                    cause: failure_details.cause.clone(),
                    failed_at: failure_details.failed_at,
                    source: FailureSource::StateMachineArea(StateMachineArea::AssignedInstance),
                },
                machine_id: *machine_id,
                retry_count: 0,
            }))
        }
        MeasuringOutcome::PassedOk => Ok(StateHandlerOutcome::transition(
            ManagedHostState::WaitingForCleanup {
                cleanup_state: CleanupState::Init,
            },
        )),
    }
}

// this is called when we are in the Ready state and checking
// if everything is ok in general
async fn check_if_should_redo_measurements(
    machine_id: &MachineId,
    txn: &mut PgConnection,
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
    txn: &mut PgConnection,
    original_failure_cause: &FailureCause,
    attestation_enabled: bool,
) -> Result<bool, StateHandlerError> {
    if !attestation_enabled {
        return Ok(true);
    }
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
pub fn identify_dpu(dpu_snapshot: &Machine) -> DpuModel {
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

/// Handle workflow of DPU reprovision
#[allow(txn_held_across_await)]
#[allow(clippy::too_many_arguments)]
async fn handle_dpu_reprovision(
    state: &ManagedHostStateSnapshot,
    reachability_params: &ReachabilityParams,
    txn: &mut PgConnection,
    next_state_resolver: &impl NextState,
    dpu_snapshot: &Machine,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    hardware_models: &FirmwareConfig,
    dpf_config: &DpfConfig,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let dpu_machine_id = &dpu_snapshot.id;
    let reprovision_state = state
        .managed_state
        .as_reprovision_state(dpu_machine_id)
        .ok_or_else(|| StateHandlerError::MissingData {
            object_id: dpu_machine_id.to_string(),
            missing: "dpu_state",
        })?;

    match reprovision_state {
        ReprovisionState::DpfStates { substate } => {
            dpf::handle_dpf_state_with_reprovision(
                state,
                dpu_snapshot,
                substate,
                txn,
                ctx,
                dpf_config,
                reachability_params,
                next_state_resolver,
            )
            .await
        }
        ReprovisionState::InstallDpuOs { substate } => {
            handle_bfb_install_state(
                state,
                substate.clone(),
                dpu_snapshot,
                txn,
                ctx,
                next_state_resolver,
            )
            .await
        }
        ReprovisionState::BmcFirmwareUpgrade { .. } => Ok(StateHandlerOutcome::transition(
            next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
        )),
        ReprovisionState::FirmwareUpgrade => {
            // Firmware upgrade is going on. Lets wait for it to over.
            Ok(StateHandlerOutcome::transition(
                next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
            ))
        }
        ReprovisionState::WaitingForNetworkInstall => {
            if let Some(dpu_id) = try_wait_for_dpu_discovery(
                state,
                reachability_params,
                ctx.services,
                true,
                txn,
                dpu_machine_id,
            )
            .await?
            {
                // Return Wait.
                return Ok(StateHandlerOutcome::wait(format!(
                    "DPU discovery for {dpu_id} is still not completed."
                )));
            }

            Ok(StateHandlerOutcome::transition(
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
                return Ok(StateHandlerOutcome::wait(
                    "Waiting for DPUs to come in PoweringOffHost state.".to_string(),
                ));
            }

            handler_host_power_control(state, ctx.services, SystemPowerControl::ForceOff, txn)
                .await?;
            Ok(StateHandlerOutcome::transition(
                next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
            ))
        }
        ReprovisionState::PowerDown => {
            let basetime = state
                .host_snapshot
                .last_reboot_requested
                .as_ref()
                .map(|x| x.time)
                .unwrap_or(state.host_snapshot.state.version.timestamp());

            if wait(&basetime, reachability_params.power_down_wait) {
                return Ok(StateHandlerOutcome::do_nothing());
            }

            let redfish_client = ctx
                .services
                .redfish_client_pool
                .create_client_from_machine(&state.host_snapshot, txn)
                .await?;
            let power_state = host_power_state(redfish_client.as_ref()).await?;

            // Host is not powered-off yet. Try again.
            if power_state != libredfish::PowerState::Off {
                tracing::error!(
                    "Machine {} is still not power-off state. Turning off for host again.",
                    state.host_snapshot.id
                );
                handler_host_power_control(state, ctx.services, SystemPowerControl::ForceOff, txn)
                    .await?;

                return Ok(StateHandlerOutcome::wait(format!(
                    "Host {} is not still powered off. Trying again.",
                    state.host_snapshot.id
                )));
            }

            // Mark all re-provisioned DPUs for topology update.
            let dpus_snapshots_for_reprov = &state
                .dpu_snapshots
                .iter()
                .filter(|x| x.reprovision_requested.is_some())
                .collect_vec();

            set_managed_host_topology_update_needed(
                txn,
                &state.host_snapshot,
                dpus_snapshots_for_reprov,
            )
            .await?;

            handler_host_power_control(state, ctx.services, SystemPowerControl::On, txn).await?;
            Ok(StateHandlerOutcome::transition(
                next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
            ))
        }
        ReprovisionState::BufferTime => Ok(StateHandlerOutcome::transition(
            next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
        )),
        ReprovisionState::VerifyFirmareVersions => {
            if let Some(outcome) =
                check_fw_component_version(ctx.services, dpu_snapshot, txn, hardware_models).await?
            {
                return Ok(outcome);
            }

            Ok(StateHandlerOutcome::transition(
                next_state_resolver.next_state(
                    &state.managed_state,
                    dpu_machine_id,
                    &state.host_snapshot,
                )?,
            ))
        }
        ReprovisionState::WaitingForNetworkConfig => {
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
                return Ok(StateHandlerOutcome::wait(
                    "Waiting for DPUs to come in WaitingForNetworkConfig state.".to_string(),
                ));
            }
            for dsnapshot in &state.dpu_snapshots {
                if !is_dpu_up(state, dsnapshot) {
                    let msg = format!("Waiting for DPU {} to come up", dsnapshot.id);
                    tracing::warn!("{msg}");

                    let mut reboot_status = None;
                    // Reboot only dpu for which handler is called.
                    if dpu_snapshot.id == dsnapshot.id {
                        reboot_status = Some(
                            trigger_reboot_if_needed(
                                dsnapshot,
                                state,
                                None,
                                reachability_params,
                                ctx.services,
                                txn,
                            )
                            .await?,
                        );
                    }

                    return Ok(StateHandlerOutcome::wait(format!(
                        "{msg};\nreboot_status: {reboot_status:#?}"
                    )));
                }

                if !managed_host_network_config_version_synced_and_dpu_healthy(dsnapshot) {
                    tracing::warn!("Waiting for network to be ready for DPU {}", dsnapshot.id);

                    // we requested a DPU reboot in ReprovisionState::WaitingForNetworkInstall
                    // let the trigger_reboot_if_needed determine if we are stuck here
                    // (based on how long it has been since the last requested reboot)
                    let mut reboot_status = None;
                    // Reboot only dpu for which handler is called.
                    if dpu_snapshot.id == dsnapshot.id {
                        reboot_status = Some(
                            trigger_reboot_if_needed(
                                dsnapshot,
                                state,
                                None,
                                reachability_params,
                                ctx.services,
                                txn,
                            )
                            .await?,
                        );
                    }
                    // TODO: Make is_network_ready give us more details as a string
                    return Ok(StateHandlerOutcome::wait(format!(
                        "Waiting for DPU {} to sync network config/become healthy;\nreboot status: {reboot_status:#?}",
                        dsnapshot.id
                    )));
                }
            }

            // Clear reprovisioning state.
            for dpu_snapshot in &state.dpu_snapshots {
                db::machine::clear_dpu_reprovisioning_request(txn, &dpu_snapshot.id, false)
                    .await
                    .map_err(StateHandlerError::from)?;
            }

            Ok(StateHandlerOutcome::transition(
                next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
            ))
        }
        ReprovisionState::RebootHostBmc => {
            // Work around for FORGE-3864
            // A NIC FW update from 24.39.2048 to 24.41.1000 can cause the Redfish service to become unavailable on Lenovos.
            // Forge initiates a NIC FW update in ReprovisionState::FirmwareUpgrade
            // At this point, all of the host's DPU have finished the NIC FW Update, been power cycled, and the ARM has come up on the DPU.
            if state.host_snapshot.bmc_vendor().is_lenovo() {
                tracing::info!(
                    "Initiating BMC reset of lenovo machine {}",
                    state.host_snapshot.id
                );

                let redfish_client = ctx
                    .services
                    .redfish_client_pool
                    .create_client_from_machine(&state.host_snapshot, txn)
                    .await?;

                if let Err(redfish_error) = redfish_client.bmc_reset().await {
                    tracing::warn!(
                        "Failed to reboot BMC for {} through redfish, will try ipmitool: {redfish_error}",
                        &state.host_snapshot.id
                    );

                    let bmc_mac_address = state.host_snapshot.bmc_info.mac.ok_or_else(|| {
                        StateHandlerError::MissingData {
                            object_id: state.host_snapshot.id.to_string(),
                            missing: "bmc_mac",
                        }
                    })?;

                    let bmc_ip_address = state
                        .host_snapshot
                        .bmc_info
                        .ip
                        .clone()
                        .ok_or_else(|| StateHandlerError::MissingData {
                            object_id: state.host_snapshot.id.to_string(),
                            missing: "bmc_ip",
                        })?
                        .parse()
                        .map_err(|e| {
                            StateHandlerError::GenericError(eyre!(
                                "parsing the host's BMC IP address failed: {}",
                                e
                            ))
                        })?;

                    if let Err(ipmitool_error) = ctx
                        .services
                        .ipmi_tool
                        .bmc_cold_reset(
                            bmc_ip_address,
                            &CredentialKey::BmcCredentials {
                                credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
                            },
                        )
                        .await
                    {
                        tracing::warn!(
                            "Failed to reset BMC for {} through IPMI tool: {ipmitool_error}",
                            &state.host_snapshot.id
                        );

                        return Err(StateHandlerError::GenericError(eyre!(
                            "Failed to reset BMC for {}; redfish error: {redfish_error}; ipmitool error: {ipmitool_error}",
                            &state.host_snapshot.id
                        )));
                    };
                }
            }

            Ok(StateHandlerOutcome::transition(
                next_state_resolver.next_state_with_all_dpus_updated(state, reprovision_state)?,
            ))
        }
        ReprovisionState::RebootHost => {
            // We can expect transient issues here in case we just rebooted the host's BMC and it has not come up yet
            handler_host_power_control(state, ctx.services, SystemPowerControl::ForceRestart, txn)
                .await?;

            // We need to wait for the host to reboot and submit its new Hardware information in
            // case of Ready.
            Ok(StateHandlerOutcome::transition(
                next_state_resolver.next_state(
                    &state.managed_state,
                    dpu_machine_id,
                    &state.host_snapshot,
                )?,
            ))
        }
        ReprovisionState::NotUnderReprovision => Ok(StateHandlerOutcome::do_nothing()),
    }
}

// Returns true if update_manager flagged this managed host as needing its firmware examined
fn host_reprovisioning_requested(state: &ManagedHostStateSnapshot) -> bool {
    state.host_snapshot.host_reprovision_requested.is_some()
}

/// This function waits for DPU to finish discovery and reboots it.
pub async fn try_wait_for_dpu_discovery(
    state: &ManagedHostStateSnapshot,
    reachability_params: &ReachabilityParams,
    services: &CommonStateHandlerServices,
    is_reprovision_case: bool,
    txn: &mut PgConnection,
    current_dpu_machine_id: &MachineId,
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
            dpu_snapshot.state.version,
            dpu_snapshot.last_discovery_time,
        ) {
            // Reboot only the DPU for which the handler loop is called.
            if current_dpu_machine_id == &dpu_snapshot.id {
                let _status = trigger_reboot_if_needed(
                    dpu_snapshot,
                    state,
                    None,
                    reachability_params,
                    services,
                    txn,
                )
                .await?;
            }
            // TODO propagate the status.status message to a StateHandlerOutcome::Wait
            return Ok(Some(dpu_snapshot.id));
        }
    }

    Ok(None)
}

/// Returns Option<StateHandlerOutcome>:
///     If Some(_) means at least one fw component is not updated.
///     If None: All fw components are updated.
#[allow(txn_held_across_await)]
async fn check_fw_component_version(
    services: &CommonStateHandlerServices,
    dpu_snapshot: &Machine,
    txn: &mut PgConnection,
    hardware_models: &FirmwareConfig,
) -> Result<Option<StateHandlerOutcome<ManagedHostState>>, StateHandlerError> {
    let redfish_client = services
        .redfish_client_pool
        .create_client_from_machine(dpu_snapshot, txn)
        .await?;

    let redfish_component_name_map = HashMap::from([
        // Note: DPU uses different name for BMC Firmware as
        // BF2: 6d53cf4d_BMC_Firmware
        // BF3: BMC_Firmware
        (FirmwareComponentType::Nic, "DPU_NIC"),
        (FirmwareComponentType::Bmc, "BMC_Firmware"),
        (FirmwareComponentType::Uefi, "DPU_UEFI"),
        (FirmwareComponentType::Cec, "Bluefield_FW_ERoT"),
    ]);
    let inventories = redfish_client
        .get_software_inventories()
        .await
        .map_err(|e| StateHandlerError::RedfishError {
            operation: "get_software_inventories",
            error: e,
        })?;

    for component in [
        FirmwareComponentType::Bmc,
        FirmwareComponentType::Cec,
        FirmwareComponentType::Nic,
    ] {
        let component_name = redfish_component_name_map.get(&component).unwrap();
        let inventory_id = inventories
            .iter()
            .find(|i| i.contains(component_name))
            .ok_or(StateHandlerError::FirmwareUpdateError(eyre!(
                "No inventory found that matches redfish component name: {component_name}; inventory list: {inventories:#?}",
            )))?;

        let inventory = match redfish_client.get_firmware(inventory_id).await {
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
            let msg = format!("Unknown {component_name:?} version");
            tracing::error!(msg);
            return Err(StateHandlerError::FirmwareUpdateError(eyre!(msg)));
        };

        let cur_version = inventory
            .version
            .unwrap_or("Unknown current installed BMC FW version".to_string());

        let model = identify_dpu(dpu_snapshot);

        let expected_version = hardware_models
            .find(bmc_vendor::BMCVendor::Nvidia, &model.to_string())
            .and_then(|fw| fw.components.get(&component).cloned())
            .and_then(|fw_component| {
                fw_component
                    .known_firmware
                    .iter()
                    .filter(|fw_entry| !fw_entry.preingestion_exclusive_config)
                    .next_back()
                    .cloned()
            })
            .map(|f| f.version)
            .unwrap_or("Unknown current configured BMC FW version".to_string());

        if cur_version != expected_version {
            // CEC_MIN_RESET_VERSION="00.02.0180.0000"
            if component == FirmwareComponentType::Cec
                && version_compare::compare_to(&cur_version, "00.02.0180.0000", Cmp::Lt)
                    .is_ok_and(|x| x)
            {
                // For this case need to run host power cycle
                tracing::info!(
                    "Need to launch host power cycle to update CEC FW from {} to {}",
                    cur_version,
                    expected_version
                );
                return Ok(None);
            }

            tracing::warn!(
                "{:#?} FW didn't update succesfully. Expected version: {}, Current version: {}",
                component,
                expected_version,
                cur_version,
            );

            // Don't return Error. In case of the error, reboot time won't be updated in db.
            // This will cause continuous reboot of machine after first failure_retry_time is
            // passed.
            return Ok(Some(StateHandlerOutcome::wait(format!(
                "{:#?} FW didn't update succesfully. Expected version: {}, Current version: {}",
                component, expected_version, cur_version,
            ))));
        }

        tracing::info!(
            "{}: {:#?} FW updated succesfully to {}",
            dpu_snapshot.id,
            component,
            expected_version,
        );

        // BMC FW version need to update in machine_topology->bmc_info
        if component == FirmwareComponentType::Bmc
            && dpu_snapshot
                .bmc_info
                .clone()
                .firmware_version
                .is_some_and(|v| v != cur_version)
            && dpu_snapshot.bmc_addr().is_some()
        {
            let mut bios_version: Option<String> =
                match redfish_client.get_firmware("DPU_UEFI").await {
                    Ok(uefi) => uefi.version.clone(),
                    Err(e) => {
                        tracing::error!("redfish command get_firmware error {}", e.to_string());
                        None
                    }
                };

            if bios_version.is_none() {
                let hardware_info = dpu_snapshot.hardware_info.clone();
                bios_version = hardware_info
                    .as_ref()
                    .and_then(|h| h.dmi_data.as_ref())
                    .map(|d| d.bios_version.clone());
            }
            db::machine_topology::update_firmware_version_by_bmc_address(
                txn,
                &dpu_snapshot.bmc_addr().unwrap().ip(),
                cur_version.as_str(),
                bios_version.unwrap_or("".to_string()).as_str(),
            )
            .await
            .map_err(|e| StateHandlerError::FirmwareUpdateError(eyre!(e)))?;
        }
    }

    // All good.
    Ok(None)
}

async fn set_managed_host_topology_update_needed(
    txn: &mut PgConnection,
    host_snapshot: &Machine,
    dpus: &[&Machine],
) -> Result<(), StateHandlerError> {
    //Update it for host and DPU both.
    for dpu_snapshot in dpus {
        db::machine_topology::set_topology_update_needed(txn, &dpu_snapshot.id, true).await?;
    }
    db::machine_topology::set_topology_update_needed(txn, &host_snapshot.id, true).await?;
    Ok(())
}

/// This function returns failure cause for both host and dpu.
fn get_failed_state(state: &ManagedHostStateSnapshot) -> Option<(MachineId, FailureDetails)> {
    // Return updated state only for errors which should cause machine to move into failed
    // state.
    if state.host_snapshot.failure_details.cause != FailureCause::NoError {
        return Some((
            state.host_snapshot.id,
            state.host_snapshot.failure_details.clone(),
        ));
    } else {
        for dpu_snapshot in &state.dpu_snapshots {
            // In case of the DPU, use first failed DPU and recover it before moving forward.
            if dpu_snapshot.failure_details.cause != FailureCause::NoError {
                return Some((dpu_snapshot.id, dpu_snapshot.failure_details.clone()));
            }
        }
    }

    None
}

/// A `StateHandler` implementation for DPU machines
#[derive(Debug, Clone)]
pub struct DpuMachineStateHandler {
    dpu_nic_firmware_initial_update_enabled: bool,
    hardware_models: FirmwareConfig,
    reachability_params: ReachabilityParams,
    enable_secure_boot: bool,
    pub dpf_config: DpfConfig,
}

impl DpuMachineStateHandler {
    pub fn new(
        dpu_nic_firmware_initial_update_enabled: bool,
        hardware_models: FirmwareConfig,
        reachability_params: ReachabilityParams,
        enable_secure_boot: bool,
        dpf_config: DpfConfig,
    ) -> Self {
        DpuMachineStateHandler {
            dpu_nic_firmware_initial_update_enabled,
            hardware_models,
            reachability_params,
            enable_secure_boot,
            dpf_config,
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
    #[allow(txn_held_across_await)]
    async fn handle_dpu_discovering_state(
        &self,
        state: &ManagedHostStateSnapshot,
        dpu_snapshot: &Machine,
        _controller_state: &ManagedHostState,
        txn: &mut PgConnection,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        let dpu_machine_id = &dpu_snapshot.id.clone();
        let current_dpu_state = match &state.managed_state {
            ManagedHostState::DpuDiscoveringState { dpu_states } => dpu_states
                .states
                .get(dpu_machine_id)
                .ok_or_else(|| StateHandlerError::MissingData {
                    object_id: dpu_machine_id.to_string(),
                    missing: "dpu_state",
                })?,
            _ => {
                return Err(StateHandlerError::InvalidState(
                    "Unexpected state.".to_string(),
                ));
            }
        };

        let dpu_redfish_client_result = ctx
            .services
            .redfish_client_pool
            .create_client_from_machine(dpu_snapshot, txn)
            .await;

        let dpu_redfish_client = match dpu_redfish_client_result {
            Ok(redfish_client) => redfish_client,
            Err(e) => {
                return Ok(StateHandlerOutcome::wait(format!(
                    "Waiting for RedFish to become available: {:?}",
                    e
                )));
            }
        };

        match current_dpu_state {
            DpuDiscoveringState::Initializing => {
                let next_state = DpuDiscoveringState::Configuring
                    .next_state(&state.managed_state, dpu_machine_id)?;
                Ok(StateHandlerOutcome::transition(next_state))
            }
            DpuDiscoveringState::Configuring => {
                let next_state = DpuDiscoveringState::EnableRshim
                    .next_state(&state.managed_state, dpu_machine_id)?;
                Ok(StateHandlerOutcome::transition(next_state))
            }
            DpuDiscoveringState::EnableRshim => {
                let _ = dpu_redfish_client
                    .enable_rshim_bmc()
                    .await
                    .map_err(|e| tracing::info!("failed to enable rshim on DPU {e}"));

                let next_dpu_discovering_state =
                    DpuDiscoveringState::next_substate_based_on_bfb_support(
                        self.enable_secure_boot,
                        state,
                        ctx.services.site_config.dpf.enabled,
                    );

                tracing::info!(
                    "DPU {dpu_machine_id} (BMC FW version: {}); next_state: {}.",
                    dpu_snapshot
                        .bmc_info
                        .firmware_version
                        .clone()
                        .unwrap_or("unknown".to_string()),
                    next_dpu_discovering_state
                );

                let next_state =
                    next_dpu_discovering_state.next_state(&state.managed_state, dpu_machine_id)?;
                Ok(StateHandlerOutcome::transition(next_state))
            }
            DpuDiscoveringState::EnableSecureBoot {
                count,
                enable_secure_boot_state,
                ..
            } => {
                self.set_secure_boot(
                    *count,
                    state,
                    enable_secure_boot_state.clone(),
                    true,
                    dpu_snapshot,
                    dpu_redfish_client.as_ref(),
                )
                .await
            }
            // The proceure to disable secure boot is documented on page 58-59 here: https://docs.nvidia.com/networking/display/nvidia-bluefield-management-and-initial-provisioning.pdf
            DpuDiscoveringState::DisableSecureBoot {
                disable_secure_boot_state,
                count,
            } => {
                self.set_secure_boot(
                    *count,
                    state,
                    disable_secure_boot_state
                        .clone()
                        .unwrap_or(SetSecureBootState::CheckSecureBootStatus),
                    false,
                    dpu_snapshot,
                    dpu_redfish_client.as_ref(),
                )
                .await
            }

            DpuDiscoveringState::SetUefiHttpBoot => {
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
                Ok(StateHandlerOutcome::transition(next_state))
            }
            DpuDiscoveringState::RebootAllDPUS => {
                if !state.managed_state.all_dpu_states_in_sync()? {
                    return Ok(StateHandlerOutcome::wait(
                        "Waiting for all dpus to finish configuring.".to_string(),
                    ));
                }

                // Checking dpf and updating state to start dpf based provisioing in this satte because this state works as a sync state as well.
                let next_state =
                    if dpf_based_dpu_provisioning_possible(state, self.dpf_config.enabled, false) {
                        mark_machine_ingestion_done_with_dpf(txn, &state.host_snapshot.id).await?;
                        for dpu in &state.dpu_snapshots {
                            mark_machine_ingestion_done_with_dpf(txn, &dpu.id).await?;
                        }
                        DpuInitState::DpfStates {
                            state: model::machine::DpfState::CreateDpuDevice,
                        }
                    } else {
                        //
                        // Next just do a ForceRestart to netboot without secureboot.
                        //
                        // This will kick off the ARM OS install since we move to DPU/Init next.
                        //
                        for dpu_snapshot in &state.dpu_snapshots {
                            handler_restart_dpu(dpu_snapshot, ctx.services, txn).await?;
                        }
                        DpuInitState::Init
                    };

                let next_state =
                    next_state.next_state_with_all_dpus_updated(&state.managed_state)?;
                Ok(StateHandlerOutcome::transition(next_state))
            }
        }
    }

    #[allow(txn_held_across_await)]
    async fn handle_dpuinit_state(
        &self,
        state: &ManagedHostStateSnapshot,
        dpu_snapshot: &Machine,
        txn: &mut PgConnection,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        let dpu_machine_id = &dpu_snapshot.id;
        let dpu_state = match &state.managed_state {
            ManagedHostState::DPUInit { dpu_states } => dpu_states
                .states
                .get(dpu_machine_id)
                .ok_or_else(|| StateHandlerError::MissingData {
                    object_id: dpu_machine_id.to_string(),
                    missing: "dpu_state",
                })?,
            _ => {
                return Err(StateHandlerError::InvalidState(
                    "Unexpected state.".to_string(),
                ));
            }
        };
        match &dpu_state {
            DpuInitState::InstallDpuOs { substate } => {
                handle_bfb_install_state(
                    state,
                    substate.clone(),
                    dpu_snapshot,
                    txn,
                    ctx,
                    &DpuInitNextStateResolver {},
                )
                .await
            }
            DpuInitState::Init => {
                // initial restart, firmware update and scout is run, first reboot of dpu discovery
                let dpu_discovery_result = try_wait_for_dpu_discovery(
                    state,
                    &self.reachability_params,
                    ctx.services,
                    false,
                    txn,
                    dpu_machine_id,
                )
                .await?;

                if let Some(dpu_id) = dpu_discovery_result {
                    return Ok(StateHandlerOutcome::wait(format!(
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
                Ok(StateHandlerOutcome::transition(next_state))
            }
            DpuInitState::DpfStates { state: dpf_state } => {
                dpf::handle_dpf_state(
                    state,
                    dpu_snapshot,
                    dpf_state,
                    txn,
                    ctx,
                    &self.dpf_config,
                    &self.reachability_params,
                )
                .await
            }
            DpuInitState::WaitingForPlatformPowercycle {
                substate: PerformPowerOperation::Off,
            } => {
                // Wait until all DPUs arrive in Off state.
                if !state.managed_state.all_dpu_states_in_sync()? {
                    return Ok(StateHandlerOutcome::wait(
                        "Waiting for all dpus to move to off state.".to_string(),
                    ));
                }

                // All DPUs are in Off state, turn off the host.
                let host_redfish_client = ctx
                    .services
                    .redfish_client_pool
                    .create_client_from_machine(&state.host_snapshot, txn)
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

                Ok(StateHandlerOutcome::transition(next_state))
            }
            DpuInitState::WaitingForPlatformPowercycle {
                substate: PerformPowerOperation::On,
            } => {
                let host_redfish_client = ctx
                    .services
                    .redfish_client_pool
                    .create_client_from_machine(&state.host_snapshot, txn)
                    .await?;

                host_redfish_client
                    .power(SystemPowerControl::On)
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "host_power_on",
                        error: e,
                    })?;

                let next_state = DpuInitState::WaitingForPlatformConfiguration
                    .next_state_with_all_dpus_updated(&state.managed_state)?;

                Ok(StateHandlerOutcome::transition(next_state))
            }
            DpuInitState::WaitingForPlatformConfiguration => {
                let dpu_redfish_client = match ctx
                    .services
                    .redfish_client_pool
                    .create_client_from_machine(dpu_snapshot, txn)
                    .await
                {
                    Ok(client) => client,
                    Err(e) => {
                        let msg = format!(
                            "failed to create redfish client for DPU {}, potentially because we turned the host off as part of error handling in this state. err: {}",
                            dpu_snapshot.id, e
                        );
                        tracing::warn!(msg);
                        // If we cannot create a redfish client for the DPU, this function call will never result in an actual DPU reboot.
                        // The only side effect is turning the DPU's host back on if we turned it off earlier.
                        let reboot_status = trigger_reboot_if_needed(
                            dpu_snapshot,
                            state,
                            None,
                            &self.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?;

                        return Ok(StateHandlerOutcome::wait(format!(
                            "{msg};\nDPU reboot status: {reboot_status:#?}",
                        )));
                    }
                };

                if let Some(outcome) = check_fw_component_version(
                    ctx.services,
                    dpu_snapshot,
                    txn,
                    &self.hardware_models,
                )
                .await?
                {
                    return Ok(outcome);
                }

                let boot_interface_mac = None; // libredfish will choose the DPU
                if self.enable_secure_boot {
                    dpu_redfish_client
                        .set_host_rshim(EnabledDisabled::Disabled)
                        .await
                        .map_err(|e| StateHandlerError::RedfishError {
                            operation: "set_host_rshim",
                            error: e,
                        })?;
                    dpu_redfish_client
                        .set_host_privilege_level(HostPrivilegeLevel::Restricted)
                        .await
                        .map_err(|e| StateHandlerError::RedfishError {
                            operation: "set_host_privilege_level",
                            error: e,
                        })?;
                } else if let Err(e) = call_machine_setup_and_handle_no_dpu_error(
                    dpu_redfish_client.as_ref(),
                    boot_interface_mac,
                    state.host_snapshot.associated_dpu_machine_ids().len(),
                    &ctx.services.site_config,
                )
                .await
                {
                    let msg = format!(
                        "redfish machine_setup failed for DPU {}, potentially due to known race condition between UEFI POST and BMC. issuing a force-restart. err: {}",
                        dpu_snapshot.id, e
                    );
                    tracing::warn!(msg);
                    let reboot_status = trigger_reboot_if_needed(
                        dpu_snapshot,
                        state,
                        None,
                        &self.reachability_params,
                        ctx.services,
                        txn,
                    )
                    .await?;

                    return Ok(StateHandlerOutcome::wait(format!(
                        "{msg};\nWaiting for DPU {} to reboot: {reboot_status:#?}",
                        dpu_snapshot.id
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
                        dpu_snapshot.id, e
                    );
                    tracing::warn!(msg);
                    let reboot_status = trigger_reboot_if_needed(
                        dpu_snapshot,
                        state,
                        None,
                        &self.reachability_params,
                        ctx.services,
                        txn,
                    )
                    .await?;

                    return Ok(StateHandlerOutcome::wait(format!(
                        "{msg};\nWaiting for DPU {} to reboot: {reboot_status:#?}",
                        dpu_snapshot.id
                    )));
                }

                // We need to reboot the DPU after configuring the BIOS settings appropriately
                // so that they are applied
                handler_restart_dpu(dpu_snapshot, ctx.services, txn).await?;

                let next_state = DpuInitState::PollingBiosSetup
                    .next_state(&state.managed_state, dpu_machine_id)?;

                Ok(StateHandlerOutcome::transition(next_state))
            }

            DpuInitState::PollingBiosSetup => {
                let next_state = DpuInitState::WaitingForNetworkConfig
                    .next_state(&state.managed_state, dpu_machine_id)?;

                let dpu_redfish_client = match ctx
                    .services
                    .redfish_client_pool
                    .create_client_from_machine(dpu_snapshot, txn)
                    .await
                {
                    Ok(client) => client,
                    Err(e) => {
                        return Err(StateHandlerError::RedfishError {
                            operation: "create_client_from_machine",
                            error: RedfishError::GenericError {
                                error: e.to_string(),
                            },
                        });
                    }
                };

                match dpu_redfish_client.is_bios_setup(None).await {
                    Ok(true) => {
                        tracing::info!(
                            dpu_id = %dpu_snapshot.id,
                            "BIOS setup verified successfully for DPU"
                        );
                        Ok(StateHandlerOutcome::transition(next_state))
                    }
                    Ok(false) => Ok(StateHandlerOutcome::wait(format!(
                        "Polling BIOS setup status, waiting for settings to be applied on DPU {}",
                        dpu_snapshot.id
                    ))),
                    Err(e) => {
                        tracing::warn!(
                            dpu_id = %dpu_snapshot.id,
                            error = %e,
                            "Failed to check DPU BIOS setup status, will retry"
                        );
                        Ok(StateHandlerOutcome::wait(format!(
                            "Failed to check BIOS setup status for DPU {}: {}. Will retry.",
                            dpu_snapshot.id, e
                        )))
                    }
                }
            }

            DpuInitState::WaitingForNetworkConfig => {
                // is_network_ready is syncing over all DPUs.
                // The code will move only when all DPUs returns network_ready signal.
                for dsnapshot in &state.dpu_snapshots {
                    if !managed_host_network_config_version_synced_and_dpu_healthy(dsnapshot) {
                        let mut reboot_status = None;
                        // Only reboot the DPU which is targeted in this event loop.
                        if dsnapshot.id == dpu_snapshot.id {
                            // we requested a DPU reboot in DpuInitState::Init
                            // let the trigger_reboot_if_needed determine if we are stuck here
                            // (based on how long it has been since the last requested reboot)
                            reboot_status = Some(
                                trigger_reboot_if_needed(
                                    dsnapshot,
                                    state,
                                    None,
                                    &self.reachability_params,
                                    ctx.services,
                                    txn,
                                )
                                .await?,
                            );
                        }

                        // TODO: Make is_network_ready give us more details as a string
                        return Ok(StateHandlerOutcome::wait(format!(
                            "Waiting for DPU agent to apply network config and report healthy network for DPU {}\nreboot status: {reboot_status:#?}",
                            dsnapshot.id
                        )));
                    }
                }

                let next_state = ManagedHostState::HostInit {
                    machine_state: MachineState::EnableIpmiOverLan,
                };
                Ok(StateHandlerOutcome::transition(next_state))
            }
            DpuInitState::WaitingForNetworkInstall => {
                tracing::warn!(
                    "Invalid State WaitingForNetworkInstall for dpu Machine {}",
                    dpu_machine_id
                );
                Err(StateHandlerError::InvalidHostState(
                    *dpu_machine_id,
                    Box::new(state.managed_state.clone()),
                ))
            }
        }
    }

    async fn set_secure_boot(
        &self,
        count: u32,
        state: &ManagedHostStateSnapshot,
        set_secure_boot_state: SetSecureBootState,
        enable_secure_boot: bool,
        dpu_snapshot: &Machine,
        dpu_redfish_client: &dyn Redfish,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        let next_state: ManagedHostState;
        let dpu_machine_id = &dpu_snapshot.id.clone();

        // Use the host snapshot instead of the DPU snapshot because
        // the state.host_snapshot.current.version might be a bit more correct:
        // the state machine is driven by the host state
        let time_since_state_change: chrono::TimeDelta =
            state.host_snapshot.state.version.since_state_change();

        let wait_for_dpu_to_come_up = if time_since_state_change.num_minutes() > 5 {
            false
        } else {
            let (has_dpu_finished_booting, dpu_boot_progress) =
                redfish::did_dpu_finish_booting(dpu_redfish_client)
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "did_dpu_finish_booting",
                        error: e,
                    })?;

            if count > 0 && !has_dpu_finished_booting {
                tracing::info!(
                    "Waiting for DPU {} to finish booting; boot progress: {dpu_boot_progress:#?}; SetSecureBoot cycle: {count}",
                    dpu_snapshot.id
                )
            }

            !has_dpu_finished_booting
        };

        match set_secure_boot_state {
            SetSecureBootState::WaitCertificateUpload { task_id } => {
                let task = dpu_redfish_client
                    .get_task(task_id.as_str())
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "get_task",
                        error: e,
                    })?;
                match task.clone().task_state {
                    Some(TaskState::New)
                    | Some(TaskState::Starting)
                    | Some(TaskState::Running)
                    | Some(TaskState::Pending) => {
                        return Ok(StateHandlerOutcome::wait(format!(
                            "Waiting for certificate upload task {task_id} to complete",
                        )));
                    }
                    Some(TaskState::Completed) => {
                        next_state = DpuDiscoveringState::EnableSecureBoot {
                            enable_secure_boot_state: SetSecureBootState::SetSecureBoot,
                            count: 0,
                        }
                        .next_state(&state.managed_state, dpu_machine_id)?;
                    }
                    None => {
                        return Err(StateHandlerError::RedfishError {
                            operation: "get_task",
                            error: RedfishError::NoContent,
                        });
                    }
                    Some(e) => {
                        return Err(StateHandlerError::RedfishError {
                            operation: "get_task",
                            error: RedfishError::GenericError {
                                error: format!("Task {task:#?} error: {e:#?}"),
                            },
                        });
                    }
                }
            }
            SetSecureBootState::CheckSecureBootStatus => {
                // This is the logic:
                // CheckSecureBootStatus -> DisableSecureBoot -> DisableSecureBootState::RebootDPU{0} -> DisableSecureBootState::RebootDPU{1}
                // The first time we check to see if secure boot is disabled, we do not need to wait. The DPU should already be up.
                // However, we need to give time in between the second reboot and checking the status again.
                if count > 0 && wait_for_dpu_to_come_up {
                    return Ok(StateHandlerOutcome::wait(format!(
                        "Waiting for DPU {dpu_machine_id} to come back up from last reboot; time since last reboot: {time_since_state_change}; DisableSecureBoot cycle: {count}",
                    )));
                }

                match self
                    .is_secure_boot_disabled(dpu_machine_id, dpu_redfish_client)
                    .await
                {
                    Ok(is_secure_boot_disabled) if !enable_secure_boot => {
                        if is_secure_boot_disabled {
                            next_state = DpuDiscoveringState::SetUefiHttpBoot
                                .next_state(&state.managed_state, dpu_machine_id)?;
                        } else {
                            next_state = DpuDiscoveringState::DisableSecureBoot {
                                disable_secure_boot_state: Some(SetSecureBootState::SetSecureBoot),
                                count,
                            }
                            .next_state(&state.managed_state, dpu_machine_id)?;
                        }
                    }
                    Ok(is_secure_boot_disabled) => {
                        if is_secure_boot_disabled {
                            let pk_certs = dpu_redfish_client
                                .get_secure_boot_certificates("PK")
                                .await
                                .map_err(|e| StateHandlerError::RedfishError {
                                    operation: "get_secure_boot_certificates",
                                    error: e,
                                })?;

                            if pk_certs.is_empty() {
                                let mut cert_file = File::open("/forge-boot-artifacts/blobs/internal/aarch64/secure-boot-pk.pem").await.map_err(|e| StateHandlerError::RedfishError {
                                    operation: "open_secure_boot_certificate_file",
                                    error: RedfishError::FileError(format!("Error opening secure boot certificate file: {e}")),
                                })?;
                                let mut cert_string = String::new();
                                cert_file
                                    .read_to_string(&mut cert_string)
                                    .await
                                    .map_err(|e| StateHandlerError::RedfishError {
                                        operation: "read_secure_boot_certificate_file",
                                        error: RedfishError::FileError(format!(
                                            "Error reading secure boot certificate file: {e}"
                                        )),
                                    })?;
                                let task = dpu_redfish_client
                                    .add_secure_boot_certificate(cert_string.as_str(), "PK")
                                    .await
                                    .map_err(|e| StateHandlerError::RedfishError {
                                        operation: "add_secure_boot_certificate",
                                        error: e,
                                    })?;
                                dpu_redfish_client
                                    .power(SystemPowerControl::ForceRestart)
                                    .await
                                    .map_err(|e| StateHandlerError::RedfishError {
                                        operation: "force_restart",
                                        error: e,
                                    })?;
                                next_state = DpuDiscoveringState::EnableSecureBoot {
                                    enable_secure_boot_state:
                                        SetSecureBootState::WaitCertificateUpload {
                                            task_id: task.id,
                                        },
                                    count: 0,
                                }
                                .next_state(&state.managed_state, dpu_machine_id)?;
                            } else {
                                next_state = DpuDiscoveringState::EnableSecureBoot {
                                    enable_secure_boot_state: SetSecureBootState::SetSecureBoot,
                                    count,
                                }
                                .next_state(&state.managed_state, dpu_machine_id)?;
                            }
                        } else {
                            next_state = DpuInitState::InstallDpuOs {
                                substate: InstallDpuOsState::InstallingBFB,
                            }
                            .next_state(&state.managed_state, dpu_machine_id)?;
                        }
                    }
                    Err(StateHandlerError::MissingData { object_id, missing }) => {
                        tracing::info!(
                            "Missing data in secure boot status response for DPU {}: {}; rebooting DPU as a work-around",
                            object_id,
                            missing
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

                        // Do not reboot the DPU indefinitely, something else might be wrong (DPU might be bust).
                        if count < 10 {
                            dpu_redfish_client
                                .power(SystemPowerControl::ForceRestart)
                                .await
                                .map_err(|e| StateHandlerError::RedfishError {
                                    operation: "force_restart",
                                    error: e,
                                })?;
                            if enable_secure_boot {
                                next_state = DpuDiscoveringState::EnableSecureBoot {
                                    enable_secure_boot_state: SetSecureBootState::RebootDPU {
                                        reboot_count: 0,
                                    },
                                    count: count + 1,
                                }
                                .next_state(&state.managed_state, dpu_machine_id)?;
                            } else {
                                next_state = DpuDiscoveringState::DisableSecureBoot {
                                    disable_secure_boot_state: Some(
                                        SetSecureBootState::CheckSecureBootStatus,
                                    ),
                                    count: count + 1,
                                }
                                .next_state(&state.managed_state, dpu_machine_id)?;
                            }
                        } else {
                            return Err(StateHandlerError::MissingData { object_id, missing });
                        }
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            SetSecureBootState::DisableSecureBoot | SetSecureBootState::SetSecureBoot => {
                if enable_secure_boot {
                    dpu_redfish_client.enable_secure_boot().await.map_err(|e| {
                        StateHandlerError::RedfishError {
                            operation: "enable_secure_boot",
                            error: e,
                        }
                    })?;

                    next_state = DpuDiscoveringState::EnableSecureBoot {
                        enable_secure_boot_state: SetSecureBootState::RebootDPU { reboot_count: 0 },
                        count,
                    }
                    .next_state(&state.managed_state, dpu_machine_id)?;
                } else {
                    dpu_redfish_client
                        .disable_secure_boot()
                        .await
                        .map_err(|e| StateHandlerError::RedfishError {
                            operation: "disable_secure_boot",
                            error: e,
                        })?;

                    next_state = DpuDiscoveringState::DisableSecureBoot {
                        disable_secure_boot_state: Some(SetSecureBootState::RebootDPU {
                            reboot_count: 0,
                        }),
                        count,
                    }
                    .next_state(&state.managed_state, dpu_machine_id)?;
                }
            }
            // DPUs requires two reboots after the previous step in order to disable secure boot.
            // From the doc linked above: "the BlueField Arm OS must be rebooted twice. The first
            // reboot is for the UEFI redfish client to read the request from the BMC and apply it; the
            // second reboot is for the setting to take effect."
            // We do not need to wait between disabling secure boot and the first reboot.
            // But, we need to give the DPU time to come up after the initial reboot,
            // before we reboot it again.
            SetSecureBootState::RebootDPU { reboot_count } => {
                if reboot_count == 0 {
                    next_state = if enable_secure_boot {
                        DpuDiscoveringState::EnableSecureBoot {
                            enable_secure_boot_state: SetSecureBootState::RebootDPU {
                                reboot_count: reboot_count + 1,
                            },
                            count,
                        }
                        .next_state(&state.managed_state, dpu_machine_id)?
                    } else {
                        DpuDiscoveringState::DisableSecureBoot {
                            disable_secure_boot_state: Some(SetSecureBootState::RebootDPU {
                                reboot_count: reboot_count + 1,
                            }),
                            count,
                        }
                        .next_state(&state.managed_state, dpu_machine_id)?
                    };
                } else {
                    if wait_for_dpu_to_come_up {
                        return Ok(StateHandlerOutcome::wait(format!(
                            "Waiting for DPU {dpu_machine_id} to come back up from last reboot; time since last reboot: {time_since_state_change}",
                        )));
                    }
                    if enable_secure_boot {
                        next_state = DpuDiscoveringState::EnableSecureBoot {
                            enable_secure_boot_state: SetSecureBootState::CheckSecureBootStatus,
                            count: count + 1,
                        }
                        .next_state(&state.managed_state, dpu_machine_id)?;
                    } else {
                        next_state = DpuDiscoveringState::DisableSecureBoot {
                            disable_secure_boot_state: Some(
                                SetSecureBootState::CheckSecureBootStatus,
                            ),
                            count: count + 1,
                        }
                        .next_state(&state.managed_state, dpu_machine_id)?;
                    }
                }

                dpu_redfish_client
                    .power(SystemPowerControl::ForceRestart)
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "force_restart",
                        error: e,
                    })?;
            }
        }

        Ok(StateHandlerOutcome::transition(next_state))
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
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<ManagedHostState>, StateHandlerError> {
        // TODO: Fix txn_held_across_await in handle_object_state_inner, then move it back inline
        let mut txn = ctx.services.db_pool.begin().await?;
        let outcome = self.handle_object_state_inner(state, &mut txn, ctx).await?;
        Ok(outcome.with_txn(Some(txn)))
    }
}

impl DpuMachineStateHandler {
    async fn handle_object_state_inner(
        &self,
        state: &mut ManagedHostStateSnapshot,
        txn: &mut PgConnection,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        let mut state_handler_outcome = StateHandlerOutcome::do_nothing();

        if state.host_snapshot.associated_dpu_machine_ids().is_empty() {
            let next_state = ManagedHostState::HostInit {
                machine_state: MachineState::WaitingForPlatformConfiguration,
            };
            Ok(StateHandlerOutcome::transition(next_state))
        } else {
            for dpu_snapshot in &state.dpu_snapshots {
                state_handler_outcome = self
                    .handle_dpuinit_state(state, dpu_snapshot, txn, ctx)
                    .await?;

                if let outcome @ StateHandlerOutcome::Transition { .. } = state_handler_outcome {
                    return Ok(outcome);
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
        return Err(StateHandlerError::GenericError(eyre::eyre!(
            "Poorly configured paramters: next_potential_reboot_time: {}, entered_state_at: {}, wait_period: {}",
            next_potential_reboot_time,
            entered_state_at,
            wait_period.num_minutes()
        )));
    }

    let cycle = next_potential_reboot_time - entered_state_at;

    // Although trigger_reboot_if_needed makes sure to not send wait_period as 0, but still if some other
    // function calls get_reboot_cycle, this function must not panic, so setting it min 1 minute
    // here as well.
    Ok(cycle.num_minutes() / wait_period.num_minutes().max(1))
}

#[derive(Debug)]
pub struct RebootStatus {
    increase_retry_count: bool, // the vague previous return value
    status: String,             // what we did or are waiting for
}

/// Outcome of configure_host_bios function.
enum BiosConfigOutcome {
    Done,
    WaitingForReboot(String),
}

/// Outcome of set_host_boot_order function.
enum SetBootOrderOutcome {
    Continue(SetBootOrderInfo),
    Done,
    WaitingForReboot(String),
}

/// In case machine does not come up until a specified duration, this function tries to reboot
/// it again. The reboot continues till 6 hours only. After that this function gives up.
/// WARNING:
/// If using this function in handler, never return Error, return wait/donothing.
/// In case a error is returned, last_reboot_requested won't be updated in db by state handler.
/// This will cause continuous reboot of machine after first failure_retry_time is
/// passed.
#[track_caller]
pub fn trigger_reboot_if_needed(
    target: &Machine,
    state: &ManagedHostStateSnapshot,
    retry_count: Option<i64>,
    reachability_params: &ReachabilityParams,
    services: &CommonStateHandlerServices,
    txn: &mut PgConnection,
) -> impl Future<Output = Result<RebootStatus, StateHandlerError>> {
    let trigger_location = std::panic::Location::caller();
    trigger_reboot_if_needed_with_location(
        target,
        state,
        retry_count,
        reachability_params,
        services,
        txn,
        trigger_location,
    )
}

#[allow(txn_held_across_await)]
pub async fn trigger_reboot_if_needed_with_location(
    target: &Machine,
    state: &ManagedHostStateSnapshot,
    retry_count: Option<i64>,
    reachability_params: &ReachabilityParams,
    services: &CommonStateHandlerServices,
    txn: &mut PgConnection,
    trigger_location: &std::panic::Location<'_>,
) -> Result<RebootStatus, StateHandlerError> {
    let host = &state.host_snapshot;
    // Its highly unlikely that the host has never been rebooted (and the last_reboot_reqeusted
    // field shouldn't get cleared), but default it if its not set
    let last_reboot_requested = match &target.last_reboot_requested {
        None => &MachineLastRebootRequested {
            time: host.state.version.timestamp(),
            mode: MachineLastRebootRequestedMode::Reboot,
            ..MachineLastRebootRequested::default()
        },
        Some(req) => req,
    };

    if let MachineLastRebootRequestedMode::PowerOff = last_reboot_requested.mode {
        // PowerOn the host.
        tracing::info!(
            "Machine {} is in power-off state. Turning on for host: {}",
            target.id,
            host.id,
        );

        if wait(
            &last_reboot_requested.time,
            reachability_params.power_down_wait,
        ) {
            return Ok(RebootStatus {
                increase_retry_count: false,
                status: format!(
                    "Waiting for host to power off. Next check at {}",
                    last_reboot_requested.time + reachability_params.power_down_wait
                ),
            });
        }

        let redfish_client = services
            .redfish_client_pool
            .create_client_from_machine(host, txn)
            .await?;

        let power_state = host_power_state(redfish_client.as_ref()).await?;

        // If power-off done, power-on now.
        // If host is not powered-off yet, try again.
        let action = if power_state == libredfish::PowerState::Off {
            SystemPowerControl::On
        } else {
            tracing::error!(
                "Machine {} is still not power-off state. Turning off again for host: {}",
                target.id,
                host.id,
            );
            SystemPowerControl::ForceOff
        };

        tracing::trace!(machine_id=%target.id, "Redfish setting host power state to {action}");
        handler_host_power_control_with_location(state, services, action, txn, trigger_location)
            .await?;
        return Ok(RebootStatus {
            increase_retry_count: false,
            status: format!("Set power state to {action} using Redfish API"),
        });
    }

    // Check if reboot is prevented by health override.
    if state.aggregate_health.is_reboot_blocked_in_state_machine() {
        tracing::info!(
            "Not trying to reboot {} since health override is set to prevent reboot.",
            target.id,
        );
        return Ok(RebootStatus {
            increase_retry_count: false,
            status: format!(
                "Not trying to reboot {} since health override is set to prevent reboot.",
                target.id
            ),
        });
    }

    let wait_period = reachability_params
        .failure_retry_time
        .max(Duration::minutes(1));

    let current_time = Utc::now();
    let entered_state_at = target.state.version.timestamp();
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
                // PowerDown (or ACPowercycle for Lenovo)
                // DPU or host, in both cases power down is triggered from host.
                let vendor = state.host_snapshot.bmc_vendor();

                let action = if vendor.is_lenovo() {
                    SystemPowerControl::ACPowercycle
                } else {
                    SystemPowerControl::ForceOff
                };

                handler_host_power_control_with_location(
                    state,
                    services,
                    action,
                    txn,
                    trigger_location,
                )
                .await?;

                format!(
                    "{vendor} has not come up after {time_elapsed_since_state_change} minutes, trying {action}, cycle: {cycle}",
                )
            } else {
                // Reboot
                if target.id.machine_type().is_dpu() {
                    handler_restart_dpu(target, services, txn).await?;
                } else {
                    handler_host_power_control_with_location(
                        state,
                        services,
                        SystemPowerControl::ForceRestart,
                        txn,
                        trigger_location,
                    )
                    .await?;
                }
                format!(
                    "Has not come up after {time_elapsed_since_state_change} minutes. Rebooting again, cycle: {cycle}."
                )
            };

            tracing::info!(machine_id=%target.id,
                "triggered reboot for machine in managed-host state {}: {}",
                state.managed_state,
                status,
            );

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
pub fn rebooted(target: &Machine) -> bool {
    target.last_reboot_time.unwrap_or_default() > target.state.version.timestamp()
}

pub fn machine_validation_completed(target: &Machine) -> bool {
    target.last_machine_validation_time.unwrap_or_default() > target.state.version.timestamp()
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

fn managed_host_network_config_version_synced_and_dpu_healthy(dpu_snapshot: &Machine) -> bool {
    if !dpu_snapshot.managed_host_network_config_version_synced() {
        return false;
    }

    let Some(dpu_health) = &dpu_snapshot.dpu_agent_health_report else {
        return false;
    };

    // Note that DPU alerts may be surpressed (classifications removed) in the aggregate health
    // report so the individual DPU's report is used.
    !dpu_health
        .has_classification(&health_report::HealthAlertClassification::prevent_host_state_changes())
}

fn check_host_health_for_alerts(state: &ManagedHostStateSnapshot) -> Result<(), StateHandlerError> {
    // In some states, DPU alerts may be surpressed (classifications removed) in the aggregate health report.
    // Since this is not called from a state that supresses DPU alerts, this is ok here.
    match state
        .aggregate_health
        .has_classification(&health_report::HealthAlertClassification::prevent_host_state_changes())
    {
        true => Err(StateHandlerError::HealthProbeAlert),
        false => Ok(()),
    }
}

async fn handle_host_boot_order_setup(
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    host_handler_params: HostHandlerParams,
    mh_snapshot: &mut ManagedHostStateSnapshot,
    set_boot_order_info: Option<SetBootOrderInfo>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    tracing::info!(
        "Starting Boot Order Configuration for {}: {set_boot_order_info:#?}",
        mh_snapshot.host_snapshot.id
    );

    let redfish_client = ctx
        .services
        .redfish_client_pool
        .create_client_from_machine(&mh_snapshot.host_snapshot, txn)
        .await?;

    let next_state = match set_boot_order_info {
        Some(info) => {
            match set_host_boot_order(
                txn,
                ctx,
                &host_handler_params.reachability_params,
                redfish_client.as_ref(),
                mh_snapshot,
                info,
            )
            .await?
            {
                SetBootOrderOutcome::Continue(boot_order_info) => ManagedHostState::HostInit {
                    machine_state: MachineState::SetBootOrder {
                        set_boot_order_info: Some(boot_order_info),
                    },
                },
                SetBootOrderOutcome::Done => {
                    if host_handler_params.attestation_enabled {
                        ManagedHostState::HostInit {
                            machine_state: MachineState::Measuring {
                                measuring_state: MeasuringState::WaitingForMeasurements,
                            },
                        }
                    } else {
                        ManagedHostState::HostInit {
                            machine_state: MachineState::WaitingForDiscovery,
                        }
                    }
                }
                SetBootOrderOutcome::WaitingForReboot(reason) => {
                    return Ok(StateHandlerOutcome::wait(reason));
                }
            }
        }
        None => ManagedHostState::HostInit {
            machine_state: MachineState::SetBootOrder {
                set_boot_order_info: Some(SetBootOrderInfo {
                    set_boot_order_jid: None,
                    set_boot_order_state: SetBootOrderState::SetBootOrder,
                    retry_count: 0,
                }),
            },
        },
    };

    Ok(StateHandlerOutcome::transition(next_state))
}

/// TODO: we need to handle the case where the job is deleted for some reason
#[allow(txn_held_across_await)]
async fn handle_host_uefi_setup(
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    state: &mut ManagedHostStateSnapshot,
    uefi_setup_info: UefiSetupInfo,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let redfish_client = ctx
        .services
        .redfish_client_pool
        .create_client_from_machine(&state.host_snapshot, txn)
        .await?;

    match uefi_setup_info.uefi_setup_state.clone() {
        UefiSetupState::UnlockHost => {
            if state.host_snapshot.bmc_vendor().is_dell() {
                redfish_client
                    .lockdown_bmc(libredfish::EnabledDisabled::Disabled)
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "lockdown",
                        error: e,
                    })?;
            }

            Ok(StateHandlerOutcome::transition(
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
                Ok(job_id) => Ok(StateHandlerOutcome::transition(
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
                        state.host_snapshot.id,
                        state.host_snapshot.bmc_vendor(),
                        e
                    );

                    // This feature has only been tested thoroughly on Dells, Lenovos, and Vikings.
                    if state.host_snapshot.bmc_vendor().is_dell()
                        || state.host_snapshot.bmc_vendor().is_lenovo()
                        || state.host_snapshot.bmc_vendor().is_nvidia()
                    {
                        return Err(StateHandlerError::GenericError(eyre::eyre!("{}", msg)));
                    }

                    // For all other vendors, allow ingestion even though we couldnt set the bios password
                    // An operator will have to set the bios password manually
                    tracing::info!(msg);

                    Ok(StateHandlerOutcome::transition(
                        ManagedHostState::HostInit {
                            machine_state: MachineState::WaitingForLockdown {
                                lockdown_info: LockdownInfo {
                                    state: LockdownState::SetLockdown,
                                    mode: LockdownMode::Enable,
                                },
                            },
                        },
                    ))
                }
            }
        }
        UefiSetupState::WaitForPasswordJobScheduled => {
            if let Some(job_id) = uefi_setup_info.uefi_password_jid.clone() {
                let job_state = redfish_client.get_job_state(&job_id).await.map_err(|e| {
                    StateHandlerError::RedfishError {
                        operation: "get_job_state",
                        error: e,
                    }
                })?;

                if !matches!(job_state, libredfish::JobState::Scheduled) {
                    return Ok(StateHandlerOutcome::wait(format!(
                        "waiting for job {:#?} to be scheduled; current state: {job_state:#?}",
                        job_id
                    )));
                }
            }

            Ok(StateHandlerOutcome::transition(
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
            Ok(StateHandlerOutcome::transition(
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
                let redfish_client = ctx
                    .services
                    .redfish_client_pool
                    .create_client_from_machine(&state.host_snapshot, txn)
                    .await?;

                let job_state = redfish_client.get_job_state(&job_id).await.map_err(|e| {
                    StateHandlerError::RedfishError {
                        operation: "get_job_state",
                        error: e,
                    }
                })?;

                if !matches!(job_state, libredfish::JobState::Completed) {
                    return Ok(StateHandlerOutcome::wait(format!(
                        "waiting for job {:#?} to complete; current state: {job_state:#?}",
                        job_id
                    )));
                }
            }

            state.host_snapshot.bios_password_set_time = Some(chrono::offset::Utc::now());
            db::machine::update_bios_password_set_time(&state.host_snapshot.id, txn)
                .await
                .map_err(|e| {
                    StateHandlerError::GenericError(eyre!(
                        "update_host_bios_password_set failed: {}",
                        e
                    ))
                })?;

            Ok(StateHandlerOutcome::transition(
                ManagedHostState::HostInit {
                    machine_state: MachineState::WaitingForLockdown {
                        lockdown_info: LockdownInfo {
                            state: LockdownState::SetLockdown,
                            mode: LockdownMode::Enable,
                        },
                    },
                },
            ))
        }
        // Deprecated: Kept for backwards compatibility with hosts that may be in this state.
        UefiSetupState::LockdownHost => Ok(StateHandlerOutcome::transition(
            ManagedHostState::HostInit {
                machine_state: MachineState::WaitingForLockdown {
                    lockdown_info: LockdownInfo {
                        state: LockdownState::SetLockdown,
                        mode: LockdownMode::Enable,
                    },
                },
            },
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
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<ManagedHostState>, StateHandlerError> {
        // TODO: Fix txn_held_across_await in handle_object_state_inner, then move it back inline
        let mut txn = ctx.services.db_pool.begin().await?;
        let outcome = self
            .handle_object_state_inner(host_machine_id, mh_snapshot, &mut txn, ctx)
            .await?;
        Ok(outcome.with_txn(Some(txn)))
    }
}

impl HostMachineStateHandler {
    #[allow(txn_held_across_await)]
    async fn handle_object_state_inner(
        &self,
        host_machine_id: &MachineId,
        mh_snapshot: &mut ManagedHostStateSnapshot,
        txn: &mut PgConnection,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        if let ManagedHostState::HostInit { machine_state } = &mh_snapshot.managed_state {
            match machine_state {
                MachineState::Init => Err(StateHandlerError::InvalidHostState(
                    *host_machine_id,
                    Box::new(mh_snapshot.managed_state.clone()),
                )),
                MachineState::EnableIpmiOverLan => {
                    let host_redfish_client = ctx
                        .services
                        .redfish_client_pool
                        .create_client_from_machine(&mh_snapshot.host_snapshot, txn)
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

                    Ok(StateHandlerOutcome::transition(next_state))
                }
                MachineState::WaitingForPlatformConfiguration => {
                    tracing::info!(
                        machine_id = %host_machine_id,
                        "Starting UEFI / BMC setup");

                    let redfish_client = ctx
                        .services
                        .redfish_client_pool
                        .create_client_from_machine(&mh_snapshot.host_snapshot, txn)
                        .await?;

                    match redfish_client.lockdown_status().await {
                        Err(libredfish::RedfishError::NotSupported(_)) => {
                            tracing::info!(
                                "BMC vendor does not support checking lockdown status for {host_machine_id}."
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Error fetching lockdown status for {host_machine_id} during machine_setup check: {e}"
                            );
                            return Ok(StateHandlerOutcome::wait(format!(
                                "Failed to fetch lockdown status: {}",
                                e
                            )));
                        }
                        Ok(lockdown_status) if !lockdown_status.is_fully_disabled() => {
                            tracing::info!(
                                "Lockdown is enabled for {host_machine_id} during machine_setup, disabling now."
                            );
                            let next_state = ManagedHostState::HostInit {
                                machine_state: MachineState::WaitingForLockdown {
                                    lockdown_info: LockdownInfo {
                                        state: LockdownState::SetLockdown,
                                        mode: LockdownMode::Disable,
                                    },
                                },
                            };
                            return Ok(StateHandlerOutcome::transition(next_state));
                        }
                        Ok(_) => {
                            // Lockdown is disabled, proceed with machine_setup
                        }
                    }

                    match configure_host_bios(
                        txn,
                        ctx,
                        &self.host_handler_params.reachability_params,
                        redfish_client.as_ref(),
                        mh_snapshot,
                    )
                    .await?
                    {
                        BiosConfigOutcome::Done => {
                            // BIOS configuration done, move to polling
                            Ok(StateHandlerOutcome::transition(
                                ManagedHostState::HostInit {
                                    machine_state: MachineState::PollingBiosSetup,
                                },
                            ))
                        }
                        BiosConfigOutcome::WaitingForReboot(reason) => {
                            Ok(StateHandlerOutcome::wait(reason))
                        }
                    }
                }
                MachineState::PollingBiosSetup => {
                    let next_state = ManagedHostState::HostInit {
                        machine_state: MachineState::SetBootOrder {
                            set_boot_order_info: Some(SetBootOrderInfo {
                                set_boot_order_jid: None,
                                set_boot_order_state: SetBootOrderState::SetBootOrder,
                                retry_count: 0,
                            }),
                        },
                    };

                    let redfish_client = ctx
                        .services
                        .redfish_client_pool
                        .create_client_from_machine(&mh_snapshot.host_snapshot, txn)
                        .await?;

                    let boot_interface_mac = if !mh_snapshot.dpu_snapshots.is_empty() {
                        let primary_interface = mh_snapshot
                            .host_snapshot
                            .interfaces
                            .iter()
                            .find(|x| x.primary_interface)
                            .ok_or_else(|| {
                                StateHandlerError::GenericError(eyre::eyre!(
                                    "Missing primary interface from host: {}",
                                    mh_snapshot.host_snapshot.id
                                ))
                            })?;
                        Some(primary_interface.mac_address.to_string())
                    } else {
                        None
                    };

                    match redfish_client
                        .is_bios_setup(boot_interface_mac.as_deref())
                        .await
                    {
                        Ok(true) => {
                            tracing::info!(
                                machine_id = %mh_snapshot.host_snapshot.id,
                                "BIOS setup verified successfully"
                            );
                            Ok(StateHandlerOutcome::transition(next_state))
                        }
                        Ok(false) => Ok(StateHandlerOutcome::wait(
                            "Polling BIOS setup status, waiting for settings to be applied"
                                .to_string(),
                        )),
                        Err(e) => {
                            tracing::warn!(
                                machine_id = %mh_snapshot.host_snapshot.id,
                                error = %e,
                                "Failed to check BIOS setup status, will retry"
                            );
                            Ok(StateHandlerOutcome::wait(format!(
                                "Failed to check BIOS setup status: {}. Will retry.",
                                e
                            )))
                        }
                    }
                }
                MachineState::SetBootOrder {
                    set_boot_order_info,
                } => Ok(handle_host_boot_order_setup(
                    txn,
                    ctx,
                    self.host_handler_params.clone(),
                    mh_snapshot,
                    set_boot_order_info.clone(),
                )
                .await?),
                MachineState::Measuring { measuring_state } => {
                    match handle_measuring_state(
                        measuring_state,
                        &mh_snapshot.host_snapshot.id,
                        txn,
                        self.host_handler_params.attestation_enabled,
                    )
                    .await
                    {
                        Ok(measuring_outcome) => {
                            map_host_init_measuring_outcome_to_state_handler_outcome(
                                &measuring_outcome,
                                measuring_state,
                            )
                        }
                        Err(StateHandlerError::MissingData {
                            object_id: _,
                            missing: "ek_cert_verification_status",
                        }) => {
                            Ok(StateHandlerOutcome::wait(
                                "Waiting for Scout to start and send registration info (in discover_machine)".to_string()
                            ))
                        }
                        Err(e) => Err(e),
                    }
                }
                MachineState::WaitingForDiscovery => {
                    if !discovered_after_state_transition(
                        mh_snapshot.host_snapshot.state.version,
                        mh_snapshot.host_snapshot.last_discovery_time,
                    ) {
                        tracing::trace!(
                            machine_id = %host_machine_id,
                            "Waiting for forge-scout to report host online. \
                                         Host last seen {:?}, must come after DPU's {}",
                            mh_snapshot.host_snapshot.last_discovery_time,
                            mh_snapshot.host_snapshot.state.version.timestamp()
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
                        return Ok(StateHandlerOutcome::wait(status.status));
                    }

                    Ok(StateHandlerOutcome::transition(
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
                    match &lockdown_info.state {
                        LockdownState::SetLockdown => {
                            tracing::info!(
                                machine_id = %host_machine_id,
                                mode = ?lockdown_info.mode,
                                "Setting lockdown and issuing reboot"
                            );

                            let redfish_client = ctx
                                .services
                                .redfish_client_pool
                                .create_client_from_machine(&mh_snapshot.host_snapshot, txn)
                                .await?;

                            let action = match lockdown_info.mode {
                                LockdownMode::Enable => libredfish::EnabledDisabled::Enabled,
                                LockdownMode::Disable => libredfish::EnabledDisabled::Disabled,
                            };

                            redfish_client.lockdown(action).await.map_err(|e| {
                                StateHandlerError::RedfishError {
                                    operation: "lockdown",
                                    error: e,
                                }
                            })?;

                            handler_host_power_control(
                                mh_snapshot,
                                ctx.services,
                                SystemPowerControl::ForceRestart,
                                txn,
                            )
                            .await?;

                            Ok(StateHandlerOutcome::transition(
                                ManagedHostState::HostInit {
                                    machine_state: MachineState::WaitingForLockdown {
                                        lockdown_info: LockdownInfo {
                                            state: LockdownState::TimeWaitForDPUDown,
                                            mode: lockdown_info.mode.clone(),
                                        },
                                    },
                                },
                            ))
                        }
                        LockdownState::TimeWaitForDPUDown => {
                            if ctx.services.site_config.force_dpu_nic_mode {
                                // skip wait for dpu reboot TimeWaitForDPUDown, WaitForDPUUp
                                // GB200/300, etc with dpu disconnected or in nic mode
                                let next_state = ManagedHostState::BomValidating {
                                    bom_validating_state: BomValidating::MatchingSku(
                                        BomValidatingContext {
                                            machine_validation_context: Some(
                                                "Discovery".to_string(),
                                            ),
                                            reboot_retry_count: None,
                                        },
                                    ),
                                };
                                return Ok(StateHandlerOutcome::transition(next_state));
                            }
                            // Lets wait for some time before checking if DPU is up or not.
                            // Waiting is needed because DPU takes some time to go down. If we check DPU
                            // reachability before it goes down, it will give us wrong result.
                            if wait(
                                &mh_snapshot.host_snapshot.state.version.timestamp(),
                                self.host_handler_params.reachability_params.dpu_wait_time,
                            ) {
                                Ok(StateHandlerOutcome::wait(format!(
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
                                Ok(StateHandlerOutcome::transition(next_state))
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

                                let next_state = ManagedHostState::HostInit {
                                    machine_state: MachineState::WaitingForLockdown {
                                        lockdown_info: LockdownInfo {
                                            state: LockdownState::PollingLockdownStatus,
                                            mode: lockdown_info.mode.clone(),
                                        },
                                    },
                                };
                                Ok(StateHandlerOutcome::transition(next_state))
                            } else {
                                Ok(StateHandlerOutcome::wait("Waiting for DPU to report UP. This requires forge-dpu-agent to call the RecordDpuNetworkStatus API".to_string()))
                            }
                        }
                        LockdownState::PollingLockdownStatus => {
                            let next_state = if LockdownMode::Enable == lockdown_info.mode {
                                ManagedHostState::BomValidating {
                                    bom_validating_state: BomValidating::MatchingSku(
                                        BomValidatingContext {
                                            machine_validation_context: Some(
                                                "Discovery".to_string(),
                                            ),
                                            ..BomValidatingContext::default()
                                        },
                                    ),
                                }
                            } else {
                                ManagedHostState::HostInit {
                                    machine_state: MachineState::WaitingForPlatformConfiguration,
                                }
                            };

                            let redfish_client = ctx
                                .services
                                .redfish_client_pool
                                .create_client_from_machine(&mh_snapshot.host_snapshot, txn)
                                .await?;

                            match redfish_client.lockdown_status().await {
                                Ok(lockdown_status) => {
                                    let expected_state = match lockdown_info.mode {
                                        LockdownMode::Enable => lockdown_status.is_fully_enabled(),
                                        LockdownMode::Disable => {
                                            lockdown_status.is_fully_disabled()
                                        }
                                    };

                                    if expected_state {
                                        tracing::info!(
                                            machine_id = %mh_snapshot.host_snapshot.id,
                                            mode = ?lockdown_info.mode,
                                            "Lockdown status verified successfully"
                                        );
                                        Ok(StateHandlerOutcome::transition(next_state))
                                    } else {
                                        Ok(StateHandlerOutcome::wait(format!(
                                            "Polling lockdown status, waiting for {:?} to be applied. Current status: {:?}",
                                            lockdown_info.mode, lockdown_status
                                        )))
                                    }
                                }
                                Err(libredfish::RedfishError::NotSupported(_)) => {
                                    tracing::info!(
                                        "BMC vendor does not support checking lockdown status for {host_machine_id}."
                                    );
                                    Ok(StateHandlerOutcome::transition(next_state))
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        machine_id = %mh_snapshot.host_snapshot.id,
                                        error = %e,
                                        "Failed to check lockdown status, will retry"
                                    );
                                    Ok(StateHandlerOutcome::wait(format!(
                                        "Failed to check lockdown status: {}. Will retry.",
                                        e
                                    )))
                                }
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
                        Ok(StateHandlerOutcome::transition(ManagedHostState::Ready))
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
                        Ok(StateHandlerOutcome::wait(format!(
                            "Waiting for scout to call RebootCompleted grpc. {}",
                            status.status
                        )))
                    }
                }
            }
        } else {
            Err(StateHandlerError::InvalidHostState(
                *host_machine_id,
                Box::new(mh_snapshot.managed_state.clone()),
            ))
        }
    }
}

/// A `StateHandler` implementation for instances
#[derive(Debug, Clone)]
pub struct InstanceStateHandler {
    attestation_enabled: bool,
    reachability_params: ReachabilityParams,
    common_pools: Option<Arc<CommonPools>>,
    host_upgrade: Arc<HostUpgradeState>,
    hardware_models: FirmwareConfig,
    enable_secure_boot: bool,
    dpf_config: DpfConfig,
}

impl InstanceStateHandler {
    fn new(
        attestation_enabled: bool,
        reachability_params: ReachabilityParams,
        common_pools: Option<Arc<CommonPools>>,
        host_upgrade: Arc<HostUpgradeState>,
        hardware_models: FirmwareConfig,
        enable_secure_boot: bool,
        dpf_config: DpfConfig,
    ) -> Self {
        InstanceStateHandler {
            attestation_enabled,
            reachability_params,
            common_pools,
            host_upgrade,
            hardware_models,
            enable_secure_boot,
            dpf_config,
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
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<ManagedHostState>, StateHandlerError> {
        // TODO: Fix txn_held_across_await in handle_object_state_inner, then move it back inline
        let mut txn = ctx.services.db_pool.begin().await?;
        let outcome = self
            .handle_object_state_inner(host_machine_id, mh_snapshot, &mut txn, ctx)
            .await?;
        Ok(outcome.with_txn(Some(txn)))
    }
}

impl InstanceStateHandler {
    #[allow(txn_held_across_await)]
    async fn handle_object_state_inner(
        &self,
        host_machine_id: &MachineId,
        mh_snapshot: &mut ManagedHostStateSnapshot,
        txn: &mut PgConnection,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
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
                        *host_machine_id,
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
                        return Ok(StateHandlerOutcome::transition(next_state));
                    }

                    let network_segments_are_ready =
                        db::network_segment::are_network_segments_ready(
                            txn,
                            &network_segment_ids_with_vpc,
                        )
                        .await?;
                    if !network_segments_are_ready {
                        return Ok(StateHandlerOutcome::wait(
                            "Waiting for all segments to come in ready state.".to_string(),
                        ));
                    }
                    Ok(StateHandlerOutcome::transition(next_state))
                }
                InstanceState::WaitingForNetworkConfig => {
                    // It should be first state to process here.
                    // Wait for instance network config to be applied
                    // Reboot host and moved to Ready.

                    // TODO GK if delete_requested skip this whole step,
                    // reboot and jump to BootingWithDiscoveryImage

                    // Check DPU network config has been applied
                    if !mh_snapshot.managed_host_network_config_version_synced() {
                        return Ok(StateHandlerOutcome::wait(
                            "Waiting for DPU agent(s) to apply network config and report healthy network"
                                .to_string()
                        ));
                    }

                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForRebootToReady,
                    };

                    // Check instance network config has been applied
                    match check_instance_network_synced_and_dpu_healthy(instance, mh_snapshot)? {
                        InstanceNetworkSyncStatus::InstanceNetworkObservationNotAvailable(
                            missing_dpus,
                        ) => {
                            return Ok(StateHandlerOutcome::wait(format!(
                                "Waiting for DPU agents to apply initial network config for DPUs: {}",
                                missing_dpus.iter().map(|dpu| dpu.to_string()).join(", ")
                            )));
                        }
                        InstanceNetworkSyncStatus::InstanceNetworkSynced => {}
                        InstanceNetworkSyncStatus::ZeroDpuNoObservationNeeded => {
                            return Ok(StateHandlerOutcome::transition(next_state));
                        }
                        InstanceNetworkSyncStatus::InstanceNetworkNotSynced(outdated_dpus) => {
                            return Ok(StateHandlerOutcome::wait(format!(
                                "Waiting for DPU agent to apply most recent network config for DPUs: {}",
                                outdated_dpus.iter().map(|dpu| dpu.to_string()).join(", ")
                            )));
                        }
                    };

                    // Check whether the IB config is synced
                    if let Err(not_synced_reason) = ib_config_synced(
                        mh_snapshot
                            .host_snapshot
                            .infiniband_status_observation
                            .as_ref(),
                        Some(&instance.config.infiniband),
                        true,
                    ) {
                        return Ok(StateHandlerOutcome::wait(format!(
                            "Waiting for IB config to be applied: {}",
                            not_synced_reason
                        )));
                    }

                    // Check if the nvlink config has been applied
                    if let Err(not_synced_reason) = nvlink_config_synced(
                        mh_snapshot.host_snapshot.nvlink_status_observation.as_ref(),
                        Some(&instance.config.nvlink),
                    ) {
                        return Ok(StateHandlerOutcome::wait(format!(
                            "Waiting for NvLink config to be applied: {}",
                            not_synced_reason.0
                        )));
                    }
                    Ok(StateHandlerOutcome::transition(next_state))
                }
                InstanceState::WaitingForStorageConfig => {
                    // This state used to do something but doesn't any more, we can delete
                    // InstanceState::WaitingForStorageConfig once we're sure no places have the
                    // state persisted.
                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForExtensionServicesConfig,
                    };
                    Ok(StateHandlerOutcome::transition(next_state))
                }
                InstanceState::WaitingForExtensionServicesConfig => {
                    // If no extension services are configured, skip the wait and proceed
                    if instance
                        .config
                        .extension_services
                        .service_configs
                        .is_empty()
                    {
                        let next_state = ManagedHostState::Assigned {
                            instance_state: InstanceState::WaitingForRebootToReady,
                        };
                        return Ok(StateHandlerOutcome::transition(next_state));
                    }

                    let extension_services_status =
                        get_extension_services_status(mh_snapshot, instance, txn).await?;
                    match extension_service::compute_extension_services_readiness(&extension_services_status) {
                        ExtensionServicesReadiness::Ready => {
                            let next_state = ManagedHostState::Assigned {
                                instance_state: InstanceState::WaitingForRebootToReady,
                            };
                            Ok(StateHandlerOutcome::transition(next_state))
                        }
                        ExtensionServicesReadiness::ConfigsPending => {
                            Ok(StateHandlerOutcome::wait(
                                "Waiting for extension services config to be applied on all DPUs.".to_string(),
                            ))
                        }
                        ExtensionServicesReadiness::NotFullyRunning => {
                            Ok(StateHandlerOutcome::wait(
                                "Waiting for all active extension services to be running on all DPUs.".to_string(),
                            ))
                        }
                        ExtensionServicesReadiness::SomeTerminating => {
                            Ok(StateHandlerOutcome::wait(
                                "Waiting for all terminating extension services to be fully terminated across all DPUs."
                                    .to_string(),
                            ))
                        }
                    }
                }
                InstanceState::WaitingForRebootToReady => {
                    let host_machine_id = &mh_snapshot.host_snapshot.id;

                    // If custom_pxe_reboot_requested is set, this reboot was triggered by
                    // the tenant requested a boot with custom iPXE. Clear the request flag.
                    // The use_custom_pxe_on_boot flag was already set by the API handler.
                    if instance.custom_pxe_reboot_requested {
                        db::instance::set_custom_pxe_reboot_requested(host_machine_id, false, txn)
                            .await?;
                    }

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
                    Ok(StateHandlerOutcome::transition(next_state))
                }
                InstanceState::Ready => {
                    // Machine is up after reboot. Hurray. Instance is up.

                    // Wait for user's approval. Once user approves for dpu
                    // reprovision/update firmware, trigger it.
                    let is_auto_approved = self.host_upgrade.is_auto_approved();

                    // We will give first priority to network config update.
                    // This is the easiest way to stop resource leakage.
                    if instance.update_network_config_request.is_some() {
                        // Tenant has requested network config update.
                        let next_state = ManagedHostState::Assigned {
                            instance_state: InstanceState::NetworkConfigUpdate {
                                network_config_update_state:
                                    NetworkConfigUpdateState::WaitingForNetworkSegmentToBeReady,
                            },
                        };
                        return Ok(StateHandlerOutcome::transition(next_state));
                    }

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
                                        .map(|x| x.user_approval_received || is_auto_approved)
                                        .unwrap_or_default()
                                })
                        } else {
                            false
                        };
                    let host_firmware_requested = if let Some(request) =
                        &mh_snapshot.host_snapshot.host_reprovision_requested
                    {
                        request.user_approval_received || is_auto_approved
                    } else {
                        false
                    };

                    if is_auto_approved && (reprov_can_be_started || host_firmware_requested) {
                        tracing::info!(machine_id = %host_machine_id, "Auto rebooting host for reprovision/upgrade due to being in approved time period");
                    }

                    // Check if the instance needs to PXE boot. The custom_pxe_reboot_requested flag
                    // is set by the API when the tenant calls InvokeInstancePower with boot_with_custom_ipxe=true
                    //
                    // This triggers the HostPlatformConfiguration flow to verify BIOS boot order
                    // before rebooting. The WaitingForRebootToReady handler will clear this flag
                    // and set use_custom_pxe_on_boot, which the iPXE handler uses to serve the
                    // tenant's script.
                    let boot_with_custom_ipxe = instance.custom_pxe_reboot_requested;

                    if instance.deleted.is_some()
                        || reprov_can_be_started
                        || host_firmware_requested
                        || boot_with_custom_ipxe
                    {
                        for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                            if dpu_snapshot.reprovision_requested.is_some() {
                                // User won't be allowed to clear reprovisioning flag after this.
                                db::machine::update_dpu_reprovision_start_time(
                                    &dpu_snapshot.id,
                                    txn,
                                )
                                .await?;
                            }
                        }
                        if mh_snapshot
                            .host_snapshot
                            .host_reprovision_requested
                            .is_some()
                        {
                            db::machine::update_host_reprovision_start_time(
                                &mh_snapshot.host_snapshot.id,
                                txn,
                            )
                            .await?;
                        }

                        // For deletion, power cycle the host first. For everything else
                        // (reprovision, firmware update, custom PXE), verify boot config first.
                        let next_state = if instance.deleted.is_some() {
                            let redfish_client = ctx
                                .services
                                .redfish_client_pool
                                .create_client_from_machine(&mh_snapshot.host_snapshot, txn)
                                .await?;

                            let power_state = host_power_state(redfish_client.as_ref()).await?;

                            ManagedHostState::Assigned {
                                instance_state: InstanceState::HostPlatformConfiguration {
                                    platform_config_state:
                                        HostPlatformConfigurationState::PowerCycle {
                                            power_on: power_state == libredfish::PowerState::Off,
                                        },
                                },
                            }
                        } else {
                            ManagedHostState::Assigned {
                                instance_state: InstanceState::HostPlatformConfiguration {
                                    platform_config_state:
                                        HostPlatformConfigurationState::CheckHostConfig,
                                },
                            }
                        };

                        if host_firmware_requested {
                            let health_override =
                        crate::machine_update_manager::machine_update_module::create_host_update_health_report_hostfw();
                            // The health report alert gets generated here, the machine update manager retains responsibilty for clearing it when we're done.
                            db::machine::insert_health_report_override(
                                txn,
                                host_machine_id,
                                health_report::OverrideMode::Merge,
                                &health_override,
                                false,
                            )
                            .await?;
                        }

                        if reprov_can_be_started {
                            let health_override = crate::machine_update_manager::machine_update_module::create_host_update_health_report_dpufw();
                            // Mark the Host as in update.
                            db::machine::insert_health_report_override(
                                txn,
                                host_machine_id,
                                health_report::OverrideMode::Merge,
                                &health_override,
                                false,
                            )
                            .await?;
                        }

                        Ok(StateHandlerOutcome::transition(next_state))
                    } else {
                        Ok(StateHandlerOutcome::do_nothing())
                    }
                }
                InstanceState::HostPlatformConfiguration {
                    platform_config_state,
                } => {
                    handle_instance_host_platform_config(
                        txn,
                        ctx,
                        mh_snapshot,
                        &self.reachability_params,
                        platform_config_state.clone(),
                    )
                    .await
                }
                InstanceState::WaitingForDpusToUp => {
                    if !are_dpus_up_trigger_reboot_if_needed(
                        mh_snapshot,
                        &self.reachability_params,
                        ctx.services,
                        txn,
                    )
                    .await
                    {
                        return Ok(StateHandlerOutcome::wait(
                            "Waiting for DPUs to come up.".to_string(),
                        ));
                    }

                    // If custom_pxe_reboot_requested is set, transition to WaitingForRebootToReady and reboot.
                    // The iPXE handler will then serve the tenant's custom script when the host PXE boots.
                    //
                    // The API sets custom_pxe_reboot_requested when the tenant explicitly requests
                    // "Reboot with Custom iPXE"
                    //
                    // Otherwise, follow the normal termination/reprovision flow through
                    // BootingWithDiscoveryImage.
                    if instance.custom_pxe_reboot_requested {
                        let next_state = ManagedHostState::Assigned {
                            instance_state: InstanceState::WaitingForRebootToReady,
                        };
                        Ok(StateHandlerOutcome::transition(next_state))
                    } else {
                        handler_host_power_control(
                            mh_snapshot,
                            ctx.services,
                            SystemPowerControl::ForceRestart,
                            txn,
                        )
                        .await?;
                        let next_state = ManagedHostState::Assigned {
                            instance_state: InstanceState::BootingWithDiscoveryImage {
                                retry: RetryInfo { count: 0 },
                            },
                        };
                        Ok(StateHandlerOutcome::transition(next_state))
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
                            StateHandlerOutcome::transition(next_state)
                        } else {
                            StateHandlerOutcome::wait(status.status)
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
                        return Ok(StateHandlerOutcome::transition(next_state));
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

                        set_managed_host_topology_update_needed(
                            txn,
                            &mh_snapshot.host_snapshot,
                            &dpus_for_reprov,
                        )
                        .await?;

                        let next_state = ReprovisionState::next_substate_based_on_bfb_support(
                            self.enable_secure_boot,
                            mh_snapshot,
                            ctx.services.site_config.dpf.enabled,
                        )
                        .next_state_with_all_dpus_updated(
                            &mh_snapshot.managed_state,
                            &mh_snapshot.dpu_snapshots,
                            dpus_for_reprov.iter().map(|x| &x.id).collect_vec(),
                        )?;
                        Ok(StateHandlerOutcome::transition(next_state))
                    } else if mh_snapshot
                        .host_snapshot
                        .host_reprovision_requested
                        .is_some()
                    {
                        Ok(StateHandlerOutcome::transition(
                            ManagedHostState::Assigned {
                                instance_state: InstanceState::HostReprovision {
                                    reprovision_state: HostReprovisionState::CheckingFirmwareV2 {
                                        firmware_type: None,
                                        firmware_number: None,
                                    },
                                },
                            },
                        ))
                    } else {
                        Ok(StateHandlerOutcome::wait(
                            "Don't know how did we reach here.".to_string(),
                        ))
                    }
                }

                InstanceState::SwitchToAdminNetwork => {
                    // Tenant is gone and so is their network, switch back to admin network
                    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                        let (mut netconf, version) = dpu_snapshot.network_config.clone().take();
                        netconf.use_admin_network = Some(true);
                        db::machine::try_update_network_config(
                            txn,
                            &dpu_snapshot.id,
                            version,
                            &netconf,
                        )
                        .await?;
                    }

                    // Machine is currently an instance, but the instance is being released and we
                    // are switching the NICs to the admin network. Set use_admin_network to true
                    // and update the network config version in the DPA interfaces. This will cause
                    // the DPA State Controller to send SetVNI commands with the VNI being zero.
                    for dpa_interface in &mh_snapshot.dpa_interface_snapshots {
                        let (mut netconf, version) = dpa_interface.network_config.clone().take();
                        netconf.use_admin_network = Some(true);
                        db::dpa_interface::try_update_network_config(
                            txn,
                            &dpa_interface.id,
                            version,
                            &netconf,
                        )
                        .await?;
                    }

                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkReconfig,
                    };
                    Ok(StateHandlerOutcome::transition(next_state))
                }
                InstanceState::WaitingForNetworkReconfig => {
                    // Has forge-dpu-agent applied the new network config so that
                    // we are back on the admin network?
                    if !mh_snapshot.managed_host_network_config_version_synced() {
                        return Ok(StateHandlerOutcome::wait(
                            "Waiting for DPU agent(s) to apply network config and report healthy network"
                                .to_string()
                        ));
                    }

                    // Check if all DPUs have terminated all extension services
                    if let Some(instance) = mh_snapshot.instance.as_ref()
                        && !instance
                            .config
                            .extension_services
                            .service_configs
                            .is_empty()
                    {
                        for (_dpu_id, extension_service_statuses) in
                            instance.observations.extension_services.iter()
                        {
                            for status in
                                extension_service_statuses.extension_service_statuses.iter()
                            {
                                if status.overall_state
                                    != ExtensionServiceDeploymentStatus::Terminated
                                {
                                    return Ok(StateHandlerOutcome::wait(
                                            "Waiting for extension services to be terminated on all DPUs."
                                                .to_string()
                                        ));
                                }
                            }
                        }
                    }

                    // Check each DPA interface associated with the machine to make sure the DPA NIC has updated
                    // its network config (setting VNI to zero in this case).
                    if ctx.services.site_config.is_dpa_enabled() {
                        for dpa_interface in &mh_snapshot.dpa_interface_snapshots {
                            if !dpa_interface.managed_host_network_config_version_synced() {
                                return Ok(StateHandlerOutcome::wait(
                                "Waiting for DPA agent(s) to apply network config and report healthy network"
                                    .to_string()
                            ));
                            }
                        }
                    }

                    check_host_health_for_alerts(mh_snapshot)?;

                    // Check whether IB config is removed
                    match ib_config_synced(
                        mh_snapshot
                            .host_snapshot
                            .infiniband_status_observation
                            .as_ref(),
                        Some(&instance.config.infiniband),
                        false,
                    ) {
                        Ok(()) => {
                            // Config is synced, proceed with termination
                        }
                        Err(IbConfigNotSyncedReason::PortStateUnobservable { guids, details }) => {
                            tracing::warn!(
                                instance_id = %instance.id,
                                machine_id = %host_machine_id,
                                guids = ?guids,
                                details = %details,
                                "IB ports not observable during termination - IB Monitor will unbind"
                            );

                            // Collect GUIDs for cleanup
                            // TODO: Include fabric name for multi-fabric deployments
                            let message = format!(
                                "IB port cleanup pending - IB Monitor will unbind. GUIDs: {}",
                                guids.join("; ")
                            );

                            // Create health report with alert that will prevent re-allocation
                            // IB Monitor will unbind before clearing
                            let health_report = HealthReport {
                                source: "ib-cleanup-validation".to_string(),
                                observed_at: Some(chrono::Utc::now()),
                                alerts: vec![HealthProbeAlert {
                                    id: HealthProbeId::from_str("IbCleanupPending")
                                        .expect("valid probe id"),
                                    target: None,
                                    in_alert_since: Some(chrono::Utc::now()),
                                    message,
                                    tenant_message: None,
                                    classifications: vec![
                                        HealthAlertClassification::prevent_allocations(),
                                    ],
                                }],
                                successes: vec![],
                            };

                            // Use health report override instead of state_controller_health_report field
                            db::machine::insert_health_report_override(
                                txn,
                                host_machine_id,
                                OverrideMode::Merge,
                                &health_report,
                                false, // no_overwrite = false (we want to update if exists)
                            )
                            .await?;

                            tracing::info!(
                                machine_id = %host_machine_id,
                                guids = ?guids,
                                "IbCleanupPending alert created - IB Monitor will handle unbind and clear alert"
                            );

                            // Termination proceeds - IB Monitor will handle cleanup
                        }
                        Err(other_reason) => {
                            return Ok(StateHandlerOutcome::wait(format!(
                                "Waiting for IB config to be removed (Reason: {})",
                                other_reason
                            )));
                        }
                    }

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
                    db::instance::delete(instance.id, txn)
                        .await
                        .map_err(|err| StateHandlerError::GenericError(err.into()))?;

                    release_network_segments_with_vpc_prefix(
                        &instance.config.network.interfaces,
                        txn,
                    )
                    .await?;

                    // Free up all loopback IPs allocated for this instance.
                    release_vpc_dpu_loopback(mh_snapshot, &self.common_pools, txn).await?;

                    let next_state = if self.attestation_enabled {
                        ManagedHostState::PostAssignedMeasuring {
                            measuring_state: MeasuringState::WaitingForMeasurements,
                        }
                    } else {
                        ManagedHostState::WaitingForCleanup {
                            cleanup_state: CleanupState::Init,
                        }
                    };

                    Ok(StateHandlerOutcome::transition(next_state))
                }
                InstanceState::DPUReprovision { .. } => {
                    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                        if let outcome @ StateHandlerOutcome::Transition { .. } =
                            handle_dpu_reprovision(
                                mh_snapshot,
                                &self.reachability_params,
                                txn,
                                &InstanceNextStateResolver,
                                dpu_snapshot,
                                ctx,
                                &self.hardware_models,
                                &self.dpf_config,
                            )
                            .await?
                        {
                            return Ok(outcome);
                        }
                    }
                    Ok(StateHandlerOutcome::do_nothing())
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
                    Ok(StateHandlerOutcome::do_nothing())
                }
                InstanceState::HostReprovision { .. } => {
                    if let Some(next_state) = self
                        .host_upgrade
                        .handle_host_reprovision(
                            mh_snapshot,
                            ctx.services,
                            host_machine_id,
                            HostFirmwareScenario::Instance,
                            txn,
                        )
                        .await?
                    {
                        Ok(StateHandlerOutcome::transition(next_state))
                    } else {
                        Ok(StateHandlerOutcome::do_nothing())
                    }
                }
                InstanceState::NetworkConfigUpdate {
                    network_config_update_state,
                } => {
                    handle_instance_network_config_update_request(
                        mh_snapshot,
                        network_config_update_state,
                        instance,
                        txn,
                        &self.common_pools,
                    )
                    .await
                }
                InstanceState::DpaProvisioning => {
                    // An instance is being created.
                    // So we set use_admin_network to false and tell each DPA interface to
                    // update its network config. This will cause the DPA state controller
                    // to transition to the DPAs from READY state to WaitingForSetVNI state
                    // and send SetVNI commands to the DPA NICs.

                    if ctx.services.site_config.is_dpa_enabled() {
                        for dpa_interface in &mh_snapshot.dpa_interface_snapshots {
                            let (mut netconf, version) =
                                dpa_interface.network_config.clone().take();
                            netconf.use_admin_network = Some(false);
                            db::dpa_interface::try_update_network_config(
                                txn,
                                &dpa_interface.id,
                                version,
                                &netconf,
                            )
                            .await?;
                        }
                    }
                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForDpaToBeReady,
                    };
                    Ok(StateHandlerOutcome::transition(next_state))
                }
                InstanceState::WaitingForDpaToBeReady => {
                    // Check each DPA interface to see if it has acted on updating the network config.
                    // This involves the DPA State Machine sending SetVNI commands to the NICs, and getting
                    // an ACK. If any of the interfaces has not yet heard back the ACk, we will continue to
                    // be in the current state.
                    if ctx.services.site_config.is_dpa_enabled() {
                        for dpa_interface in &mh_snapshot.dpa_interface_snapshots {
                            if !dpa_interface.managed_host_network_config_version_synced() {
                                return Ok(StateHandlerOutcome::wait(
                                "Waiting for DPA agent(s) to apply network config and report healthy network"
                                    .to_string()
                            ));
                            }
                        }
                    }

                    // Switch to using the network we just created for the tenant
                    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
                        let (mut netconf, version) = dpu_snapshot.network_config.clone().take();
                        netconf.use_admin_network = Some(false);
                        db::machine::try_update_network_config(
                            txn,
                            &dpu_snapshot.id,
                            version,
                            &netconf,
                        )
                        .await?;
                    }

                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkSegmentToBeReady,
                    };
                    Ok(StateHandlerOutcome::transition(next_state))
                }
            }
        } else {
            // We are not in Assigned state. Should this be Err(StateHandlerError::InvalidHostState)?
            Ok(StateHandlerOutcome::do_nothing())
        }
    }
}

// Gets extension services status from DB, checks if any removed services are fully terminated
// across all DPUs, if so, remove them from the instance config in the DB(without updating the version).
async fn get_extension_services_status(
    mh_snapshot: &ManagedHostStateSnapshot,
    instance: &InstanceSnapshot,
    txn: &mut PgConnection,
) -> Result<InstanceExtensionServicesStatus, StateHandlerError> {
    let (_, dpu_id_to_device_map) = mh_snapshot
        .host_snapshot
        .get_dpu_device_and_id_mappings()
        .unwrap_or_else(|_| (HashMap::default(), HashMap::default()));

    // Gather instance extension services status from all DPU observations
    let mut extension_services_status =
        InstanceExtensionServicesStatus::from_config_and_observations(
            &dpu_id_to_device_map,
            Versioned::new(
                &instance.config.extension_services,
                instance.extension_services_config_version,
            ),
            &instance.observations.extension_services,
        );

    if extension_services_status.configs_synced == SyncState::Synced {
        let terminated_service_ids = extension_services_status.get_terminated_service_ids();
        if !terminated_service_ids.is_empty() {
            tracing::info!(
                instance_id = %instance.id,
                service_ids = ?terminated_service_ids,
                "Cleaning up fully terminated extension services from instance config"
            );

            let new_config = instance
                .config
                .extension_services
                .remove_terminated_services(&terminated_service_ids);

            db::instance::update_extension_services_config(
                txn,
                instance.id,
                instance.extension_services_config_version,
                &new_config,
                false,
            )
            .await?;

            extension_services_status
                .extension_services
                .retain(|svc| !terminated_service_ids.contains(&svc.service_id));
        }
    }

    Ok(extension_services_status)
}

async fn handle_instance_network_config_update_request(
    mh_snapshot: &ManagedHostStateSnapshot,
    network_config_update_state: &NetworkConfigUpdateState,
    instance: &InstanceSnapshot,
    txn: &mut PgConnection,
    common_pools: &Option<Arc<CommonPools>>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    match network_config_update_state {
        NetworkConfigUpdateState::WaitingForNetworkSegmentToBeReady => {
            let next_state = ManagedHostState::Assigned {
                instance_state: InstanceState::NetworkConfigUpdate {
                    network_config_update_state: NetworkConfigUpdateState::WaitingForConfigSynced,
                },
            };

            let Some(update_request) = &instance.update_network_config_request else {
                return Err(StateHandlerError::GenericError(eyre::eyre!(
                    "Network config update request is missing from db. instance: {}",
                    instance.id
                )));
            };

            let network_segment_ids_with_vpc = update_request
                .new_config
                .interfaces
                .iter()
                .filter_map(|x| match x.network_details {
                    Some(NetworkDetails::VpcPrefixId(_)) => x.network_segment_id,
                    _ => None,
                })
                .collect_vec();

            // No network segment is configured with vpc_prefix_id.
            if !network_segment_ids_with_vpc.is_empty() {
                let network_segments_are_ready = db::network_segment::are_network_segments_ready(
                    txn,
                    &network_segment_ids_with_vpc,
                )
                .await?;
                if !network_segments_are_ready {
                    return Ok(StateHandlerOutcome::wait(
                        "Waiting for all segments to come in ready state.".to_string(),
                    ));
                }
            }

            // Update requested network config and increment version.
            db::instance::update_network_config(
                txn,
                instance.id,
                instance.network_config_version,
                &update_request.new_config,
                true,
            )
            .await?;

            Ok(StateHandlerOutcome::transition(next_state))
        }
        NetworkConfigUpdateState::WaitingForConfigSynced => {
            let next_state = ManagedHostState::Assigned {
                instance_state: InstanceState::NetworkConfigUpdate {
                    network_config_update_state: NetworkConfigUpdateState::ReleaseOldResources,
                },
            };

            Ok(
                match check_instance_network_synced_and_dpu_healthy(instance, mh_snapshot)? {
                    InstanceNetworkSyncStatus::InstanceNetworkObservationNotAvailable(
                        missing_dpus,
                    ) => StateHandlerOutcome::wait(format!(
                        "Waiting for DPU agents to apply initial network config for DPUs: {}",
                        missing_dpus.iter().map(|dpu| dpu.to_string()).join(", ")
                    )),
                    InstanceNetworkSyncStatus::ZeroDpuNoObservationNeeded
                    | InstanceNetworkSyncStatus::InstanceNetworkSynced => {
                        StateHandlerOutcome::transition(next_state)
                    }
                    InstanceNetworkSyncStatus::InstanceNetworkNotSynced(outdated_dpus) => {
                        StateHandlerOutcome::wait(format!(
                            "Waiting for DPU agent to apply most recent network config for DPUs: {}",
                            outdated_dpus.iter().map(|dpu| dpu.to_string()).join(", ")
                        ))
                    }
                },
            )
        }
        NetworkConfigUpdateState::ReleaseOldResources => {
            // Identify all the resources which have to be released.
            // Release Ips.
            // Release segments.
            // Release VpcDpuLoopbackIps.
            // Free the update_network_config_request field.
            let Some(update_request) = &instance.update_network_config_request else {
                return Err(StateHandlerError::GenericError(eyre::eyre!(
                    "Network config update request is missing from db. instance: {}",
                    instance.id
                )));
            };

            // Logically new_config is current_config now.
            let mut new_config = update_request.new_config.clone();
            let copied_resources = new_config.copy_existing_resources(&update_request.old_config);

            let resources_to_be_released = update_request
                .old_config
                .interfaces
                .iter()
                .filter(|x| !copied_resources.contains(x))
                .cloned()
                .collect_vec();

            if !resources_to_be_released.is_empty() {
                let addresses = resources_to_be_released
                    .iter()
                    .flat_map(|x| x.ip_addrs.values().collect_vec())
                    .collect_vec();

                tracing::info!(
                    "Releasing network resources for instance {}: addresses: {:?}",
                    instance.id,
                    addresses,
                );
                db::instance_address::delete_addresses(txn, &addresses).await?;
                release_network_segments_with_vpc_prefix(&resources_to_be_released, txn).await?;

                // TODO: This is not the best way, but will work fine. If you delete all loopback IPs
                // associated with all DPUs, dpu_agent will assign new IPs during next managed_host_network_config
                // iteration.
                // The best way would be to find out the VPCs per DPU which are not used in new config
                // and delete them only. This can be taken care once multi-dpu instance allocation is
                // completed.
                release_vpc_dpu_loopback(mh_snapshot, common_pools, txn).await?;
            }
            db::instance::delete_update_network_config_request(&instance.id, txn).await?;
            let next_state = ManagedHostState::Assigned {
                instance_state: InstanceState::Ready,
            };
            Ok(StateHandlerOutcome::transition(next_state))
        }
    }
}

/// Checks if an instance's network is synced and its DPU is healthy.
///
/// This function compares the expected network configuration version with the actual version.
/// It also checks the health of the DPU by calling `check_host_health_for_alerts`.
///
/// # Notes
/// This function currently does not support multi-DPU handling.
fn check_instance_network_synced_and_dpu_healthy(
    instance: &InstanceSnapshot,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<InstanceNetworkSyncStatus, StateHandlerError> {
    if mh_snapshot
        .host_snapshot
        .associated_dpu_machine_ids()
        .is_empty()
    {
        tracing::info!(
            machine_id = %mh_snapshot.host_snapshot.id,
            "Skipping network config because machine has no DPUs"
        );
        return Ok(InstanceNetworkSyncStatus::ZeroDpuNoObservationNeeded);
    }

    let device_locators: Vec<DeviceLocator> = instance
        .config
        .network
        .interfaces
        .iter()
        .filter_map(|i| i.device_locator.clone())
        .collect();

    let maps = mh_snapshot
        .host_snapshot
        .get_dpu_device_and_id_mappings()
        .unwrap_or_else(|_| (HashMap::default(), HashMap::default()));

    let legacy_physical_interface_count = instance
        .config
        .network
        .interfaces
        .iter()
        .filter(|iface| {
            iface.function_id == InterfaceFunctionId::Physical {} && iface.device_locator.is_none()
        })
        .count();

    let use_primary_dpu_only = legacy_physical_interface_count > 0
        || device_locators.is_empty()
        || maps.0.is_empty()
        || maps.1.is_empty();

    let dpu_machine_ids: Vec<MachineId> = if use_primary_dpu_only {
        if legacy_physical_interface_count != 1 {
            return Err(StateHandlerError::GenericError(eyre!(
                "More than one interface configured when only the primary dpu is allowed"
            )));
        }
        // allow primary dpu to be used when using one config with no device_locators
        match mh_snapshot
            .host_snapshot
            .interfaces
            .iter()
            .find(|iface| iface.primary_interface)
            .and_then(|iface| iface.attached_dpu_machine_id)
        {
            Some(primary_dpu_id) => vec![primary_dpu_id],
            None => {
                return Err(StateHandlerError::GenericError(eyre!(
                    "Could not find primary dpu id"
                )));
            }
        }
    } else {
        if maps.0.is_empty() || maps.1.is_empty() {
            return Err(StateHandlerError::GenericError(eyre!(
                "No interface device locators for when using multiple interfaces"
            )));
        }

        let id_to_device_map = maps.0;
        let device_to_id_map = maps.1;
        // filter out dpus that do not have interfaces configured
        mh_snapshot
            .host_snapshot
            .associated_dpu_machine_ids()
            .iter()
            .filter(|dpu_machine_id| {
                if let Some(device) = id_to_device_map.get(dpu_machine_id) {
                    tracing::info!("Found device {} for dpu {}", device, dpu_machine_id);
                    if let Some(id_vec) = device_to_id_map.get(device)
                        && let Some(device_instance) =
                            id_vec.iter().position(|id| id == *dpu_machine_id)
                    {
                        tracing::info!(
                            "Found device_instance {} for dpu {}",
                            device_instance,
                            dpu_machine_id
                        );
                        let device_locator = DeviceLocator {
                            device: device.clone(),
                            device_instance,
                        };
                        return instance.config.network.interfaces.iter().any(|i| {
                            i.device_locator
                                .as_ref()
                                .is_some_and(|dl| dl == &device_locator)
                        });
                    }
                }
                false
            })
            .copied()
            .collect()
    };

    if instance.observations.network.len() != dpu_machine_ids.len() {
        tracing::info!(
            "obs: {} dpus: {}",
            instance.observations.network.len(),
            dpu_machine_ids.len()
        );

        let mut missing_dpus = Vec::default();
        for dpu_id in dpu_machine_ids {
            tracing::info!("checking dpu: {}", dpu_id);
            if !instance.observations.network.contains_key(&dpu_id) {
                tracing::info!("missing");
                missing_dpus.push(dpu_id);
            }
        }
        return Ok(InstanceNetworkSyncStatus::InstanceNetworkObservationNotAvailable(missing_dpus));
    }
    // Check instance network config has been applied
    let expected = &instance.network_config_version;

    let mut outdated_dpus = Vec::default();
    for (dpu_machine_id, network_obs) in &instance.observations.network {
        if &network_obs.config_version != expected {
            outdated_dpus.push(*dpu_machine_id);
        }
    }

    if !outdated_dpus.is_empty() {
        return Ok(InstanceNetworkSyncStatus::InstanceNetworkNotSynced(
            outdated_dpus,
        ));
    }

    check_host_health_for_alerts(mh_snapshot)?;
    Ok(InstanceNetworkSyncStatus::InstanceNetworkSynced)
}

pub async fn release_vpc_dpu_loopback(
    mh_snapshot: &ManagedHostStateSnapshot,
    common_pools: &Option<Arc<CommonPools>>,
    txn: &mut PgConnection,
) -> Result<(), StateHandlerError> {
    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
        if let Some(common_pools) = common_pools {
            db::vpc_dpu_loopback::delete_and_deallocate(common_pools, &dpu_snapshot.id, txn, false)
                .await
                .map_err(|e| StateHandlerError::ResourceCleanupError {
                    resource: "VpcLoopbackIp",
                    error: e.to_string(),
                })?;
        }
    }

    Ok(())
}

async fn release_network_segments_with_vpc_prefix(
    interfaces: &[InstanceInterfaceConfig],
    txn: &mut PgConnection,
) -> Result<(), StateHandlerError> {
    let network_segment_ids_with_vpc = interfaces
        .iter()
        .filter_map(|x| match x.network_details {
            Some(NetworkDetails::VpcPrefixId(_)) => x.network_segment_id,
            _ => None,
        })
        .collect_vec();

    // Mark all network ready for delete which were created for vpc_prefixes.
    if !network_segment_ids_with_vpc.is_empty() {
        db::network_segment::mark_as_deleted_no_validation(txn, &network_segment_ids_with_vpc)
            .await
            .map_err(|err| StateHandlerError::ResourceCleanupError {
                resource: "network_segment",
                error: err.to_string(),
            })?;
    }

    Ok(())
}

#[derive(Debug)]
enum HostFirmwareScenario {
    Ready,
    Instance,
}

impl HostFirmwareScenario {
    fn actual_new_state(
        &self,
        reprovision_state: HostReprovisionState,
        host_retry_count: u32,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        match self {
            HostFirmwareScenario::Ready => Ok(Some(ManagedHostState::HostReprovision {
                reprovision_state,
                retry_count: host_retry_count,
            })),
            HostFirmwareScenario::Instance => Ok(Some(ManagedHostState::Assigned {
                instance_state: InstanceState::HostReprovision { reprovision_state },
            })),
        }
    }

    fn complete_state(&self) -> Result<Option<ManagedHostState>, StateHandlerError> {
        match self {
            HostFirmwareScenario::Ready => Ok(Some(ManagedHostState::Ready)),
            HostFirmwareScenario::Instance => Ok(Some(ManagedHostState::Assigned {
                instance_state: InstanceState::Ready,
            })),
        }
    }
}

#[derive(Debug, Clone)]
enum UploadResult {
    Success { task_id: String },
    Failure,
}

struct HostUpgradeState {
    parsed_hosts: Arc<FirmwareConfig>,
    downloader: FirmwareDownloader,
    upload_limiter: Arc<Semaphore>,
    no_firmware_update_reset_retries: bool,
    instance_autoreboot_period: Option<TimePeriod>,
    upgrade_script_state: Arc<UpdateScriptManager>,
    credential_provider: Option<Arc<dyn CredentialProvider>>,
    async_firmware_uploader: Arc<AsyncFirmwareUploader>,
    hgx_bmc_gpu_reboot_delay: tokio::time::Duration,
}

impl std::fmt::Debug for HostUpgradeState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "HostUpgradeState: parsed_hosts: {:?} downloader: {:?} upload_limiter: {:?} no_firmware_update_reset_retries: {:?} instance_autoreboot_period: {:?}, upgrade_script_state: {:?}",
            self.parsed_hosts,
            self.downloader,
            self.upload_limiter,
            self.no_firmware_update_reset_retries,
            self.instance_autoreboot_period,
            self.upgrade_script_state
        )
    }
}

impl HostUpgradeState {
    // Handles when in HostReprovisioning or when entering it
    async fn handle_host_reprovision(
        &self,
        state: &mut ManagedHostStateSnapshot,
        services: &CommonStateHandlerServices,
        machine_id: &MachineId,
        scenario: HostFirmwareScenario,
        txn: &mut PgConnection,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        // Treat Ready (but flagged to do updates) the same as HostReprovisionState/CheckingFirmware
        let original_state = &state.managed_state.clone();
        let (mut host_reprovision_state, retry_count) = match &state.managed_state {
            ManagedHostState::HostReprovision {
                reprovision_state,
                retry_count,
            } => (reprovision_state, *retry_count),
            ManagedHostState::Ready => (
                &HostReprovisionState::CheckingFirmwareV2 {
                    firmware_type: None,
                    firmware_number: None,
                },
                0,
            ),
            ManagedHostState::Assigned { instance_state } => match &instance_state {
                InstanceState::HostReprovision { reprovision_state } => (reprovision_state, 0),
                InstanceState::Ready => (
                    &HostReprovisionState::CheckingFirmwareV2 {
                        firmware_type: None,
                        firmware_number: None,
                    },
                    0,
                ),
                _ => {
                    return Err(StateHandlerError::InvalidState(format!(
                        "Invalid state for calling handle_host_reprovision {:?}",
                        state.managed_state
                    )));
                }
            },
            _ => {
                return Err(StateHandlerError::InvalidState(format!(
                    "Invalid state for calling handle_host_reprovision {:?}",
                    state.managed_state
                )));
            }
        };

        if state
            .host_snapshot
            .host_reprovision_requested
            .as_ref()
            .is_some_and(|host_reprovision_requested| {
                host_reprovision_requested.request_reset.unwrap_or(false)
            })
        {
            tracing::info!(%machine_id, "Host firmware upgrade reset requested, returning to CheckingFirmwareRepeat");
            host_reprovision_state = &HostReprovisionState::CheckingFirmwareRepeatV2 {
                firmware_type: None,
                firmware_number: None,
            };
            state.managed_state = ManagedHostState::HostReprovision {
                reprovision_state: HostReprovisionState::CheckingFirmwareRepeatV2 {
                    firmware_type: None,
                    firmware_number: None,
                },
                retry_count: 0,
            };
            db::host_machine_update::reset_host_reprovisioning_request(txn, machine_id, true)
                .await?;
        }

        match host_reprovision_state {
            HostReprovisionState::CheckingFirmware => {
                self.host_checking_fw(
                    &HostReprovisionState::CheckingFirmwareV2 {
                        firmware_type: None,
                        firmware_number: None,
                    },
                    state,
                    services,
                    original_state,
                    scenario,
                    false,
                    txn,
                )
                .await
            }
            HostReprovisionState::CheckingFirmwareRepeat => {
                self.host_checking_fw(
                    &HostReprovisionState::CheckingFirmwareRepeatV2 {
                        firmware_type: None,
                        firmware_number: None,
                    },
                    state,
                    services,
                    original_state,
                    scenario,
                    false,
                    txn,
                )
                .await
            }
            details @ HostReprovisionState::CheckingFirmwareV2 { .. } => {
                self.host_checking_fw(
                    details,
                    state,
                    services,
                    original_state,
                    scenario,
                    false,
                    txn,
                )
                .await
            }
            details @ HostReprovisionState::CheckingFirmwareRepeatV2 { .. } => {
                self.host_checking_fw(
                    details,
                    state,
                    services,
                    original_state,
                    scenario,
                    true,
                    txn,
                )
                .await
            }
            HostReprovisionState::WaitingForManualUpgrade { .. } => {
                self.waiting_for_manual_upgrade(state, scenario)
            }
            HostReprovisionState::WaitingForScript { .. } => {
                self.waiting_for_script(state, services, scenario)
            }
            HostReprovisionState::InitialReset { phase, last_time } => {
                self.pre_update_resets(
                    state,
                    services,
                    scenario,
                    Some(phase.clone()),
                    &Some(*last_time),
                    txn,
                )
                .await
            }
            details @ HostReprovisionState::WaitingForUpload { .. } => {
                self.waiting_for_upload(details, state, scenario, txn).await
            }
            details @ HostReprovisionState::WaitingForFirmwareUpgrade { .. } => {
                self.host_waiting_fw(details, state, services, machine_id, scenario, txn)
                    .await
            }
            details @ HostReprovisionState::ResetForNewFirmware { .. } => {
                self.host_reset_for_new_firmware(
                    state, services, machine_id, details, scenario, txn,
                )
                .await
            }
            details @ HostReprovisionState::NewFirmwareReportedWait { .. } => {
                self.host_new_firmware_reported_wait(
                    state, services, details, machine_id, scenario, txn,
                )
                .await
            }
            HostReprovisionState::FailedFirmwareUpgrade { report_time, .. } => {
                let can_retry = retry_count < MAX_FIRMWARE_UPGRADE_RETRIES;
                let waited_enough = Utc::now()
                    .signed_duration_since(report_time.unwrap_or(Utc::now()))
                    >= services
                        .site_config
                        .firmware_global
                        .host_firmware_upgrade_retry_interval;
                let should_retry = can_retry && waited_enough;

                if should_retry {
                    tracing::info!("Retrying firmware upgrade on {}", state.host_snapshot.id);

                    let reprovision_state = HostReprovisionState::CheckingFirmwareV2 {
                        firmware_type: None,
                        firmware_number: None,
                    };
                    scenario.actual_new_state(reprovision_state, retry_count + 1)
                } else {
                    // doesn't make sense to retry anymore, remain in this failure state
                    Ok(None)
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn host_checking_fw(
        &self,
        details: &HostReprovisionState,
        state: &ManagedHostStateSnapshot,
        services: &CommonStateHandlerServices,
        original_state: &ManagedHostState,
        scenario: HostFirmwareScenario,
        repeat: bool,
        txn: &mut PgConnection,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let machine_id = &state.host_snapshot.id;
        let mut ret = self
            .host_checking_fw_noclear(details, state, services, machine_id, scenario, repeat, txn)
            .await?;

        // Check if we are returning to the ready state, and clear the host reprovisioning request if so.
        if let Some(ret) = &ret {
            match ret {
                ManagedHostState::HostReprovision { .. } => {}
                ManagedHostState::Assigned {
                    instance_state: InstanceState::HostReprovision { .. },
                } => {}
                _ => {
                    db::host_machine_update::clear_host_reprovisioning_request(txn, machine_id)
                        .await?;

                    // TODO: Remove when manual upgrade feature is removed
                    db::host_machine_update::clear_manual_firmware_upgrade_completed(
                        txn, machine_id,
                    )
                    .await?;
                }
            };
        }

        if ret == Some(original_state.clone()) {
            // host_checking_fw_noclear can return Ready to indicate that we're moving out of CheckingFirmware,
            // but we also take this path when we're actually in Ready - for that case, return Ok(None) so that
            // we don't keep retransitioning to the same state.
            ret = None;
        }

        Ok(ret)
    }

    #[allow(txn_held_across_await)]
    #[allow(clippy::too_many_arguments)]
    async fn host_checking_fw_noclear(
        &self,
        details: &HostReprovisionState,
        state: &ManagedHostStateSnapshot,
        services: &CommonStateHandlerServices,
        machine_id: &MachineId,
        scenario: HostFirmwareScenario,
        repeat: bool,
        txn: &mut PgConnection,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        // temporary check if manual upgrade is required before proceeding with automatic ones,
        // should be removed once we complete upgrades through the scout.
        // For now, only gb200s need manual upgrades.
        if requires_manual_firmware_upgrade(state, &services.site_config) {
            tracing::info!(
                "Machine {} (GB200) requires manual firmware upgrade, transitioning to WaitingForManualUpgrade",
                machine_id
            );
            return scenario.actual_new_state(
                HostReprovisionState::WaitingForManualUpgrade {
                    manual_upgrade_started: Utc::now(),
                },
                state.managed_state.get_host_repro_retry_count(),
            );
        }

        let (current_firmware_type, current_firmware_number): (Option<FirmwareComponentType>, u32) =
            match details {
                HostReprovisionState::CheckingFirmwareV2 {
                    firmware_number,
                    firmware_type,
                }
                | HostReprovisionState::CheckingFirmwareRepeatV2 {
                    firmware_number,
                    firmware_type,
                } => (*firmware_type, firmware_number.unwrap_or(0)),
                _ => {
                    return Err(StateHandlerError::GenericError(eyre!(
                        "Wrong enum in host_checking_fw_noclear"
                    )));
                }
            };

        let Some(explored_endpoint) =
            find_explored_refreshed_endpoint(state, machine_id, txn).await?
        else {
            // find_explored_refreshed_endpoint's behavior is to return None to indicate we're waiting for an update, not to indicate there isn't anything.

            tracing::debug!("Managed host {machine_id} waiting for site explorer to revisit");
            return scenario.actual_new_state(
                HostReprovisionState::CheckingFirmwareRepeatV2 {
                    firmware_type: current_firmware_type,
                    firmware_number: Some(current_firmware_number),
                },
                state.managed_state.get_host_repro_retry_count(),
            );
        };

        let Some(fw_info) = self.parsed_hosts.find_fw_info_for_host(&explored_endpoint) else {
            return scenario.complete_state();
        };

        for firmware_type in fw_info.ordering() {
            // ordering() will give a list of firmware types in the order they should be installed.
            // So, `firmware_type` may not be equal to `current_firmware_type` inside this loop.
            // We need to set `firmware_number` to 0 in case they are not equal because `firmware_number` coming
            // from outside this loop belongs only to the `current_firmware_type`
            let firmware_number = if let Some(ft) = current_firmware_type
                && ft == firmware_type
            {
                current_firmware_number
            } else {
                0
            };

            if let Some(to_install) =
                need_host_fw_upgrade(&explored_endpoint, &fw_info, firmware_type)
            {
                if to_install.script.is_some() {
                    return self
                        .by_script(to_install, state, explored_endpoint, scenario, txn)
                        .await;
                }
                tracing::info!(%machine_id,
                    "Installing {:?} (number #{}) on {}",
                    to_install,
                    firmware_number,
                    explored_endpoint.address
                );

                if !repeat && to_install.pre_update_resets {
                    return self
                        .pre_update_resets(state, services, scenario, None, &None, txn)
                        .await;
                }

                return self
                    .initiate_host_fw_update(
                        explored_endpoint.address,
                        state,
                        services,
                        FullFirmwareInfo {
                            model: fw_info.model.as_str(),
                            to_install: &to_install,
                            component_type: &firmware_type,
                            firmware_number: &firmware_number,
                        },
                        scenario,
                        txn,
                    )
                    .await;
            }
        }

        // Nothing needs updates, return to ready.  But first, we may need to reenable lockdown.

        let redfish_client = services
            .redfish_client_pool
            .create_client_from_machine(&state.host_snapshot, txn)
            .await?;

        let lockdown_disabled = match redfish_client.lockdown_status().await {
            Ok(status) => !status.is_fully_enabled(), // If it was partial, treat as disabled so we will fully enable it
            Err(e) => {
                if let libredfish::RedfishError::NotSupported(_) = e {
                    // Returned when the platform doesn't support lockdown, so here we say it's not disabled
                    // Note that this is different from the place where we do something similar
                    false
                } else {
                    tracing::warn!("Could not get lockdown status for {machine_id}: {e}",);
                    return Ok(None);
                }
            }
        };
        if lockdown_disabled {
            tracing::debug!("host firmware update: Reenabling lockdown");
            // Already disabled, we need to reenable.
            if let Err(e) = redfish_client
                .lockdown(libredfish::EnabledDisabled::Enabled)
                .await
            {
                tracing::error!("Could not set lockdown for {machine_id}: {e}");
                return Ok(None);
            }
            // Reenabling lockdown will poll lockdown status to verify settings are applied.
            match scenario {
                HostFirmwareScenario::Ready => Ok(Some(ManagedHostState::HostInit {
                    machine_state: MachineState::WaitingForLockdown {
                        lockdown_info: LockdownInfo {
                            state: LockdownState::PollingLockdownStatus,
                            mode: Enable,
                        },
                    },
                })),
                HostFirmwareScenario::Instance => {
                    handler_host_power_control(
                        state,
                        services,
                        SystemPowerControl::ForceRestart,
                        txn,
                    )
                    .await?;
                    scenario.complete_state()
                }
            }
        } else {
            tracing::debug!("host firmware update: Don't need to reenable lockdown");
            if let HostFirmwareScenario::Instance = scenario {
                handler_host_power_control(state, services, SystemPowerControl::ForceRestart, txn)
                    .await?;
            }
            scenario.complete_state()
        }
    }

    #[allow(txn_held_across_await)]
    async fn by_script(
        &self,
        to_install: FirmwareEntry,
        state: &ManagedHostStateSnapshot,
        explored_endpoint: ExploredEndpoint,
        scenario: HostFirmwareScenario,
        _txn: &mut PgConnection,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let machine_id = state.host_snapshot.id;

        self.upgrade_script_state.started(machine_id.to_string());

        let address = explored_endpoint.address.to_string().clone();
        let script = to_install.script.unwrap_or("/bin/false".into()); // Should always be Some at this point
        let upgrade_script_state = self.upgrade_script_state.clone();
        let (username, password) = if let Some(credential_provider) = &self.credential_provider {
            let bmc_mac_address =
                state
                    .host_snapshot
                    .bmc_info
                    .mac
                    .ok_or_else(|| StateHandlerError::MissingData {
                        object_id: state.host_snapshot.id.to_string(),
                        missing: "bmc_mac",
                    })?;
            let key = CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
            };
            match credential_provider.get_credentials(&key).await {
                Ok(Some(credentials)) => match credentials {
                    Credentials::UsernamePassword { username, password } => (username, password),
                },
                Ok(None) => {
                    return Err(StateHandlerError::GenericError(eyre!(
                        "No BMC credentials exists"
                    )));
                }
                Err(e) => {
                    return Err(StateHandlerError::GenericError(eyre!(
                        "Unable to get BMC credentials: {e}"
                    )));
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
                    tracing::error!(
                        "Upgrade script {machine_id} {address} command creation failed: {e}"
                    );
                    upgrade_script_state.completed(machine_id.to_string(), false);
                    return;
                }
            };

            let Some(stdout) = cmd.stdout.take() else {
                tracing::error!("Upgrade script {machine_id} {address} STDOUT creation failed");
                let _ = cmd.kill().await;
                let _ = cmd.wait().await;
                upgrade_script_state.completed(machine_id.to_string(), false);
                return;
            };
            let stdout = tokio::io::BufReader::new(stdout);

            let Some(stderr) = cmd.stderr.take() else {
                tracing::error!("Upgrade script {machine_id} {address} STDERR creation failed");
                let _ = cmd.kill().await;
                let _ = cmd.wait().await;
                upgrade_script_state.completed(machine_id.to_string(), false);
                return;
            };
            let stderr = tokio::io::BufReader::new(stderr);

            // Take the stdout and stderr from the script and write them to a log with a searchable prefix
            let machine_id2 = address.clone();
            let address2 = address.clone();
            let thread = tokio::spawn(async move {
                let mut lines = stderr.lines();
                while let Some(line) = lines.next_line().await.unwrap_or(None) {
                    tracing::info!("Upgrade script {machine_id2} {address2} STDERR {line}");
                }
            });
            let mut lines = stdout.lines();
            while let Some(line) = lines.next_line().await.unwrap_or(None) {
                tracing::info!("Upgrade script {machine_id} {address} {line}");
            }
            let _ = tokio::join!(thread);

            match cmd.wait().await {
                Err(e) => {
                    tracing::info!(
                        "Upgrade script {machine_id} {address} FAILED: Wait failure {e}"
                    );
                    upgrade_script_state.completed(machine_id.to_string(), false);
                }
                Ok(errorcode) => {
                    if errorcode.success() {
                        tracing::info!(
                            "Upgrade script {machine_id} {address} completed successfully"
                        );
                        upgrade_script_state.completed(machine_id.to_string(), true);
                    } else {
                        tracing::warn!(
                            "Upgrade script {machine_id} {address} FAILED: Exited with {errorcode}"
                        );
                        upgrade_script_state.completed(machine_id.to_string(), false);
                    }
                }
            }
        });

        scenario.actual_new_state(
            HostReprovisionState::WaitingForScript {},
            state.managed_state.get_host_repro_retry_count(),
        )
    }

    fn waiting_for_manual_upgrade(
        &self,
        state: &ManagedHostStateSnapshot,
        scenario: HostFirmwareScenario,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let machine_id = &state.host_snapshot.id;

        if let Some(completed_at) = state.host_snapshot.manual_firmware_upgrade_completed {
            tracing::info!(
                "Manual firmware upgrade completed for {} at {}, proceeding to automatic upgrades",
                machine_id,
                completed_at
            );

            return scenario.actual_new_state(
                HostReprovisionState::CheckingFirmwareRepeatV2 {
                    firmware_type: None,
                    firmware_number: None,
                },
                state.managed_state.get_host_repro_retry_count(),
            );
        }

        tracing::debug!(
            "Machine {} still waiting for manual firmware upgrade to be marked complete",
            machine_id
        );
        Ok(None)
    }

    fn waiting_for_script(
        &self,
        state: &ManagedHostStateSnapshot,
        _services: &CommonStateHandlerServices,
        scenario: HostFirmwareScenario,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let machine_id = state.host_snapshot.id.to_string();
        let Some(success) = self.upgrade_script_state.state(&machine_id) else {
            // Not yet completed, or we restarted (which specifically needs a manual restart of interrupted scripts)
            return Ok(None);
        };

        self.upgrade_script_state.clear(&machine_id);

        if success {
            scenario.actual_new_state(
                HostReprovisionState::CheckingFirmwareRepeatV2 {
                    firmware_type: None,
                    firmware_number: None,
                },
                state.managed_state.get_host_repro_retry_count(),
            )
        } else {
            let reprovision_state = HostReprovisionState::FailedFirmwareUpgrade {
                firmware_type: FirmwareComponentType::Unknown,
                report_time: Some(Utc::now()),
                reason: Some(format!(
                    "The upgrade script failed.  Search the log for \"Upgrade script {}\" for script output.  Use \"forge-admin-cli mh reset-host-reprovisioning --machine {}\" to retry.",
                    state.host_snapshot.id, state.host_snapshot.id
                )),
            };
            scenario.actual_new_state(
                reprovision_state,
                state.managed_state.get_host_repro_retry_count(),
            )
        }
    }

    #[allow(txn_held_across_await)]
    async fn pre_update_resets(
        &self,
        state: &ManagedHostStateSnapshot,
        services: &CommonStateHandlerServices,
        scenario: HostFirmwareScenario,
        phase: Option<InitialResetPhase>,
        last_time: &Option<DateTime<Utc>>,
        txn: &mut PgConnection,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let redfish_client = services
            .redfish_client_pool
            .create_client_from_machine(&state.host_snapshot, txn)
            .await?;

        match phase.unwrap_or(InitialResetPhase::Start) {
            InitialResetPhase::Start => {
                redfish_client
                    .power(SystemPowerControl::ForceOff)
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "power off",
                        error: e,
                    })?;
                let status = redfish_client.get_power_state().await.map_err(|e| {
                    StateHandlerError::RedfishError {
                        operation: "get power state",
                        error: e,
                    }
                })?;
                if status != PowerState::Off {
                    return Err(StateHandlerError::GenericError(eyre!(
                        "Host {} did not turn off when requested",
                        state.host_snapshot.id
                    )));
                }
                redfish_client
                    .bmc_reset()
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "BMC reset",
                        error: e,
                    })?;

                scenario.actual_new_state(
                    HostReprovisionState::InitialReset {
                        phase: InitialResetPhase::BMCWasReset,
                        last_time: Utc::now(),
                    },
                    state.managed_state.get_host_repro_retry_count(),
                )
            }
            InitialResetPhase::BMCWasReset => {
                if let Err(_e) = redfish_client.get_tasks().await {
                    // BMC not fully up yet
                    return Ok(None);
                }
                redfish_client
                    .power(SystemPowerControl::On)
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "power on",
                        error: e,
                    })?;
                let status = redfish_client.get_power_state().await.map_err(|e| {
                    StateHandlerError::RedfishError {
                        operation: "get power state",
                        error: e,
                    }
                })?;
                if status != PowerState::On {
                    return Err(StateHandlerError::GenericError(eyre!(
                        "Host {} did not turn on when requested",
                        state.host_snapshot.id
                    )));
                }
                scenario.actual_new_state(
                    HostReprovisionState::InitialReset {
                        phase: InitialResetPhase::WaitHostBoot,
                        last_time: Utc::now(),
                    },
                    state.managed_state.get_host_repro_retry_count(),
                )
            }
            InitialResetPhase::WaitHostBoot => {
                if Utc::now().signed_duration_since(last_time.unwrap_or(Utc::now()))
                    < chrono::TimeDelta::minutes(20)
                {
                    // Wait longer
                    return Ok(None);
                }
                // Now we can actually proceed with the upgrade.  Go back to checking firmware so we don't have to store all of that info.
                scenario.actual_new_state(
                    HostReprovisionState::CheckingFirmwareRepeatV2 {
                        firmware_type: None,
                        firmware_number: None,
                    },
                    state.managed_state.get_host_repro_retry_count(),
                )
            }
        }
    }
    /// Uploads a firmware update via multipart, returning the task ID, or None if upload was deferred
    #[allow(txn_held_across_await)]
    async fn initiate_host_fw_update(
        &self,
        address: IpAddr,
        state: &ManagedHostStateSnapshot,
        services: &CommonStateHandlerServices,
        fw_info: FullFirmwareInfo<'_>,
        scenario: HostFirmwareScenario,
        txn: &mut PgConnection,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let snapshot = &state.host_snapshot;
        let to_install = fw_info.to_install;
        let component_type = fw_info.component_type;

        if !self.downloader.available(
            &to_install.get_filename(*fw_info.firmware_number),
            &to_install.get_url(),
            &to_install.get_checksum(),
        ) {
            tracing::debug!(
                "{} is being downloaded from {}, update deferred",
                to_install.get_filename(*fw_info.firmware_number).display(),
                to_install.get_url()
            );

            return Ok(None);
        }

        let Ok(_active) = self.upload_limiter.try_acquire() else {
            tracing::debug!(
                "Deferring installation of {:?} on {}, too many uploads already active",
                to_install,
                snapshot.id,
            );
            return Ok(None);
        };

        // Setup the Redfish connection
        let redfish_client = services
            .redfish_client_pool
            .create_client_from_machine(snapshot, txn)
            .await?;

        let lockdown_disabled = match redfish_client.lockdown_status().await {
            Ok(status) => status.is_fully_disabled(), // If we're partial, we want to act like it was enabled so we disable it
            Err(e) => {
                if let libredfish::RedfishError::NotSupported(_) = e {
                    // Returned when the platform doesn't support lockdown, so here we say it's already disabled
                    // Note that this is different from the place where we do something similar
                    true
                } else {
                    tracing::warn!(
                        "Could not get lockdown status for {}: {e}",
                        state.host_snapshot.id
                    );
                    return Ok(None);
                }
            }
        };
        if lockdown_disabled {
            // Already disabled, we can go ahead
            tracing::debug!("Host fw update: No need for disabling lockdown");
        } else {
            tracing::info!(%address, "Host fw update: Disabling lockdown");
            if let Err(e) = redfish_client
                .lockdown(libredfish::EnabledDisabled::Disabled)
                .await
            {
                tracing::warn!("Could not set lockdown for {}: {e}", address.to_string());
                return Ok(None);
            }
            if fw_info.model == "Dell" {
                tracing::info!(%address, "Host fw update: Rebooting after disabling lockdown because Dell");
                handler_host_power_control(state, services, SystemPowerControl::ForceRestart, txn)
                    .await?;
                // Wait until the next state machine iteration to let it restart
                return Ok(None);
            }
        }

        let machine_id = state.host_snapshot.id.to_string();
        let filename = to_install.get_filename(*fw_info.firmware_number);
        let redfish_component_type: libredfish::model::update_service::ComponentType =
            match to_install.install_only_specified {
                false => libredfish::model::update_service::ComponentType::Unknown,
                true => (*component_type).into(),
            };
        let address = address.to_string();

        self.async_firmware_uploader.start_upload(
            machine_id,
            redfish_client,
            filename,
            redfish_component_type,
            address,
        );

        // Upload complete and updated started, will monitor task in future iterations
        let reprovision_state = HostReprovisionState::WaitingForUpload {
            firmware_type: *fw_info.component_type,
            final_version: fw_info.to_install.version.clone(),
            power_drains_needed: fw_info.to_install.power_drains_needed,
            firmware_number: Some(*fw_info.firmware_number),
        };

        scenario.actual_new_state(
            reprovision_state,
            state.managed_state.get_host_repro_retry_count(),
        )
    }

    #[allow(txn_held_across_await)]
    async fn waiting_for_upload(
        &self,
        details: &HostReprovisionState,
        state: &ManagedHostStateSnapshot,
        scenario: HostFirmwareScenario,
        txn: &mut PgConnection,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let (final_version, firmware_type, power_drains_needed, firmware_number) = match details {
            HostReprovisionState::WaitingForUpload {
                final_version,
                firmware_type,
                power_drains_needed,
                firmware_number,
            } => (
                final_version,
                firmware_type,
                power_drains_needed,
                firmware_number,
            ),
            _ => {
                return Err(StateHandlerError::GenericError(eyre!(
                    "Wrong enum in waiting_for_upload"
                )));
            }
        };

        let machine_id = state.host_snapshot.id;
        let address = match find_explored_refreshed_endpoint(state, &machine_id, txn).await {
            Ok(explored_endpoint) => match explored_endpoint {
                Some(explored_endpoint) => explored_endpoint.address.to_string(),
                None => "unknown".to_string(),
            },
            Err(_) => "unknown".to_string(),
        };
        let machine_id = machine_id.to_string();
        match self.async_firmware_uploader.upload_status(&machine_id) {
            None => {
                tracing::info!(
                    "Apparent restart before upload to {machine_id} {address} completion, returning to CheckingFirmware"
                );
                scenario.actual_new_state(
                    HostReprovisionState::CheckingFirmwareRepeatV2 {
                        firmware_type: Some(*firmware_type),
                        firmware_number: *firmware_number,
                    },
                    state.managed_state.get_host_repro_retry_count(),
                )
            }
            Some(upload_status) => {
                match upload_status {
                    None => {
                        tracing::debug!("Upload to {machine_id} {address} not yet complete");
                        Ok(None)
                    }
                    Some(result) => {
                        match result {
                            UploadResult::Success { task_id } => {
                                // We want to remove the machine ID from the hashmap, but do not do it here, because we may fail the commit.  Run it in the next state handling.  Failure case doesn't matter, it would have identical behavior.
                                tracing::info!(
                                    "Upload to {machine_id} {address} completed with task ID {task_id}"
                                );
                                // Upload complete and updated started, will monitor task in future iterations
                                let reprovision_state =
                                    HostReprovisionState::WaitingForFirmwareUpgrade {
                                        task_id,
                                        firmware_type: *firmware_type,
                                        final_version: final_version.clone(),
                                        power_drains_needed: *power_drains_needed,
                                        firmware_number: *firmware_number,
                                        started_waiting: Some(Utc::now()),
                                    };
                                scenario.actual_new_state(
                                    reprovision_state,
                                    state.managed_state.get_host_repro_retry_count(),
                                )
                            }
                            UploadResult::Failure => {
                                self.async_firmware_uploader.finish_upload(&machine_id);
                                // The upload thread already logged this
                                scenario.actual_new_state(
                                    HostReprovisionState::CheckingFirmwareRepeatV2 {
                                        firmware_type: Some(*firmware_type),
                                        firmware_number: *firmware_number,
                                    },
                                    state.managed_state.get_host_repro_retry_count(),
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    #[allow(txn_held_across_await)]
    async fn host_waiting_fw(
        &self,
        details: &HostReprovisionState,
        state: &ManagedHostStateSnapshot,
        services: &CommonStateHandlerServices,
        machine_id: &MachineId,
        scenario: HostFirmwareScenario,
        txn: &mut PgConnection,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let (
            task_id,
            final_version,
            firmware_type,
            power_drains_needed,
            firmware_number,
            started_waiting,
        ) = match details {
            HostReprovisionState::WaitingForFirmwareUpgrade {
                task_id,
                final_version,
                firmware_type,
                power_drains_needed,
                firmware_number,
                started_waiting,
            } => (
                task_id,
                final_version,
                firmware_type,
                power_drains_needed,
                firmware_number,
                started_waiting,
            ),
            _ => {
                return Err(StateHandlerError::GenericError(eyre!(
                    "Wrong enum in host_waiting_fw"
                )));
            }
        };

        // Now it's safe to clear the hashmap for the upload status
        self.async_firmware_uploader
            .finish_upload(&state.host_snapshot.id.to_string());

        let address = state
            .host_snapshot
            .bmc_info
            .ip_addr()
            .map_err(StateHandlerError::GenericError)?;
        // Setup the Redfish connection
        let redfish_client = services
            .redfish_client_pool
            .create_client_from_machine(&state.host_snapshot, txn)
            .await?;

        match redfish_client.get_task(task_id.as_str()).await {
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

                        // If we have multiple firmware files to be uploaded, do the next one.
                        if let Some(endpoint) =
                            find_explored_refreshed_endpoint(state, machine_id, txn).await?
                            && let Some(fw_info) =
                                self.parsed_hosts.find_fw_info_for_host(&endpoint)
                            && let Some(component_info) = fw_info.components.get(firmware_type)
                            && let Some(selected_firmware) =
                                component_info.known_firmware.iter().find(|&x| x.default)
                        {
                            let firmware_number = firmware_number.unwrap_or(0) + 1;
                            if firmware_number
                                < selected_firmware.filenames.len().try_into().unwrap_or(0)
                            {
                                tracing::debug!(
                                    "Moving {:?} chain step {} on {} to CheckingFirmware",
                                    selected_firmware,
                                    firmware_number,
                                    endpoint.address
                                );

                                // There are more files to install.
                                // Move to CheckingFirmware and start installing
                                let reprovision_state = HostReprovisionState::CheckingFirmwareV2 {
                                    firmware_type: Some(*firmware_type),
                                    firmware_number: Some(firmware_number),
                                };

                                return scenario.actual_new_state(
                                    reprovision_state,
                                    state.managed_state.get_host_repro_retry_count(),
                                );
                            }
                        }

                        tracing::debug!(
                            "Saw completion of host firmware upgrade task for {}",
                            machine_id
                        );

                        let reprovision_state = HostReprovisionState::ResetForNewFirmware {
                            final_version: final_version.to_string(),
                            firmware_type: *firmware_type,
                            firmware_number: *firmware_number,
                            power_drains_needed: *power_drains_needed,
                            delay_until: None,
                            last_power_drain_operation: None,
                        };
                        scenario.actual_new_state(
                            reprovision_state,
                            state.managed_state.get_host_repro_retry_count(),
                        )
                    }
                    Some(TaskState::Exception)
                    | Some(TaskState::Interrupted)
                    | Some(TaskState::Killed)
                    | Some(TaskState::Cancelled) => {
                        let msg = format!(
                            "Failure in firmware upgrade for {}: {} {:?}",
                            machine_id,
                            task_info.task_state.unwrap(),
                            task_info
                                .messages
                                .last()
                                .map_or("".to_string(), |m| m.message.clone())
                        );
                        tracing::warn!(msg);

                        // We need site explorer to requery the version, just in case it actually did get done
                        db::explored_endpoints::set_waiting_for_explorer_refresh(address, txn)
                            .await?;
                        scenario.actual_new_state(
                            HostReprovisionState::FailedFirmwareUpgrade {
                                firmware_type: *firmware_type,
                                report_time: Some(Utc::now()),
                                reason: Some(msg),
                            },
                            state.managed_state.get_host_repro_retry_count(),
                        )
                    }
                    _ => {
                        // Unexpected state
                        let msg = format!(
                            "Unrecognized task state for {}: {:?}",
                            machine_id, task_info.task_state
                        );
                        tracing::warn!(msg);

                        let reprovision_state = HostReprovisionState::FailedFirmwareUpgrade {
                            firmware_type: *firmware_type,
                            report_time: Some(Utc::now()),
                            reason: Some(msg),
                        };
                        scenario.actual_new_state(
                            reprovision_state,
                            state.managed_state.get_host_repro_retry_count(),
                        )
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

                        if let Some(fw_info) = self.parsed_hosts.find_fw_info_for_host(&endpoint)
                            && let Some(current_version) =
                                endpoint.find_version(&fw_info, *firmware_type)
                            && current_version == final_version
                        {
                            tracing::info!(
                                "Marking completion of Redfish task of firmware upgrade for {} with missing task",
                                &endpoint.address
                            );

                            return scenario.actual_new_state(
                                HostReprovisionState::CheckingFirmwareRepeatV2 {
                                    firmware_type: Some(*firmware_type),
                                    firmware_number: *firmware_number,
                                },
                                state.managed_state.get_host_repro_retry_count(),
                            );
                        }

                        // We have also observed (FORGE-6177) the upgrade somehow disappearing, but working when retried.  If a long time has passed, go back to checking to retry.
                        if let Some(started_waiting) = started_waiting
                            && Utc::now().signed_duration_since(started_waiting)
                                > chrono::TimeDelta::minutes(15)
                        {
                            tracing::info!(%machine_id,
                                "Timed out with missing Redfish task for firmware upgrade for {}, returning to CheckingFirmware",
                                &endpoint.address
                            );
                            return scenario.actual_new_state(
                                HostReprovisionState::CheckingFirmwareRepeatV2 {
                                    firmware_type: Some(*firmware_type),
                                    firmware_number: *firmware_number,
                                },
                                state.managed_state.get_host_repro_retry_count(),
                            );
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

    #[allow(txn_held_across_await)]
    async fn host_reset_for_new_firmware(
        &self,
        state: &ManagedHostStateSnapshot,
        services: &CommonStateHandlerServices,
        machine_id: &MachineId,
        details: &HostReprovisionState,
        scenario: HostFirmwareScenario,
        txn: &mut PgConnection,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let (
            final_version,
            firmware_type,
            firmware_number,
            power_drains_needed,
            delay_until,
            last_power_drain_operation,
        ) = match details {
            HostReprovisionState::ResetForNewFirmware {
                final_version,
                firmware_type,
                firmware_number,
                power_drains_needed,
                delay_until,
                last_power_drain_operation,
            } => (
                final_version,
                firmware_type,
                firmware_number,
                power_drains_needed,
                delay_until,
                last_power_drain_operation,
            ),
            _ => {
                return Err(StateHandlerError::GenericError(eyre!(
                    "Wrong enum in host_reset_for_new_firmware"
                )));
            }
        };

        let Some(endpoint) = find_explored_refreshed_endpoint(state, machine_id, txn).await? else {
            tracing::debug!("Waiting for site explorer to revisit {machine_id}");
            return Ok(None);
        };

        if let Some(power_drains_needed) = power_drains_needed {
            if let Some(delay_until) = delay_until
                && *delay_until > chrono::Utc::now().timestamp()
            {
                tracing::info!(
                    "Waiting after {last_power_drain_operation:?} of {}",
                    &endpoint.address
                );
                return Ok(None);
            }

            match last_power_drain_operation {
                None | Some(PowerDrainState::On) => {
                    // The 1000 is for unit tests; values above this will skip delays.
                    if *power_drains_needed == 0 || *power_drains_needed == 1000 {
                        tracing::info!("Power drains for {} done", &endpoint.address);
                        // This path, and only this path of the match, exits the match and lets us proceed.  All others should return after updating state.
                    } else {
                        tracing::info!(
                            "Upgrade task has completed for {} but needs {} power drain(s), initiating one",
                            &endpoint.address,
                            power_drains_needed
                        );
                        handler_host_power_control(
                            state,
                            services,
                            SystemPowerControl::ForceOff,
                            txn,
                        )
                        .await?;

                        // Wait 60 seconds after powering off to do AC powercycle
                        let delay = if *power_drains_needed < 1000 { 60 } else { 0 };
                        let reprovision_state = HostReprovisionState::ResetForNewFirmware {
                            final_version: final_version.clone(),
                            firmware_type: *firmware_type,
                            firmware_number: *firmware_number,
                            power_drains_needed: Some(*power_drains_needed),
                            delay_until: Some(chrono::Utc::now().timestamp() + delay),
                            last_power_drain_operation: Some(PowerDrainState::Off),
                        };
                        return scenario.actual_new_state(
                            reprovision_state,
                            state.managed_state.get_host_repro_retry_count(),
                        );
                    }
                }
                Some(PowerDrainState::Off) => {
                    tracing::info!("Doing powercycle now for {}", &endpoint.address);
                    handler_host_power_control(
                        state,
                        services,
                        SystemPowerControl::ACPowercycle,
                        txn,
                    )
                    .await?;

                    let delay = if *power_drains_needed < 1000 { 90 } else { 0 };
                    let reprovision_state = HostReprovisionState::ResetForNewFirmware {
                        final_version: final_version.clone(),
                        firmware_type: *firmware_type,
                        firmware_number: *firmware_number,
                        power_drains_needed: Some(*power_drains_needed),
                        delay_until: Some(chrono::Utc::now().timestamp() + delay),
                        last_power_drain_operation: Some(PowerDrainState::Powercycle),
                    };
                    return scenario.actual_new_state(
                        reprovision_state,
                        state.managed_state.get_host_repro_retry_count(),
                    );
                }
                Some(PowerDrainState::Powercycle) => {
                    tracing::info!("Turning back on {}", &endpoint.address);
                    handler_host_power_control(state, services, SystemPowerControl::On, txn)
                        .await?;

                    let delay = if *power_drains_needed < 1000 { 5 } else { 0 };
                    let reprovision_state = HostReprovisionState::ResetForNewFirmware {
                        final_version: final_version.clone(),
                        firmware_type: *firmware_type,
                        firmware_number: *firmware_number,
                        power_drains_needed: Some(power_drains_needed - 1),
                        delay_until: Some(chrono::Utc::now().timestamp() + delay),
                        last_power_drain_operation: Some(PowerDrainState::On),
                    };
                    return scenario.actual_new_state(
                        reprovision_state,
                        state.managed_state.get_host_repro_retry_count(),
                    );
                }
            };
        } else if firmware_type.is_uefi() {
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
            let redfish_client = services
                .redfish_client_pool
                .create_client_from_machine(&state.host_snapshot, txn)
                .await?;

            if let Err(e) = redfish_client.bmc_reset().await {
                tracing::warn!("Failed to reboot {}: {e}", &endpoint.address);
                return Ok(None);
            }
        }

        if (*firmware_type == FirmwareComponentType::HGXBmc
            || *firmware_type == FirmwareComponentType::Gpu)
            && !power_drains_needed.is_some()
        {
            // Needs a host power reset.  We might also have used the power drains to do an AC powercycle.
            let redfish_client = services
                .redfish_client_pool
                .create_client_from_machine(&state.host_snapshot, txn)
                .await?;

            // We previously possibly tried to use ACPowerycle here, however that requires enough time for the BMC to come back.  We use
            // the power_drains_needed setting instead for that which is already aware of how to keep track of that sort of thing.
            if let Err(e) = redfish_client.power(SystemPowerControl::ForceOff).await {
                tracing::error!("Failed to power off {}: {e}", &endpoint.address);
                return Ok(None);
            }
            tokio::time::sleep(self.hgx_bmc_gpu_reboot_delay).await;
            if let Err(e) = redfish_client.power(SystemPowerControl::On).await {
                tracing::error!("Failed to power on {}: {e}", &endpoint.address);
                return Ok(None);
            }
            // Okay to proceed
        }

        // Now we can go on to waiting for the correct version to be reported
        let reprovision_state = HostReprovisionState::NewFirmwareReportedWait {
            firmware_type: *firmware_type,
            firmware_number: *firmware_number,
            final_version: final_version.to_string(),
            previous_reset_time: Some(Utc::now().timestamp()),
        };
        scenario.actual_new_state(
            reprovision_state,
            state.managed_state.get_host_repro_retry_count(),
        )
    }

    async fn host_new_firmware_reported_wait(
        &self,
        state: &ManagedHostStateSnapshot,
        services: &CommonStateHandlerServices,
        details: &HostReprovisionState,
        machine_id: &MachineId,
        scenario: HostFirmwareScenario,
        txn: &mut PgConnection,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let (final_version, firmware_type, firmware_number, previous_reset_time) = match details {
            HostReprovisionState::NewFirmwareReportedWait {
                final_version,
                firmware_type,
                firmware_number,
                previous_reset_time,
            } => (
                final_version,
                firmware_type,
                firmware_number,
                previous_reset_time,
            ),
            _ => {
                return Err(StateHandlerError::GenericError(eyre!(
                    "Wrong enum in host_new_firmware_reported_wait"
                )));
            }
        };

        let Some(endpoint) = find_explored_refreshed_endpoint(state, machine_id, txn).await? else {
            tracing::debug!("Waiting for site explorer to revisit {machine_id}");
            return Ok(None);
        };

        let Some(fw_info) = self.parsed_hosts.find_fw_info_for_host(&endpoint) else {
            tracing::error!("Could no longer find firmware info for {machine_id}");
            return scenario.actual_new_state(
                HostReprovisionState::CheckingFirmwareRepeatV2 {
                    firmware_type: Some(*firmware_type),
                    firmware_number: *firmware_number,
                },
                state.managed_state.get_host_repro_retry_count(),
            );
        };

        let current_versions = endpoint.find_all_versions(&fw_info, *firmware_type);
        if current_versions.is_empty() {
            tracing::error!("Could no longer find current versions for {machine_id}");
            return scenario.actual_new_state(
                HostReprovisionState::CheckingFirmwareRepeatV2 {
                    firmware_type: Some(*firmware_type),
                    firmware_number: *firmware_number,
                },
                state.managed_state.get_host_repro_retry_count(),
            );
        };

        let versions_match_final_version = current_versions.iter().all(|v| *v == final_version);
        if !versions_match_final_version {
            tracing::warn!(
                "{}: Not all firmware versions match. Expected: {final_version}, Found: {:?}",
                endpoint.address,
                current_versions
            );
        };

        if versions_match_final_version {
            // Done waiting, go back to overall checking of version`2s
            tracing::debug!("Done waiting for {machine_id} to reach version");
            scenario.actual_new_state(
                HostReprovisionState::CheckingFirmwareRepeatV2 {
                    firmware_type: Some(*firmware_type),
                    firmware_number: *firmware_number,
                },
                state.managed_state.get_host_repro_retry_count(),
            )
        } else {
            if !self.no_firmware_update_reset_retries
                && let Some(previous_reset_time) = previous_reset_time
                && previous_reset_time + 30 * 60 <= Utc::now().timestamp()
            {
                tracing::info!(
                    "Upgrade for {} {:?} has taken more than 30 minutes to report new version; resetting again.",
                    &endpoint.address,
                    firmware_type
                );
                let details = &HostReprovisionState::ResetForNewFirmware {
                    final_version: final_version.to_string(),
                    firmware_type: *firmware_type,
                    firmware_number: *firmware_number,
                    power_drains_needed: None,
                    delay_until: None,
                    last_power_drain_operation: None,
                };
                return self
                    .host_reset_for_new_firmware(
                        state, services, machine_id, details, scenario, txn,
                    )
                    .await;
            }
            tracing::info!(
                "Waiting for {machine_id} {firmware_type:?} to reach version {final_version} currently {current_versions:?}"
            );
            db::explored_endpoints::re_explore_if_version_matches(
                endpoint.address,
                endpoint.report_version,
                txn,
            )
            .await?;
            Ok(None)
        }
    }

    fn is_auto_approved(&self) -> bool {
        let Some(ref period) = self.instance_autoreboot_period else {
            return false;
        };
        let start = period.start;
        let end = period.end;

        let now = chrono::Utc::now();

        now > start && now < end
    }
}

#[derive(Debug, Default)]
struct UpdateScriptManager {
    active: Mutex<HashMap<String, Option<bool>>>,
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

#[derive(Clone, Default, Debug)]
struct AsyncFirmwareUploader {
    active_uploads: Arc<Mutex<HashMap<String, Option<UploadResult>>>>,
}

impl AsyncFirmwareUploader {
    fn start_upload(
        &self,
        id: String,
        redfish_client: Box<dyn Redfish>,
        filename: std::path::PathBuf,
        redfish_component_type: libredfish::model::update_service::ComponentType,
        address: String,
    ) {
        if self.upload_status(&id).is_some() {
            // This situation can happen during an upgrade (typically a config upgrade) where the new instance of carbide-api starts an upgrade,
            // the old one sees that it's not the uploader and returns us to Checking, then the new one is following this path.  As we would be
            // trying to return to the exact same state that we generated before and the upload is already in progress, all we need to do here is
            // return.  It's possible that we may fluctuate the state a few times, but once the old instance dies we will be fine.
            //
            // In the odd situation where the old one was doing the upload, a similar thing will happen, but when the old one dies it will kill
            // the upload and the restart is the correct thing to do.
            //
            // Log it so we can see what's going on in case there's problems.
            tracing::info!(
                "Uploading conflict for {id} {address}; our upload should still be in progress."
            );
            return;
        }
        // We set a None value to indicate that we know about this.  If we restart and we're in the next state but it's not set, we'll not find anything and know that the connection was reset.
        self.active_uploads
            .lock()
            .expect("lock poisoned")
            .insert(id.clone(), None);

        let active_uploads = self.active_uploads.clone();
        tokio::spawn(async move {
            match redfish_client
                .update_firmware_multipart(
                    filename.as_path(),
                    true,
                    std::time::Duration::from_secs(3600),
                    redfish_component_type,
                )
                .await
            {
                Ok(task_id) => {
                    let mut hashmap = active_uploads.lock().expect("lock poisoned");
                    hashmap.insert(id, Some(UploadResult::Success { task_id }));
                }
                Err(e) => {
                    tracing::warn!("Failed uploading firmware to {id} {address}: {e}");
                    let mut hashmap = active_uploads.lock().expect("lock poisoned");
                    hashmap.insert(id, Some(UploadResult::Failure));
                }
            };
        });
    }
    fn upload_status(&self, id: &String) -> Option<Option<UploadResult>> {
        let hashmap = self.active_uploads.lock().expect("lock poisoned");
        hashmap.get(id).cloned()
    }
    fn finish_upload(&self, id: &String) {
        let mut hashmap = self.active_uploads.lock().expect("lock poisoned");
        hashmap.remove(id);
    }
}

/// Issues a reboot request command to a host or DPU
async fn handler_restart_dpu(
    machine: &Machine,
    services: &CommonStateHandlerServices,
    txn: &mut PgConnection,
) -> Result<(), StateHandlerError> {
    db::machine::update_reboot_requested_time(
        &machine.id,
        txn,
        model::machine::MachineLastRebootRequestedMode::Reboot,
    )
    .await?;

    restart_dpu(machine, services, txn).await
    //handler_host_power_control(state, services, SystemPowerControl::ForceRestart, txn).await
}

pub async fn host_power_state(
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

fn requires_manual_firmware_upgrade(
    state: &ManagedHostStateSnapshot,
    config: &CarbideConfig,
) -> bool {
    if !config.firmware_global.requires_manual_upgrade {
        return false;
    }

    let is_gb200 = state
        .host_snapshot
        .hardware_info
        .as_ref()
        .map(|hi| hi.is_gbx00())
        .unwrap_or(false);

    if !is_gb200 {
        return false;
    }

    state
        .host_snapshot
        .manual_firmware_upgrade_completed
        .is_none()
}

fn get_next_state_boss_job_failure(
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<(ManagedHostState, PowerState), StateHandlerError> {
    let (next_state, expected_power_state) = match &mh_snapshot.host_snapshot.state.value {
        ManagedHostState::WaitingForCleanup { cleanup_state } => match cleanup_state {
            CleanupState::SecureEraseBoss {
                secure_erase_boss_context,
            } => match &secure_erase_boss_context.secure_erase_boss_state {
                SecureEraseBossState::HandleJobFailure {
                    failure,
                    power_state,
                } => match power_state {
                    libredfish::PowerState::Off => (
                        ManagedHostState::WaitingForCleanup {
                            cleanup_state: CleanupState::SecureEraseBoss {
                                secure_erase_boss_context: SecureEraseBossContext {
                                    boss_controller_id: secure_erase_boss_context
                                        .boss_controller_id
                                        .clone(),
                                    secure_erase_jid: None,
                                    iteration: secure_erase_boss_context.iteration,
                                    secure_erase_boss_state:
                                        SecureEraseBossState::HandleJobFailure {
                                            failure: failure.to_string(),
                                            power_state: libredfish::PowerState::On,
                                        },
                                },
                            },
                        },
                        *power_state,
                    ),
                    libredfish::PowerState::On => (
                        ManagedHostState::WaitingForCleanup {
                            cleanup_state: CleanupState::SecureEraseBoss {
                                secure_erase_boss_context: SecureEraseBossContext {
                                    boss_controller_id: secure_erase_boss_context
                                        .boss_controller_id
                                        .clone(),
                                    secure_erase_jid: None,
                                    iteration: Some(
                                        secure_erase_boss_context.iteration.unwrap_or_default() + 1,
                                    ),
                                    secure_erase_boss_state: SecureEraseBossState::SecureEraseBoss,
                                },
                            },
                        },
                        *power_state,
                    ),
                    _ => {
                        return Err(StateHandlerError::GenericError(eyre::eyre!(
                            "unexpected SecureEraseBossState::HandleJobFailure power_state for {}: {:#?}",
                            mh_snapshot.host_snapshot.id,
                            mh_snapshot.host_snapshot.state,
                        )));
                    }
                },
                _ => {
                    return Err(StateHandlerError::GenericError(eyre::eyre!(
                        "unexpected SecureEraseBossState state for {}: {:#?}",
                        mh_snapshot.host_snapshot.id,
                        mh_snapshot.host_snapshot.state,
                    )));
                }
            },
            CleanupState::CreateBossVolume {
                create_boss_volume_context,
            } => match &create_boss_volume_context.create_boss_volume_state {
                CreateBossVolumeState::HandleJobFailure {
                    failure,
                    power_state,
                } => match power_state {
                    libredfish::PowerState::Off => (
                        ManagedHostState::WaitingForCleanup {
                            cleanup_state: CleanupState::CreateBossVolume {
                                create_boss_volume_context: CreateBossVolumeContext {
                                    boss_controller_id: create_boss_volume_context
                                        .boss_controller_id
                                        .clone(),
                                    create_boss_volume_jid: None,
                                    iteration: create_boss_volume_context.iteration,
                                    create_boss_volume_state:
                                        CreateBossVolumeState::HandleJobFailure {
                                            failure: failure.to_string(),
                                            power_state: libredfish::PowerState::On,
                                        },
                                },
                            },
                        },
                        *power_state,
                    ),
                    libredfish::PowerState::On => (
                        ManagedHostState::WaitingForCleanup {
                            cleanup_state: CleanupState::CreateBossVolume {
                                create_boss_volume_context: CreateBossVolumeContext {
                                    boss_controller_id: create_boss_volume_context
                                        .boss_controller_id
                                        .clone(),
                                    create_boss_volume_jid: None,
                                    iteration: Some(
                                        create_boss_volume_context.iteration.unwrap_or_default()
                                            + 1,
                                    ),
                                    create_boss_volume_state:
                                        CreateBossVolumeState::CreateBossVolume,
                                },
                            },
                        },
                        *power_state,
                    ),
                    _ => {
                        return Err(StateHandlerError::GenericError(eyre::eyre!(
                            "unexpected CreateBossVolumeState::HandleJobFailure power state for {}: {:#?}",
                            mh_snapshot.host_snapshot.id,
                            mh_snapshot.host_snapshot.state,
                        )));
                    }
                },
                _ => {
                    return Err(StateHandlerError::GenericError(eyre::eyre!(
                        "unexpected CreateBossVolume state for {}: {:#?}",
                        mh_snapshot.host_snapshot.id,
                        mh_snapshot.host_snapshot.state,
                    )));
                }
            },
            _ => {
                return Err(StateHandlerError::GenericError(eyre::eyre!(
                    "unexpected WaitingForCleanup state for {}: {:#?}",
                    mh_snapshot.host_snapshot.id,
                    mh_snapshot.host_snapshot.state,
                )));
            }
        },
        _ => {
            return Err(StateHandlerError::GenericError(eyre::eyre!(
                "unexpected host state for {}: {:#?}",
                mh_snapshot.host_snapshot.id,
                mh_snapshot.host_snapshot.state,
            )));
        }
    };
    Ok((next_state, expected_power_state))
}

fn handle_boss_controller_job_error(
    boss_controller_id: String,
    iterations: u32,
    secure_erase_boss_controller: bool,
    err: StateHandlerError,
    time_since_state_change: chrono::TimeDelta,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    // Wait for 5 minutes before declaring a true failure and transition to the error handling state.
    // As we use this function to handle two different kinds of errors (and maybe others in the future),
    // the defensive nature of this check will be broadly helpful to differentiate between transient errors
    // and true failures. Here is one particular edge case:
    // It takes a little time between creating and scheduling the secure erase job.
    // If the state machine queries the BMC for the job's state prior to the job being scheduled,
    // the BMC's job service will return a 404. Wait here for five minutes to ensure
    // that the job is scheduled prior to declaring an error.
    if time_since_state_change.num_minutes() < 5 {
        return Err(err);
    }

    // we have retried this operation too many times, lets wait for manual intervention
    if iterations > 3 {
        let action = match secure_erase_boss_controller {
            true => "secure erase",
            false => "create the R1 volume on",
        };

        return Err(StateHandlerError::GenericError(eyre::eyre!(
            "We have gone through {} iterations of trying to {action} the BOSS controller; Waiting for manual intervention: {err}",
            iterations
        )));
    }

    // failure path
    let cleanup_state = match secure_erase_boss_controller {
        // the job to decomission the boss controller failed--lets retry
        true => CleanupState::SecureEraseBoss {
            secure_erase_boss_context: SecureEraseBossContext {
                boss_controller_id,
                secure_erase_jid: None,
                secure_erase_boss_state: SecureEraseBossState::HandleJobFailure {
                    failure: err.to_string(),
                    power_state: libredfish::PowerState::Off,
                },
                iteration: Some(iterations),
            },
        },
        // the job to crate the R1 Volume on top of the BOSS controller failed--lets retry
        false => CleanupState::CreateBossVolume {
            create_boss_volume_context: CreateBossVolumeContext {
                boss_controller_id,
                create_boss_volume_jid: None,
                create_boss_volume_state: CreateBossVolumeState::HandleJobFailure {
                    failure: err.to_string(),
                    power_state: libredfish::PowerState::Off,
                },
                iteration: Some(iterations),
            },
        },
    };

    let next_state: ManagedHostState = ManagedHostState::WaitingForCleanup { cleanup_state };

    Ok(StateHandlerOutcome::transition(next_state))
}

async fn wait_for_boss_controller_job_to_complete(
    redfish_client: &dyn Redfish,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let (boss_controller_id, boss_job_id, iterations, secure_erase_boss_controller) =
        match &mh_snapshot.host_snapshot.state.value {
            ManagedHostState::WaitingForCleanup { cleanup_state } => match cleanup_state {
                CleanupState::SecureEraseBoss {
                    secure_erase_boss_context,
                } => match &secure_erase_boss_context.secure_erase_boss_state {
                    SecureEraseBossState::WaitForJobCompletion => (
                        secure_erase_boss_context.boss_controller_id.clone(),
                        secure_erase_boss_context.secure_erase_jid.clone(),
                        secure_erase_boss_context.iteration.unwrap_or_default(),
                        // we are waiting for the secure erase job to complete
                        true,
                    ),
                    _ => {
                        return Err(StateHandlerError::GenericError(eyre::eyre!(
                            "unexpected SecureEraseBoss state for {}: {:#?}",
                            mh_snapshot.host_snapshot.id,
                            mh_snapshot.host_snapshot.state,
                        )));
                    }
                },
                CleanupState::CreateBossVolume {
                    create_boss_volume_context,
                } => match &create_boss_volume_context.create_boss_volume_state {
                    CreateBossVolumeState::WaitForJobCompletion => (
                        create_boss_volume_context.boss_controller_id.clone(),
                        create_boss_volume_context.create_boss_volume_jid.clone(),
                        create_boss_volume_context.iteration.unwrap_or_default(),
                        // we are waiting for the BOSS volume creation job to complete
                        false,
                    ),
                    _ => todo!(),
                },
                _ => {
                    return Err(StateHandlerError::GenericError(eyre::eyre!(
                        "unexpected CreateBossVolume state for {}: {:#?}",
                        mh_snapshot.host_snapshot.id,
                        mh_snapshot.host_snapshot.state,
                    )));
                }
            },
            _ => {
                return Err(StateHandlerError::GenericError(eyre::eyre!(
                    "unexpected host state for {}: {:#?}",
                    mh_snapshot.host_snapshot.id,
                    mh_snapshot.host_snapshot.state,
                )));
            }
        };

    let job_id = match boss_job_id {
        Some(jid) => Ok(jid),
        None => Err(StateHandlerError::GenericError(eyre::eyre!(
            "could not find job ID in the state's context"
        ))),
    }?;

    let job_state = match redfish_client.get_job_state(&job_id).await {
        Ok(state) => state,
        Err(e) => {
            return handle_boss_controller_job_error(
                boss_controller_id,
                iterations,
                secure_erase_boss_controller,
                StateHandlerError::RedfishError {
                    operation: "get_job_state",
                    error: e,
                },
                mh_snapshot.host_snapshot.state.version.since_state_change(),
            );
        }
    };

    match job_state {
        // The job has completed; transition to next step in host cleanup
        libredfish::JobState::Completed => {
            // healthy path
            let cleanup_state = match secure_erase_boss_controller {
                // now that we have finished doing a secure erase of the BOSS controller
                // we can do a standard secure erase of the remaining drives through the /usr/sbin/nvme tool
                true => CleanupState::HostCleanup {
                    boss_controller_id: Some(boss_controller_id),
                },
                // now that we have recreated the R1 volume on top of the BOSS controller, we can lock the host back down again.
                false => CleanupState::CreateBossVolume {
                    create_boss_volume_context: CreateBossVolumeContext {
                        boss_controller_id,
                        create_boss_volume_jid: None,
                        create_boss_volume_state: CreateBossVolumeState::LockHost,
                        iteration: Some(iterations),
                    },
                },
            };

            let next_state = ManagedHostState::WaitingForCleanup { cleanup_state };
            Ok(StateHandlerOutcome::transition(next_state))
        }
        // The job has failed; handle error
        libredfish::JobState::ScheduledWithErrors | libredfish::JobState::CompletedWithErrors => {
            handle_boss_controller_job_error(
                boss_controller_id,
                iterations,
                secure_erase_boss_controller,
                StateHandlerError::GenericError(eyre::eyre!(
                    "job {job_id} will not complete because it is in a failure state: {job_state:#?}",
                )),
                mh_snapshot.host_snapshot.state.version.since_state_change(),
            )
        }
        // The job is still running (hopefully...); wait for the job to complete
        _ => Ok(StateHandlerOutcome::wait(format!(
            "waiting for job {job_id} to complete; current state: {job_state:#?}"
        ))),
    }
}

#[allow(txn_held_across_await)]
async fn handle_boss_job_failure(
    redfish_client: &dyn Redfish,
    mh_snapshot: &ManagedHostStateSnapshot,
    services: &CommonStateHandlerServices,
    txn: &mut PgConnection,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let (next_state, expected_power_state) = get_next_state_boss_job_failure(mh_snapshot)?;

    let current_power_state =
        redfish_client
            .get_power_state()
            .await
            .map_err(|e| StateHandlerError::RedfishError {
                operation: "get_power_state",
                error: e,
            })?;

    match expected_power_state {
        libredfish::PowerState::Off => {
            if current_power_state != libredfish::PowerState::Off {
                handler_host_power_control(
                    mh_snapshot,
                    services,
                    SystemPowerControl::ForceOff,
                    txn,
                )
                .await?;

                return Ok(StateHandlerOutcome::wait(format!(
                    "waiting for {} to power down; current power state: {current_power_state}",
                    mh_snapshot.host_snapshot.id
                )));
            }

            redfish_client
                .bmc_reset()
                .await
                .map_err(|e| StateHandlerError::RedfishError {
                    operation: "bmc_reset",
                    error: e,
                })?;

            Ok(StateHandlerOutcome::transition(next_state))
        }
        libredfish::PowerState::On => {
            let basetime = mh_snapshot
                .host_snapshot
                .last_reboot_requested
                .as_ref()
                .map(|x| x.time)
                .unwrap_or(mh_snapshot.host_snapshot.state.version.timestamp());

            if wait(
                &basetime,
                services
                    .site_config
                    .machine_state_controller
                    .power_down_wait,
            ) {
                return Ok(StateHandlerOutcome::wait(format!(
                    "waiting for {} to power down; power_down_wait: {}",
                    mh_snapshot.host_snapshot.id,
                    services
                        .site_config
                        .machine_state_controller
                        .power_down_wait
                )));
            }

            if current_power_state != libredfish::PowerState::On {
                handler_host_power_control(mh_snapshot, services, SystemPowerControl::On, txn)
                    .await?;

                return Ok(StateHandlerOutcome::wait(format!(
                    "waiting for {} to power on; current power state: {current_power_state}",
                    mh_snapshot.host_snapshot.id,
                )));
            }

            Ok(StateHandlerOutcome::transition(next_state))
        }
        _ => Err(StateHandlerError::GenericError(eyre::eyre!(
            "unexpected expected_power_state while handling a boss job failure: {expected_power_state}"
        ))),
    }
}

#[track_caller]
pub fn handler_host_power_control(
    managedhost_snapshot: &ManagedHostStateSnapshot,
    services: &CommonStateHandlerServices,
    action: SystemPowerControl,
    txn: &mut PgConnection,
) -> impl Future<Output = Result<(), StateHandlerError>> {
    let trigger_location = std::panic::Location::caller();
    handler_host_power_control_with_location(
        managedhost_snapshot,
        services,
        action,
        txn,
        trigger_location,
    )
}

#[allow(txn_held_across_await)]
pub async fn handler_host_power_control_with_location(
    managedhost_snapshot: &ManagedHostStateSnapshot,
    services: &CommonStateHandlerServices,
    action: SystemPowerControl,
    txn: &mut PgConnection,
    location: &std::panic::Location<'_>,
) -> Result<(), StateHandlerError> {
    let mut action = action;
    let redfish_client = services
        .redfish_client_pool
        .create_client_from_machine(&managedhost_snapshot.host_snapshot, txn)
        .await?;

    let power_state = host_power_state(redfish_client.as_ref()).await?;

    let target_power_state_reached = (power_state == libredfish::PowerState::Off
        && (action == SystemPowerControl::ForceOff
            || action == SystemPowerControl::GracefulShutdown))
        || (power_state == libredfish::PowerState::On && action == SystemPowerControl::On);

    if target_power_state_reached {
        let machine_id = &managedhost_snapshot.host_snapshot.id;
        tracing::warn!(%machine_id, %power_state, %action, "Target power state is already reached. Skipping power control action");
    } else {
        if power_state == libredfish::PowerState::Off
            && (action == SystemPowerControl::ForceRestart
                || action == SystemPowerControl::GracefulRestart)
        {
            // A host can't be restarted if it is in power-off state.
            // In this call, power on the system. State machine restart the system in next iteration.
            tracing::warn!(%power_state, %action, "Power state is Off and requested action is restart. Trying to power on the host.");
            action = SystemPowerControl::On;
        }
        host_power_control_with_location(
            redfish_client.as_ref(),
            &managedhost_snapshot.host_snapshot,
            action,
            services.ipmi_tool.clone(),
            txn,
            location,
        )
        .await
        .map_err(|e| {
            StateHandlerError::GenericError(eyre!("handler_host_power_control failed: {}", e))
        })?;
    }

    // If host is forcedOff/ACPowercycled/On, it will impact DPU also. So DPU timestamp should also be updated
    // here.
    let dpu_impacting_actions = [
        SystemPowerControl::ForceOff,
        SystemPowerControl::ACPowercycle,
        SystemPowerControl::On,
    ];
    let should_update_dpu_timestamp = dpu_impacting_actions.contains(&action);

    if should_update_dpu_timestamp {
        for dpu_snapshot in &managedhost_snapshot.dpu_snapshots {
            db::machine::update_reboot_requested_time(&dpu_snapshot.id, txn, action.into()).await?;
        }
    }

    Ok(())
}

#[allow(txn_held_across_await)]
async fn restart_dpu(
    machine: &Machine,
    services: &CommonStateHandlerServices,
    txn: &mut PgConnection,
) -> Result<(), StateHandlerError> {
    let dpu_redfish_client = services
        .redfish_client_pool
        .create_client_from_machine(machine, txn)
        .await?;

    // We have seen the boot order be reset on DPUs in some edge cases (for example, after upgrading the BMC and CEC on BF3s)
    // This should take care of handling such cases. It is a no-op most of the time
    if let Err(e) = dpu_redfish_client
        .boot_once(libredfish::Boot::UefiHttp)
        .await
    {
        // We use a Dell to mock our BMC responses in the integration tests. UefiHttp boot is not implemented
        // for Dells, so this call is failing in our tests. Regardless, it is ok to not make this call blocking.
        tracing::error!(%e, "Failed to configure DPU {} to boot once", machine.id);
    }

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

/// find_explored_refreshed_endpoint will locate the explored endpoint for the given state.
/// It will return an error for not finding any endpoint, and Ok(None) when we're still waiting
/// on explorer to have a chance to run again.
pub async fn find_explored_refreshed_endpoint(
    state: &ManagedHostStateSnapshot,
    machine_id: &MachineId,
    txn: &mut PgConnection,
) -> Result<Option<ExploredEndpoint>, StateHandlerError> {
    let addr: IpAddr = state
        .host_snapshot
        .bmc_info
        .ip_addr()
        .map_err(StateHandlerError::GenericError)?;

    let endpoint = db::explored_endpoints::find_by_ips(&mut *txn, vec![addr]).await?;
    let endpoint = endpoint
        .into_iter()
        .next()
        .ok_or(StateHandlerError::GenericError(
            eyre! {"Unable to find explored_endpoint for {machine_id}"},
        ))?;

    if endpoint.waiting_for_explorer_refresh {
        // In the cases where this was called, we care about prompt updates, so poke site explorer to revisit this endpoint next time it runs
        db::explored_endpoints::re_explore_if_version_matches(
            endpoint.address,
            endpoint.report_version,
            txn,
        )
        .await?;
        return Ok(None);
    }
    Ok(Some(endpoint))
}

// If already reprovisioning is started, we can restart.
// Also check that this is not some old request. The restart requested time must be greater than
// last state change.
fn can_restart_reprovision(dpu_snapshots: &[Machine], version: ConfigVersion) -> bool {
    let mut reprov_started = false;
    let mut requested_at = vec![];
    for dpu_snapshot in dpu_snapshots {
        if let Some(reprov_req) = &dpu_snapshot.reprovision_requested {
            if reprov_req.started_at.is_some() {
                reprov_started = true;
            }
            requested_at.push(reprov_req.restart_reprovision_requested_at);
        }
    }

    if !reprov_started {
        return false;
    }

    // Get the latest time of restart requested.
    requested_at.sort();

    let Some(latest_requested_at) = requested_at.last() else {
        return false;
    };

    dpu_reprovision_restart_requested_after_state_transition(version, *latest_requested_at)
}

/// Call [`Redfish::machine_setup`], but ignore any [`RedfishError::NoDpu`] if we expect there to be no DPUs.
///
/// TODO(ken): This is a temporary workaround for work-in-progress on zero-DPU support (August 2024)
/// The way we should do this going forward is to plumb the actual non-DPU MAC address we want to
/// boot from, but that information is not in scope at this time. Once it is, and we pass it to
/// machine_setup, we should no longer expect a NoDpu error and can thus call vanilla machine_setup again.
async fn call_machine_setup_and_handle_no_dpu_error(
    redfish_client: &dyn Redfish,
    boot_interface_mac: Option<&str>,
    expected_dpu_count: usize,
    site_config: &CarbideConfig,
) -> Result<(), RedfishError> {
    let setup_result = redfish_client
        .machine_setup(
            boot_interface_mac,
            &site_config.bios_profiles,
            site_config.selected_profile,
        )
        .await;
    match (
        setup_result,
        expected_dpu_count,
        site_config.site_explorer.allow_zero_dpu_hosts,
    ) {
        (Err(RedfishError::NoDpu), 0, true) => {
            tracing::info!(
                "redfish machine_setup failed due to there being no DPUs on the host. This is expected as the host has no DPUs, and we are configured to allow this."
            );
            Ok(())
        }
        (Ok(()), _, _) => Ok(()),
        (Err(e), _, _) => Err(e),
    }
}

async fn set_boot_order_dpu_first_and_handle_no_dpu_error(
    redfish_client: &dyn Redfish,
    boot_interface_mac: &str,
    expected_dpu_count: usize,
    site_config: &CarbideConfig,
) -> Result<Option<String>, RedfishError> {
    let setup_result = redfish_client
        .set_boot_order_dpu_first(boot_interface_mac)
        .await;
    match (
        setup_result,
        expected_dpu_count,
        site_config.site_explorer.allow_zero_dpu_hosts,
    ) {
        (Err(RedfishError::NoDpu), 0, true) => {
            tracing::info!(
                "redfish set_boot_order_dpu_first failed due to there being no DPUs on the host. This is expected as the host has no DPUs, and we are configured to allow this."
            );
            Ok(None)
        }
        (Ok(job_id), _, _) => Ok(job_id),
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
        tracing::info!(machine_id = %state.host_snapshot.id, "Machine Validation is requested");
    }

    on_demand_machine_validation_request
}

#[allow(txn_held_across_await)]
async fn handle_instance_host_platform_config(
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    mh_snapshot: &mut ManagedHostStateSnapshot,
    reachability_params: &ReachabilityParams,
    platform_config_state: HostPlatformConfigurationState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let redfish_client = ctx
        .services
        .redfish_client_pool
        .create_client_from_machine(&mh_snapshot.host_snapshot, txn)
        .await?;

    let instance_state = match platform_config_state {
        HostPlatformConfigurationState::PowerCycle { power_on } => {
            let power_state = redfish_client.get_power_state().await.map_err(|e| {
                StateHandlerError::RedfishError {
                    operation: "get_power_state",
                    error: e,
                }
            })?;

            // Phase 1: Power OFF (power_on=false means we need to power off first)
            if !power_on {
                if power_state == PowerState::Off {
                    // Host is already off, proceed to power on phase
                    return Ok(StateHandlerOutcome::transition(
                        ManagedHostState::Assigned {
                            instance_state: InstanceState::HostPlatformConfiguration {
                                platform_config_state: HostPlatformConfigurationState::PowerCycle {
                                    power_on: true,
                                },
                            },
                        },
                    ));
                }

                // Host is still on, issue power off command
                host_power_control(
                    redfish_client.as_ref(),
                    &mh_snapshot.host_snapshot,
                    SystemPowerControl::ForceOff,
                    ctx.services.ipmi_tool.clone(),
                    txn,
                )
                .await
                .map_err(|e| {
                    StateHandlerError::GenericError(eyre!("failed to power off host: {}", e))
                })?;

                return Ok(StateHandlerOutcome::wait(format!(
                    "waiting for {} to power OFF; current power state: {}",
                    mh_snapshot.host_snapshot.id, power_state
                )));
            }

            // Phase 2: Power ON (power_on=true means host was off, now power it on)

            // Wait for the power-down grace period before powering back on
            let basetime = mh_snapshot
                .host_snapshot
                .last_reboot_requested
                .as_ref()
                .map(|x| x.time)
                .unwrap_or(mh_snapshot.host_snapshot.state.version.timestamp());

            if wait(&basetime, reachability_params.power_down_wait) {
                return Ok(StateHandlerOutcome::wait(format!(
                    "waiting for power-down grace period before powering on {}; power_down_wait: {}",
                    mh_snapshot.host_snapshot.id, reachability_params.power_down_wait
                )));
            }

            if power_state == PowerState::On {
                // Host is already on, proceed to check config
                return Ok(StateHandlerOutcome::transition(
                    ManagedHostState::Assigned {
                        instance_state: InstanceState::HostPlatformConfiguration {
                            platform_config_state: HostPlatformConfigurationState::CheckHostConfig,
                        },
                    },
                ));
            }

            // Host is still off, issue power on command
            host_power_control(
                redfish_client.as_ref(),
                &mh_snapshot.host_snapshot,
                SystemPowerControl::On,
                ctx.services.ipmi_tool.clone(),
                txn,
            )
            .await
            .map_err(|e| {
                StateHandlerError::GenericError(eyre!("failed to power on host: {}", e))
            })?;

            return Ok(StateHandlerOutcome::wait(format!(
                "waiting for {} to power ON; current power state: {}",
                mh_snapshot.host_snapshot.id, power_state
            )));
        }
        HostPlatformConfigurationState::CheckHostConfig => {
            let configure_host_boot_order = if !mh_snapshot.dpu_snapshots.is_empty() {
                // Given that we are checking the boot order of a server immediately after a power cycle, we
                // shoudl do some waiting to ensure that the host is not reporting stale redfish information from
                // before Carbide powered it off.
                // This check guarantees that the host has finished loading the BIOS after the DPUs have come up.
                // If Carbide is still reading an incorrect boot order at this point, something is wrong, and
                // we should configure this host properly.
                if !are_dpus_up_trigger_reboot_if_needed(
                    mh_snapshot,
                    reachability_params,
                    ctx.services,
                    txn,
                )
                .await
                {
                    return Ok(StateHandlerOutcome::wait(
                        "Waiting for DPUs to come up.".to_string(),
                    ));
                }

                let primary_interface = mh_snapshot
                    .host_snapshot
                    .interfaces
                    .iter()
                    .find(|x| x.primary_interface)
                    .ok_or_else(|| {
                        StateHandlerError::GenericError(eyre::eyre!(
                            "Missing primary interface from host: {}",
                            mh_snapshot.host_snapshot.id
                        ))
                    })?;

                let vendor = mh_snapshot.host_snapshot.bmc_vendor();

                if !(redfish_client
                    .is_boot_order_setup(&primary_interface.mac_address.to_string())
                    .await
                    .map_err(|e| StateHandlerError::RedfishError {
                        operation: "is_boot_order_setup",
                        error: e,
                    })?)
                {
                    tracing::warn!(
                        "Tenant has released {} but the {} does not have its boot order configured properly",
                        mh_snapshot.host_snapshot.id,
                        vendor.to_string()
                    );
                    // TODO: remove this vendor specific check once we have tested it against Lenovos
                    !vendor.is_lenovo()
                } else {
                    tracing::info!(
                        "Tenant has released {} and the {} has its boot order configured properly",
                        mh_snapshot.host_snapshot.id,
                        vendor.to_string()
                    );

                    false
                }
            } else {
                false
            };

            if configure_host_boot_order {
                InstanceState::HostPlatformConfiguration {
                    platform_config_state: HostPlatformConfigurationState::UnlockHost,
                }
            } else {
                InstanceState::WaitingForDpusToUp
            }
        }
        HostPlatformConfigurationState::UnlockHost => {
            redfish_client
                .lockdown_bmc(EnabledDisabled::Disabled)
                .await
                .map_err(|e| StateHandlerError::RedfishError {
                    operation: "lockdown_bmc",
                    error: e,
                })?;

            InstanceState::HostPlatformConfiguration {
                platform_config_state: HostPlatformConfigurationState::ConfigureBios,
            }
        }
        HostPlatformConfigurationState::ConfigureBios => {
            match configure_host_bios(
                txn,
                ctx,
                reachability_params,
                redfish_client.as_ref(),
                mh_snapshot,
            )
            .await?
            {
                BiosConfigOutcome::Done => {
                    // BIOS configuration done, move to polling
                    return Ok(StateHandlerOutcome::transition(
                        ManagedHostState::Assigned {
                            instance_state: InstanceState::HostPlatformConfiguration {
                                platform_config_state:
                                    HostPlatformConfigurationState::PollingBiosSetup,
                            },
                        },
                    ));
                }
                BiosConfigOutcome::WaitingForReboot(reason) => {
                    return Ok(StateHandlerOutcome::wait(reason));
                }
            }
        }
        HostPlatformConfigurationState::PollingBiosSetup => {
            let next_instance_state = InstanceState::HostPlatformConfiguration {
                platform_config_state: HostPlatformConfigurationState::SetBootOrder {
                    set_boot_order_info: SetBootOrderInfo {
                        set_boot_order_jid: None,
                        set_boot_order_state: SetBootOrderState::SetBootOrder,
                        retry_count: 0,
                    },
                },
            };

            let boot_interface_mac = if !mh_snapshot.dpu_snapshots.is_empty() {
                let primary_interface = mh_snapshot
                    .host_snapshot
                    .interfaces
                    .iter()
                    .find(|x| x.primary_interface)
                    .ok_or_else(|| {
                        StateHandlerError::GenericError(eyre::eyre!(
                            "Missing primary interface from host: {}",
                            mh_snapshot.host_snapshot.id
                        ))
                    })?;
                Some(primary_interface.mac_address.to_string())
            } else {
                None
            };

            match redfish_client
                .is_bios_setup(boot_interface_mac.as_deref())
                .await
            {
                Ok(true) => {
                    tracing::info!(
                        machine_id = %mh_snapshot.host_snapshot.id,
                        "BIOS setup verified successfully"
                    );
                    next_instance_state
                }
                Ok(false) => {
                    return Ok(StateHandlerOutcome::wait(
                        "Polling BIOS setup status, waiting for settings to be applied".to_string(),
                    ));
                }
                Err(e) => {
                    tracing::warn!(
                        machine_id = %mh_snapshot.host_snapshot.id,
                        error = %e,
                        "Failed to check BIOS setup status, will retry"
                    );
                    return Ok(StateHandlerOutcome::wait(format!(
                        "Failed to check BIOS setup status: {}. Will retry.",
                        e
                    )));
                }
            }
        }
        HostPlatformConfigurationState::SetBootOrder {
            set_boot_order_info,
        } => {
            match set_host_boot_order(
                txn,
                ctx,
                reachability_params,
                redfish_client.as_ref(),
                mh_snapshot,
                set_boot_order_info,
            )
            .await?
            {
                SetBootOrderOutcome::Continue(boot_order_info) => {
                    InstanceState::HostPlatformConfiguration {
                        platform_config_state: HostPlatformConfigurationState::SetBootOrder {
                            set_boot_order_info: boot_order_info,
                        },
                    }
                }
                SetBootOrderOutcome::Done => InstanceState::HostPlatformConfiguration {
                    platform_config_state: HostPlatformConfigurationState::LockHost,
                },
                SetBootOrderOutcome::WaitingForReboot(reason) => {
                    return Ok(StateHandlerOutcome::wait(reason));
                }
            }
        }
        HostPlatformConfigurationState::LockHost => {
            redfish_client
                .lockdown_bmc(EnabledDisabled::Enabled)
                .await
                .map_err(|e| StateHandlerError::RedfishError {
                    operation: "lockdown_bmc",
                    error: e,
                })?;

            InstanceState::WaitingForDpusToUp
        }
    };

    let next_state = ManagedHostState::Assigned { instance_state };

    Ok(StateHandlerOutcome::transition(next_state))
}

#[allow(txn_held_across_await)]
async fn configure_host_bios(
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    reachability_params: &ReachabilityParams,
    redfish_client: &dyn Redfish,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<BiosConfigOutcome, StateHandlerError> {
    let boot_interface_mac = if !mh_snapshot.dpu_snapshots.is_empty() {
        let primary_interface = mh_snapshot
            .host_snapshot
            .interfaces
            .iter()
            .find(|x| x.primary_interface)
            .ok_or_else(|| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "Missing primary interface from host: {}",
                    mh_snapshot.host_snapshot.id
                ))
            })?;
        Some(primary_interface.mac_address.to_string())
    } else {
        // This is the Zero-DPU case
        None
    };

    if let Err(e) = call_machine_setup_and_handle_no_dpu_error(
        redfish_client,
        boot_interface_mac.as_deref(),
        mh_snapshot.host_snapshot.associated_dpu_machine_ids().len(),
        &ctx.services.site_config,
    )
    .await
    {
        tracing::warn!(
            "redfish machine_setup failed for {}, potentially due to known race condition between UEFI POST and BMC. triggering force-restart if needed. err: {}",
            mh_snapshot.host_snapshot.id,
            e
        );

        // if machine_setup failed, rebooted to potentially work around
        // a known race between the DPU UEFI and the BMC, where if
        // the BMC is not up when DPU UEFI runs, then Attributes might
        // not come through. The fix is to force-restart the DPU to
        // re-POST.
        //
        // As of July 2024, Josh Price said there's an NBU FR to fix
        // this, but it wasn't target to a release yet.
        let reboot_status = if mh_snapshot.host_snapshot.last_reboot_requested.is_none() {
            handler_host_power_control(
                mh_snapshot,
                ctx.services,
                SystemPowerControl::ForceRestart,
                txn,
            )
            .await?;

            RebootStatus {
                increase_retry_count: true,
                status: "Restarted host".to_string(),
            }
        } else {
            trigger_reboot_if_needed(
                &mh_snapshot.host_snapshot,
                mh_snapshot,
                None,
                reachability_params,
                ctx.services,
                txn,
            )
            .await?
        };
        // Return WaitingForReboot instead of Err to ensure the transaction is committed
        // and last_reboot_requested is persisted. Returning Err would cause a transaction
        // rollback, leading to a tight reboot loop since the reboot timestamp is lost.
        return Ok(BiosConfigOutcome::WaitingForReboot(format!(
            "redfish machine_setup failed: {e}; triggered host reboot: {reboot_status:#?}"
        )));
    };

    // Host needs to be rebooted to pick up the changes after calling machine_setup
    handler_host_power_control(
        mh_snapshot,
        ctx.services,
        SystemPowerControl::ForceRestart,
        txn,
    )
    .await?;
    Ok(BiosConfigOutcome::Done)
}

#[allow(txn_held_across_await)]
async fn set_host_boot_order(
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    reachability_params: &ReachabilityParams,
    redfish_client: &dyn Redfish,
    mh_snapshot: &ManagedHostStateSnapshot,
    set_boot_order_info: SetBootOrderInfo,
) -> Result<SetBootOrderOutcome, StateHandlerError> {
    match set_boot_order_info.set_boot_order_state {
        SetBootOrderState::SetBootOrder => {
            if mh_snapshot.dpu_snapshots.is_empty() {
                // MachineState::SetBootOrder is a NO-OP for the Zero-DPU case
                Ok(SetBootOrderOutcome::Done)
            } else {
                let primary_interface = mh_snapshot
                    .host_snapshot
                    .interfaces
                    .iter()
                    .find(|x| x.primary_interface)
                    .ok_or_else(|| {
                        StateHandlerError::GenericError(eyre::eyre!(
                            "Missing primary interface from host: {}",
                            mh_snapshot.host_snapshot.id
                        ))
                    })?;

                let jid = match set_boot_order_dpu_first_and_handle_no_dpu_error(
                    redfish_client,
                    &primary_interface.mac_address.to_string(),
                    mh_snapshot.host_snapshot.associated_dpu_machine_ids().len(),
                    &ctx.services.site_config,
                )
                .await
                {
                    Ok(jid) => jid,
                    Err(e) => {
                        tracing::warn!(
                            "redfish set_boot_order_dpu_first failed for {}, potentially due to known race condition between UEFI POST and BMC. triggering force-restart if needed. err: {}",
                            mh_snapshot.host_snapshot.id,
                            e
                        );

                        let reboot_status =
                            if mh_snapshot.host_snapshot.last_reboot_requested.is_none() {
                                handler_host_power_control(
                                    mh_snapshot,
                                    ctx.services,
                                    SystemPowerControl::ForceRestart,
                                    txn,
                                )
                                .await?;

                                RebootStatus {
                                    increase_retry_count: true,
                                    status: "Restarted host".to_string(),
                                }
                            } else {
                                trigger_reboot_if_needed(
                                    &mh_snapshot.host_snapshot,
                                    mh_snapshot,
                                    None,
                                    reachability_params,
                                    ctx.services,
                                    txn,
                                )
                                .await?
                            };
                        // Return wait instead of Err to ensure the transaction is committed
                        // and last_reboot_requested is persisted. Returning Err would cause a transaction
                        // rollback, leading to a tight reboot loop since the reboot timestamp is lost.
                        return Ok(SetBootOrderOutcome::WaitingForReboot(format!(
                            "redfish set_boot_order_dpu_first failed: {e}; triggered host reboot: {reboot_status:#?}"
                        )));
                    }
                };

                Ok(SetBootOrderOutcome::Continue(SetBootOrderInfo {
                    set_boot_order_jid: jid,
                    set_boot_order_state: SetBootOrderState::WaitForSetBootOrderJobScheduled,
                    retry_count: set_boot_order_info.retry_count,
                }))
            }
        }
        SetBootOrderState::WaitForSetBootOrderJobScheduled => {
            if let Some(job_id) = &set_boot_order_info.set_boot_order_jid {
                let job_state = redfish_client.get_job_state(job_id).await.map_err(|e| {
                    StateHandlerError::RedfishError {
                        operation: "get_job_state",
                        error: e,
                    }
                })?;

                if !matches!(job_state, libredfish::JobState::Scheduled) {
                    return Err(StateHandlerError::GenericError(eyre::eyre!(
                        "waiting for job {:#?} to be scheduled; current state: {job_state:#?}",
                        job_id
                    )));
                }
            }

            Ok(SetBootOrderOutcome::Continue(SetBootOrderInfo {
                set_boot_order_jid: set_boot_order_info.set_boot_order_jid.clone(),
                set_boot_order_state: SetBootOrderState::RebootHost,
                retry_count: set_boot_order_info.retry_count,
            }))
        }
        SetBootOrderState::RebootHost => {
            // Host needs to be rebooted to pick up the changes after calling machine_setup
            handler_host_power_control(
                mh_snapshot,
                ctx.services,
                SystemPowerControl::ForceRestart,
                txn,
            )
            .await?;

            Ok(SetBootOrderOutcome::Continue(SetBootOrderInfo {
                set_boot_order_jid: set_boot_order_info.set_boot_order_jid.clone(),
                set_boot_order_state: SetBootOrderState::WaitForSetBootOrderJobCompletion,
                retry_count: set_boot_order_info.retry_count,
            }))
        }
        SetBootOrderState::WaitForSetBootOrderJobCompletion => {
            if let Some(job_id) = &set_boot_order_info.set_boot_order_jid {
                let job_state = redfish_client.get_job_state(job_id).await.map_err(|e| {
                    StateHandlerError::RedfishError {
                        operation: "get_job_state",
                        error: e,
                    }
                })?;

                if !matches!(job_state, libredfish::JobState::Completed) {
                    return Err(StateHandlerError::GenericError(eyre::eyre!(
                        "waiting for job {:#?} to complete; current state: {job_state:#?}",
                        job_id
                    )));
                }
            }

            Ok(SetBootOrderOutcome::Continue(SetBootOrderInfo {
                set_boot_order_jid: set_boot_order_info.set_boot_order_jid.clone(),
                set_boot_order_state: SetBootOrderState::CheckBootOrder,
                retry_count: set_boot_order_info.retry_count,
            }))
        }
        SetBootOrderState::CheckBootOrder => {
            const MAX_BOOT_ORDER_RETRIES: u32 = 3;
            const CHECK_BOOT_ORDER_TIMEOUT_MINUTES: i64 = 30;

            let retry_count = set_boot_order_info.retry_count;

            let primary_interface = mh_snapshot
                .host_snapshot
                .interfaces
                .iter()
                .find(|x| x.primary_interface)
                .ok_or_else(|| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "Missing primary interface from host: {}",
                        mh_snapshot.host_snapshot.id
                    ))
                })?;

            let boot_order_configured = redfish_client
                .is_boot_order_setup(&primary_interface.mac_address.to_string())
                .await
                .map_err(|e| StateHandlerError::RedfishError {
                    operation: "is_boot_order_setup",
                    error: e,
                })?;

            if boot_order_configured {
                tracing::info!(
                    "Boot order verified for {} - the host has its boot order configured properly",
                    mh_snapshot.host_snapshot.id,
                );
                return Ok(SetBootOrderOutcome::Done);
            }

            // Boot order is not configured properly - check if we should retry
            let time_since_state_change =
                mh_snapshot.host_snapshot.state.version.since_state_change();

            tracing::warn!(
                "Boot order check failed for {} - the host does not have its boot order configured properly after SetBootOrder (retry_count: {}, time_in_state: {} minutes)",
                mh_snapshot.host_snapshot.id,
                retry_count,
                time_since_state_change.num_minutes()
            );

            // If we've been stuck for 30+ minutes and haven't exhausted retries, retry SetBootOrder
            if time_since_state_change.num_minutes() >= CHECK_BOOT_ORDER_TIMEOUT_MINUTES
                && retry_count < MAX_BOOT_ORDER_RETRIES
            {
                tracing::info!(
                    "Boot order check timed out for {} after {} minutes, retrying SetBootOrder (retry {} of {})",
                    mh_snapshot.host_snapshot.id,
                    time_since_state_change.num_minutes(),
                    retry_count + 1,
                    MAX_BOOT_ORDER_RETRIES
                );

                return Ok(SetBootOrderOutcome::Continue(SetBootOrderInfo {
                    set_boot_order_jid: None,
                    set_boot_order_state: SetBootOrderState::SetBootOrder,
                    retry_count: retry_count + 1,
                }));
            }

            // Either still within timeout window or exhausted retries - return error
            Err(StateHandlerError::GenericError(eyre::eyre!(
                "Boot order is not configured properly for host {} after SetBootOrder completed (retry_count: {}, time_in_state: {} minutes)",
                mh_snapshot.host_snapshot.id,
                retry_count,
                time_since_state_change.num_minutes()
            )))
        }
    }
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
