// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use carbide_rack::firmware_object::rack_maintenance_access_token_key;
use carbide_redfish::libredfish::RedfishClientPool;
use carbide_secrets::credentials::{CredentialManager, Credentials};
use carbide_uuid::machine::MachineId;
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use db::{ObjectColumnFilter, WithTransaction};
use librms::RmsApi;
use model::machine::MachineMaintenanceOperation;
use model::rack::{MaintenanceActivity, MaintenanceScope, RackState};
use model::rack_type::RackProfileConfig;
use model::switch::SwitchMaintenanceOperation;
use sqlx::PgPool;

use crate::compute_tray_manager::{Backend as ComputeBackend, ComputeTrayManager};
use crate::config::ComponentManagerConfig;
use crate::error::ComponentManagerError;
use crate::nv_switch_manager::{
    Backend as NvSwitchBackend, ConfigureSwitchCertificateJobStatus, NvSwitchManager,
    SwitchEndpoint, SwitchPasswordRotationState,
};
use crate::power_shelf_manager::{Backend as PowerShelfBackend, PowerShelfManager};
use crate::rms::{RmsSwitchSystemImageStatusApi, validate_rms_backend_rack_profiles};

/// Holds the configured backend implementations for each component type.
#[derive(Debug, Clone)]
pub struct ComponentManager {
    // The HAL configured for nv-switch power and f/w control
    pub nv_switch: Arc<dyn NvSwitchManager>,
    // The HAL configured for powershelf power and f/w control
    pub power_shelf: Arc<dyn PowerShelfManager>,
    // The HAL configured for compute power and f/w control
    pub compute_tray: Arc<dyn ComputeTrayManager>,
    // if true, the component management interface will route through the state controller for switch power and f/w control.
    // the expectation is that the state controller will then call the configured HAL for switches (RMS or NSM)
    // if false, the component management interface will directly dispatch to the configured HAL for switches, bypassing the state controller
    pub nv_switch_use_state_controller: bool,
    // if true, the component management interface will route through the state controller for powershelf power and f/w control.
    // the expectation is that the state controller will then call the configured HAL for powershelves (RMS or PSM)
    // if false, the component management interface will directly dispatch to the configured HAL for powershelves, bypassing the state controller
    pub power_shelf_use_state_controller: bool,
    // if true, the component management interface will route through the state controller for compute tray power and f/w control.
    // the expectation is that the state controller will then call the configured HAL for compute tray
    // if false, the component management interface will directly dispatch to the configured HAL for compute trays, bypassing the state controller
    pub compute_tray_use_state_controller: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchMaintenanceRequestResult {
    pub switch_id: SwitchId,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineMaintenanceRequestResult {
    pub machine_id: MachineId,
    pub error: Option<String>,
}

/// Which rack states a maintenance caller is willing to schedule from.
///
/// Automatic maintenance uses [`RequireReady`](Self::RequireReady), while the
/// operator-facing API retains its existing ability to recover racks in
/// `Error` via [`AllowErrorRecovery`](Self::AllowErrorRecovery).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RackMaintenanceEligibility {
    RequireReady,
    AllowErrorRecovery,
}

/// The complete, non-error result of attempting to schedule rack maintenance.
///
/// Keeping contention and eligibility as outcomes (rather than string errors)
/// lets periodic callers retry without marking certificate rotation failed,
/// while operator-facing callers can map the same result to their public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RackMaintenanceRequestOutcome {
    /// This call persisted the requested scope.
    Scheduled,
    /// The exact same scope is already pending. This is an idempotent retry.
    AlreadyPending,
    /// A different maintenance request is pending and was left untouched.
    Busy,
    /// No request is pending, but the rack's current state is not eligible.
    Deferred { state: RackState },
}

/// Credential to persist if this call wins the rack-maintenance scheduling
/// race. It is written only after the scheduling transaction commits, so no
/// database lock is held during the external credential-store operation.
pub struct RackMaintenanceAccessToken<'a> {
    pub credential_manager: &'a dyn CredentialManager,
    pub token: String,
}

/// Atomically request rack maintenance through the rack state controller.
///
/// The rack row is locked before inspecting its state and existing scope, and
/// remains locked through the config write. Exact retries are idempotent;
/// unrelated pending work is never overwritten. Existing work is checked
/// before state eligibility so a retry can still observe `AlreadyPending`
/// after the rack controller has started transitioning the rack.
///
/// This is a free function because the API supports rack maintenance even when
/// no `ComponentManager` backend is configured.
pub async fn request_rack_maintenance_via_state_controller(
    db_pool: &PgPool,
    rack_id: &RackId,
    scope: MaintenanceScope,
    eligibility: RackMaintenanceEligibility,
    maintenance_access_token: Option<RackMaintenanceAccessToken<'_>>,
) -> Result<RackMaintenanceRequestOutcome, ComponentManagerError> {
    let rack_id = rack_id.clone();
    let scheduled_scope = scope.clone();
    let transaction_rack_id = rack_id.clone();

    let result = db_pool
        .with_txn(|txn| {
            Box::pin(async move {
                if !db::rack::lock_for_update(txn.as_mut(), &transaction_rack_id)
                    .await
                    .map_err(|error| ComponentManagerError::Internal(error.to_string()))?
                {
                    return Err(ComponentManagerError::NotFound(format!(
                        "rack {transaction_rack_id} not found"
                    )));
                }
                let rack = db::rack::find_by(
                    txn.as_mut(),
                    ObjectColumnFilter::One(db::rack::IdColumn, &transaction_rack_id),
                )
                .await
                .map_err(|error| ComponentManagerError::Internal(error.to_string()))?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    ComponentManagerError::NotFound(format!("rack {transaction_rack_id} not found"))
                })?;

                if let Some(existing_scope) = rack.config.maintenance_requested.as_ref() {
                    return Ok(if existing_scope == &scope {
                        RackMaintenanceRequestOutcome::AlreadyPending
                    } else {
                        RackMaintenanceRequestOutcome::Busy
                    });
                }

                let state = rack.controller_state.value.clone();
                let eligible = match eligibility {
                    RackMaintenanceEligibility::RequireReady => state == RackState::Ready,
                    RackMaintenanceEligibility::AllowErrorRecovery => {
                        matches!(&state, RackState::Ready | RackState::Error { .. })
                    }
                };
                if !eligible {
                    return Ok(RackMaintenanceRequestOutcome::Deferred { state });
                }

                let reset_firmware_upgrade_job =
                    scope.should_run(&MaintenanceActivity::FirmwareUpgrade {
                        firmware_version: None,
                        components: vec![],
                        force_update: false,
                    });
                let mut config = rack.config;
                config.maintenance_requested = Some(scope);
                db::rack::update(txn.as_mut(), &transaction_rack_id, &config)
                    .await
                    .map_err(|error| ComponentManagerError::Internal(error.to_string()))?;

                // Preserve the operator API's existing behavior, and keep this
                // reset atomic with accepting the maintenance request.
                if reset_firmware_upgrade_job {
                    db::rack::update_firmware_upgrade_job(txn.as_mut(), &transaction_rack_id, None)
                        .await
                        .map_err(|error| ComponentManagerError::Internal(error.to_string()))?;
                }

                Ok(RackMaintenanceRequestOutcome::Scheduled)
            })
        })
        .await;

    let outcome = match result {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(error)) => return Err(error),
        Err(error) => return Err(ComponentManagerError::Internal(error.to_string())),
    };

    if outcome == RackMaintenanceRequestOutcome::Scheduled
        && let Some(RackMaintenanceAccessToken {
            credential_manager,
            token,
        }) = maintenance_access_token
        && let Err(error) = credential_manager
            .set_credentials(
                &rack_maintenance_access_token_key(&rack_id),
                &Credentials::UsernamePassword {
                    username: "access_token".into(),
                    password: token,
                },
            )
            .await
    {
        let recovery =
            recover_rack_maintenance_after_credential_failure(db_pool, &rack_id, &scheduled_scope)
                .await;
        return Err(ComponentManagerError::Internal(match recovery {
            Ok(recovery) => format!(
                "failed to store rack maintenance access token: {error}; recovery: {recovery:?}"
            ),
            Err(recovery_error) => format!(
                "failed to store rack maintenance access token: {error}; failed to recover maintenance request: {recovery_error}"
            ),
        }));
    }

    Ok(outcome)
}

#[derive(Debug)]
enum RackMaintenanceCredentialRecovery {
    Cleared,
    RequestChanged,
    ExecutionStarted,
    RackNotFound,
}

async fn recover_rack_maintenance_after_credential_failure(
    db_pool: &PgPool,
    rack_id: &RackId,
    scheduled_scope: &MaintenanceScope,
) -> Result<RackMaintenanceCredentialRecovery, ComponentManagerError> {
    let rack_id = rack_id.clone();
    let scheduled_scope = scheduled_scope.clone();
    let result = db_pool
        .with_txn(|txn| {
            Box::pin(async move {
                if !db::rack::lock_for_update(txn.as_mut(), &rack_id)
                    .await
                    .map_err(|error| ComponentManagerError::Internal(error.to_string()))?
                {
                    return Ok(RackMaintenanceCredentialRecovery::RackNotFound);
                }
                let Some(mut rack) = db::rack::find_by(
                    txn.as_mut(),
                    ObjectColumnFilter::One(db::rack::IdColumn, &rack_id),
                )
                .await
                .map_err(|error| ComponentManagerError::Internal(error.to_string()))?
                .into_iter()
                .next()
                else {
                    return Ok(RackMaintenanceCredentialRecovery::RackNotFound);
                };

                if rack.config.maintenance_requested.as_ref() != Some(&scheduled_scope) {
                    return Ok(RackMaintenanceCredentialRecovery::RequestChanged);
                }

                let state = rack.controller_state.value.clone();
                if !matches!(&state, RackState::Ready | RackState::Error { .. }) {
                    // Once execution starts, clearing the scope would make the rack controller
                    // interpret the default scope as "run all activities". Leave recovery to
                    // its established missing-credential error path instead.
                    tracing::warn!(
                        rack_id = %rack_id,
                        ?state,
                        "rack maintenance started before credential storage failed; leaving cleanup to the rack state controller",
                    );
                    return Ok(RackMaintenanceCredentialRecovery::ExecutionStarted);
                }

                rack.config.maintenance_requested = None;
                db::rack::update(txn.as_mut(), &rack_id, &rack.config)
                    .await
                    .map_err(|error| ComponentManagerError::Internal(error.to_string()))?;
                Ok(RackMaintenanceCredentialRecovery::Cleared)
            })
        })
        .await;

    match result {
        Ok(Ok(recovery)) => Ok(recovery),
        Ok(Err(error)) => Err(error),
        Err(error) => Err(ComponentManagerError::Internal(error.to_string())),
    }
}

impl ComponentManager {
    pub async fn request_switch_maintenance_via_state_controller(
        &self,
        db_pool: &PgPool,
        switch_ids: &[SwitchId],
        operation: SwitchMaintenanceOperation,
        initiator: &str,
    ) -> Result<Vec<SwitchMaintenanceRequestResult>, ComponentManagerError> {
        if !self.nv_switch_use_state_controller {
            return Err(ComponentManagerError::InvalidArgument(
                "nv_switch_use_state_controller is disabled; switch maintenance through the state controller is unavailable"
                    .to_string(),
            ));
        }

        let switch_ids = switch_ids.to_vec();
        let initiator = initiator.to_string();
        db_pool
            .with_txn(|txn| {
                Box::pin(async move {
                    let existing = db::switch::find_by(
                        txn,
                        db::ObjectColumnFilter::List(db::switch::IdColumn, &switch_ids),
                    )
                    .await
                    .map_err(|error| ComponentManagerError::Internal(error.to_string()))?;

                    let by_id: HashMap<SwitchId, model::switch::Switch> =
                        existing.into_iter().map(|sw| (sw.id, sw)).collect();
                    let mut results = Vec::with_capacity(switch_ids.len());

                    for switch_id in &switch_ids {
                        let Some(switch) = by_id.get(switch_id) else {
                            results.push(SwitchMaintenanceRequestResult {
                                switch_id: *switch_id,
                                error: Some(format!("switch {switch_id} not found")),
                            });
                            continue;
                        };

                        if switch.is_marked_as_deleted() {
                            results.push(SwitchMaintenanceRequestResult {
                                switch_id: *switch_id,
                                error: Some(format!("switch {switch_id} is marked for deletion")),
                            });
                            continue;
                        }

                        db::switch::set_switch_maintenance_requested(
                            txn, *switch_id, &initiator, operation,
                        )
                        .await
                        .map_err(|error| ComponentManagerError::Internal(error.to_string()))?;

                        results.push(SwitchMaintenanceRequestResult {
                            switch_id: *switch_id,
                            error: None,
                        });
                    }

                    Ok(results)
                })
            })
            .await
            .map_err(|error| ComponentManagerError::Internal(error.to_string()))?
    }

    pub async fn request_machine_maintenance_via_state_controller(
        &self,
        db_pool: &PgPool,
        machine_ids: &[MachineId],
        operation: MachineMaintenanceOperation,
        initiator: &str,
    ) -> Result<Vec<MachineMaintenanceRequestResult>, ComponentManagerError> {
        if !self.compute_tray_use_state_controller {
            return Err(ComponentManagerError::InvalidArgument(
                "compute_tray_use_state_controller is disabled; machine maintenance through the state controller is unavailable"
                    .to_string(),
            ));
        }

        let machine_ids = machine_ids.to_vec();
        let initiator = initiator.to_string();
        db_pool
            .with_txn(|txn| {
                Box::pin(async move {
                    let existing = db::machine::find(
                        txn.as_mut(),
                        db::ObjectFilter::List(&machine_ids),
                        model::machine::machine_search_config::MachineSearchConfig::default(),
                    )
                    .await
                    .map_err(|error| ComponentManagerError::Internal(error.to_string()))?;

                    let by_id: HashMap<MachineId, model::machine::Machine> = existing
                        .into_iter()
                        .map(|machine| (machine.id, machine))
                        .collect();
                    let mut results = Vec::with_capacity(machine_ids.len());

                    for machine_id in &machine_ids {
                        let Some(machine) = by_id.get(machine_id) else {
                            results.push(MachineMaintenanceRequestResult {
                                machine_id: *machine_id,
                                error: Some(format!("machine {machine_id} not found")),
                            });
                            continue;
                        };

                        if !machine_id.machine_type().is_host() {
                            results.push(MachineMaintenanceRequestResult {
                                machine_id: *machine_id,
                                error: Some(format!("machine {machine_id} is not a host machine")),
                            });
                            continue;
                        }

                        if matches!(
                            machine.state.value,
                            model::machine::ManagedHostState::ForceDeletion
                        ) {
                            results.push(MachineMaintenanceRequestResult {
                                machine_id: *machine_id,
                                error: Some(format!(
                                    "machine {machine_id} is marked for forced deletion"
                                )),
                            });
                            continue;
                        }

                        db::machine::set_machine_maintenance_requested(
                            txn,
                            *machine_id,
                            &initiator,
                            operation,
                        )
                        .await
                        .map_err(|error| ComponentManagerError::Internal(error.to_string()))?;

                        results.push(MachineMaintenanceRequestResult {
                            machine_id: *machine_id,
                            error: None,
                        });
                    }

                    Ok(results)
                })
            })
            .await
            .map_err(|error| ComponentManagerError::Internal(error.to_string()))?
    }

    pub async fn configure_switch_certificate(
        &self,
        endpoint: &SwitchEndpoint,
        domain_name: Option<&str>,
        services: Option<&[i32]>,
    ) -> Result<String, ComponentManagerError> {
        self.nv_switch
            .configure_switch_certificate(endpoint, domain_name, services)
            .await
    }

    pub async fn get_configure_switch_certificate_job_status(
        &self,
        job_id: &str,
    ) -> Result<ConfigureSwitchCertificateJobStatus, ComponentManagerError> {
        self.nv_switch
            .get_configure_switch_certificate_job_status(job_id)
            .await
    }

    /// Starts an NVOS password rotation through the configured switch backend.
    pub async fn start_switch_password_rotation(
        &self,
        endpoint: &SwitchEndpoint,
        next_password: &str,
    ) -> Result<String, ComponentManagerError> {
        self.nv_switch
            .start_password_rotation(endpoint, next_password)
            .await
    }

    /// Returns the latest backend state for an NVOS password-rotation job.
    pub async fn get_switch_password_rotation_job_status(
        &self,
        job_id: &str,
    ) -> Result<SwitchPasswordRotationState, ComponentManagerError> {
        self.nv_switch
            .get_password_rotation_job_status(job_id)
            .await
    }

    pub fn new(
        nv_switch: Arc<dyn NvSwitchManager>,
        power_shelf: Arc<dyn PowerShelfManager>,
        compute_tray: Arc<dyn ComputeTrayManager>,
        nv_switch_use_state_controller: bool,
        power_shelf_use_state_controller: bool,
        compute_tray_use_state_controller: bool,
    ) -> Self {
        Self {
            nv_switch,
            power_shelf,
            compute_tray,
            nv_switch_use_state_controller,
            power_shelf_use_state_controller,
            compute_tray_use_state_controller,
        }
    }
}

/// Build `ComponentManager` from configuration.
///
/// The factory inspects the configured nv-switch, power-shelf, and compute-tray
/// backend selectors to decide which concrete implementations to instantiate.
/// Unknown backend names are rejected at config-deserialization time by the
/// backend enums. When any backend uses RMS, `rack_profiles` must contain enough
/// product-family and vendor data to resolve RMS node types before startup
/// continues.
pub async fn build_component_manager(
    config: &ComponentManagerConfig,
    rack_profiles: RackProfileConfig,
    rms_client: Option<Arc<dyn RmsApi>>,
    rms_switch_system_image_client: Option<Arc<dyn RmsSwitchSystemImageStatusApi>>,
    db: Option<PgPool>,
    redfish_pool: Option<Arc<dyn RedfishClientPool>>,
) -> Result<ComponentManager, ComponentManagerError> {
    validate_rms_backend_rack_profiles(config, &rack_profiles)?;

    let rack_profiles = Arc::new(rack_profiles);

    let nv_switch: Arc<dyn NvSwitchManager> = match config.nv_switch_backend {
        NvSwitchBackend::Nsm => {
            let endpoint = config.nsm.as_ref().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "nv_switch_backend is 'nsm' but [component_manager.nsm] config is missing"
                        .into(),
                )
            })?;
            Arc::new(
                crate::nsm::NsmSwitchBackend::connect(&endpoint.url, endpoint.tls.as_ref()).await?,
            )
        }
        NvSwitchBackend::Rms => {
            let client = rms_client.clone().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "nv_switch_backend is 'rms' but RMS client is not configured".into(),
                )
            })?;
            let db = db.clone().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "nv_switch_backend is 'rms' but database pool is not configured".into(),
                )
            })?;
            Arc::new(crate::rms::RmsBackend::new(
                client,
                rms_switch_system_image_client.clone(),
                db,
                rack_profiles.clone(),
                config.nvos_password_rotation_enabled,
            ))
        }
        NvSwitchBackend::Mock => Arc::new(crate::mock::MockNvSwitchManager::default()),
    };

    let power_shelf: Arc<dyn PowerShelfManager> = match config.power_shelf_backend {
        PowerShelfBackend::Psm => {
            let endpoint = config.psm.as_ref().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "power_shelf_backend is 'psm' but [component_manager.psm] config is missing"
                        .into(),
                )
            })?;
            Arc::new(
                crate::psm::PsmPowerShelfBackend::connect(&endpoint.url, endpoint.tls.as_ref())
                    .await?,
            )
        }
        PowerShelfBackend::Rms => {
            let client = rms_client.clone().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "power_shelf_backend is 'rms' but RMS client is not configured".into(),
                )
            })?;
            let db = db.clone().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "power_shelf_backend is 'rms' but database pool is not configured".into(),
                )
            })?;
            Arc::new(crate::rms::RmsBackend::new(
                client,
                rms_switch_system_image_client.clone(),
                db,
                rack_profiles.clone(),
                config.nvos_password_rotation_enabled,
            ))
        }
        PowerShelfBackend::Mock => Arc::new(crate::mock::MockPowerShelfManager),
    };

    let compute_tray: Arc<dyn ComputeTrayManager> = match config.compute_tray_backend {
        ComputeBackend::Rms => {
            let client = rms_client.clone().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "compute_tray_backend is 'rms' but RMS client is not configured".into(),
                )
            })?;
            let db = db.clone().ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "compute_tray_backend is 'rms' but database pool is not configured".into(),
                )
            })?;
            Arc::new(crate::rms::RmsBackend::new(
                client,
                rms_switch_system_image_client.clone(),
                db,
                rack_profiles.clone(),
                config.nvos_password_rotation_enabled,
            ))
        }
        ComputeBackend::Core => {
            let pool = redfish_pool.ok_or_else(|| {
                ComponentManagerError::InvalidArgument(
                    "compute_tray_backend is 'core' but Redfish client pool is not configured"
                        .into(),
                )
            })?;
            Arc::new(crate::core_compute_manager::CoreComputeTrayManager::new(
                pool,
            ))
        }
        ComputeBackend::Mock => Arc::new(crate::mock::MockComputeTrayManager),
    };

    Ok(ComponentManager::new(
        nv_switch,
        power_shelf,
        compute_tray,
        config.nv_switch_use_state_controller,
        config.power_shelf_use_state_controller,
        config.compute_tray_use_state_controller,
    ))
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use carbide_secrets::SecretsError;
    use carbide_secrets::credentials::{CredentialKey, CredentialReader, CredentialWriter};
    use carbide_secrets::test_support::credentials::TestCredentialManager;
    use carbide_uuid::rack::RackId;
    use db::ObjectColumnFilter;
    use model::rack::{
        FirmwareUpgradeJob, MaintenanceActivity, MaintenanceScope, RackConfig, RackState,
    };
    use model::rack_type::{
        RackCapabilitiesSet, RackCapabilityCompute, RackCapabilityPowerShelf, RackCapabilitySwitch,
        RackHardwareTopology, RackProductFamily, RackProfile,
    };

    use super::*;
    use crate::config::ComponentManagerConfig;

    struct FailingCredentialManager;

    #[async_trait]
    impl CredentialReader for FailingCredentialManager {
        async fn get_credentials(
            &self,
            _key: &CredentialKey,
        ) -> Result<Option<Credentials>, SecretsError> {
            Ok(None)
        }
    }

    #[async_trait]
    impl CredentialWriter for FailingCredentialManager {
        async fn set_credentials(
            &self,
            _key: &CredentialKey,
            _credentials: &Credentials,
        ) -> Result<(), SecretsError> {
            Err(SecretsError::GenericError(
                std::io::Error::other("test credential write failure").into(),
            ))
        }

        async fn create_credentials(
            &self,
            _key: &CredentialKey,
            _credentials: &Credentials,
        ) -> Result<(), SecretsError> {
            unreachable!("test only exercises set_credentials")
        }

        async fn delete_credentials(&self, _key: &CredentialKey) -> Result<(), SecretsError> {
            Ok(())
        }
    }

    impl CredentialManager for FailingCredentialManager {}

    async fn create_rack_in_state(pool: &PgPool, state: RackState) -> RackId {
        let rack_id = RackId::new(uuid::Uuid::new_v4().to_string());
        let mut txn = pool.begin().await.unwrap();
        let rack = db::rack::create(txn.as_mut(), &rack_id, None, &RackConfig::default(), None)
            .await
            .unwrap();
        if state != RackState::Created {
            assert!(
                db::rack::try_update_controller_state(
                    txn.as_mut(),
                    &rack_id,
                    rack.controller_state.version,
                    rack.controller_state.version.increment(),
                    &state,
                )
                .await
                .unwrap()
            );
        }
        txn.commit().await.unwrap();
        rack_id
    }

    async fn load_rack(pool: &PgPool, rack_id: &RackId) -> model::rack::Rack {
        let mut conn = pool.acquire().await.unwrap();
        db::rack::find_by(
            conn.as_mut(),
            ObjectColumnFilter::One(db::rack::IdColumn, rack_id),
        )
        .await
        .unwrap()
        .pop()
        .unwrap()
    }

    fn nmx_scope() -> MaintenanceScope {
        MaintenanceScope {
            activities: vec![MaintenanceActivity::ConfigureNmxCluster],
            ..Default::default()
        }
    }

    #[carbide_macros::sqlx_test]
    async fn rack_maintenance_scheduler_is_atomic_and_idempotent(pool: PgPool) {
        let ready_rack = create_rack_in_state(&pool, RackState::Ready).await;
        let scope = nmx_scope();

        assert_eq!(
            request_rack_maintenance_via_state_controller(
                &pool,
                &ready_rack,
                scope.clone(),
                RackMaintenanceEligibility::RequireReady,
                None,
            )
            .await
            .unwrap(),
            RackMaintenanceRequestOutcome::Scheduled,
        );
        assert_eq!(
            load_rack(&pool, &ready_rack)
                .await
                .config
                .maintenance_requested,
            Some(scope.clone()),
        );

        // Exact retries are idempotent, including after the rack state has
        // moved on. A different request is busy and cannot replace it.
        let rack = load_rack(&pool, &ready_rack).await;
        let mut txn = pool.begin().await.unwrap();
        assert!(
            db::rack::try_update_controller_state(
                txn.as_mut(),
                &ready_rack,
                rack.controller_state.version,
                rack.controller_state.version.increment(),
                &RackState::Discovering,
            )
            .await
            .unwrap()
        );
        txn.commit().await.unwrap();
        assert_eq!(
            request_rack_maintenance_via_state_controller(
                &pool,
                &ready_rack,
                scope.clone(),
                RackMaintenanceEligibility::RequireReady,
                None,
            )
            .await
            .unwrap(),
            RackMaintenanceRequestOutcome::AlreadyPending,
        );

        let unrelated_scope = MaintenanceScope {
            activities: vec![MaintenanceActivity::PowerSequence],
            ..Default::default()
        };
        assert_eq!(
            request_rack_maintenance_via_state_controller(
                &pool,
                &ready_rack,
                unrelated_scope,
                RackMaintenanceEligibility::RequireReady,
                None,
            )
            .await
            .unwrap(),
            RackMaintenanceRequestOutcome::Busy,
        );
        assert_eq!(
            load_rack(&pool, &ready_rack)
                .await
                .config
                .maintenance_requested,
            Some(scope),
        );

        // Automatic callers defer non-Ready racks; operator callers may
        // explicitly opt into recovering a rack from Error.
        let error_state = RackState::Error {
            cause: "test".into(),
        };
        let error_rack = create_rack_in_state(&pool, error_state.clone()).await;
        assert_eq!(
            request_rack_maintenance_via_state_controller(
                &pool,
                &error_rack,
                nmx_scope(),
                RackMaintenanceEligibility::RequireReady,
                None,
            )
            .await
            .unwrap(),
            RackMaintenanceRequestOutcome::Deferred { state: error_state },
        );
        assert_eq!(
            request_rack_maintenance_via_state_controller(
                &pool,
                &error_rack,
                nmx_scope(),
                RackMaintenanceEligibility::AllowErrorRecovery,
                None,
            )
            .await
            .unwrap(),
            RackMaintenanceRequestOutcome::Scheduled,
        );

        // Two different requests racing for an empty slot serialize on the
        // rack row: one wins and the other observes Busy.
        let race_rack = create_rack_in_state(&pool, RackState::Ready).await;
        let first_scope = MaintenanceScope {
            activities: vec![MaintenanceActivity::FirmwareUpgrade {
                firmware_version: Some(r#"{"Id":"first"}"#.into()),
                components: vec![],
                force_update: false,
            }],
            ..Default::default()
        };
        let second_scope = MaintenanceScope {
            activities: vec![MaintenanceActivity::FirmwareUpgrade {
                firmware_version: Some(r#"{"Id":"second"}"#.into()),
                components: vec![],
                force_update: false,
            }],
            ..Default::default()
        };
        let credential_manager = TestCredentialManager::default();
        let (first, second) = tokio::join!(
            request_rack_maintenance_via_state_controller(
                &pool,
                &race_rack,
                first_scope,
                RackMaintenanceEligibility::RequireReady,
                Some(RackMaintenanceAccessToken {
                    credential_manager: &credential_manager,
                    token: "first-token".into(),
                }),
            ),
            request_rack_maintenance_via_state_controller(
                &pool,
                &race_rack,
                second_scope,
                RackMaintenanceEligibility::RequireReady,
                Some(RackMaintenanceAccessToken {
                    credential_manager: &credential_manager,
                    token: "second-token".into(),
                }),
            ),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        let winning_token = match (&first, &second) {
            (RackMaintenanceRequestOutcome::Scheduled, RackMaintenanceRequestOutcome::Busy) => {
                "first-token"
            }
            (RackMaintenanceRequestOutcome::Busy, RackMaintenanceRequestOutcome::Scheduled) => {
                "second-token"
            }
            unexpected => panic!("expected one Scheduled and one Busy outcome, got {unexpected:?}"),
        };
        let stored_credentials = credential_manager
            .get_credentials(&CredentialKey::RackMaintenanceAccessToken {
                rack_id: race_rack.clone(),
            })
            .await
            .unwrap()
            .expect("the winning request should persist its token");
        assert_eq!(
            stored_credentials,
            Credentials::UsernamePassword {
                username: "access_token".into(),
                password: winning_token.into(),
            }
        );

        // Firmware bookkeeping is cleared in the same transaction that
        // accepts a firmware maintenance request.
        let firmware_rack = create_rack_in_state(&pool, RackState::Ready).await;
        let mut txn = pool.begin().await.unwrap();
        db::rack::update_firmware_upgrade_job(
            txn.as_mut(),
            &firmware_rack,
            Some(&FirmwareUpgradeJob {
                job_id: Some("stale-job".into()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        txn.commit().await.unwrap();
        let firmware_scope = MaintenanceScope {
            activities: vec![MaintenanceActivity::FirmwareUpgrade {
                firmware_version: Some("{}".into()),
                components: vec![],
                force_update: false,
            }],
            ..Default::default()
        };
        assert_eq!(
            request_rack_maintenance_via_state_controller(
                &pool,
                &firmware_rack,
                firmware_scope,
                RackMaintenanceEligibility::RequireReady,
                None,
            )
            .await
            .unwrap(),
            RackMaintenanceRequestOutcome::Scheduled,
        );
        assert!(
            load_rack(&pool, &firmware_rack)
                .await
                .firmware_upgrade_job
                .is_none()
        );

        // Soft-deleted racks cannot accept new maintenance work.
        let deleted_rack = create_rack_in_state(&pool, RackState::Ready).await;
        let mut txn = pool.begin().await.unwrap();
        db::rack::mark_as_deleted(&deleted_rack, txn.as_mut())
            .await
            .unwrap();
        txn.commit().await.unwrap();
        assert!(matches!(
            request_rack_maintenance_via_state_controller(
                &pool,
                &deleted_rack,
                nmx_scope(),
                RackMaintenanceEligibility::RequireReady,
                None,
            )
            .await,
            Err(ComponentManagerError::NotFound(_)),
        ));

        // Credential storage happens after commit. If it fails before the rack controller
        // starts the request, the compensating transaction removes that exact request.
        let credential_failure_rack = create_rack_in_state(&pool, RackState::Ready).await;
        let credential_failure_scope = MaintenanceScope {
            activities: vec![MaintenanceActivity::FirmwareUpgrade {
                firmware_version: Some("{}".into()),
                components: vec![],
                force_update: false,
            }],
            ..Default::default()
        };
        let error = request_rack_maintenance_via_state_controller(
            &pool,
            &credential_failure_rack,
            credential_failure_scope,
            RackMaintenanceEligibility::RequireReady,
            Some(RackMaintenanceAccessToken {
                credential_manager: &FailingCredentialManager,
                token: "test-token".into(),
            }),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("recovery: Cleared"),
            "unexpected error: {error}"
        );
        assert!(
            load_rack(&pool, &credential_failure_rack)
                .await
                .config
                .maintenance_requested
                .is_none()
        );
    }

    fn rms_rack_profiles(profile: RackProfile) -> RackProfileConfig {
        RackProfileConfig {
            rack_profiles: [("NVL72".to_string(), profile)].into_iter().collect(),
        }
    }

    fn rms_rack_profile() -> RackProfile {
        RackProfile {
            product_family: Some(RackProductFamily::Gb200),
            rack_hardware_topology: Some(RackHardwareTopology::Gb200Nvl72r1C2g4Topology),
            rack_capabilities: RackCapabilitiesSet {
                compute: RackCapabilityCompute {
                    vendor: Some("NVIDIA".to_string()),
                    ..Default::default()
                },
                switch: RackCapabilitySwitch {
                    vendor: Some("NVIDIA".to_string()),
                    ..Default::default()
                },
                power_shelf: RackCapabilityPowerShelf {
                    vendor: Some("LiteOn".to_string()),
                    ..Default::default()
                },
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn build_with_mock_backends() {
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Mock,
            power_shelf_backend: PowerShelfBackend::Mock,
            compute_tray_backend: ComputeBackend::Mock,
            ..Default::default()
        };

        let cm = build_component_manager(&config, Default::default(), None, None, None, None)
            .await
            .unwrap();

        assert_eq!(cm.nv_switch.name(), "mock-nsm");
        assert_eq!(cm.power_shelf.name(), "mock-psm");
        assert_eq!(cm.compute_tray.name(), "mock-ctm");
    }

    #[test]
    fn deserialize_rejects_unknown_backend_names() {
        use serde::Deserialize;
        use serde::de::IntoDeserializer;
        use serde::de::value::{Error as DeError, StrDeserializer};

        let de: StrDeserializer<DeError> = "bogus".into_deserializer();
        assert!(NvSwitchBackend::deserialize(de).is_err());
        let de: StrDeserializer<DeError> = "bogus".into_deserializer();
        assert!(PowerShelfBackend::deserialize(de).is_err());
        let de: StrDeserializer<DeError> = "bogus".into_deserializer();
        assert!(ComputeBackend::deserialize(de).is_err());
    }

    #[tokio::test]
    async fn build_nsm_without_config_returns_error() {
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Nsm,
            power_shelf_backend: PowerShelfBackend::Mock,
            compute_tray_backend: ComputeBackend::Mock,
            ..Default::default()
        };

        let err = build_component_manager(&config, Default::default(), None, None, None, None)
            .await
            .unwrap_err();

        assert!(matches!(err, ComponentManagerError::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn build_psm_without_config_returns_error() {
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Mock,
            power_shelf_backend: PowerShelfBackend::Psm,
            compute_tray_backend: ComputeBackend::Mock,
            ..Default::default()
        };

        let err = build_component_manager(&config, Default::default(), None, None, None, None)
            .await
            .unwrap_err();

        assert!(matches!(err, ComponentManagerError::InvalidArgument(_)));
    }

    // A config that explicitly selects working switch/power-shelf backends but
    // leaves `compute_tray_backend` at its default (now `Rms`) must not be able
    // to silently come up half-configured: RMS validation rejects missing rack
    // profile config before any partial component manager can be built. This
    // keeps the default flip to RMS a deliberate, visible choice.
    #[tokio::test]
    async fn rms_compute_tray_default_requires_rack_profiles() {
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Mock,
            power_shelf_backend: PowerShelfBackend::Mock,
            // compute_tray_backend intentionally left at its default.
            ..Default::default()
        };

        assert_eq!(config.compute_tray_backend, ComputeBackend::Rms);

        let err = build_component_manager(&config, Default::default(), None, None, None, None)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            ComponentManagerError::InvalidArgument(msg)
                if msg.contains("rack_profiles must contain at least one profile")
        ));
    }

    #[tokio::test]
    async fn build_requires_rack_profiles_for_rms_backend() {
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Rms,
            power_shelf_backend: PowerShelfBackend::Mock,
            compute_tray_backend: ComputeBackend::Mock,
            ..Default::default()
        };

        let result =
            build_component_manager(&config, Default::default(), None, None, None, None).await;
        let Err(error) = result else {
            panic!("missing RMS rack profiles should be rejected");
        };

        assert_eq!(
            error.to_string(),
            "invalid argument: rack_profiles must contain at least one profile when component_manager uses an RMS backend"
        );
    }

    #[tokio::test]
    async fn build_requires_vendor_for_rms_backend_role() {
        let mut profile = rms_rack_profile();
        profile.rack_capabilities.power_shelf.vendor = None;

        let rack_profiles = rms_rack_profiles(profile);
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Mock,
            power_shelf_backend: PowerShelfBackend::Rms,
            compute_tray_backend: ComputeBackend::Mock,
            ..Default::default()
        };

        let result = build_component_manager(&config, rack_profiles, None, None, None, None).await;
        let Err(error) = result else {
            panic!("missing RMS vendor should be rejected");
        };

        assert_eq!(
            error.to_string(),
            "invalid argument: rack profile NVL72 rack_capabilities.power_shelf.vendor is required when power_shelf_backend is 'rms'"
        );
    }

    #[tokio::test]
    async fn build_validates_rms_backend_vendor_value() {
        let mut profile = rms_rack_profile();
        profile.rack_capabilities.switch.vendor = Some("Other".to_string());

        let rack_profiles = rms_rack_profiles(profile);
        let config = ComponentManagerConfig {
            nv_switch_backend: NvSwitchBackend::Rms,
            power_shelf_backend: PowerShelfBackend::Mock,
            compute_tray_backend: ComputeBackend::Mock,
            ..Default::default()
        };

        let result = build_component_manager(&config, rack_profiles, None, None, None, None).await;
        let Err(error) = result else {
            panic!("unsupported RMS vendor should be rejected");
        };

        assert_eq!(
            error.to_string(),
            "invalid argument: rack profile NVL72 cannot resolve RMS switch node type: RMS does not support switch vendor Other"
        );
    }
}
