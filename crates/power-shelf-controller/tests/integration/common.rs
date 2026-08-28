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

use std::sync::Arc;
use std::time::Duration;

use carbide_health_metrics::PerObjectMetricsRegistry;
use carbide_power_shelf_controller::context::{
    PowerShelfStateHandlerContextObjects, PowerShelfStateHandlerServices,
};
use carbide_power_shelf_controller::handler::PowerShelfStateHandler;
use carbide_power_shelf_controller::metrics::PowerShelfMetrics;
use carbide_rack::rms_client::test_support::RmsSim;
use carbide_redfish::libredfish::test_support::RedfishSim;
use carbide_secrets::test_support::credentials::TestCredentialManager;
use carbide_test_harness::TestHarness;
use carbide_uuid::power_shelf::PowerShelfId;
use component_manager::compute_tray_manager::Backend as ComputeBackend;
use component_manager::config::ComponentManagerConfig;
use component_manager::nv_switch_manager::Backend as NvSwitchBackend;
use component_manager::power_shelf_manager::Backend as PowerShelfBackend;
use db::power_shelf as db_power_shelf;
use model::power_shelf::{PowerShelf, PowerShelfControllerState};
use model::rack_type::RackProfileConfig;
use model::test_support::rms_rack_profiles;
use sqlx::{PgConnection, PgPool};
use state_controller::db_write_batch::DbWriteBatch;
use state_controller::state_handler::{StateHandler, StateHandlerContext, StateHandlerOutcome};

pub(super) struct ControllerEnv {
    pub(super) harness: TestHarness,
    pub(super) pool: PgPool,
    pub(super) redfish_sim: Arc<RedfishSim>,
    pub(super) rms_sim: Arc<RmsSim>,
    pub(super) rack_profiles: RackProfileConfig,
    pub(super) per_object_metrics_registry: Arc<PerObjectMetricsRegistry>,
}

impl ControllerEnv {
    pub(super) async fn new(pool: PgPool) -> Self {
        let redfish_sim = Arc::new(RedfishSim::default());
        let rms_sim = Arc::new(RmsSim::default());
        let rack_profiles = rms_rack_profiles();
        let mut runtime_config = carbide_test_harness::test_support::default_config::get();
        runtime_config.rack_profiles = rack_profiles.clone();
        let per_object_metrics_registry = PerObjectMetricsRegistry::new(
            runtime_config
                .observability
                .per_object_metrics_for_classifications
                .clone(),
            Duration::from_secs(60),
        );
        let api_component_manager = component_manager::component_manager::build_component_manager(
            &ComponentManagerConfig {
                nv_switch_backend: NvSwitchBackend::Rms,
                power_shelf_backend: PowerShelfBackend::Rms,
                compute_tray_backend: ComputeBackend::Mock,
                nv_switch_use_state_controller: true,
                power_shelf_use_state_controller: true,
                ..Default::default()
            },
            rack_profiles.clone(),
            rms_sim.as_rms_client(),
            None,
            Some(pool.clone()),
            None,
        )
        .await
        .expect("test component manager should build");
        let api_redfish_sim = redfish_sim.clone();
        let api_rms_client = rms_sim
            .as_rms_client()
            .expect("RMS simulator should provide a client");
        let runtime_config = Arc::new(runtime_config);
        let harness = TestHarness::builder(pool.clone())
            .with_api_builder_fn(move |builder| {
                builder
                    .with_runtime_config(runtime_config)
                    .with_redfish_pool(api_redfish_sim)
                    .with_rms_client(api_rms_client)
                    .with_component_manager(Arc::new(api_component_manager))
            })
            .build()
            .await;

        Self {
            harness,
            pool,
            redfish_sim,
            rms_sim,
            rack_profiles,
            per_object_metrics_registry,
        }
    }
}

pub(super) fn services_without_component_manager(
    pool: &PgPool,
    rack_firmware_reprovisioning_enabled: bool,
) -> PowerShelfStateHandlerServices {
    PowerShelfStateHandlerServices {
        db_pool: pool.clone(),
        component_manager: None,
        credential_manager: Arc::new(TestCredentialManager::default()),
        per_object_metrics_registry: carbide_health_metrics::PerObjectMetricsRegistry::new(
            Vec::new(),
            Duration::from_secs(60),
        ),
        rack_firmware_reprovisioning_enabled,
        redfish_client_pool: Arc::new(RedfishSim::default()),
        bmc_rotation_gate: carbide_credential_rotation::RotationGate::new_for_family(
            db::credential_rotation::CredentialRotationType::Bmc,
        ),
        bmc_rotation_enabled: false,
    }
}

pub(super) async fn load_power_shelf(pool: &PgPool, id: &PowerShelfId) -> PowerShelf {
    let mut conn = pool.acquire().await.unwrap();
    db_power_shelf::find_by_id(conn.as_mut(), id)
        .await
        .unwrap()
        .expect("power shelf should exist")
}

pub(super) async fn run_handler(
    services: &mut PowerShelfStateHandlerServices,
    state: &mut PowerShelf,
) -> StateHandlerOutcome<PowerShelfControllerState> {
    let handler = PowerShelfStateHandler::default();
    let mut metrics = PowerShelfMetrics::default();
    let mut writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<PowerShelfStateHandlerContextObjects> {
        services,
        metrics: &mut metrics,
        pending_db_writes: &mut writes,
    };
    let controller_state = state.controller_state.value.clone();
    let power_shelf_id = state.id;
    handler
        .handle_object_state(&power_shelf_id, state, &controller_state, &mut ctx)
        .await
        .expect("state handler should not return an error result")
}

pub(super) fn extract_transition(
    outcome: StateHandlerOutcome<PowerShelfControllerState>,
) -> Option<PowerShelfControllerState> {
    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => Some(next_state),
        _ => None,
    }
}

pub(super) async fn set_power_shelf_controller_state(
    txn: &mut PgConnection,
    power_shelf_id: &PowerShelfId,
    state: PowerShelfControllerState,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE power_shelves SET controller_state = $1 WHERE id = $2")
        .bind(serde_json::to_value(state).unwrap())
        .bind(power_shelf_id)
        .execute(txn)
        .await?;

    Ok(())
}

pub(super) async fn mark_power_shelf_as_deleted(
    txn: &mut PgConnection,
    power_shelf_id: &PowerShelfId,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE power_shelves SET deleted = NOW() WHERE id = $1")
        .bind(power_shelf_id)
        .execute(txn)
        .await?;

    Ok(())
}
