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

//! Tests that DPF state handling is safe under duplicate events.
//!
//! The DPF watcher fires callbacks on every DPU resource update, not
//! only on phase transitions. Each callback enqueues the host for state
//! handling, so duplicate events cause the state controller to process
//! the same host multiple times in the same state. These tests verify
//! that repeated processing produces the same correct outcome.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use carbide_dpf::DpuPhase;
use carbide_redfish::libredfish::test_support::RedfishSimAction;
use carbide_uuid::machine::MachineId;
use libredfish::SystemPowerControl;
use model::machine::{DpfState, DpuInitState, ManagedHostState};
use tokio::time::timeout;

use crate::dpf::MockDpfOperations;
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, TestManagedHost, create_managed_host_with_dpf,
    create_test_env_with_overrides, get_config, reboot_completed,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(30);
const DUPLICATE_ITERATIONS: usize = 10;

fn dpf_left_operator_provisioning_substates(host: &ManagedHostState) -> bool {
    match host {
        ManagedHostState::DPUInit { dpu_states } => dpu_states
            .states
            .values()
            .all(|s| !matches!(s, DpuInitState::DpfStates { .. })),
        ManagedHostState::HostInit { .. } => true,
        _ => false,
    }
}

fn dpf_config() -> crate::cfg::file::DpfConfig {
    crate::cfg::file::DpfConfig {
        enabled: true,
        bfb_url: "http://example.com/test.bfb".to_string(),
        v2: true,
        ..Default::default()
    }
}

fn expect_provisioning(mock: &mut MockDpfOperations) {
    mock.expect_register_dpu_device().returning(|_| Ok(()));
    mock.expect_register_dpu_node().returning(|_| Ok(()));
    mock.expect_verify_node_labels().returning(|_| Ok(true));
}

async fn reset_host_to_waiting_for_ready(
    pool: &sqlx::PgPool,
    host_id: &MachineId,
    dpu_id: &MachineId,
) {
    let state = ManagedHostState::DPUInit {
        dpu_states: model::machine::DpuInitStates {
            states: HashMap::from([(
                *dpu_id,
                DpuInitState::DpfStates {
                    state: DpfState::WaitingForReady { phase_detail: None },
                },
            )]),
        },
    };
    let state_json = serde_json::to_value(&state).unwrap();
    let version = format!("V999-T{}", chrono::Utc::now().timestamp_micros());

    sqlx::query(
        "UPDATE machines SET \
            controller_state = $1, \
            controller_state_version = $2, \
            controller_state_outcome = NULL, \
            health_reports = '{\"merges\": {}, \"replace\": null}'::jsonb, \
            last_reboot_requested = NULL, \
            last_reboot_time = NULL \
         WHERE id = $3",
    )
    .bind(sqlx::types::Json(&state_json))
    .bind(&version)
    .bind(host_id)
    .execute(pool)
    .await
    .unwrap();
}

async fn get_host_state(
    env: &crate::tests::common::api_fixtures::TestEnv,
    mh: &TestManagedHost,
) -> ManagedHostState {
    let mut txn = env.db_txn().await;
    let machine = mh.host().db_machine(&mut txn).await;
    machine.state.value
}

/// Many iterations while the device is ready and no reboot is required.
/// The host must leave DPF `DpfStates` (or enter host init) and stay there
/// despite repeated processing.
#[crate::sqlx_test]
async fn test_duplicate_ready_events_reach_ready(pool: sqlx::PgPool) {
    let mut mock = MockDpfOperations::new();
    expect_provisioning(&mut mock);
    mock.expect_get_dpu_phase()
        .returning(|_, _| Ok(DpuPhase::Ready));
    mock.expect_release_maintenance_hold().returning(|_| Ok(()));
    mock.expect_is_reboot_required().returning(|_| Ok(false));

    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> = Arc::new(mock);
    let mut config = get_config();
    config.dpf = dpf_config();

    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await;

    let mh = timeout(TEST_TIMEOUT, create_managed_host_with_dpf(&env))
        .await
        .expect("timed out during initial provisioning");

    reset_host_to_waiting_for_ready(&pool, &mh.id, &mh.dpu_ids[0]).await;

    // Simulate duplicate events: run many iterations for the same state.
    timeout(TEST_TIMEOUT, async {
        for _ in 0..DUPLICATE_ITERATIONS {
            env.run_machine_state_controller_iteration().await;
        }
    })
    .await
    .expect("timed out during duplicate iterations");

    let host = get_host_state(&env, &mh).await;
    assert!(
        dpf_left_operator_provisioning_substates(&host),
        "Host should have left DPF operator substates after {} iterations, got: {:?}",
        DUPLICATE_ITERATIONS,
        host
    );
}

/// Many iterations while reboot is required. ForceOff must be issued
/// exactly once regardless of how many times the state is processed.
#[crate::sqlx_test]
async fn test_duplicate_reboot_events_send_single_reboot(pool: sqlx::PgPool) {
    let mut mock = MockDpfOperations::new();
    expect_provisioning(&mut mock);

    let dpu_ready = Arc::new(AtomicBool::new(true));
    let dr = dpu_ready.clone();
    mock.expect_get_dpu_phase().returning(move |_, _| {
        if dr.load(Ordering::SeqCst) {
            Ok(DpuPhase::Ready)
        } else {
            Ok(DpuPhase::Provisioning("OsInstalling".into()))
        }
    });
    mock.expect_release_maintenance_hold().returning(|_| Ok(()));

    let reboot_required = Arc::new(AtomicBool::new(false));
    let rr = reboot_required.clone();
    mock.expect_is_reboot_required()
        .returning(move |_| Ok(rr.load(Ordering::SeqCst)));
    let rr2 = reboot_required.clone();
    mock.expect_reboot_complete()
        .times(1..)
        .returning(move |_| {
            rr2.store(false, Ordering::SeqCst);
            Ok(())
        });

    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> = Arc::new(mock);
    let mut config = get_config();
    config.dpf = dpf_config();

    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await;

    let mh = timeout(TEST_TIMEOUT, create_managed_host_with_dpf(&env))
        .await
        .expect("timed out during initial provisioning");

    reboot_required.store(true, Ordering::SeqCst);
    dpu_ready.store(false, Ordering::SeqCst);

    reset_host_to_waiting_for_ready(&pool, &mh.id, &mh.dpu_ids[0]).await;

    let redfish_timepoint = env.redfish_sim.timepoint();

    // Simulate duplicate reboot events: many iterations in the same state.
    timeout(TEST_TIMEOUT, async {
        for _ in 0..DUPLICATE_ITERATIONS {
            env.run_machine_state_controller_iteration().await;
        }
    })
    .await
    .expect("timed out during duplicate iterations");

    let actions = env
        .redfish_sim
        .actions_since(&redfish_timepoint)
        .all_hosts();
    let force_off_count = actions
        .iter()
        .filter(|x| matches!(x, RedfishSimAction::Power(SystemPowerControl::ForceOff)))
        .count();

    assert_eq!(
        force_off_count, 1,
        "ForceOff must be sent exactly once despite {} duplicate iterations, got {}",
        DUPLICATE_ITERATIONS, force_off_count
    );
}

/// Many iterations after reboot completes. The host must leave DPF `DpfStates`
/// and not regress or panic.
#[crate::sqlx_test]
async fn test_duplicate_events_after_reboot_complete(pool: sqlx::PgPool) {
    let mut mock = MockDpfOperations::new();
    expect_provisioning(&mut mock);

    mock.expect_get_dpu_phase()
        .returning(|_, _| Ok(DpuPhase::Ready));
    mock.expect_release_maintenance_hold().returning(|_| Ok(()));

    let reboot_required = Arc::new(AtomicBool::new(false));
    let rr = reboot_required.clone();
    mock.expect_is_reboot_required()
        .returning(move |_| Ok(rr.load(Ordering::SeqCst)));
    let rr2 = reboot_required.clone();
    mock.expect_reboot_complete().returning(move |_| {
        rr2.store(false, Ordering::SeqCst);
        Ok(())
    });

    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> = Arc::new(mock);
    let mut config = get_config();
    config.dpf = dpf_config();

    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await;

    let mh = timeout(TEST_TIMEOUT, create_managed_host_with_dpf(&env))
        .await
        .expect("timed out during initial provisioning");

    reboot_required.store(true, Ordering::SeqCst);

    reset_host_to_waiting_for_ready(&pool, &mh.id, &mh.dpu_ids[0]).await;

    // Process through reboot.
    timeout(TEST_TIMEOUT, async {
        for _ in 0..3 {
            env.run_machine_state_controller_iteration().await;
        }
    })
    .await
    .expect("timed out during reboot iterations");

    reboot_completed(&env, mh.id).await;

    // Simulate duplicate events after reboot: many iterations.
    timeout(TEST_TIMEOUT, async {
        for _ in 0..DUPLICATE_ITERATIONS {
            env.run_machine_state_controller_iteration().await;
        }
    })
    .await
    .expect("timed out during post-reboot duplicate iterations");

    let host = get_host_state(&env, &mh).await;
    assert!(
        dpf_left_operator_provisioning_substates(&host),
        "Host should have left DPF operator substates after reboot + {} duplicate iterations, got: {:?}",
        DUPLICATE_ITERATIONS,
        host
    );
}

/// Duplicate events while the DPU CR is NOT ready. The host must stay
/// in DPUInit/WaitingForReady without panicking or regressing.
#[crate::sqlx_test]
async fn test_duplicate_events_while_not_ready(pool: sqlx::PgPool) {
    let mut mock = MockDpfOperations::new();
    expect_provisioning(&mut mock);

    let dpu_ready = Arc::new(AtomicBool::new(true));
    let dr = dpu_ready.clone();
    mock.expect_get_dpu_phase().returning(move |_, _| {
        if dr.load(Ordering::SeqCst) {
            Ok(DpuPhase::Ready)
        } else {
            Ok(DpuPhase::Provisioning("OsInstalling".into()))
        }
    });
    mock.expect_release_maintenance_hold().returning(|_| Ok(()));
    mock.expect_is_reboot_required().returning(|_| Ok(false));

    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> = Arc::new(mock);
    let mut config = get_config();
    config.dpf = dpf_config();

    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await;

    let mh = timeout(TEST_TIMEOUT, create_managed_host_with_dpf(&env))
        .await
        .expect("timed out during initial provisioning");

    dpu_ready.store(false, Ordering::SeqCst);

    reset_host_to_waiting_for_ready(&pool, &mh.id, &mh.dpu_ids[0]).await;

    // Simulate many duplicate events while DPU is not ready.
    timeout(TEST_TIMEOUT, async {
        for _ in 0..DUPLICATE_ITERATIONS {
            env.run_machine_state_controller_iteration().await;
        }
    })
    .await
    .expect("timed out during duplicate iterations");

    let host = get_host_state(&env, &mh).await;
    assert!(
        matches!(host, ManagedHostState::DPUInit { .. }),
        "Host should remain in DPUInit while DPU is not ready, got: {:?}",
        host
    );

    // Now make DPU ready and run more duplicate iterations.
    dpu_ready.store(true, Ordering::SeqCst);

    timeout(TEST_TIMEOUT, async {
        for _ in 0..DUPLICATE_ITERATIONS {
            env.run_machine_state_controller_iteration().await;
        }
    })
    .await
    .expect("timed out during post-ready duplicate iterations");

    let host = get_host_state(&env, &mh).await;
    assert!(
        dpf_left_operator_provisioning_substates(&host),
        "Host should have left DPF operator substates after DPU became ready, got: {:?}",
        host
    );
}
