/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Tests for the WaitingForReady DPF state handler.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use carbide_dpf::DpuPhase;
use carbide_uuid::machine::MachineId;
use libredfish::SystemPowerControl;
use model::machine::{DpfState, DpuInitState, ManagedHostState};
use tokio::time::timeout;

use crate::dpf::MockDpfOperations;
use crate::redfish::test_support::RedfishSimAction;
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, TestManagedHost, create_managed_host_with_dpf,
    create_test_env_with_overrides, get_config, reboot_completed,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Set up the initial provisioning expectations shared by all WaitingForReady tests.
fn expect_provisioning(mock: &mut MockDpfOperations) {
    mock.expect_register_dpu_device().returning(|_| Ok(()));
    mock.expect_register_dpu_node().returning(|_| Ok(()));
    mock.expect_get_dpu_phase()
        .returning(|_, _| Ok(DpuPhase::Ready));
}

fn dpf_config() -> crate::cfg::file::DpfConfig {
    crate::cfg::file::DpfConfig {
        enabled: true,
        bfb_url: "http://example.com/test.bfb".to_string(),
        deployment_name: None,
        services: None,
    }
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
            health_report_overrides = '{\"merges\": {}, \"replace\": null}'::jsonb, \
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

/// WaitingForReady with reboot required:
///   1. Releases maintenance hold, sees reboot required, power-cycles host (ForceOff + On)
///   2. After reboot_completed, device ready -> HostInit
#[crate::sqlx_test]
async fn test_waiting_for_ready_reboot_flow(pool: sqlx::PgPool) {
    let mut mock = MockDpfOperations::new();
    expect_provisioning(&mut mock);

    mock.expect_is_dpu_device_ready().returning(|_| Ok(true));
    mock.expect_release_maintenance_hold()
        .times(1..)
        .returning(|_| Ok(()));

    // Starts false so initial provisioning completes, flipped to true for the test phase.
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

    reset_host_to_waiting_for_ready(&pool, &mh.id, &mh.dpu_ids[0]).await;

    let redfish_timepoint = env.redfish_sim.timepoint();

    timeout(TEST_TIMEOUT, async {
        env.run_machine_state_controller_iteration().await;
        env.run_machine_state_controller_iteration().await;
        env.run_machine_state_controller_iteration().await;
    })
    .await
    .expect("timed out during state controller iterations");

    let actions = env
        .redfish_sim
        .actions_since(&redfish_timepoint)
        .all_hosts();
    assert!(
        actions.contains(&RedfishSimAction::Power(SystemPowerControl::ForceOff)),
        "Expected ForceOff to be sent, actions: {:?}",
        actions
    );
    assert!(
        actions.contains(&RedfishSimAction::Power(SystemPowerControl::On)),
        "Expected On to be sent after ForceOff, actions: {:?}",
        actions
    );

    reboot_completed(&env, mh.id).await;

    timeout(TEST_TIMEOUT, async {
        env.run_machine_state_controller_iteration().await;
        env.run_machine_state_controller_iteration().await;
    })
    .await
    .expect("timed out during post-reboot iterations");

    let host = get_host_state(&env, &mh).await;
    assert!(
        !matches!(host, ManagedHostState::DPUInit { .. }),
        "Host should have transitioned out of DPUInit, got: {:?}",
        host
    );
}

/// WaitingForReady without reboot: enters maintenance, releases hold,
/// waits for device ready, then transitions.
#[crate::sqlx_test]
async fn test_waiting_for_ready_no_reboot(pool: sqlx::PgPool) {
    let mut mock = MockDpfOperations::new();
    expect_provisioning(&mut mock);

    let device_ready = Arc::new(AtomicBool::new(true));
    let dr = device_ready.clone();
    mock.expect_is_dpu_device_ready()
        .returning(move |_| Ok(dr.load(Ordering::SeqCst)));
    mock.expect_release_maintenance_hold()
        .times(1..)
        .returning(|_| Ok(()));
    mock.expect_is_reboot_required().returning(|_| Ok(false));
    // No expectation for reboot_complete: automock panics if called.

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

    device_ready.store(false, Ordering::SeqCst);

    reset_host_to_waiting_for_ready(&pool, &mh.id, &mh.dpu_ids[0]).await;

    timeout(TEST_TIMEOUT, async {
        for _ in 0..5 {
            env.run_machine_state_controller_iteration().await;
        }
    })
    .await
    .expect("timed out during state controller iterations");

    let host = get_host_state(&env, &mh).await;
    assert!(
        matches!(host, ManagedHostState::DPUInit { .. }),
        "Host should still be in DPUInit waiting for device, got: {:?}",
        host
    );

    device_ready.store(true, Ordering::SeqCst);

    timeout(TEST_TIMEOUT, async {
        env.run_machine_state_controller_iteration().await;
        env.run_machine_state_controller_iteration().await;
    })
    .await
    .expect("timed out during post-ready iterations");

    let host = get_host_state(&env, &mh).await;
    assert!(
        !matches!(host, ManagedHostState::DPUInit { .. }),
        "Host should have transitioned out of DPUInit after device ready, got: {:?}",
        host
    );
}

/// WaitingForReady idempotent reboot: ForceOff is only sent once,
/// not on every iteration while waiting for the host to come back.
#[crate::sqlx_test]
async fn test_waiting_for_ready_idempotent_reboot(pool: sqlx::PgPool) {
    let mut mock = MockDpfOperations::new();
    expect_provisioning(&mut mock);

    // Starts true so initial provisioning completes, flipped to false for the test phase.
    let device_ready = Arc::new(AtomicBool::new(true));
    let dr = device_ready.clone();
    mock.expect_is_dpu_device_ready()
        .returning(move |_| Ok(dr.load(Ordering::SeqCst)));
    mock.expect_release_maintenance_hold().returning(|_| Ok(()));

    // Starts false so initial provisioning completes, flipped to true for the test phase.
    let reboot_required = Arc::new(AtomicBool::new(false));
    let rr = reboot_required.clone();
    mock.expect_is_reboot_required()
        .returning(move |_| Ok(rr.load(Ordering::SeqCst)));
    // No expectation for reboot_complete: automock panics if called.

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
    device_ready.store(false, Ordering::SeqCst);

    reset_host_to_waiting_for_ready(&pool, &mh.id, &mh.dpu_ids[0]).await;

    let redfish_timepoint = env.redfish_sim.timepoint();

    timeout(TEST_TIMEOUT, async {
        for _ in 0..5 {
            env.run_machine_state_controller_iteration().await;
        }
    })
    .await
    .expect("timed out during state controller iterations");

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
        "ForceOff should be sent exactly once (idempotent guard), got {}",
        force_off_count
    );

    let redfish_timepoint2 = env.redfish_sim.timepoint();
    timeout(TEST_TIMEOUT, async {
        for _ in 0..5 {
            env.run_machine_state_controller_iteration().await;
        }
    })
    .await
    .expect("timed out during second iteration batch");

    let actions2 = env
        .redfish_sim
        .actions_since(&redfish_timepoint2)
        .all_hosts();
    let force_off_count2 = actions2
        .iter()
        .filter(|x| matches!(x, RedfishSimAction::Power(SystemPowerControl::ForceOff)))
        .count();

    assert_eq!(
        force_off_count2, 0,
        "No additional ForceOff should be sent while waiting for reboot, got {}",
        force_off_count2
    );
}
