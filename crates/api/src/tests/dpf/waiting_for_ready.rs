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

//! Tests for the WaitingForReady DPF state handler.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use carbide_dpf::DpuPhase;
use carbide_redfish::libredfish::RedfishClientPool;
use carbide_redfish::libredfish::test_support::RedfishSimAction;
use carbide_uuid::machine::MachineId;
use libredfish::SystemPowerControl;
use model::machine::{DpfState, DpuInitState, ManagedHostState};
use tokio::time::timeout;

use crate::dpf::MockDpfOperations;
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, TestManagedHost, create_managed_host_with_dpf,
    create_managed_host_with_dpf_multi, create_test_env_with_overrides, discovery_completed,
    get_config, reboot_completed,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// True after the DPF `DeviceReady` sync: no DPU remains in `DpfStates`, or host init has started.
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

/// Set up the initial provisioning expectations shared by all WaitingForReady tests.
/// Does NOT set up `get_dpu_phase` -- each test configures it to control the
/// DPU CR phase (the authoritative readiness signal).
fn expect_provisioning(mock: &mut MockDpfOperations) {
    mock.expect_register_dpu_device().returning(|_| Ok(()));
    mock.expect_register_dpu_node().returning(|_| Ok(()));
    mock.expect_verify_node_labels().returning(|_| Ok(true));
}

fn dpf_config() -> crate::cfg::file::DpfConfig {
    crate::cfg::file::DpfConfig {
        enabled: true,
        bfb_url: "http://example.com/test.bfb".to_string(),
        v2: true,
        ..Default::default()
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

/// WaitingForReady with reboot required:
///   1. Releases maintenance hold, sees reboot required, power-cycles host (ForceOff + On)
///   2. After reboot_completed, device ready -> leaves DPF `DpfStates` (then may advance further)
#[crate::sqlx_test]
async fn test_waiting_for_ready_reboot_flow(pool: sqlx::PgPool) {
    let mut mock = MockDpfOperations::new();
    expect_provisioning(&mut mock);

    mock.expect_get_dpu_phase()
        .returning(|_, _| Ok(DpuPhase::Ready));
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
        dpf_left_operator_provisioning_substates(&host),
        "Host should have left DPF operator substates after DeviceReady, got: {:?}",
        host
    );
}

/// WaitingForReady without reboot: enters maintenance, releases hold,
/// waits for DPU CR to reach Ready phase, then transitions.
#[crate::sqlx_test]
async fn test_waiting_for_ready_no_reboot(pool: sqlx::PgPool) {
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
    mock.expect_release_maintenance_hold()
        .times(1..)
        .returning(|_| Ok(()));
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
        "Host should still be in DPUInit waiting for DPU Ready phase, got: {:?}",
        host
    );

    dpu_ready.store(true, Ordering::SeqCst);

    timeout(TEST_TIMEOUT, async {
        env.run_machine_state_controller_iteration().await;
        env.run_machine_state_controller_iteration().await;
    })
    .await
    .expect("timed out during post-ready iterations");

    let host = get_host_state(&env, &mh).await;
    assert!(
        dpf_left_operator_provisioning_substates(&host),
        "Host should have left DPF operator substates after DeviceReady, got: {:?}",
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
    dpu_ready.store(false, Ordering::SeqCst);

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

/// When the host is already Off and last_reboot_requested is None,
/// the reboot handler should skip ForceOff and go straight to PowerOn.
#[crate::sqlx_test]
async fn test_waiting_for_ready_host_already_off(pool: sqlx::PgPool) {
    let mut mock = MockDpfOperations::new();
    expect_provisioning(&mut mock);

    mock.expect_get_dpu_phase()
        .returning(|_, _| Ok(DpuPhase::Ready));
    mock.expect_release_maintenance_hold()
        .times(1..)
        .returning(|_| Ok(()));

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

    // Set the host BMC power state to Off before entering the reboot path.
    let host_snapshot = {
        let mut txn = env.pool.begin().await.unwrap();
        let s = mh.host().db_machine(&mut txn).await;
        txn.commit().await.unwrap();
        s
    };
    env.redfish_sim
        .create_client_from_machine(&host_snapshot, &env.pool)
        .await
        .unwrap()
        .power(SystemPowerControl::ForceOff)
        .await
        .unwrap();

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

    let force_off_count = actions
        .iter()
        .filter(|x| matches!(x, RedfishSimAction::Power(SystemPowerControl::ForceOff)))
        .count();
    assert_eq!(
        force_off_count, 0,
        "ForceOff should NOT be sent when host is already Off, got {} in {:?}",
        force_off_count, actions
    );

    assert!(
        actions.contains(&RedfishSimAction::Power(SystemPowerControl::On)),
        "Expected PowerOn to be sent for already-off host, actions: {:?}",
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
        dpf_left_operator_provisioning_substates(&host),
        "Host should have left DPF operator substates after DeviceReady, got: {:?}",
        host
    );
}

async fn clear_dpu_discovery_time(pool: &sqlx::PgPool, dpu_id: &MachineId) {
    sqlx::query("UPDATE machines SET last_discovery_time = NULL WHERE id = $1")
        .bind(dpu_id)
        .execute(pool)
        .await
        .unwrap();
}

/// When the DPU has not completed discovery, reboot must be blocked
/// even if is_reboot_required returns true.
#[crate::sqlx_test]
async fn test_waiting_for_ready_reboot_blocked_without_discovery(pool: sqlx::PgPool) {
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
    mock.expect_release_maintenance_hold()
        .times(1..)
        .returning(|_| Ok(()));

    let reboot_required = Arc::new(AtomicBool::new(false));
    let rr = reboot_required.clone();
    mock.expect_is_reboot_required()
        .returning(move |_| Ok(rr.load(Ordering::SeqCst)));
    mock.expect_reboot_complete().returning(|_| Ok(()));

    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> = Arc::new(mock);
    let mut config = get_config();
    config.dpf = dpf_config();
    config.dpf.v2 = false;

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
    clear_dpu_discovery_time(&pool, &mh.dpu_ids[0]).await;

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
    let power_actions: Vec<_> = actions
        .iter()
        .filter(|x| matches!(x, RedfishSimAction::Power(_)))
        .collect();
    assert!(
        power_actions.is_empty(),
        "No power actions should be sent while discovery is pending, got: {:?}",
        power_actions
    );

    let host = get_host_state(&env, &mh).await;
    assert!(
        matches!(host, ManagedHostState::DPUInit { .. }),
        "Host should still be in DPUInit waiting for discovery, got: {:?}",
        host
    );
}

/// When the DPU completes discovery after being blocked, the reboot
/// proceeds normally.
#[crate::sqlx_test]
async fn test_waiting_for_ready_reboot_proceeds_after_discovery(pool: sqlx::PgPool) {
    let mut mock = MockDpfOperations::new();
    expect_provisioning(&mut mock);

    mock.expect_get_dpu_phase()
        .returning(|_, _| Ok(DpuPhase::Ready));
    mock.expect_release_maintenance_hold()
        .times(1..)
        .returning(|_| Ok(()));

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
    config.dpf.v2 = false;

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
    clear_dpu_discovery_time(&pool, &mh.dpu_ids[0]).await;

    // Without discovery, reboot should be blocked.
    let redfish_timepoint = env.redfish_sim.timepoint();
    timeout(TEST_TIMEOUT, async {
        for _ in 0..3 {
            env.run_machine_state_controller_iteration().await;
        }
    })
    .await
    .expect("timed out during pre-discovery iterations");

    let actions = env
        .redfish_sim
        .actions_since(&redfish_timepoint)
        .all_hosts();
    let power_actions: Vec<_> = actions
        .iter()
        .filter(|x| matches!(x, RedfishSimAction::Power(_)))
        .collect();
    assert!(
        power_actions.is_empty(),
        "No power actions before discovery, got: {:?}",
        power_actions
    );

    // Signal discovery, then reboot should proceed.
    discovery_completed(&env, mh.dpu_ids[0]).await;

    let redfish_timepoint2 = env.redfish_sim.timepoint();
    timeout(TEST_TIMEOUT, async {
        env.run_machine_state_controller_iteration().await;
        env.run_machine_state_controller_iteration().await;
        env.run_machine_state_controller_iteration().await;
    })
    .await
    .expect("timed out during post-discovery iterations");

    let actions2 = env
        .redfish_sim
        .actions_since(&redfish_timepoint2)
        .all_hosts();
    assert!(
        actions2.contains(&RedfishSimAction::Power(SystemPowerControl::ForceOff)),
        "Expected ForceOff after discovery completed, actions: {:?}",
        actions2
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
        dpf_left_operator_provisioning_substates(&host),
        "Host should have left DPF operator substates after DeviceReady, got: {:?}",
        host
    );
}

async fn reset_host_to_waiting_for_ready_multi(
    pool: &sqlx::PgPool,
    host_id: &MachineId,
    dpu_ids: &[MachineId],
) {
    let state = ManagedHostState::DPUInit {
        dpu_states: model::machine::DpuInitStates {
            states: dpu_ids
                .iter()
                .map(|id| {
                    (
                        *id,
                        DpuInitState::DpfStates {
                            state: DpfState::WaitingForReady { phase_detail: None },
                        },
                    )
                })
                .collect(),
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

/// With multiple DPUs, reboot must wait for ALL DPUs to complete discovery.
/// If only one of two DPUs has discovered, reboot stays blocked.
#[crate::sqlx_test]
async fn test_waiting_for_ready_reboot_blocked_until_all_dpus_discover(pool: sqlx::PgPool) {
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
    mock.expect_release_maintenance_hold()
        .times(1..)
        .returning(|_| Ok(()));

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
    config.dpf.v2 = false;

    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await;

    let mh = timeout(TEST_TIMEOUT, create_managed_host_with_dpf_multi(&env, 2))
        .await
        .expect("timed out during initial provisioning");
    assert_eq!(mh.dpu_ids.len(), 2);

    reboot_required.store(true, Ordering::SeqCst);
    dpu_ready.store(false, Ordering::SeqCst);
    reset_host_to_waiting_for_ready_multi(&pool, &mh.id, &mh.dpu_ids).await;

    // Clear discovery for both DPUs.
    for dpu_id in &mh.dpu_ids {
        clear_dpu_discovery_time(&pool, dpu_id).await;
    }

    // Signal discovery for only the first DPU.
    discovery_completed(&env, mh.dpu_ids[0]).await;

    let redfish_timepoint = env.redfish_sim.timepoint();
    timeout(TEST_TIMEOUT, async {
        for _ in 0..5 {
            env.run_machine_state_controller_iteration().await;
        }
    })
    .await
    .expect("timed out during partial-discovery iterations");

    let actions = env
        .redfish_sim
        .actions_since(&redfish_timepoint)
        .all_hosts();
    let power_actions: Vec<_> = actions
        .iter()
        .filter(|x| matches!(x, RedfishSimAction::Power(_)))
        .collect();
    assert!(
        power_actions.is_empty(),
        "No power actions while second DPU discovery is pending, got: {:?}",
        power_actions
    );

    // Signal discovery for the second DPU -- reboot should now proceed.
    discovery_completed(&env, mh.dpu_ids[1]).await;

    let redfish_timepoint2 = env.redfish_sim.timepoint();
    timeout(TEST_TIMEOUT, async {
        for _ in 0..3 {
            env.run_machine_state_controller_iteration().await;
        }
    })
    .await
    .expect("timed out during post-discovery iterations");

    let actions2 = env
        .redfish_sim
        .actions_since(&redfish_timepoint2)
        .all_hosts();
    assert!(
        actions2.contains(&RedfishSimAction::Power(SystemPowerControl::ForceOff)),
        "Expected ForceOff after all DPUs discovered, actions: {:?}",
        actions2
    );
}

/// Write a raw DPUInit state with a bogus `dpfstate` tag to simulate
/// a stale/invalid state stored by a previous implementation.
async fn write_unknown_dpf_init_state(
    pool: &sqlx::PgPool,
    host_id: &MachineId,
    dpu_id: &MachineId,
) {
    let state_json: serde_json::Value = serde_json::json!({
        "state": "dpuinit",
        "dpu_states": {
            "states": {
                dpu_id.to_string(): {
                    "dpustate": "dpfstates",
                    "state": {
                        "dpfstate": "oldimplstate"
                    }
                }
            }
        }
    });
    let version = format!("V999-T{}", chrono::Utc::now().timestamp_micros());
    sqlx::query(
        "UPDATE machines SET \
            controller_state = $1, \
            controller_state_version = $2, \
            controller_state_outcome = NULL \
         WHERE id = $3",
    )
    .bind(sqlx::types::Json(&state_json))
    .bind(&version)
    .bind(host_id)
    .execute(pool)
    .await
    .unwrap();
}

/// Unknown DPF state in DPUInit transitions to Provisioning.
#[crate::sqlx_test]
async fn test_unknown_dpf_state_transitions_to_provisioning(pool: sqlx::PgPool) {
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

    write_unknown_dpf_init_state(&pool, &mh.id, &mh.dpu_ids[0]).await;

    timeout(TEST_TIMEOUT, env.run_machine_state_controller_iteration())
        .await
        .expect("timed out during state controller iteration");

    let host_state = get_host_state(&env, &mh).await;
    match &host_state {
        ManagedHostState::DPUInit { dpu_states } => {
            let dpu_state = &dpu_states.states[&mh.dpu_ids[0]];
            assert!(
                matches!(
                    dpu_state,
                    DpuInitState::DpfStates {
                        state: DpfState::Provisioning
                    }
                ),
                "Unknown DPF state should transition to Provisioning, got: {dpu_state:?}"
            );
        }
        other => panic!("Expected DPUInit, got: {other:?}"),
    }
}
