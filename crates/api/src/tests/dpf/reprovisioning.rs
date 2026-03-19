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

//! Tests for DPF state transitions during reprovisioning.
//!
//! Verifies that DPF states (`Reprovisioning` -> `Provisioning` -> `WaitingForReady`)
//! transition correctly when the outer state is `DPUReprovision`.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use carbide_dpf::DpuPhase;
use carbide_uuid::machine::MachineId;
use model::machine::{
    DpfState, DpuReprovisionStates, InstanceState, ManagedHostState, ReprovisionState,
};
use tokio::time::timeout;

use crate::dpf::MockDpfOperations;
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, TestManagedHost, create_managed_host_with_dpf,
    create_managed_host_with_dpf_multi, create_test_env_with_overrides, get_config,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Build a `MockDpfOperations` with only the expectations needed for the
/// initial provisioning flow triggered by `create_managed_host_with_dpf`.
/// `dpu_ready` controls whether `get_dpu_phase` returns `Ready` or `Provisioning`.
fn provisioning_mock(dpu_ready: Arc<AtomicBool>) -> MockDpfOperations {
    let mut mock = MockDpfOperations::new();
    mock.expect_register_dpu_device().returning(|_| Ok(()));
    mock.expect_register_dpu_node().returning(|_| Ok(()));
    mock.expect_release_maintenance_hold().returning(|_| Ok(()));
    mock.expect_is_reboot_required().returning(|_| Ok(false));
    mock.expect_get_dpu_phase().returning(move |_, _| {
        if dpu_ready.load(Ordering::SeqCst) {
            Ok(DpuPhase::Ready)
        } else {
            Ok(DpuPhase::Provisioning("OsInstalling".into()))
        }
    });
    mock
}

fn dpf_config() -> crate::cfg::file::DpfConfig {
    crate::cfg::file::DpfConfig {
        enabled: true,
        bfb_url: "http://example.com/test.bfb".to_string(),
        deployment_name: None,
        services: None,
    }
}

/// Build the DPU reprovision states map for the given DPF sub-state.
fn build_dpf_reprovision_states(
    dpu_ids: &[MachineId],
    dpf_state: DpfState,
) -> DpuReprovisionStates {
    let states: HashMap<MachineId, ReprovisionState> = dpu_ids
        .iter()
        .map(|id| {
            (
                *id,
                ReprovisionState::DpfStates {
                    substate: dpf_state.clone(),
                },
            )
        })
        .collect();
    DpuReprovisionStates { states }
}

/// Write a managed-host state directly to the database.
async fn write_host_state(pool: &sqlx::PgPool, host_id: &MachineId, state: &ManagedHostState) {
    let state_json = serde_json::to_value(state).unwrap();
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

/// Set the host to `DPUReprovision` with the given DPF sub-state for each DPU.
async fn set_reprovision_dpf_state(
    pool: &sqlx::PgPool,
    host_id: &MachineId,
    dpu_ids: &[MachineId],
    dpf_state: DpfState,
) {
    let state = ManagedHostState::DPUReprovision {
        dpu_states: build_dpf_reprovision_states(dpu_ids, dpf_state),
    };
    write_host_state(pool, host_id, &state).await;
}

/// Set the host to `Assigned { InstanceState::DPUReprovision }` with the given DPF sub-state.
/// The host must already have a real instance allocated via `instance_builer().build_and_return()`.
async fn set_assigned_reprovision_dpf_state(
    pool: &sqlx::PgPool,
    host_id: &MachineId,
    dpu_ids: &[MachineId],
    dpf_state: DpfState,
) {
    let state = ManagedHostState::Assigned {
        instance_state: InstanceState::DPUReprovision {
            dpu_states: build_dpf_reprovision_states(dpu_ids, dpf_state),
        },
    };
    write_host_state(pool, host_id, &state).await;
}

async fn get_host_state(
    env: &crate::tests::common::api_fixtures::TestEnv,
    mh: &TestManagedHost,
) -> ManagedHostState {
    let mut txn = env.db_txn().await;
    let machine = mh.host().db_machine(&mut txn).await;
    machine.state.value
}

async fn dpu_device_names(pool: &sqlx::PgPool, mh: &TestManagedHost) -> HashSet<String> {
    let mut txn = pool.begin().await.unwrap();
    let mut names = HashSet::new();
    for dpu_id in &mh.dpu_ids {
        let dpu = db::machine::find_one(txn.as_mut(), dpu_id, Default::default())
            .await
            .unwrap()
            .unwrap();
        names.insert(dpu.dpf_id().unwrap());
    }
    names
}

/// Reprovisioning handler: `DpfState::Reprovisioning` transitions the DPU
/// to `DpfState::WaitingForReady` under `DPUReprovision`.
#[crate::sqlx_test]
async fn test_dpf_reprovisioning_transitions_to_provisioning(pool: sqlx::PgPool) {
    let device_ready = Arc::new(AtomicBool::new(true));
    let mut mock = provisioning_mock(device_ready);
    mock.expect_reprovision_dpu().returning(|_, _| Ok(()));
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

    set_reprovision_dpf_state(&pool, &mh.id, &mh.dpu_ids, DpfState::Reprovisioning).await;

    // One iteration: Reprovisioning -> WaitingForReady
    timeout(TEST_TIMEOUT, env.run_machine_state_controller_iteration())
        .await
        .expect("timed out during state controller iteration");

    let host_state = get_host_state(&env, &mh).await;

    match &host_state {
        ManagedHostState::DPUReprovision { dpu_states } => {
            for (dpu_id, state) in &dpu_states.states {
                assert!(
                    matches!(
                        state,
                        ReprovisionState::DpfStates {
                            substate: DpfState::WaitingForReady { .. }
                        }
                    ),
                    "DPU {dpu_id} should be in DpfStates::WaitingForReady after Reprovisioning, got: {state:?}"
                );
            }
        }
        other => {
            panic!("Expected DPUReprovision state, got: {other:?}");
        }
    }
}

/// Provisioning handler under reprovisioning: `DpfState::Provisioning`
/// transitions all DPUs to `DpfState::WaitingForReady` under `DPUReprovision`.
#[crate::sqlx_test]
async fn test_dpf_provisioning_transitions_to_waiting_for_ready_during_reprovision(
    pool: sqlx::PgPool,
) {
    let device_ready = Arc::new(AtomicBool::new(true));
    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> =
        Arc::new(provisioning_mock(device_ready.clone()));
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

    // Prevent the WaitingForReady handler from advancing past this state.
    device_ready.store(false, Ordering::SeqCst);

    set_reprovision_dpf_state(&pool, &mh.id, &mh.dpu_ids, DpfState::Provisioning).await;

    // Run several iterations: Provisioning -> WaitingForReady, then stays
    // in WaitingForReady because the device is not ready.
    for _ in 0..5 {
        timeout(TEST_TIMEOUT, env.run_machine_state_controller_iteration())
            .await
            .expect("timed out during state controller iteration");
    }

    let host_state = get_host_state(&env, &mh).await;

    match &host_state {
        ManagedHostState::DPUReprovision { dpu_states } => {
            for (dpu_id, state) in &dpu_states.states {
                assert!(
                    matches!(
                        state,
                        ReprovisionState::DpfStates {
                            substate: DpfState::WaitingForReady { .. }
                        }
                    ),
                    "DPU {dpu_id} should be in DpfStates::WaitingForReady after Provisioning, got: {state:?}"
                );
            }
        }
        other => {
            panic!("Expected DPUReprovision state, got: {other:?}");
        }
    }
}

/// When WaitingForReady completes during reprovisioning, the host must
/// transition to `PoweringOffHost` (the reprovisioning power-cycle path),
/// **not** to `HostInit` which is the initial-provisioning exit.
#[crate::sqlx_test]
async fn test_dpf_waiting_for_ready_exits_to_powering_off_host_during_reprovision(
    pool: sqlx::PgPool,
) {
    let device_ready = Arc::new(AtomicBool::new(true));
    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> = Arc::new(provisioning_mock(device_ready));
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

    // Start with WaitingForReady under DPUReprovision, device is ready.
    set_reprovision_dpf_state(
        &pool,
        &mh.id,
        &mh.dpu_ids,
        DpfState::WaitingForReady { phase_detail: None },
    )
    .await;

    // Run iterations: enter maintenance -> release hold + check ready -> exit
    for _ in 0..5 {
        timeout(TEST_TIMEOUT, env.run_machine_state_controller_iteration())
            .await
            .expect("timed out during state controller iteration");
    }

    let host_state = get_host_state(&env, &mh).await;

    match &host_state {
        ManagedHostState::DPUReprovision { dpu_states } => {
            for (dpu_id, state) in &dpu_states.states {
                assert!(
                    matches!(state, ReprovisionState::PoweringOffHost),
                    "DPU {dpu_id} should be in PoweringOffHost after WaitingForReady during reprovision, got: {state:?}"
                );
            }
        }
        // It is acceptable if the state controller advanced past PoweringOffHost
        // within the 5 iterations, as long as it did NOT go to HostInit.
        ManagedHostState::HostInit { .. } => {
            panic!(
                "WaitingForReady during reprovisioning must NOT exit to HostInit. \
                 Expected DPUReprovision/PoweringOffHost."
            );
        }
        _other => {
            // May have advanced further in the reprovisioning flow; that's OK.
        }
    }
}

/// Build a capturing mock that records device names from `register_dpu_device`
/// and `reprovision_dpu`.
fn capturing_mock(
    dpu_ready: Arc<AtomicBool>,
    registered_devices: Arc<Mutex<Vec<String>>>,
    reprovisioned_devices: Arc<Mutex<Vec<String>>>,
) -> MockDpfOperations {
    let mut mock = MockDpfOperations::new();

    mock.expect_register_dpu_device().returning(move |info| {
        registered_devices.lock().unwrap().push(info.device_id);
        Ok(())
    });

    mock.expect_register_dpu_node().returning(|_| Ok(()));
    mock.expect_release_maintenance_hold().returning(|_| Ok(()));
    mock.expect_is_reboot_required().returning(|_| Ok(false));

    let reprovisioned_for_ready = reprovisioned_devices.clone();
    mock.expect_get_dpu_phase()
        .returning(move |device_name, _| {
            let ready_global = dpu_ready.load(Ordering::SeqCst);
            let repro = reprovisioned_for_ready.lock().unwrap();
            let ready_if_reprovisioned = repro.iter().any(|d| d == device_name);
            if ready_global || ready_if_reprovisioned {
                Ok(DpuPhase::Ready)
            } else {
                Ok(DpuPhase::Provisioning("OsInstalling".into()))
            }
        });

    mock.expect_reprovision_dpu()
        .returning(move |device_name, _| {
            reprovisioned_devices
                .lock()
                .unwrap()
                .push(device_name.to_string());
            Ok(())
        });

    mock
}

// ---------------------------------------------------------------------------
// Multi-DPU tests
// ---------------------------------------------------------------------------

/// Provisioning with multiple DPUs: `register_dpu_device` must be called for
/// every DPU, not just the first.
#[crate::sqlx_test]
async fn test_multi_dpu_provisioning_registers_all_devices(pool: sqlx::PgPool) {
    let device_ready = Arc::new(AtomicBool::new(true));
    let registered_devices = Arc::new(Mutex::new(Vec::new()));
    let reprovisioned_devices = Arc::new(Mutex::new(Vec::new()));
    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> = Arc::new(capturing_mock(
        device_ready.clone(),
        registered_devices.clone(),
        reprovisioned_devices.clone(),
    ));
    let mut config = get_config();
    config.dpf = dpf_config();

    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await;

    let mh = timeout(TEST_TIMEOUT, create_managed_host_with_dpf_multi(&env, 2))
        .await
        .expect("timed out during initial provisioning");
    assert_eq!(mh.dpu_ids.len(), 2, "Expected 2 DPUs");

    // Clear registrations captured during initial provisioning.
    registered_devices.lock().unwrap().clear();
    // Block WaitingForReady so we can observe the Provisioning -> WaitingForReady transition.
    device_ready.store(false, Ordering::SeqCst);

    // Put host into DPUReprovision / Provisioning with 2 DPUs.
    set_reprovision_dpf_state(&pool, &mh.id, &mh.dpu_ids, DpfState::Provisioning).await;

    timeout(TEST_TIMEOUT, env.run_machine_state_controller_iteration())
        .await
        .expect("timed out during state controller iteration");

    let registered: HashSet<String> = registered_devices
        .lock()
        .unwrap()
        .clone()
        .into_iter()
        .collect();
    let expected = dpu_device_names(&pool, &mh).await;
    assert_eq!(
        registered, expected,
        "register_dpu_device must be called for every DPU.\n\
         Registered: {registered:?}\n\
         Expected:   {expected:?}"
    );
}

/// Reprovisioning with multiple DPUs: each DPU in Reprovisioning is
/// reprovisioned when its DpfState is reconciled. Run iterations until
/// all DPUs have been reprovisioned.
#[crate::sqlx_test]
async fn test_multi_dpu_reprovisioning_calls_all_dpus(pool: sqlx::PgPool) {
    let device_ready = Arc::new(AtomicBool::new(true));
    let registered_devices = Arc::new(Mutex::new(Vec::new()));
    let reprovisioned_devices = Arc::new(Mutex::new(Vec::new()));
    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> = Arc::new(capturing_mock(
        device_ready.clone(),
        registered_devices,
        reprovisioned_devices.clone(),
    ));
    let mut config = get_config();
    config.dpf = dpf_config();

    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await;

    let mh = timeout(TEST_TIMEOUT, create_managed_host_with_dpf_multi(&env, 2))
        .await
        .expect("timed out during initial provisioning");
    assert_eq!(mh.dpu_ids.len(), 2, "Expected 2 DPUs");

    device_ready.store(false, Ordering::SeqCst);
    set_reprovision_dpf_state(&pool, &mh.id, &mh.dpu_ids, DpfState::Reprovisioning).await;

    let expected = dpu_device_names(&pool, &mh).await;
    for _ in 0..10 {
        timeout(TEST_TIMEOUT, env.run_machine_state_controller_iteration())
            .await
            .expect("timed out during state controller iteration");
        let reprovisioned: HashSet<String> = reprovisioned_devices
            .lock()
            .unwrap()
            .clone()
            .into_iter()
            .collect();
        if reprovisioned == expected {
            break;
        }
    }

    let reprovisioned: HashSet<String> = reprovisioned_devices
        .lock()
        .unwrap()
        .clone()
        .into_iter()
        .collect();
    assert_eq!(
        reprovisioned, expected,
        "Every DPU marked for reprovisioning must be reprovisioned when its DpfState is reconciled.\n\
         Reprovisioned: {reprovisioned:?}\n\
         Expected:      {expected:?}"
    );
}

// ---------------------------------------------------------------------------
// Assigned / InstanceState::DPUReprovision tests
// ---------------------------------------------------------------------------

/// DPF reprovisioning under `Assigned { DPUReprovision }` transitions to
/// `WaitingForReady` without returning `InvalidState`.
#[crate::sqlx_test]
async fn test_assigned_dpf_reprovisioning_transitions_to_provisioning(pool: sqlx::PgPool) {
    let device_ready = Arc::new(AtomicBool::new(true));
    let mut mock = provisioning_mock(device_ready);
    mock.expect_reprovision_dpu().returning(|_, _| Ok(()));
    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> = Arc::new(mock);
    let mut config = get_config();
    config.dpf = dpf_config();

    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await;

    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = timeout(TEST_TIMEOUT, create_managed_host_with_dpf(&env))
        .await
        .expect("timed out during initial provisioning");

    // Allocate a real instance so the InstanceStateHandler has valid instance data.
    let (_tinstance, _rpc_instance) = mh
        .instance_builer(&env)
        .single_interface_network_config(segment_id)
        .build_and_return()
        .await;

    set_assigned_reprovision_dpf_state(&pool, &mh.id, &mh.dpu_ids, DpfState::Reprovisioning).await;

    // One iteration: Reprovisioning -> WaitingForReady
    timeout(TEST_TIMEOUT, env.run_machine_state_controller_iteration())
        .await
        .expect("timed out during state controller iteration");

    let host_state = get_host_state(&env, &mh).await;
    match &host_state {
        ManagedHostState::Assigned {
            instance_state:
                InstanceState::DPUReprovision {
                    dpu_states: DpuReprovisionStates { states },
                },
        } => {
            for (dpu_id, state) in states {
                assert!(
                    matches!(
                        state,
                        ReprovisionState::DpfStates {
                            substate: DpfState::WaitingForReady { .. },
                        }
                    ),
                    "DPU {dpu_id} expected WaitingForReady, got: {state:?}"
                );
            }
        }
        other => {
            panic!("Expected Assigned/DPUReprovision with WaitingForReady, got: {other:?}");
        }
    }
}

/// `WaitingForReady` under `Assigned { DPUReprovision }` exits to
/// `PoweringOffHost`, not `HostInit`.
#[crate::sqlx_test]
async fn test_assigned_waiting_for_ready_exits_to_powering_off_host(pool: sqlx::PgPool) {
    let device_ready = Arc::new(AtomicBool::new(true));
    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> = Arc::new(provisioning_mock(device_ready));
    let mut config = get_config();
    config.dpf = dpf_config();

    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await;

    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = timeout(TEST_TIMEOUT, create_managed_host_with_dpf(&env))
        .await
        .expect("timed out during initial provisioning");

    // Allocate a real instance so the InstanceStateHandler has valid instance data.
    let (_tinstance, _rpc_instance) = mh
        .instance_builer(&env)
        .single_interface_network_config(segment_id)
        .build_and_return()
        .await;

    set_assigned_reprovision_dpf_state(
        &pool,
        &mh.id,
        &mh.dpu_ids,
        DpfState::WaitingForReady { phase_detail: None },
    )
    .await;

    for _ in 0..5 {
        timeout(TEST_TIMEOUT, env.run_machine_state_controller_iteration())
            .await
            .expect("timed out during state controller iteration");
    }

    let host_state = get_host_state(&env, &mh).await;
    match &host_state {
        ManagedHostState::Assigned {
            instance_state:
                InstanceState::DPUReprovision {
                    dpu_states: DpuReprovisionStates { states },
                },
        } => {
            for (dpu_id, state) in states {
                assert!(
                    matches!(state, ReprovisionState::PoweringOffHost),
                    "DPU {dpu_id} should be PoweringOffHost after WaitingForReady \
                     during assigned reprovision, got: {state:?}"
                );
            }
        }
        ManagedHostState::HostInit { .. } => {
            panic!(
                "WaitingForReady during assigned reprovisioning must NOT exit to HostInit. \
                 Expected Assigned/DPUReprovision/PoweringOffHost."
            );
        }
        _other => {
            // May have advanced further in the reprovisioning flow; that's OK.
        }
    }
}

/// Each DPU is reprovisioned independently: the per-DPU handler advances
/// one DPU per iteration. After enough iterations both DPUs complete the
/// DPF cycle and reach PoweringOffHost.
#[crate::sqlx_test]
async fn test_multi_dpu_reprovisioning_per_dpu(pool: sqlx::PgPool) {
    let device_ready = Arc::new(AtomicBool::new(true));
    let registered_devices = Arc::new(Mutex::new(Vec::new()));
    let reprovisioned_devices = Arc::new(Mutex::new(Vec::new()));
    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> = Arc::new(capturing_mock(
        device_ready.clone(),
        registered_devices,
        reprovisioned_devices.clone(),
    ));
    let mut config = get_config();
    config.dpf = dpf_config();

    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config).with_dpf_sdk(dpf_sdk),
    )
    .await;

    let mh = timeout(TEST_TIMEOUT, create_managed_host_with_dpf_multi(&env, 2))
        .await
        .expect("timed out during initial provisioning");
    assert_eq!(mh.dpu_ids.len(), 2, "Expected 2 DPUs");

    device_ready.store(false, Ordering::SeqCst);
    reprovisioned_devices.lock().unwrap().clear();
    set_reprovision_dpf_state(&pool, &mh.id, &mh.dpu_ids, DpfState::Reprovisioning).await;

    for _ in 0..10 {
        timeout(TEST_TIMEOUT, env.run_machine_state_controller_iteration())
            .await
            .expect("timed out during state controller iteration");
    }

    let reprovisioned: HashSet<String> = reprovisioned_devices
        .lock()
        .unwrap()
        .clone()
        .into_iter()
        .collect();
    let expected = dpu_device_names(&pool, &mh).await;
    assert_eq!(
        reprovisioned, expected,
        "Both DPUs must be reprovisioned after multiple iterations.\n\
         Reprovisioned: {reprovisioned:?}\n\
         Expected:      {expected:?}"
    );

    let host_state = get_host_state(&env, &mh).await;
    match &host_state {
        ManagedHostState::DPUReprovision { dpu_states } => {
            for (dpu_id, state) in &dpu_states.states {
                assert!(
                    !matches!(
                        state,
                        ReprovisionState::DpfStates {
                            substate: DpfState::Reprovisioning
                        }
                    ),
                    "DPU {dpu_id} should have completed DPF reprovisioning, got: {state:?}"
                );
            }
        }
        other => {
            panic!("Expected DPUReprovision state, got: {other:?}");
        }
    }
}

/// Unknown DPF state during reprovisioning transitions to Provisioning.
#[crate::sqlx_test]
async fn test_unknown_dpf_state_transitions_to_provisioning_during_reprovision(pool: sqlx::PgPool) {
    let device_ready = Arc::new(AtomicBool::new(true));
    let dpf_sdk: Arc<dyn crate::dpf::DpfOperations> = Arc::new(provisioning_mock(device_ready));
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

    set_reprovision_dpf_state(&pool, &mh.id, &mh.dpu_ids, DpfState::Unknown).await;

    timeout(TEST_TIMEOUT, env.run_machine_state_controller_iteration())
        .await
        .expect("timed out during state controller iteration");

    let host_state = get_host_state(&env, &mh).await;
    match &host_state {
        ManagedHostState::DPUReprovision { dpu_states } => {
            for (dpu_id, state) in &dpu_states.states {
                assert!(
                    matches!(
                        state,
                        ReprovisionState::DpfStates {
                            substate: DpfState::Provisioning
                        }
                    ),
                    "DPU {dpu_id} should transition from Unknown to Provisioning, got: {state:?}"
                );
            }
        }
        other => panic!("Expected DPUReprovision, got: {other:?}"),
    }
}
