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

//! End-to-end coverage for power-shelf-controller BMC (PMC) credential rotation:
//! with the site-wide flag enabled, a staged target drives a Ready
//! power shelf through `PowerShelfControllerState::RotatingBmc` and back to
//! Ready, converging the device and persisting the rotated per-device secret.
//! Mirrors the switch-controller integration test
//! `ready_switch_converges_bmc_to_site_target`.

use std::sync::Arc;
use std::time::Duration;

use carbide_credential_rotation::RotationGate;
use carbide_power_shelf_controller::context::PowerShelfStateHandlerServices;
use carbide_power_shelf_controller::handler::PowerShelfStateHandler;
use carbide_power_shelf_controller::io::PowerShelfStateControllerIO;
use carbide_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialReader, CredentialWriter, Credentials,
};
use carbide_uuid::machine::MachineInterfaceId;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::power_shelf::PowerShelfId;
use chrono::Utc;
use db::credential_rotation::{
    CredentialRotationType, device_rotation_status, increment_rotate_attempt,
    record_device_converged, set_next_target_version,
};
use db::power_shelf as db_power_shelf;
use mac_address::MacAddress;
use model::allocation_type::AllocationType;
use model::bmc_suppression::BmcSuppressionSubsystem;
use model::power_shelf::{PowerShelf, PowerShelfControllerState};
use state_controller::config::IterationConfig;
use state_controller::controller::StateController;
use tokio_util::sync::CancellationToken;

use super::fixtures::power_shelf::set_power_shelf_controller_state;
use crate::tests::common;
use crate::tests::common::api_fixtures::{TestEnv, create_test_env};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BMC: CredentialRotationType = CredentialRotationType::Bmc;

/// Stand in for site-explorer acknowledging every pending BMC suppression -- the
/// barrier the rotation gate waits on before changing a credential. This test
/// drives only the power-shelf controller, so it plays the site-explorer ack
/// pass itself.
async fn ack_all_site_explorer_suppressions(pool: &sqlx::PgPool) {
    let mut conn = pool.acquire().await.expect("acquire connection");
    let macs: Vec<MacAddress> = db::bmc_suppression::find_all_by_subsystem(
        &mut *conn,
        BmcSuppressionSubsystem::SiteExplorer,
    )
    .await
    .expect("read suppressions")
    .into_iter()
    .map(|s| s.bmc_mac_address)
    .collect();
    db::bmc_suppression::acknowledge_unacknowledged(
        &mut conn,
        &macs,
        BmcSuppressionSubsystem::SiteExplorer,
    )
    .await
    .expect("acknowledge suppressions");
}

fn per_device_key(mac: MacAddress) -> CredentialKey {
    CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: mac,
        },
    }
}

fn rotate_to_key(version: u32) -> CredentialKey {
    CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::site_wide_root(version),
    }
}

fn creds(username: &str, password: &str) -> Credentials {
    Credentials::UsernamePassword {
        username: username.to_string(),
        password: password.to_string(),
    }
}

/// Services with the passive BMC-rotation gate toggled by `bmc_rotation_enabled`
/// and no component manager, so a Ready power shelf idles on power-state polling
/// and reaches the BMC gate. A fresh [`RotationGate`] refreshes its cached
/// aggregate live on first use each iteration.
fn power_shelf_services(
    env: &TestEnv,
    pool: &sqlx::PgPool,
    bmc_rotation_enabled: bool,
) -> PowerShelfStateHandlerServices {
    PowerShelfStateHandlerServices {
        db_pool: pool.clone(),
        component_manager: None,
        credential_manager: env.test_credential_manager.clone(),
        per_object_metrics_registry: env.per_object_metrics_registry(),
        rack_firmware_reprovisioning_enabled: false,
        redfish_client_pool: env.redfish_sim.clone(),
        bmc_rotation_gate: RotationGate::new_for_family(CredentialRotationType::Bmc),
        bmc_rotation_enabled,
    }
}

/// Run a single power-shelf-controller iteration with a fresh controller (and a
/// fresh rotation gate), mirroring `run_switch_controller_with_services`.
async fn run_power_shelf_controller_with_services(
    pool: sqlx::PgPool,
    work_lock_manager_handle: db::work_lock_manager::WorkLockManagerHandle,
    services: PowerShelfStateHandlerServices,
) {
    let cancel_token = CancellationToken::new();
    let mut controller = StateController::<PowerShelfStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: Duration::from_millis(50),
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool, work_lock_manager_handle)
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(services.into())
        .state_handler(Arc::new(PowerShelfStateHandler::default()))
        .build_for_manual_iterations(cancel_token)
        .unwrap();
    controller.run_single_iteration().await;
}

/// Link a `Bmc` machine_interface (with a MAC and IP) back to the power shelf so
/// the shelf load query resolves `bmc_info`, giving the controller an
/// addressable PMC endpoint to rotate. Returns the PMC MAC.
async fn seed_pmc_endpoint(
    pool: &sqlx::PgPool,
    power_shelf_id: PowerShelfId,
) -> TestResult<MacAddress> {
    let mut txn = pool.begin().await?;

    let segment_id: NetworkSegmentId = sqlx::query_scalar(
        "INSERT INTO network_segments (name, version, network_segment_type)
         VALUES ($1, 'V1-T0', 'tenant') RETURNING id",
    )
    .bind(format!("pmc-{power_shelf_id}"))
    .fetch_one(txn.as_mut())
    .await?;

    let pmc_mac = "02:00:00:00:0b:01";
    let bmc_interface_id: MachineInterfaceId = sqlx::query_scalar(
        "INSERT INTO machine_interfaces
             (power_shelf_id, association_type, segment_id, mac_address,
              primary_interface, hostname, interface_type)
         VALUES ($1, 'PowerShelf', $2, $3::macaddr, false, 'pmc', 'Bmc')
         RETURNING id",
    )
    .bind(power_shelf_id)
    .bind(segment_id)
    .bind(pmc_mac)
    .fetch_one(txn.as_mut())
    .await?;

    db::machine_interface_address::insert(
        txn.as_mut(),
        bmc_interface_id,
        "10.30.40.50".parse()?,
        AllocationType::Dhcp,
    )
    .await?;

    txn.commit().await?;

    Ok(pmc_mac.parse()?)
}

async fn load_power_shelf(pool: &sqlx::PgPool, id: &PowerShelfId) -> TestResult<PowerShelf> {
    let mut conn = pool.acquire().await?;
    Ok(db_power_shelf::find_by_id(&mut conn, id)
        .await?
        .expect("power shelf should exist"))
}

/// Stage a PMC that lags a freshly published site-wide target v1: seed the PMC's
/// "old" per-device secret, record it converged at the v0 baseline, advance the
/// target to v1, and write the rotate-to secret `RotateCredential` would have
/// staged. After this the device's rotation row lags the target, so the passive
/// gate (or a force request) will drive a rotation that converges it to "new".
async fn stage_lagging_pmc(env: &TestEnv, pool: &sqlx::PgPool, pmc_mac: MacAddress) -> TestResult {
    env.redfish_sim.seed_user("root", "old");
    env.test_credential_manager
        .set_credentials(&per_device_key(pmc_mac), &creds("root", "old"))
        .await
        .expect("staging the per-device secret should succeed");
    {
        let mut conn = pool.acquire().await?;
        record_device_converged(&mut conn, pmc_mac, BMC).await?;
        set_next_target_version(&mut conn, BMC, 0, serde_json::json!({}))
            .await?
            .expect("target must advance from version 0");
    }
    env.test_credential_manager
        .set_credentials(&rotate_to_key(1), &creds("root", "new"))
        .await
        .expect("staging the rotate-to secret should succeed");
    Ok(())
}

/// Move a power shelf directly to `Ready` so the BMC-rotation gate is the only
/// pending work when the controller next sweeps it.
async fn move_to_ready(pool: &sqlx::PgPool, power_shelf_id: &PowerShelfId) -> TestResult {
    let mut txn = pool.begin().await?;
    set_power_shelf_controller_state(
        txn.as_mut(),
        power_shelf_id,
        PowerShelfControllerState::Ready,
    )
    .await?;
    txn.commit().await?;
    Ok(())
}

/// A Ready power shelf whose PMC lags a freshly staged site-wide target rotates
/// on its own once the feature flag is on: the entry guard promotes it to
/// `RotatingBmc`, the rotation converges the device and rewrites the per-device
/// secret, and the power shelf returns to Ready.
#[crate::sqlx_test]
async fn ready_power_shelf_converges_pmc_to_site_target(pool: sqlx::PgPool) -> TestResult {
    let env = create_test_env(pool.clone()).await;

    let power_shelf_id = common::api_fixtures::site_explorer::new_power_shelf(
        &env,
        Some("BMC Rotation Test Power Shelf".to_string()),
        Some(5000),
        Some(240),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;
    let pmc_mac = seed_pmc_endpoint(&pool, power_shelf_id).await?;

    // Move the power shelf to Ready so the BMC-rotation gate is the only pending
    // work.
    {
        let mut txn = pool.begin().await?;
        set_power_shelf_controller_state(
            txn.as_mut(),
            &power_shelf_id,
            PowerShelfControllerState::Ready,
        )
        .await?;
        txn.commit().await?;
    }

    // The PMC currently holds the per-device "old" secret.
    env.redfish_sim.seed_user("root", "old");
    env.test_credential_manager
        .set_credentials(&per_device_key(pmc_mac), &creds("root", "old"))
        .await
        .expect("staging the per-device secret should succeed");

    // Stage a site-wide rotation to version 1: record the device converged at
    // the v0 baseline, advance the target, and write the rotate-to secret that
    // `RotateCredential` would have staged.
    {
        let mut conn = pool.acquire().await?;
        record_device_converged(&mut conn, pmc_mac, BMC).await?;
        set_next_target_version(&mut conn, BMC, 0, serde_json::json!({}))
            .await?
            .expect("target must advance from version 0");
    }
    env.test_credential_manager
        .set_credentials(&rotate_to_key(1), &creds("root", "new"))
        .await
        .expect("staging the rotate-to secret should succeed");

    // The device lags the staged target before the controller runs.
    {
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, pmc_mac)
            .await?
            .expect("device rotation row should exist");
        assert!(
            !status.converged,
            "device should lag the staged target before rotation"
        );
    }

    // Iteration 1: Ready observes the lag and enters RotatingBmc.
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, true),
    )
    .await;
    let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
    assert!(
        matches!(
            power_shelf.controller_state.value,
            PowerShelfControllerState::RotatingBmc { .. }
        ),
        "expected RotatingBmc after the entry guard fires, got {:?}",
        power_shelf.controller_state.value,
    );

    // Iteration 2: the gate records a site-explorer suppression for the PMC and
    // waits for its acknowledgement before touching the credential, so the shelf
    // stays in RotatingBmc and nothing is rotated yet.
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, true),
    )
    .await;
    let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
    assert!(
        matches!(
            power_shelf.controller_state.value,
            PowerShelfControllerState::RotatingBmc { .. }
        ),
        "rotation must wait in RotatingBmc until site-explorer acknowledges, got {:?}",
        power_shelf.controller_state.value,
    );

    // Site-explorer acknowledges the suppression (its skip barrier).
    ack_all_site_explorer_suppressions(&pool).await;

    // Iteration 3: with the barrier satisfied, the rotation converges the device
    // and returns to Ready.
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, true),
    )
    .await;
    let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
    assert!(
        matches!(
            power_shelf.controller_state.value,
            PowerShelfControllerState::Ready
        ),
        "expected Ready once rotation settles, got {:?}",
        power_shelf.controller_state.value,
    );

    // The device is converged at the target, and the per-device secret is the
    // rotated value.
    {
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, pmc_mac)
            .await?
            .expect("device rotation row should exist");
        assert!(
            status.converged,
            "device should be converged after rotation"
        );
        assert_eq!(
            status.current_version,
            Some(1),
            "device should be recorded at target version 1"
        );
    }
    let persisted = env
        .test_credential_manager
        .get_credentials(&per_device_key(pmc_mac))
        .await
        .expect("reading the per-device secret should succeed")
        .expect("per-device secret should still be set");
    assert_eq!(
        persisted,
        creds("root", "new"),
        "per-device secret should be rotated to the new password"
    );

    Ok(())
}

/// A failing PMC rotation must not trap the power shelf in `RotatingBmc`: the
/// engine quarantines the device (backoff) and the handler returns to `Ready`,
/// and because the passive gate skips quarantined devices the shelf then stays
/// in `Ready` rather than hot-looping Ready -> RotatingBmc every sweep. The
/// bounded transient-retry budget is unit-tested separately on `advance`; this
/// covers the device-fault (quarantine) arm end-to-end.
#[crate::sqlx_test]
async fn failing_pmc_rotation_returns_to_ready_and_quarantines(pool: sqlx::PgPool) -> TestResult {
    let env = create_test_env(pool.clone()).await;

    let power_shelf_id = common::api_fixtures::site_explorer::new_power_shelf(
        &env,
        Some("BMC Rotation Failure Test Power Shelf".to_string()),
        Some(5000),
        Some(240),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;
    let pmc_mac = seed_pmc_endpoint(&pool, power_shelf_id).await?;

    {
        let mut txn = pool.begin().await?;
        set_power_shelf_controller_state(
            txn.as_mut(),
            &power_shelf_id,
            PowerShelfControllerState::Ready,
        )
        .await?;
        txn.commit().await?;
    }

    env.redfish_sim.seed_user("root", "old");
    env.test_credential_manager
        .set_credentials(&per_device_key(pmc_mac), &creds("root", "old"))
        .await
        .expect("staging the per-device secret should succeed");

    // Stage a lagging target to version 1 but deliberately do NOT stage the
    // rotate-to secret, so the rotation attempt fails and the engine quarantines
    // the device (the `rotate_bmc_quarantines_when_rotate_to_secret_is_not_staged`
    // arm) rather than converging.
    {
        let mut conn = pool.acquire().await?;
        record_device_converged(&mut conn, pmc_mac, BMC).await?;
        set_next_target_version(&mut conn, BMC, 0, serde_json::json!({}))
            .await?
            .expect("target must advance from version 0");
    }

    // Iteration 1: Ready observes the lag and enters RotatingBmc.
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, true),
    )
    .await;
    let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
    assert!(
        matches!(
            power_shelf.controller_state.value,
            PowerShelfControllerState::RotatingBmc { .. }
        ),
        "expected RotatingBmc after the entry guard fires, got {:?}",
        power_shelf.controller_state.value,
    );

    // Iteration 2: the gate records a site-explorer suppression and waits for its
    // acknowledgement, so the shelf stays in RotatingBmc before any rotation is
    // attempted.
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, true),
    )
    .await;
    let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
    assert!(
        matches!(
            power_shelf.controller_state.value,
            PowerShelfControllerState::RotatingBmc { .. }
        ),
        "rotation must wait in RotatingBmc until site-explorer acknowledges, got {:?}",
        power_shelf.controller_state.value,
    );
    ack_all_site_explorer_suppressions(&pool).await;

    // Iteration 3: the rotation attempt fails; the engine quarantines the device
    // and the handler settles back to Ready (RotatingBmc is not terminal).
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, true),
    )
    .await;
    let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
    assert!(
        matches!(
            power_shelf.controller_state.value,
            PowerShelfControllerState::Ready
        ),
        "expected Ready after a failed rotation settles, got {:?}",
        power_shelf.controller_state.value,
    );
    {
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, pmc_mac)
            .await?
            .expect("device rotation row should exist");
        assert!(!status.converged, "a failed rotation must not converge");
        assert!(
            status.quarantined,
            "a failed rotation must quarantine the device with backoff"
        );
        assert!(
            status.rotate_attempts >= 1,
            "a failed rotation must record at least one attempt, got {}",
            status.rotate_attempts
        );
    }

    // Further sweeps must NOT re-enter RotatingBmc: the passive gate skips the
    // quarantined device, so the shelf idles in Ready until backoff elapses
    // instead of hot-looping Ready -> RotatingBmc -> Ready forever.
    for _ in 0..3 {
        run_power_shelf_controller_with_services(
            pool.clone(),
            env.api.work_lock_manager_handle.clone(),
            power_shelf_services(&env, &pool, true),
        )
        .await;
        let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
        assert!(
            matches!(
                power_shelf.controller_state.value,
                PowerShelfControllerState::Ready
            ),
            "a quarantined shelf must stay in Ready, got {:?}",
            power_shelf.controller_state.value,
        );
    }

    Ok(())
}

/// With the site-wide feature flag off (the production default), a Ready power
/// shelf whose PMC lags the staged target must NOT rotate on its own: the
/// passive gate is the fleet kill-switch, so the shelf stays in `Ready`. Mirrors
/// the machine-controller `feature_flag_off_suppresses_passive_rotation`.
#[crate::sqlx_test]
async fn feature_flag_off_suppresses_pmc_rotation(pool: sqlx::PgPool) -> TestResult {
    let env = create_test_env(pool.clone()).await;

    let power_shelf_id = common::api_fixtures::site_explorer::new_power_shelf(
        &env,
        Some("BMC Rotation Kill-Switch Test Power Shelf".to_string()),
        Some(5000),
        Some(240),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;
    let pmc_mac = seed_pmc_endpoint(&pool, power_shelf_id).await?;
    move_to_ready(&pool, &power_shelf_id).await?;
    stage_lagging_pmc(&env, &pool, pmc_mac).await?;

    // A full sweep with the flag OFF must leave the lagging shelf in Ready.
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, false),
    )
    .await;
    let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
    assert!(
        matches!(
            power_shelf.controller_state.value,
            PowerShelfControllerState::Ready
        ),
        "expected Ready to be preserved while the feature flag is off, got {:?}",
        power_shelf.controller_state.value,
    );
    {
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, pmc_mac)
            .await?
            .expect("device rotation row should exist");
        assert!(
            !status.converged,
            "the PMC must remain unrotated while the feature flag is off"
        );
    }

    Ok(())
}

/// The operator force-converge escape hatch overrides both the site-wide flag
/// (off here) and the device's active backoff quarantine: the targeted PMC is
/// rotated on the next sweep and the one-shot request is cleared afterward.
/// Mirrors the machine-controller `force_request_converges_quarantined_bmc_when_disabled`.
#[crate::sqlx_test]
async fn force_request_converges_quarantined_pmc_when_disabled(pool: sqlx::PgPool) -> TestResult {
    let env = create_test_env(pool.clone()).await;

    let power_shelf_id = common::api_fixtures::site_explorer::new_power_shelf(
        &env,
        Some("BMC Rotation Force Test Power Shelf".to_string()),
        Some(5000),
        Some(240),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;
    let pmc_mac = seed_pmc_endpoint(&pool, power_shelf_id).await?;
    move_to_ready(&pool, &power_shelf_id).await?;
    stage_lagging_pmc(&env, &pool, pmc_mac).await?;

    // Quarantine the device (so the passive gate would skip it even if enabled)
    // and record the operator's force-converge request on the shelf row.
    {
        let mut conn = pool.acquire().await?;
        increment_rotate_attempt(
            &mut conn,
            pmc_mac,
            BMC,
            "seed backoff",
            Utc::now() + chrono::Duration::seconds(3600),
        )
        .await?;
        db_power_shelf::set_bmc_credential_rotation_requested(&mut conn, power_shelf_id).await?;
    }

    // Iteration 1: the force request drives entry into RotatingBmc despite the
    // disabled site-wide flag.
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, false),
    )
    .await;
    let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
    assert!(
        matches!(
            power_shelf.controller_state.value,
            PowerShelfControllerState::RotatingBmc { .. }
        ),
        "expected RotatingBmc from the force request, got {:?}",
        power_shelf.controller_state.value,
    );

    // Iteration 2: even a forced rotation first gates on site-explorer, so it
    // waits in RotatingBmc until the suppression is acknowledged.
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, false),
    )
    .await;
    let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
    assert!(
        matches!(
            power_shelf.controller_state.value,
            PowerShelfControllerState::RotatingBmc { .. }
        ),
        "a forced rotation must still wait for site-explorer acknowledgement, got {:?}",
        power_shelf.controller_state.value,
    );
    ack_all_site_explorer_suppressions(&pool).await;

    // Iteration 3: the forced tick bypasses backoff, converges the device, and
    // returns to Ready.
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, false),
    )
    .await;
    let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
    assert!(
        matches!(
            power_shelf.controller_state.value,
            PowerShelfControllerState::Ready
        ),
        "expected Ready once the forced rotation settles, got {:?}",
        power_shelf.controller_state.value,
    );

    // The device converged despite its quarantine, and the one-shot request was
    // cleared so the shelf does not re-enter RotatingBmc on the next sweep.
    {
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, pmc_mac)
            .await?
            .expect("device rotation row should exist");
        assert!(
            status.converged,
            "the forced rotation must converge the PMC despite its quarantine"
        );
    }
    assert!(
        !power_shelf.bmc_credential_rotation_requested,
        "the one-shot force request must be cleared after a settled forced rotation"
    );

    Ok(())
}

/// When the PMC password change lands but persisting the new per-device secret
/// to the store fails, the hardware is AHEAD of the store. The power shelf must
/// hold in `RotatingBmc` (keeping the site-explorer suppression) rather than
/// settling to Ready with a stale stored secret, and keep retrying until the
/// store reconciles.
#[crate::sqlx_test]
async fn store_persist_failure_holds_in_rotating_bmc_until_reconciled(
    pool: sqlx::PgPool,
) -> TestResult {
    let env = create_test_env(pool.clone()).await;

    let power_shelf_id = common::api_fixtures::site_explorer::new_power_shelf(
        &env,
        Some("BMC Rotation Store-Lag Test Power Shelf".to_string()),
        Some(5000),
        Some(240),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;
    let pmc_mac = seed_pmc_endpoint(&pool, power_shelf_id).await?;
    move_to_ready(&pool, &power_shelf_id).await?;
    stage_lagging_pmc(&env, &pool, pmc_mac).await?;

    // Enter RotatingBmc, let the gate record the suppression, and acknowledge it.
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, true),
    )
    .await; // Ready -> RotatingBmc
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, true),
    )
    .await; // gate records the suppression and waits
    ack_all_site_explorer_suppressions(&pool).await;

    // The store write now fails: the hardware change will land but the persist
    // will not, leaving the PMC ahead of the store.
    env.test_credential_manager
        .set_set_credentials_failure(true);

    // The password change succeeds on the hardware but the persist fails, so the
    // shelf holds in RotatingBmc instead of returning to Ready.
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, true),
    )
    .await;
    let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
    assert!(
        matches!(
            power_shelf.controller_state.value,
            PowerShelfControllerState::RotatingBmc { .. }
        ),
        "a persist failure must hold in RotatingBmc, got {:?}",
        power_shelf.controller_state.value,
    );
    assert!(
        db::bmc_suppression::is_suppressed(&pool, pmc_mac, BmcSuppressionSubsystem::SiteExplorer)
            .await?,
        "the rotation suppression must be retained while the store lags"
    );
    {
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, pmc_mac)
            .await?
            .expect("device rotation row should exist");
        assert!(
            !status.converged,
            "hardware ahead of store is not converged"
        );
        assert!(
            !status.quarantined,
            "a persist failure must not record a backoff"
        );
    }
    assert_eq!(
        env.redfish_sim.user_password("root").as_deref(),
        Some("new"),
        "the hardware change must have landed even though the persist failed"
    );
    assert_eq!(
        env.test_credential_manager
            .get_credentials(&per_device_key(pmc_mac))
            .await
            .expect("reading the per-device secret should succeed")
            .expect("per-device secret should still be set"),
        creds("root", "old"),
        "the stored secret must still lag after the failed persist"
    );

    // The store becomes writable again: the next tick reconciles and returns to
    // Ready.
    env.test_credential_manager
        .set_set_credentials_failure(false);
    run_power_shelf_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        power_shelf_services(&env, &pool, true),
    )
    .await;
    let power_shelf = load_power_shelf(&pool, &power_shelf_id).await?;
    assert!(
        matches!(
            power_shelf.controller_state.value,
            PowerShelfControllerState::Ready
        ),
        "expected Ready once the store reconciles, got {:?}",
        power_shelf.controller_state.value,
    );
    assert!(
        !db::bmc_suppression::is_suppressed(&pool, pmc_mac, BmcSuppressionSubsystem::SiteExplorer)
            .await?,
        "resume must delete the rotation suppression once reconciled"
    );
    {
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, pmc_mac)
            .await?
            .expect("device rotation row should exist");
        assert!(
            status.converged,
            "device should converge once the store reconciles"
        );
        assert_eq!(status.current_version, Some(1));
    }
    assert_eq!(
        env.test_credential_manager
            .get_credentials(&per_device_key(pmc_mac))
            .await
            .expect("reading the per-device secret should succeed")
            .expect("per-device secret should still be set"),
        creds("root", "new"),
        "the store is reconciled to the new password once the write succeeds"
    );

    Ok(())
}
