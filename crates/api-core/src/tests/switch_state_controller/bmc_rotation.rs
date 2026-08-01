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

//! End-to-end coverage for switch-controller BMC credential rotation:
//! with the site-wide flag enabled, a staged target drives a Ready switch
//! through `SwitchControllerState::RotatingBmc` and back to Ready, converging
//! the device and persisting the rotated per-device secret. Mirrors the
//! machine-controller integration test `ready_host_converges_bmc_to_site_target`.

use carbide_credential_rotation::RotationGate;
use carbide_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialReader, CredentialWriter, Credentials,
};
use carbide_switch_controller::context::SwitchStateHandlerServices;
use db::credential_rotation::{
    CredentialRotationType, device_rotation_status, record_device_converged,
    set_next_target_version,
};
use db::switch as db_switch;
use mac_address::MacAddress;
use model::switch::{Switch, SwitchControllerState};

use super::fixtures::switch::transition_switch_controller_state;
use super::{common, default_switch_mtls_services, run_switch_controller_with_services};
use crate::tests::common::api_fixtures::create_test_env;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const BMC: CredentialRotationType = CredentialRotationType::Bmc;

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
/// and no component manager, so a Ready switch is not diverted to NVOS
/// reconciliation before reaching the BMC gate. A fresh [`RotationGate`]
/// refreshes its cached aggregate live on first use each iteration.
fn switch_services(
    env: &common::api_fixtures::TestEnv,
    pool: &sqlx::PgPool,
    bmc_rotation_enabled: bool,
) -> SwitchStateHandlerServices {
    SwitchStateHandlerServices {
        db_pool: pool.clone(),
        component_manager: None,
        credential_manager: env.test_credential_manager.clone(),
        switch_mtls_services: default_switch_mtls_services(),
        per_object_metrics_registry: env.per_object_metrics_registry(),
        redfish_client_pool: env.redfish_sim.clone(),
        bmc_rotation_gate: RotationGate::new_for_family(CredentialRotationType::Bmc),
        bmc_rotation_enabled,
    }
}

async fn load_switch(
    pool: &sqlx::PgPool,
    switch_id: &carbide_uuid::switch::SwitchId,
) -> TestResult<Switch> {
    let mut conn = pool.acquire().await?;
    Ok(db_switch::find_by_id(&mut conn, switch_id)
        .await?
        .expect("switch should exist"))
}

/// A Ready switch whose BMC lags a freshly staged site-wide target rotates on
/// its own once the feature flag is on: the entry guard promotes it to
/// `RotatingBmc`, the rotation converges the device and rewrites the per-device
/// secret, and the switch returns to Ready.
#[crate::sqlx_test]
async fn ready_switch_converges_bmc_to_site_target(pool: sqlx::PgPool) -> TestResult {
    let env = create_test_env(pool.clone()).await;

    let switch_id = common::api_fixtures::site_explorer::new_switch(&env, None, None).await?;
    let bmc_mac = db_switch::find_switch_endpoints_by_ids(&pool, &[switch_id])
        .await?
        .first()
        .expect("switch endpoint row")
        .bmc_mac;

    // Move the switch to Ready so the BMC-rotation gate is the only pending work.
    {
        let mut txn = pool.begin().await?;
        transition_switch_controller_state(txn.as_mut(), &switch_id, SwitchControllerState::Ready)
            .await?;
        txn.commit().await?;
    }

    // The switch BMC currently holds the per-device "old" secret.
    env.redfish_sim.seed_user("root", "old");
    env.test_credential_manager
        .set_credentials(&per_device_key(bmc_mac), &creds("root", "old"))
        .await
        .expect("staging the per-device secret should succeed");

    // Stage a site-wide rotation to version 1: record the device converged at
    // the v0 baseline, advance the target, and write the rotate-to secret that
    // `RotateCredential` would have staged.
    {
        let mut conn = pool.acquire().await?;
        record_device_converged(&mut conn, bmc_mac, BMC).await?;
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
        let status = device_rotation_status(&mut conn, BMC, bmc_mac)
            .await?
            .expect("device rotation row should exist");
        assert!(
            !status.converged,
            "device should lag the staged target before rotation"
        );
    }

    // Iteration 1: Ready observes the lag and enters RotatingBmc.
    run_switch_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        switch_services(&env, &pool, true),
    )
    .await;
    let switch = load_switch(&pool, &switch_id).await?;
    assert!(
        matches!(
            switch.controller_state.value,
            SwitchControllerState::RotatingBmc { .. }
        ),
        "expected RotatingBmc after the entry guard fires, got {:?}",
        switch.controller_state.value,
    );

    // Iteration 2: the rotation converges the device and returns to Ready.
    run_switch_controller_with_services(
        pool.clone(),
        env.api.work_lock_manager_handle.clone(),
        switch_services(&env, &pool, true),
    )
    .await;
    let switch = load_switch(&pool, &switch_id).await?;
    assert!(
        matches!(switch.controller_state.value, SwitchControllerState::Ready),
        "expected Ready once rotation settles, got {:?}",
        switch.controller_state.value,
    );

    // The device is converged at the target, and the per-device secret is the
    // rotated value.
    {
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, bmc_mac)
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
        .get_credentials(&per_device_key(bmc_mac))
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
