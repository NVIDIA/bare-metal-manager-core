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

//! End-to-end coverage for machine-controller BMC credential rotation (REQ-2):
//! a staged site-wide target drives a Ready host through
//! `ManagedHostState::RotatingBmc` and back to Ready, converging the device and
//! persisting the rotated per-device secret.

use std::sync::Arc;

use carbide_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialReader, CredentialWriter, Credentials,
};
use carbide_secrets::test_support::credentials::TestCredentialManager;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::FixtureDefault as _;
use chrono::{Duration, Utc};
use db::credential_rotation::{
    CredentialRotationType, device_rotation_status, increment_rotate_attempt,
    record_device_converged, set_next_target_version,
};
use mac_address::MacAddress;
use model::machine::ManagedHostState;
use model::test_support::ManagedHostConfig;

use crate::env::Env;

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

/// A Ready pool host whose BMC lags a freshly staged site-wide target rotates on
/// its own: the entry guard promotes it to `RotatingBmc`, the rotation converges
/// the device and rewrites the per-device secret, and the host returns to Ready.
#[sqlx_test]
async fn ready_host_converges_bmc_to_site_target(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Own the credential manager so we can stage secrets and later assert the
    // rotated value; the controller reads and writes through this same store.
    let cm = Arc::new(TestCredentialManager::default());

    let mut env = Env::builder(pool.clone())
        .with_credential_manager(cm.clone())
        // The passive rotation guard is gated behind the site-wide feature flag.
        .configure_runtime(|c| c.bmc_rotation_enabled = true)
        .build()
        .await;

    // Build a Ready pool host on the shared Redfish sim.
    let domain = env.test_harness.test_domain().await;
    let network_controller = env.test_harness.network_controller();
    let underlay_segment = network_controller.create_underlay_segment(&domain).await;
    network_controller.create_admin_segment(&domain).await;
    let site_explorer = env.test_harness.default_test_site_explorer();
    let mh = env
        .test_harness
        .managed_host_builder(&site_explorer, underlay_segment)
        .with_config(ManagedHostConfig::default())
        .build()
        .await
        .0;
    mh.advance_state(ManagedHostState::Ready).await;

    let host_mac = mh
        .host
        .machine()
        .await
        .status
        .bmc_info
        .mac
        .expect("fixture host should have a BMC MAC");

    // The host BMC currently holds the per-device "old" secret.
    env.redfish_sim.seed_user("root", "old");
    cm.set_credentials(&per_device_key(host_mac), &creds("root", "old"))
        .await
        .expect("staging the per-device secret should succeed");

    // Stage a site-wide rotation to version 1: record the device converged at
    // the v0 baseline, advance the target, and write the rotate-to secret that
    // `RotateCredential` would have staged.
    {
        let mut conn = pool.acquire().await?;
        record_device_converged(&mut conn, host_mac, BMC).await?;
        set_next_target_version(&mut conn, BMC, 0, serde_json::json!({}))
            .await?
            .expect("target must advance from version 0");
    }
    cm.set_credentials(&rotate_to_key(1), &creds("root", "new"))
        .await
        .expect("staging the rotate-to secret should succeed");

    // The device lags the staged target before the controller runs.
    {
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, host_mac)
            .await?
            .expect("device rotation row should exist");
        assert!(
            !status.converged,
            "device should lag the staged target before rotation"
        );
    }

    // Iteration 1: Ready observes the lag and enters RotatingBmc.
    env.run_single_iteration().await;
    assert!(
        matches!(
            mh.host.machine().await.state.value,
            ManagedHostState::RotatingBmc { .. }
        ),
        "expected RotatingBmc after the entry guard fires, got {:?}",
        mh.host.machine().await.state.value,
    );

    // Iteration 2: the rotation converges the device and returns to Ready.
    env.run_single_iteration().await;
    assert!(
        matches!(mh.host.machine().await.state.value, ManagedHostState::Ready),
        "expected Ready once rotation settles, got {:?}",
        mh.host.machine().await.state.value,
    );

    // The device is converged at the target, and the per-device secret is the
    // rotated value.
    {
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, host_mac)
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
    let persisted = cm
        .get_credentials(&per_device_key(host_mac))
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

/// Stage a site-wide rotation to version 1 with the host BMC lagging at the v0
/// baseline: seed the per-device "old" secret in both the sim and the store,
/// advance the target, and stage the rotate-to "new" secret.
async fn stage_lagging_bmc(
    pool: &PgPool,
    cm: &TestCredentialManager,
    host_mac: MacAddress,
) -> Result<(), Box<dyn std::error::Error>> {
    cm.set_credentials(&per_device_key(host_mac), &creds("root", "old"))
        .await
        .expect("staging the per-device secret should succeed");
    {
        let mut conn = pool.acquire().await?;
        record_device_converged(&mut conn, host_mac, BMC).await?;
        set_next_target_version(&mut conn, BMC, 0, serde_json::json!({}))
            .await?
            .expect("target must advance from version 0");
    }
    cm.set_credentials(&rotate_to_key(1), &creds("root", "new"))
        .await
        .expect("staging the rotate-to secret should succeed");
    Ok(())
}

/// With the site-wide feature flag off (the default), a Ready host that lags the
/// staged target must NOT rotate on its own: the passive gate is the fleet
/// kill-switch, so the host stays Ready.
#[sqlx_test]
async fn feature_flag_off_suppresses_passive_rotation(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let cm = Arc::new(TestCredentialManager::default());
    // No configure_runtime: bmc_rotation_enabled defaults to false.
    let mut env = Env::builder(pool.clone())
        .with_credential_manager(cm.clone())
        .build()
        .await;

    let domain = env.test_harness.test_domain().await;
    let network_controller = env.test_harness.network_controller();
    let underlay_segment = network_controller.create_underlay_segment(&domain).await;
    network_controller.create_admin_segment(&domain).await;
    let site_explorer = env.test_harness.default_test_site_explorer();
    let mh = env
        .test_harness
        .managed_host_builder(&site_explorer, underlay_segment)
        .with_config(ManagedHostConfig::default())
        .build()
        .await
        .0;
    mh.advance_state(ManagedHostState::Ready).await;

    let host_mac = mh
        .host
        .machine()
        .await
        .status
        .bmc_info
        .mac
        .expect("fixture host should have a BMC MAC");
    env.redfish_sim.seed_user("root", "old");
    stage_lagging_bmc(&pool, &cm, host_mac).await?;

    // A full sweep must leave the lagging host in Ready: the disabled flag keeps
    // the passive gate from ever promoting it to RotatingBmc.
    env.run_single_iteration().await;
    assert!(
        matches!(mh.host.machine().await.state.value, ManagedHostState::Ready),
        "expected Ready to be preserved while the feature flag is off, got {:?}",
        mh.host.machine().await.state.value,
    );
    {
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, host_mac)
            .await?
            .expect("device rotation row should exist");
        assert!(
            !status.converged,
            "device must remain unrotated while the feature flag is off"
        );
    }

    Ok(())
}

/// The operator force-converge escape hatch overrides both the site-wide flag
/// (off here) and the device's active backoff quarantine: the targeted BMC is
/// rotated on the next sweep and the one-shot request is cleared afterward.
#[sqlx_test]
async fn force_request_converges_quarantined_bmc_when_disabled(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let cm = Arc::new(TestCredentialManager::default());
    // Feature flag stays off: only the force request should drive rotation.
    let mut env = Env::builder(pool.clone())
        .with_credential_manager(cm.clone())
        .build()
        .await;

    let domain = env.test_harness.test_domain().await;
    let network_controller = env.test_harness.network_controller();
    let underlay_segment = network_controller.create_underlay_segment(&domain).await;
    network_controller.create_admin_segment(&domain).await;
    let site_explorer = env.test_harness.default_test_site_explorer();
    let mh = env
        .test_harness
        .managed_host_builder(&site_explorer, underlay_segment)
        .with_config(ManagedHostConfig::default())
        .build()
        .await
        .0;
    mh.advance_state(ManagedHostState::Ready).await;

    let host = mh.host.machine().await;
    let machine_id = host.id;
    let host_mac = host
        .status
        .bmc_info
        .mac
        .expect("fixture host should have a BMC MAC");
    env.redfish_sim.seed_user("root", "old");
    stage_lagging_bmc(&pool, &cm, host_mac).await?;

    // Quarantine the device (so the passive gate would skip it even if enabled)
    // and record the operator's force-converge request for this BMC.
    {
        let mut conn = pool.acquire().await?;
        increment_rotate_attempt(
            &mut conn,
            host_mac,
            BMC,
            "seed backoff",
            Utc::now() + Duration::seconds(3600),
        )
        .await?;
        db::machine::set_bmc_credential_rotation_requested(&mut conn, machine_id).await?;
    }

    // Iteration 1: the force request drives entry into RotatingBmc despite the
    // disabled flag.
    env.run_single_iteration().await;
    assert!(
        matches!(
            mh.host.machine().await.state.value,
            ManagedHostState::RotatingBmc { .. }
        ),
        "expected RotatingBmc from the force request, got {:?}",
        mh.host.machine().await.state.value,
    );

    // Iteration 2: the forced tick bypasses backoff, converges the device, and
    // returns to Ready.
    env.run_single_iteration().await;
    assert!(
        matches!(mh.host.machine().await.state.value, ManagedHostState::Ready),
        "expected Ready once the forced rotation settles, got {:?}",
        mh.host.machine().await.state.value,
    );

    // The device converged despite its quarantine, and the one-shot request was
    // cleared so it does not re-enter.
    {
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, host_mac)
            .await?
            .expect("device rotation row should exist");
        assert!(status.converged, "forced device should be converged");
        assert_eq!(status.current_version, Some(1));
    }
    assert!(
        !mh.host.machine().await.bmc_credential_rotation_requested,
        "the one-shot force request must be cleared once rotation settles"
    );
    let persisted = cm
        .get_credentials(&per_device_key(host_mac))
        .await
        .expect("reading the per-device secret should succeed")
        .expect("per-device secret should still be set");
    assert_eq!(persisted, creds("root", "new"));

    Ok(())
}
