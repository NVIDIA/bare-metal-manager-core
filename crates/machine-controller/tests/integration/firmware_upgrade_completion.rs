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

use carbide_machine_controller::handler::MAX_NEW_FIRMWARE_REPORTED_RESET_RETRIES;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::FixtureDefault as _;
use model::firmware::FirmwareComponentType;
use model::machine::{HostReprovisionState, ManagedHostState, ScoutUpgradeResult};
use model::test_support::ManagedHostConfig;

use crate::env::Env;

struct TestContext {
    env: Env,
    mh: TestManagedHost,
}

impl TestContext {
    async fn init(pool: PgPool) -> Self {
        let env = Env::builder(pool).build().await;
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
        Self { env, mh }
    }
}

trait TestManagedHostFirmwareExt {
    async fn put_in_waiting_for_scout_upgrade(
        &self,
        deadline: chrono::DateTime<chrono::Utc>,
        power_drains_needed: Option<u32>,
        result: Option<ScoutUpgradeResult>,
    );

    async fn put_in_new_firmware_reported_wait(
        &self,
        previous_reset_time: i64,
        reset_retry_count: u32,
    );
}

impl TestManagedHostFirmwareExt for TestManagedHost {
    async fn put_in_waiting_for_scout_upgrade(
        &self,
        deadline: chrono::DateTime<chrono::Utc>,
        power_drains_needed: Option<u32>,
        result: Option<ScoutUpgradeResult>,
    ) {
        self.advance_state(ManagedHostState::HostReprovision {
            reprovision_state: HostReprovisionState::WaitingForScoutUpgrade {
                upgrade_task_id: "scout-upgrade-task-id".to_string(),
                firmware_type: FirmwareComponentType::Bmc,
                final_version: "1.2.3".to_string(),
                power_drains_needed,
                started_at: chrono::Utc::now(),
                deadline,
                task_json: String::new(),
                result,
            },
            retry_count: 0,
        })
        .await;
    }

    async fn put_in_new_firmware_reported_wait(
        &self,
        previous_reset_time: i64,
        reset_retry_count: u32,
    ) {
        self.advance_state(ManagedHostState::HostReprovision {
            reprovision_state: HostReprovisionState::NewFirmwareReportedWait {
                firmware_type: FirmwareComponentType::Uefi,
                firmware_number: Some(0),
                final_version: "1.13.2".to_string(),
                previous_reset_time: Some(previous_reset_time),
                reset_retry_count,
            },
            retry_count: 0,
        })
        .await;
    }
}

#[sqlx_test]
async fn new_firmware_reported_wait_retries_reset_after_timeout(pool: PgPool) {
    let TestContext { mut env, mh } = TestContext::init(pool).await;
    mh.put_in_new_firmware_reported_wait(chrono::Utc::now().timestamp() - 31 * 60, 0)
        .await;

    env.run_single_iteration().await;

    let machine = mh.host.machine().await;
    let ManagedHostState::HostReprovision {
        reprovision_state, ..
    } = machine.current_state()
    else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::NewFirmwareReportedWait {
        reset_retry_count, ..
    } = reprovision_state
    else {
        panic!("expected NewFirmwareReportedWait, got {reprovision_state:?}");
    };
    assert_eq!(*reset_retry_count, 1);
}

#[sqlx_test]
async fn new_firmware_reported_wait_fails_after_reset_retry_limit(pool: PgPool) {
    let TestContext { mut env, mh } = TestContext::init(pool).await;
    mh.put_in_new_firmware_reported_wait(
        chrono::Utc::now().timestamp() - 31 * 60,
        MAX_NEW_FIRMWARE_REPORTED_RESET_RETRIES,
    )
    .await;

    env.run_single_iteration().await;

    let machine = mh.host.machine().await;
    let ManagedHostState::HostReprovision {
        reprovision_state, ..
    } = machine.current_state()
    else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::FailedFirmwareUpgrade { reason, .. } = reprovision_state else {
        panic!("expected FailedFirmwareUpgrade, got {reprovision_state:?}");
    };
    let reason = reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("Firmware version did not converge after completed update"),
        "unexpected reason: {reason}",
    );
    assert!(
        reason.contains("expected 1.13.2"),
        "unexpected reason: {reason}",
    );
    assert!(reason.contains("1.12.0"), "unexpected reason: {reason}");
}

#[sqlx_test]
async fn successful_scout_upgrade_transitions_to_reset_for_new_firmware(pool: PgPool) {
    let TestContext { mut env, mh } = TestContext::init(pool).await;
    mh.put_in_waiting_for_scout_upgrade(
        chrono::Utc::now() + chrono::TimeDelta::minutes(60),
        Some(1),
        Some(ScoutUpgradeResult {
            success: true,
            exit_code: 0,
            stdout: "ok".to_string(),
            stderr: String::new(),
            error: String::new(),
        }),
    )
    .await;

    env.run_single_iteration().await;

    let machine = mh.host.machine().await;
    let ManagedHostState::HostReprovision {
        reprovision_state, ..
    } = machine.current_state()
    else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::ResetForNewFirmware {
        power_drains_needed,
        ..
    } = reprovision_state
    else {
        panic!("expected ResetForNewFirmware, got {reprovision_state:?}");
    };
    assert_eq!(*power_drains_needed, Some(1));
}

#[sqlx_test]
async fn failed_scout_upgrade_uses_error_as_reason(pool: PgPool) {
    let TestContext { mut env, mh } = TestContext::init(pool).await;
    mh.put_in_waiting_for_scout_upgrade(
        chrono::Utc::now() + chrono::TimeDelta::minutes(60),
        None,
        Some(ScoutUpgradeResult {
            success: false,
            exit_code: 1,
            stdout: String::new(),
            stderr: String::new(),
            error: "boom".to_string(),
        }),
    )
    .await;

    env.run_single_iteration().await;

    let machine = mh.host.machine().await;
    let ManagedHostState::HostReprovision {
        reprovision_state, ..
    } = machine.current_state()
    else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::FailedFirmwareUpgrade { reason, .. } = reprovision_state else {
        panic!("expected FailedFirmwareUpgrade, got {reprovision_state:?}");
    };
    assert_eq!(reason.as_deref(), Some("boom"));
}

#[sqlx_test]
async fn failed_scout_upgrade_without_error_uses_exit_code(pool: PgPool) {
    let TestContext { mut env, mh } = TestContext::init(pool).await;
    mh.put_in_waiting_for_scout_upgrade(
        chrono::Utc::now() + chrono::TimeDelta::minutes(60),
        None,
        Some(ScoutUpgradeResult {
            success: false,
            exit_code: 7,
            stdout: String::new(),
            stderr: String::new(),
            error: String::new(),
        }),
    )
    .await;

    env.run_single_iteration().await;

    let machine = mh.host.machine().await;
    let ManagedHostState::HostReprovision {
        reprovision_state, ..
    } = machine.current_state()
    else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::FailedFirmwareUpgrade { reason, .. } = reprovision_state else {
        panic!("expected FailedFirmwareUpgrade, got {reprovision_state:?}");
    };
    assert_eq!(
        reason.as_deref(),
        Some("Scout upgrade failed with exit code 7"),
    );
}

#[sqlx_test]
async fn scout_upgrade_past_deadline_times_out(pool: PgPool) {
    let TestContext { mut env, mh } = TestContext::init(pool).await;
    mh.put_in_waiting_for_scout_upgrade(
        chrono::Utc::now() - chrono::TimeDelta::minutes(1),
        None,
        None,
    )
    .await;

    env.run_single_iteration().await;

    let machine = mh.host.machine().await;
    let ManagedHostState::HostReprovision {
        reprovision_state, ..
    } = machine.current_state()
    else {
        panic!("Not in HostReprovision");
    };
    let HostReprovisionState::FailedFirmwareUpgrade { reason, .. } = reprovision_state else {
        panic!("expected FailedFirmwareUpgrade, got {reprovision_state:?}");
    };
    assert!(
        reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("Scout firmware upgrade timed out")),
        "unexpected reason: {reason:?}",
    );
}

#[sqlx_test]
async fn scout_upgrade_before_deadline_waits(pool: PgPool) {
    let TestContext { mut env, mh } = TestContext::init(pool).await;
    mh.put_in_waiting_for_scout_upgrade(
        chrono::Utc::now() + chrono::TimeDelta::minutes(60),
        None,
        None,
    )
    .await;

    env.run_single_iteration().await;

    let machine = mh.host.machine().await;
    let ManagedHostState::HostReprovision {
        reprovision_state, ..
    } = machine.current_state()
    else {
        panic!("Not in HostReprovision");
    };
    assert!(
        matches!(
            reprovision_state,
            HostReprovisionState::WaitingForScoutUpgrade { result: None, .. }
        ),
        "expected to remain in WaitingForScoutUpgrade, got {reprovision_state:?}",
    );
}
