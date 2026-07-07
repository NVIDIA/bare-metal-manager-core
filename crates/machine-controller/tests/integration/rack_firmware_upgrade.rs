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

use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::FixtureDefault as _;
use model::machine::{HostReprovisionState, ManagedHostState};
use model::rack::{RackFirmwareUpgradeState, RackFirmwareUpgradeStatus};
use model::test_support::ManagedHostConfig;

use crate::env::Env;

async fn managed_host(env: &TestHarness) -> TestManagedHost {
    let domain = env.test_domain().await;
    let network_controller = env.network_controller();
    let underlay_segment = network_controller.create_underlay_segment(&domain).await;
    network_controller.create_admin_segment(&domain).await;
    let site_explorer = env.default_test_site_explorer();
    env.managed_host_builder(&site_explorer, underlay_segment)
        .with_config(ManagedHostConfig::default())
        .build()
        .await
        .0
}

async fn prepare_rack_upgrade(
    env: &TestHarness,
    host: &TestManagedHost,
    status: RackFirmwareUpgradeState,
    started_at_offset: chrono::Duration,
    ended_at_offset: Option<chrono::Duration>,
) {
    let mut txn = env.db_txn().await;
    db::host_machine_update::trigger_host_reprovisioning_request(
        txn.as_mut(),
        "rack-test",
        &host.host.id,
    )
    .await
    .unwrap();
    let machine = host.host.db_machine(&mut txn).await;
    let requested_at = machine
        .host_reprovision_requested
        .as_ref()
        .expect("rack reprovision request should exist")
        .requested_at;
    machine
        .update_state(
            &mut txn,
            ManagedHostState::HostReprovision {
                reprovision_state: HostReprovisionState::WaitingForRackFirmwareUpgrade,
                retry_count: 0,
            },
        )
        .await;
    db::machine::update_rack_fw_details(
        txn.as_mut(),
        &host.host.id,
        Some(&RackFirmwareUpgradeStatus {
            task_id: "rack-job".to_string(),
            status,
            started_at: Some(requested_at + started_at_offset),
            ended_at: ended_at_offset.map(|offset| requested_at + offset),
        }),
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();
}

#[sqlx_test]
async fn waits_for_terminal_status(pool: PgPool) {
    let mut env = Env::builder(pool).build().await;
    let host = managed_host(&env.test_harness).await;
    prepare_rack_upgrade(
        &env.test_harness,
        &host,
        RackFirmwareUpgradeState::InProgress,
        chrono::Duration::zero(),
        None,
    )
    .await;

    env.run_single_iteration().await;

    let machine = host.host.machine().await;
    assert!(matches!(
        machine.current_state(),
        ManagedHostState::HostReprovision {
            reprovision_state: HostReprovisionState::WaitingForRackFirmwareUpgrade,
            ..
        }
    ));
    assert!(machine.host_reprovision_requested.is_some());
}

#[sqlx_test]
async fn advances_on_completion(pool: PgPool) {
    let mut env = Env::builder(pool).build().await;
    let host = managed_host(&env.test_harness).await;
    prepare_rack_upgrade(
        &env.test_harness,
        &host,
        RackFirmwareUpgradeState::Completed,
        chrono::Duration::zero(),
        Some(chrono::Duration::zero()),
    )
    .await;

    env.run_single_iteration().await;

    let machine = host.host.machine().await;
    assert!(matches!(
        machine.current_state(),
        ManagedHostState::HostReprovision {
            reprovision_state: HostReprovisionState::CheckingFirmwareRepeatV2 { .. },
            ..
        }
    ));
    assert!(machine.host_reprovision_requested.is_none());
}

#[sqlx_test]
async fn accepts_completion_when_only_ended_at_is_current(pool: PgPool) {
    let mut env = Env::builder(pool).build().await;
    let host = managed_host(&env.test_harness).await;
    prepare_rack_upgrade(
        &env.test_harness,
        &host,
        RackFirmwareUpgradeState::Completed,
        -chrono::Duration::seconds(1),
        Some(chrono::Duration::seconds(1)),
    )
    .await;

    env.run_single_iteration().await;

    let machine = host.host.machine().await;
    assert!(matches!(
        machine.current_state(),
        ManagedHostState::HostReprovision {
            reprovision_state: HostReprovisionState::CheckingFirmwareRepeatV2 { .. },
            ..
        }
    ));
    assert!(machine.host_reprovision_requested.is_none());
}
