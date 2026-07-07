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

use carbide_redfish::libredfish::RedfishClientPool as _;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::FixtureDefault as _;
use carbide_utils::redfish::BmcAccessInfo;
use model::machine::ManagedHostState;
use model::power_manager::PowerState;
use model::test_support::ManagedHostConfig;
use rpc::forge::{
    MaintenanceOperation, MaintenanceRequest, PowerOptionRequest, PowerOptionUpdateRequest,
};
use tonic::Request;

use crate::env::Env;

struct TestContext {
    env: Env,
    mh: TestManagedHost,
}

impl TestContext {
    async fn init(pool: PgPool) -> Self {
        let env = Env::builder(pool)
            .configure_runtime(|config| {
                let zero = chrono::Duration::zero();
                config.power_manager_options.enabled = true;
                config.power_manager_options.next_try_duration_on_success = zero;
                config.power_manager_options.next_try_duration_on_failure = zero;
                config.power_manager_options.wait_duration_until_host_reboot = zero;
            })
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
        Self { env, mh }
    }
}

trait TestManagedHostPowerExt {
    async fn bmc_access_info(&self) -> BmcAccessInfo;

    async fn set_next_power_poll_now(&self);
}

impl TestManagedHostPowerExt for TestManagedHost {
    async fn bmc_access_info(&self) -> BmcAccessInfo {
        let machine = self.host.machine().await;
        let bmc_address = machine.bmc_addr().expect("host should have a BMC address");
        let mut txn = self
            .api
            .database_connection
            .begin()
            .await
            .expect("database transaction should start");
        let bmc_access_info = db::machine_interface::lookup_bmc_access_info(
            txn.as_mut(),
            bmc_address.ip(),
            Some(bmc_address.port()),
        )
        .await
        .expect("host BMC access information should exist");
        txn.commit()
            .await
            .expect("database transaction should commit");
        bmc_access_info
    }

    async fn set_next_power_poll_now(&self) {
        let mut txn = self
            .api
            .database_connection
            .begin()
            .await
            .expect("database transaction should start");
        sqlx::query("UPDATE power_options SET last_fetched_next_try_at = now() WHERE host_id = $1")
            .bind(self.host.id)
            .execute(txn.as_mut())
            .await
            .expect("next power poll should be updated");
        txn.commit()
            .await
            .expect("database transaction should commit");
    }
}

#[sqlx_test]
async fn desired_on_polls_powered_off_machine(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let TestContext { mut env, mh } = TestContext::init(pool).await;

    let mut txn = env.test_harness.db_txn().await;
    let power_options = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_options[0].desired_power_state, PowerState::On);
    assert_eq!(power_options[0].last_fetched_power_state, PowerState::On);
    txn.rollback().await?;
    let bmc_access_info = mh.bmc_access_info().await;

    let sim = env.redfish_sim.client_by_info(&bmc_access_info).await?;
    sim.power(libredfish::SystemPowerControl::ForceOff).await?;
    assert_eq!(sim.get_power_state().await?, libredfish::PowerState::Off);
    mh.set_next_power_poll_now().await;

    env.run_single_iteration().await;
    // Since delay is set to 0 for test, db must be updated immediately.
    let mut txn = env.test_harness.db_txn().await;
    let power_options = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_options[0].desired_power_state, PowerState::On);
    assert_eq!(power_options[0].last_fetched_power_state, PowerState::Off);
    txn.rollback().await?;

    // Wait for one cycle.
    env.run_single_iteration().await;
    let mut txn = env.test_harness.db_txn().await;
    let power_options = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_options[0].desired_power_state, PowerState::On);
    assert_eq!(power_options[0].last_fetched_power_state, PowerState::Off);
    txn.rollback().await?;

    // State machine should power on the host.
    env.run_single_iteration().await;
    let mut txn = env.test_harness.db_txn().await;
    let power_options = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_options[0].desired_power_state, PowerState::On);
    assert_eq!(power_options[0].last_fetched_power_state, PowerState::Off);
    txn.rollback().await?;

    Ok(())
}

#[sqlx_test]
async fn desired_on_limits_power_on_attempts(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let TestContext { mut env, mh } = TestContext::init(pool).await;

    let mut txn = env.test_harness.db_txn().await;
    let power_options = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_options[0].desired_power_state, PowerState::On);
    assert_eq!(power_options[0].last_fetched_power_state, PowerState::On);
    txn.rollback().await?;
    let bmc_access_info = mh.bmc_access_info().await;

    let sim = env.redfish_sim.client_by_info(&bmc_access_info).await?;
    sim.power(libredfish::SystemPowerControl::ForceOff).await?;
    assert_eq!(sim.get_power_state().await?, libredfish::PowerState::Off);
    mh.set_next_power_poll_now().await;

    // Run a iteration.
    // Since delay is set to 0 for test, db must be updated immediately.
    env.run_single_iteration().await;
    let mut txn = env.test_harness.db_txn().await;
    let power_options = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_options[0].desired_power_state, PowerState::On);
    assert_eq!(power_options[0].last_fetched_power_state, PowerState::Off);
    txn.rollback().await?;

    for _ in 1..10 {
        // Keep power off
        sim.power(libredfish::SystemPowerControl::ForceOff).await?;
        env.run_single_iteration().await;

        let mut txn = env.test_harness.db_txn().await;
        let power_options = db::power_options::get_all(&mut txn).await?;
        assert_eq!(power_options[0].desired_power_state, PowerState::On);
        assert_eq!(power_options[0].last_fetched_power_state, PowerState::Off);
        txn.rollback().await?;
    }

    let response = env
        .test_harness
        .api()
        .get_power_options(Request::new(PowerOptionRequest {
            machine_id: vec![mh.host.id],
        }))
        .await?
        .into_inner();
    assert_eq!(response.response[0].tried_triggering_on_counter, 3);

    Ok(())
}

#[sqlx_test]
async fn desired_off_persists_observed_off_state(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let TestContext { mut env, mh } = TestContext::init(pool).await;

    let mut txn = env.test_harness.db_txn().await;
    let power_options = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_options[0].desired_power_state, PowerState::On);
    assert_eq!(power_options[0].last_fetched_power_state, PowerState::On);
    txn.rollback().await?;
    let bmc_access_info = mh.bmc_access_info().await;

    // Set maintenance mode (required before setting desired=Off).
    env.test_harness
        .api()
        .set_maintenance(Request::new(MaintenanceRequest {
            operation: MaintenanceOperation::Enable as i32,
            host_id: Some(mh.host.id),
            reference: Some("testing".to_string()),
        }))
        .await?;

    // Set desired power state to Off.
    env.test_harness
        .api()
        .update_power_option(Request::new(PowerOptionUpdateRequest {
            machine_id: Some(mh.host.id),
            power_state: rpc::forge::PowerState::Off as i32,
        }))
        .await?;

    let mut txn = env.test_harness.db_txn().await;
    let power_options = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_options[0].desired_power_state, PowerState::Off);
    txn.rollback().await?;

    // Simulate the host being powered off via BMC.
    let sim = env.redfish_sim.client_by_info(&bmc_access_info).await?;
    sim.power(libredfish::SystemPowerControl::ForceOff).await?;
    assert_eq!(sim.get_power_state().await?, libredfish::PowerState::Off);

    // Record timestamps before the state controller iteration.
    let mut txn = env.test_harness.db_txn().await;
    let power_options = db::power_options::get_all(&mut txn).await?;
    let updated_at_before_poll = power_options[0].last_fetched_updated_at;
    txn.rollback().await?;

    // Advance next_try_at so the state controller will poll BMC.
    mh.set_next_power_poll_now().await;

    // Run state controller iteration — should poll BMC, see Off, and persist the update.
    env.run_single_iteration().await;

    let mut txn = env.test_harness.db_txn().await;
    let power_options = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_options[0].desired_power_state, PowerState::Off);
    assert_eq!(power_options[0].last_fetched_power_state, PowerState::Off);
    assert!(power_options[0].last_fetched_updated_at > updated_at_before_poll);
    txn.rollback().await?;

    Ok(())
}
