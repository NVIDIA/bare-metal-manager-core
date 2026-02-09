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
use db::managed_host::load_snapshot;
use db::{self};
use model::machine::LoadSnapshotOptions;
use model::power_manager::PowerState;
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    MaintenanceOperation, MaintenanceRequest, PowerOptionRequest, PowerOptionUpdateRequest,
};

use crate::redfish::RedfishClientPool;
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, create_managed_host, create_test_env_with_overrides,
};

#[crate::sqlx_test]
async fn test_power_manager_create_entry_on_host_creation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool, TestEnvOverrides::default().enable_power_manager())
            .await;
    let mut txn = env.pool.begin().await?;
    let power_entry = db::power_options::get_all(&mut txn).await?;
    assert!(power_entry.is_empty());
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

    let mut txn = env.pool.begin().await?;
    let power_entry = db::power_options::get_all(&mut txn).await?;

    assert_eq!(power_entry.len(), 1);
    assert_eq!(power_entry[0].host_id, host_machine_id);
    assert_eq!(power_entry[0].desired_power_state, PowerState::On);
    txn.rollback().await?;

    env.api
        .set_maintenance(tonic::Request::new(MaintenanceRequest {
            operation: MaintenanceOperation::Enable as i32,
            host_id: Some(host_machine_id),
            reference: Some("testing".to_string()),
        }))
        .await?;

    env.api
        .update_power_option(tonic::Request::new(PowerOptionUpdateRequest {
            machine_id: Some(host_machine_id),
            power_state: rpc::forge::PowerState::Off as i32,
        }))
        .await?;

    let mut txn = env.pool.begin().await?;
    let power_entry = db::power_options::get_all(&mut txn).await?;

    assert_eq!(power_entry.len(), 1);
    assert_eq!(power_entry[0].desired_power_state, PowerState::Off);
    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_manager_update_fail_since_no_maintenance_set(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool, TestEnvOverrides::default().enable_power_manager())
            .await;
    let mut txn = env.pool.begin().await?;
    let power_entry = db::power_options::get_all(&mut txn).await?;
    assert!(power_entry.is_empty());
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

    let mut txn = env.pool.begin().await?;
    let power_entry = db::power_options::get_all(&mut txn).await?;

    assert_eq!(power_entry.len(), 1);
    assert_eq!(power_entry[0].host_id, host_machine_id);
    assert_eq!(power_entry[0].desired_power_state, PowerState::On);
    txn.rollback().await?;

    let res = env
        .api
        .update_power_option(tonic::Request::new(PowerOptionUpdateRequest {
            machine_id: Some(host_machine_id),
            power_state: rpc::forge::PowerState::Off as i32,
        }))
        .await;

    assert!(res.is_err());
    assert_eq!(
        res.map_err(|x| x.message().to_string()).err(),
        Some(
            "Machine must have a 'Maintenance' Health Alert with 'SupressExternalAlerting' classification.".to_string()
        )
    );

    Ok(())
}

pub async fn update_next_try_now(
    host_id: &::carbide_uuid::machine::MachineId,
    txn: &mut sqlx::PgConnection,
) {
    let query = "UPDATE power_options SET 
                                    last_fetched_next_try_at=now()
                                WHERE host_id=$1";

    sqlx::query(query).bind(host_id).execute(txn).await.unwrap();
}

#[crate::sqlx_test]
async fn test_power_manager_state_machine_desired_on_machine_off(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool, TestEnvOverrides::default().enable_power_manager())
            .await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

    let mut txn = env.pool.begin().await?;
    let power_entry = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_entry[0].desired_power_state, PowerState::On);
    assert_eq!(power_entry[0].last_fetched_power_state, PowerState::On);
    let mh_snapshot = load_snapshot(&mut txn, &host_machine_id, LoadSnapshotOptions::default())
        .await?
        .unwrap();
    txn.commit().await?;

    // Create redfish client
    let mut txn = env.pool.begin().await?;
    let sim = env
        .redfish_sim
        .create_client_from_machine(&mh_snapshot.host_snapshot, &mut txn)
        .await?;
    txn.commit().await?;

    // Set power state Off.
    sim.power(libredfish::SystemPowerControl::ForceOff).await?;

    assert_eq!(
        sim.get_power_state().await.unwrap(),
        libredfish::PowerState::Off
    );

    let mut txn = env.pool.begin().await?;
    update_next_try_now(&host_machine_id, &mut txn).await;
    txn.commit().await?;

    // Run a iteration.
    // Since delay is set to 0 for test, db must be updated immediately.
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.pool.begin().await?;
    let power_entry = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_entry[0].desired_power_state, PowerState::On);
    assert_eq!(power_entry[0].last_fetched_power_state, PowerState::Off);
    txn.rollback().await?;

    // Wait for one cycle.
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.pool.begin().await?;
    let power_entry = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_entry[0].desired_power_state, PowerState::On);
    assert_eq!(power_entry[0].last_fetched_power_state, PowerState::Off);
    txn.rollback().await?;

    // State machine should power on the host.
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.pool.begin().await?;
    let power_entry = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_entry[0].desired_power_state, PowerState::On);
    assert_eq!(power_entry[0].last_fetched_power_state, PowerState::Off);
    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_manager_state_machine_desired_on_machine_off_counter(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool, TestEnvOverrides::default().enable_power_manager())
            .await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

    let mut txn = env.pool.begin().await?;
    let power_entry = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_entry[0].desired_power_state, PowerState::On);
    assert_eq!(power_entry[0].last_fetched_power_state, PowerState::On);
    let mh_snapshot = load_snapshot(&mut txn, &host_machine_id, LoadSnapshotOptions::default())
        .await?
        .unwrap();
    txn.commit().await?;

    // Create redfish client
    let mut txn = env.pool.begin().await?;
    let sim = env
        .redfish_sim
        .create_client_from_machine(&mh_snapshot.host_snapshot, &mut txn)
        .await?;
    txn.commit().await?;

    // Set power state Off.
    sim.power(libredfish::SystemPowerControl::ForceOff).await?;

    assert_eq!(
        sim.get_power_state().await.unwrap(),
        libredfish::PowerState::Off
    );

    let mut txn = env.pool.begin().await?;
    update_next_try_now(&host_machine_id, &mut txn).await;
    txn.commit().await?;

    // Run a iteration.
    // Since delay is set to 0 for test, db must be updated immediately.
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.pool.begin().await?;
    let power_entry = db::power_options::get_all(&mut txn).await?;
    assert_eq!(power_entry[0].desired_power_state, PowerState::On);
    assert_eq!(power_entry[0].last_fetched_power_state, PowerState::Off);
    txn.rollback().await?;

    for _ in 1..10 {
        // Keep power off
        sim.power(libredfish::SystemPowerControl::ForceOff).await?;

        env.run_machine_state_controller_iteration().await;
        let mut txn = env.pool.begin().await?;
        let power_entry = db::power_options::get_all(&mut txn).await?;
        assert_eq!(power_entry[0].desired_power_state, PowerState::On);
        assert_eq!(power_entry[0].last_fetched_power_state, PowerState::Off);
        txn.rollback().await?;
    }

    // Get Power option
    let res = env
        .api
        .get_power_options(tonic::Request::new(PowerOptionRequest {
            machine_id: vec![host_machine_id],
        }))
        .await?
        .into_inner();

    assert_eq!(res.response[0].tried_triggering_on_counter, 3);

    Ok(())
}
