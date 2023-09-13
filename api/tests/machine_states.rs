/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
pub mod common;

use std::sync::Arc;

use carbide::db::machine::{Machine, MachineSearchConfig};
use carbide::model::machine::{FailureDetails, ManagedHostState};
use carbide::state_controller::machine::handler::MachineStateHandler;
use common::api_fixtures::{create_managed_host, create_test_env};

use crate::common::api_fixtures::run_state_controller_iteration;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_and_host_till_ready(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (_host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(dpu.current_state(), ManagedHostState::Ready));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_failed_state_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, _dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    host.update_failure_details(
        &mut txn,
        FailureDetails {
            cause: carbide::model::machine::FailureCause::NVMECleanFailed {
                err: "failed in module xyz.".to_string(),
            },
            failed_at: chrono::Utc::now(),
            source: carbide::model::machine::FailureSource::Scout,
        },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    // let state machine check the failure condition.

    let handler = MachineStateHandler::default();
    let services = Arc::new(env.state_handler_services());
    run_state_controller_iteration(
        &services,
        &pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
    )
    .await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed { .. }
    ));
}

/// If the DPU stops sending us health updates we eventually mark it unhealthy
#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_dpu_heartbeat(pool: sqlx::PgPool) -> sqlx::Result<()> {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
    let mut txn = pool.begin().await.unwrap();

    // create_dpu_machine runs record_dpu_network_status, so machine should be healthy
    let dpu_machine = Machine::find_by_query(&mut txn, &dpu_machine_id.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert!(matches!(dpu_machine.has_healthy_network(), Ok(true)));

    // Tell state handler to mark DPU as unhealthy after 1 second
    let handler = MachineStateHandler::new(chrono::Duration::seconds(1));
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Run the state state handler
    let services = Arc::new(env.state_handler_services());
    run_state_controller_iteration(
        &services,
        &pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
    )
    .await;

    // Now the network should be marked unhealthy
    let dpu_machine = Machine::find_by_query(&mut txn, &dpu_machine_id.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert!(matches!(dpu_machine.has_healthy_network(), Ok(false)));

    Ok(())
}
