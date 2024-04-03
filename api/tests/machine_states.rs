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

use carbide::cfg::DpuFwUpdateConfig;
use carbide::db::machine::{Machine, MachineSearchConfig};
use carbide::model::machine::{FailureDetails, MachineState, ManagedHostState};
use carbide::state_controller::machine::handler::MachineStateHandler;
use carbide::state_controller::metrics::IterationMetrics;
use common::api_fixtures::{create_managed_host, create_test_env};
use rpc::forge::forge_server::Forge;
use rpc::forge_agent_control_response::Action;

use crate::common::api_fixtures::{
    discovery_completed, forge_agent_control, network_configured, run_state_controller_iteration,
    update_time_params,
};

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

    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        DpuFwUpdateConfig::default(),
        env.reachability_params,
    );
    let services = Arc::new(env.state_handler_services());
    let mut iteration_metrics = IterationMetrics::default();
    run_state_controller_iteration(
        &services,
        &pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
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
    let handler = MachineStateHandler::new(
        chrono::Duration::seconds(1),
        true,
        true,
        DpuFwUpdateConfig::default(),
        env.reachability_params,
    );
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Run the state state handler
    let services = Arc::new(env.state_handler_services());
    let mut iteration_metrics = IterationMetrics::default();
    run_state_controller_iteration(
        &services,
        &pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_failed_state_host_discovery_recovery(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    host.update_failure_details(
        &mut txn,
        FailureDetails {
            cause: carbide::model::machine::FailureCause::Discovery {
                err: "host discovery failed".to_string(),
            },
            failed_at: chrono::Utc::now(),
            source: carbide::model::machine::FailureSource::Scout,
        },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    // let state machine check the failure condition.

    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        DpuFwUpdateConfig::default(),
        env.reachability_params,
    );
    let services = Arc::new(env.state_handler_services());
    let mut iteration_metrics = IterationMetrics::default();
    run_state_controller_iteration(
        &services,
        &pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed { retry_count: 0, .. }
    ));
    txn.commit().await.unwrap();

    update_time_params(&env.pool, &host, 1).await;
    run_state_controller_iteration(
        &services,
        &pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed { retry_count: 1, .. }
    ));

    txn.commit().await.unwrap();
    let host_rpc_machine_id: rpc::MachineId = host_machine_id.to_string().into();
    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: rpc::forge::MachineArchitecture::X86 as i32,
            interface_id: Some(rpc::Uuid {
                value: host.interfaces()[0].id.clone().to_string(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(pxe.pxe_script.contains("scout.efi"));

    let response = forge_agent_control(&env, host_rpc_machine_id.clone()).await;
    assert_eq!(response.action, Action::Discovery as i32);

    discovery_completed(&env, host_rpc_machine_id.clone(), None).await;

    run_state_controller_iteration(
        &services,
        &pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;
    assert_eq!(
        iteration_metrics
            .specific
            .machine_reboot_attempts_in_failed_during_discovery()
            .iter()
            .sum::<u64>(),
        1
    );

    run_state_controller_iteration(
        &services,
        &pool,
        &env.machine_state_controller_io,
        host_machine_id.clone(),
        &handler,
        &mut iteration_metrics,
    )
    .await;
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(host.last_reboot_requested().is_some());
    let last_reboot_requested_time = host.last_reboot_requested().unwrap().time;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostNotReady {
            machine_state: MachineState::WaitingForLockdown { .. },
        }
    ));
    txn.commit().await.unwrap();

    // We use forge_dpu_agent's health reporting as a signal that
    // DPU has rebooted.
    network_configured(&env, &dpu_machine_id).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        handler.clone(),
        3,
        &mut txn,
        ManagedHostState::HostNotReady {
            machine_state: MachineState::Discovered,
        },
    )
    .await;
    txn.commit().await.unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_ne!(
        last_reboot_requested_time,
        host.last_reboot_requested().unwrap().time
    );
    txn.commit().await.unwrap();

    let response = forge_agent_control(&env, host_rpc_machine_id.clone()).await;
    assert_eq!(response.action, Action::Noop as i32);
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        handler,
        1,
        &mut txn,
        ManagedHostState::Ready,
    )
    .await;
    txn.commit().await.unwrap();
}
