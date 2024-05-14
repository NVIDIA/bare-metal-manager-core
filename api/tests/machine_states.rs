/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use carbide::cfg::default_dpu_models;
use carbide::cfg::DpuFwUpdateConfig;
use carbide::db::machine::{Machine, MachineSearchConfig};
use carbide::model::controller_outcome::PersistentStateHandlerOutcome;
use carbide::model::machine::{FailureDetails, MachineState, ManagedHostState};
use carbide::state_controller::machine::handler::MachineStateHandler;
use common::api_fixtures::dpu::create_dpu_machine_in_waiting_for_network_install;
use common::api_fixtures::{create_managed_host, create_test_env};
use rpc::forge::forge_server::Forge;
use rpc::forge_agent_control_response::Action;

use crate::common::api_fixtures::{
    discovery_completed,
    dpu::{
        DEFAULT_DPU_FIRMWARE_VERSION, TEST_DOCA_HBN_VERSION, TEST_DOCA_TELEMETRY_VERSION,
        TEST_DPU_AGENT_VERSION,
    },
    forge_agent_control, network_configured, update_time_params,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_and_host_till_ready(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (_host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let dpu = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(dpu.current_state(), ManagedHostState::Ready));

    assert!(env
        .test_meter
        .parsed_metrics("forge_machines_per_state")
        .contains(&(
            "{fresh=\"true\",state=\"ready\",substate=\"\"}".to_string(),
            "1".to_string()
        )));

    let expected_states_entered = &[
        (
            r#"{state="dpunotready",substate="waitingfornetworkconfig"}"#,
            1,
        ),
        (
            r#"{state="dpunotready",substate="waitingfornetworkinstall"}"#,
            1,
        ),
        (r#"{state="hostnotready",substate="discovered"}"#, 1),
        (
            r#"{state="hostnotready",substate="waitingfordiscovery"}"#,
            1,
        ),
        (r#"{state="hostnotready",substate="waitingforlockdown"}"#, 2),
        (r#"{state="ready",substate=""}"#, 1),
    ];

    let states_entered = env
        .test_meter
        .parsed_metrics("forge_machines_state_entered_total");

    for expected in expected_states_entered.iter() {
        let actual = states_entered
            .iter()
            .find(|s| s.0 == expected.0)
            .unwrap_or_else(|| panic!("Did not enter state {}", expected.0));
        assert_eq!(
            actual.1.parse::<i64>().unwrap(),
            expected.1,
            "Did not enter state {} {} times",
            expected.0,
            expected.1
        );
    }

    let expected_states_exited = &[
        ("{state=\"dpunotready\",substate=\"init\"}", 1),
        (
            "{state=\"dpunotready\",substate=\"waitingfornetworkconfig\"}",
            1,
        ),
        (
            "{state=\"dpunotready\",substate=\"waitingfornetworkinstall\"}",
            1,
        ),
        ("{state=\"hostnotready\",substate=\"discovered\"}", 1),
        (
            "{state=\"hostnotready\",substate=\"waitingfordiscovery\"}",
            1,
        ),
        (
            "{state=\"hostnotready\",substate=\"waitingforlockdown\"}",
            2,
        ),
    ];

    let states_exited = env
        .test_meter
        .parsed_metrics("forge_machines_state_exited_total");

    for expected in expected_states_exited.iter() {
        let actual = states_exited
            .iter()
            .find(|s| s.0 == expected.0)
            .unwrap_or_else(|| panic!("Did not exit state {}", expected.0));
        assert_eq!(
            actual.1.parse::<i64>().unwrap(),
            expected.1,
            "Did not exit state {} {} times",
            expected.0,
            expected.1
        );
    }
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_failed_state_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
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
        default_dpu_models(),
        env.reachability_params,
    );
    env.run_machine_state_controller_iteration(handler.clone())
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_nvme_clean_failed_state_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;

    let clean_failed_req = tonic::Request::new(rpc::MachineCleanupInfo {
        machine_id: Some(rpc::MachineId {
            id: host_machine_id.to_string(),
        }),
        nvme: Some(
            rpc::protos::forge::machine_cleanup_info::CleanupStepResult {
                result: rpc::protos::forge::machine_cleanup_info::CleanupResult::Error as i32,
                message: "test nvme failure".to_string(),
            },
        ),
        ram: None,
        mem_overwrite: None,
        ib: None,
        result: 0,
    });

    env.api
        .cleanup_machine_completed(clean_failed_req)
        .await
        .unwrap();

    // let state machine check the failure condition.
    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        DpuFwUpdateConfig::default(),
        env.reachability_params,
    );
    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: carbide::model::machine::FailureCause::NVMECleanFailed { .. },
                ..
            },
            ..
        }
    ));

    // Now the host cleans up successfully.
    let clean_succeeded_req = tonic::Request::new(rpc::MachineCleanupInfo {
        machine_id: Some(rpc::MachineId {
            id: host_machine_id.to_string(),
        }),
        nvme: None,
        ram: None,
        mem_overwrite: None,
        ib: None,
        result: 0,
    });
    env.api
        .cleanup_machine_completed(clean_succeeded_req)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    // Run the state machine.
    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    // Check that we've moved the machine to the WaitingForCleanup state.
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(
        host.current_state(),
        ManagedHostState::WaitingForCleanup { .. }
    ));
}
/// If the DPU stops sending us health updates we eventually mark it unhealthy
#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_dpu_heartbeat(pool: sqlx::PgPool) -> sqlx::Result<()> {
    let env = create_test_env(pool).await;
    let (_host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();

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
        default_dpu_models(),
        env.reachability_params,
    );
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Run the state state handler
    env.run_machine_state_controller_iteration(handler.clone())
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
    let env = create_test_env(pool).await;
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
        default_dpu_models(),
        env.reachability_params,
    );
    env.run_machine_state_controller_iteration(handler.clone())
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
    env.run_machine_state_controller_iteration(handler.clone())
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

    env.run_machine_state_controller_iteration(handler.clone())
        .await;
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_reboot_attempts_in_failed_during_discovery_sum")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_reboot_attempts_in_failed_during_discovery_count")
            .unwrap(),
        "1"
    );

    env.run_machine_state_controller_iteration(handler.clone())
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

/// Check whether metrics that describe hardware/software versions of discovered machines
/// are emitted correctly
#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_managed_host_version_metrics(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (_host_machine_id_1, _dpu_machine_id_1) =
        common::api_fixtures::create_managed_host(&env).await;
    let (_host_machine_id_2, _dpu_machine_id_2) =
        common::api_fixtures::create_managed_host(&env).await;

    assert_eq!(
        env.test_meter
            .formatted_metric("forge_dpu_firmware_version_count")
            .unwrap(),
        format!(
            r#"{{firmware_version="{}",fresh="true"}} 2"#,
            DEFAULT_DPU_FIRMWARE_VERSION
        )
    );

    assert_eq!(
        env.test_meter
            .formatted_metric("forge_dpu_agent_version_count")
            .unwrap(),
        format!(r#"{{fresh="true",version="{}"}} 2"#, TEST_DPU_AGENT_VERSION)
    );

    let mut inventory_metrics = env
        .test_meter
        .formatted_metrics("forge_machine_inventory_component_version_count");
    inventory_metrics.sort();

    for expected in &[
        format!(
            r#"{{fresh="true",name="doca-hbn",version="{}"}} 2"#,
            TEST_DOCA_HBN_VERSION
        ),
        format!(
            r#"{{fresh="true",name="doca-telemetry",version="{}"}} 2"#,
            TEST_DOCA_TELEMETRY_VERSION
        ),
    ] {
        assert!(
            inventory_metrics
                .iter()
                .any(|m| m.as_str() == expected.as_str()),
            "Expected to find {}. Got {:?}",
            expected,
            inventory_metrics
        );
    }
}

/// Check that controller state reason is correct as we work through the states
#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_state_outcome(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let host_config = &host_sim.config;
    let (dpu_machine_id, _host_machine_id) =
        create_dpu_machine_in_waiting_for_network_install(&env, host_config).await;

    // Setup code did Transition to WaitingForNetworkInstall
    let mut txn = env.pool.begin().await.unwrap();
    let host_machine = Machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .unwrap();
    txn.rollback().await.unwrap();
    assert!(matches!(
        host_machine.current_state(),
        ManagedHostState::DPUNotReady {
            machine_state: MachineState::WaitingForNetworkInstall
        }
    ));
    assert!(
        matches!(
            host_machine.current_state_iteration_outcome(),
            Some(PersistentStateHandlerOutcome::Transition)
        ),
        "Machine should have just transitioned into WaitingForNetworkInstall"
    );

    // Scout does it's thing
    env.api
        .forge_agent_control(tonic::Request::new(rpc::forge::ForgeAgentControlRequest {
            machine_id: Some(dpu_machine_id.to_string().into()),
        }))
        .await
        .unwrap();

    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(5),
        true,
        true,
        DpuFwUpdateConfig::default(),
        default_dpu_models(),
        env.reachability_params,
    );

    // Transition to WaitingForNetworkConfig
    env.run_machine_state_controller_iteration(handler.clone())
        .await;
    let mut txn = env.pool.begin().await.unwrap();
    let host_machine = Machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .unwrap();
    txn.rollback().await.unwrap();
    assert!(matches!(
        host_machine.current_state(),
        ManagedHostState::DPUNotReady {
            machine_state: MachineState::WaitingForNetworkConfig
        }
    ));
    assert!(
        matches!(
            host_machine.current_state_iteration_outcome(),
            Some(PersistentStateHandlerOutcome::Transition)
        ),
        "Second state controller iteration should also change state"
    );

    // Now we're stuck waiting for DPU agent to run
    env.run_machine_state_controller_iteration(handler.clone())
        .await;
    let mut txn = env.pool.begin().await.unwrap();
    let host_machine = Machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .unwrap();
    txn.rollback().await.unwrap();
    let outcome = host_machine.current_state_iteration_outcome().unwrap();
    assert!(
        matches!(outcome, PersistentStateHandlerOutcome::Wait{ reason } if !reason.is_empty()),
        "Third iteration should be waiting for DPU agent, and include a wait reason",
    );
}
