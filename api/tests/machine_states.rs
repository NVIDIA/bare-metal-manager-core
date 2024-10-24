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

use carbide::db;
use carbide::db::machine::{Machine, MachineSearchConfig};
use carbide::measured_boot::dto::records::MeasurementBundleState;
use carbide::measured_boot::model::bundle::MeasurementBundle;
use carbide::model::controller_outcome::PersistentStateHandlerOutcome;
use carbide::model::hardware_info::TpmEkCertificate;
use carbide::model::machine::machine_id::try_parse_machine_id;
use carbide::model::machine::{DpuInitState, FailureDetails, MachineState, ManagedHostState};
use carbide::state_controller::machine::handler::{
    handler_host_power_control, MachineStateHandlerBuilder,
};
use common::api_fixtures::dpu::{
    create_dpu_machine, create_dpu_machine_in_waiting_for_network_install,
};
use common::api_fixtures::host::create_host_machine;
use common::api_fixtures::tpm_attestation::{CA_CERT_SERIALIZED, EK_CERT_SERIALIZED};
use common::api_fixtures::{
    create_managed_host, create_test_env, machine_validation_completed, TestEnv,
};
use forge_uuid::machine::MachineId;

use carbide::model::machine::{FailureCause, FailureSource};
use common::api_fixtures::{create_test_env_with_config, get_config};
use rpc::forge::forge_server::Forge;
use rpc::forge::{TpmCaCert, TpmCaCertId};
use rpc::forge_agent_control_response::Action;
use std::collections::HashMap;
use tonic::Request;

use crate::common::api_fixtures::managed_host::{ManagedHostConfig, ManagedHostSim};
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
            r#"{state="dpunotready",substate="waitingforplatformconfiguration"}"#,
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
            "{state=\"dpunotready\",substate=\"waitingforplatformconfiguration\"}",
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
    env.run_machine_state_controller_iteration().await;

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
    env.run_machine_state_controller_iteration().await;

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
    env.run_machine_state_controller_iteration().await;

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
    assert!(dpu_machine
        .dpu_agent_health_report()
        .as_ref()
        .unwrap()
        .alerts
        .is_empty());

    // Tell state handler to mark DPU as unhealthy after 1 second
    let handler = MachineStateHandlerBuilder::builder()
        .dpu_up_threshold(chrono::Duration::seconds(1))
        .reachability_params(env.reachability_params)
        .attestation_enabled(env.attestation_enabled)
        .hardware_models(env.config.get_firmware_config())
        .build();
    env.override_machine_state_controller_handler(handler).await;
    env.run_machine_state_controller_iteration().await;

    assert_eq!(
        env.test_meter
            .formatted_metric("forge_dpus_up_count{fresh=\"true\"}")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_dpus_healthy_count{fresh=\"true\"}")
            .unwrap(),
        r#"1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_dpu_health_check_failed_count"),
        None
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_hosts_unhealthy_by_probe_id_count{fresh=\"true\",probe_id=\"HeartbeatTimeout\",probe_target=\"forge-dpu-agent\"}"),
        None,
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_hosts_unhealthy_by_probe_id_count{fresh=\"true\",probe_id=\"HeartbeatTimeout\",probe_target=\"hardware-health\"}"),
        None,
    );

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Run the state state handler *twice* because metrics are reported before
    // state transitions occur in `handle_object_state`. Thus, we can only see
    // the updated metrics set in the first iteration by running another round.
    env.run_machine_state_controller_iteration().await;
    env.run_machine_state_controller_iteration().await;

    // Now the network should be marked unhealthy
    let dpu_machine = Machine::find_by_query(&mut txn, &dpu_machine_id.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert!(!dpu_machine
        .dpu_agent_health_report()
        .as_ref()
        .unwrap()
        .alerts
        .is_empty());

    // The up count reflects the heartbeat timeout.
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_dpus_up_count{fresh=\"true\"}")
            .unwrap(),
        "0"
    );
    // The report now says heartbeat timeout, which is unhealthy.
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_dpus_healthy_count{fresh=\"true\"}")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_dpu_health_check_failed_count{failure=\"HeartbeatTimeout [Target: forge-dpu-agent]\",fresh=\"true\",probe_id=\"HeartbeatTimeout\",probe_target=\"forge-dpu-agent\"}")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_hosts_unhealthy_by_probe_id_count{assigned=\"false\",fresh=\"true\",probe_id=\"HeartbeatTimeout\",probe_target=\"forge-dpu-agent\"}")
            .unwrap(),
        "1",
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_hosts_unhealthy_by_probe_id_count{assigned=\"false\",fresh=\"true\",probe_id=\"HeartbeatTimeout\",probe_target=\"hardware-health\"}"),
        None,
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_hosts_health_status_count{assigned=\"false\",fresh=\"true\",healthy=\"false\"}")
            .unwrap(),
        "1"
    );

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

    env.run_machine_state_controller_iteration().await;

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
    env.run_machine_state_controller_iteration().await;

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

    discovery_completed(&env, host_rpc_machine_id.clone()).await;

    env.run_machine_state_controller_iteration().await;
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

    env.run_machine_state_controller_iteration().await;
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(host.last_reboot_requested().is_some());
    let last_reboot_requested_time = host.last_reboot_requested().unwrap().time;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostInit {
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
        3,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::MachineValidating {
                context: "Discovery".to_string(),
                id: uuid::Uuid::default(),
                completed: 1,
                total: 1,
                is_enabled: true,
            },
        },
    )
    .await;
    txn.commit().await.unwrap();

    machine_validation_completed(&env, host_rpc_machine_id.clone(), None).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        3,
        &mut txn,
        ManagedHostState::HostInit {
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
            .formatted_metric("forge_assigned_gpus_count")
            .unwrap(),
        r#"{fresh="true"} 0"#
    );
    // TODO: For some reason the 2nd created Host stays in state `Discovered`
    // and never becomes ready. Once it does, the test should be updated.
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_allocatable_hosts_count")
            .unwrap(),
        r#"{fresh="true"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_allocatable_gpus_count")
            .unwrap(),
        r#"{fresh="true"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_available_gpus_count")
            .unwrap(),
        r#"{fresh="true"} 2"#
    );

    let mut health_status_metrics = env
        .test_meter
        .formatted_metrics("forge_hosts_health_status_count");
    health_status_metrics.sort();
    assert_eq!(health_status_metrics.len(), 4);

    for expected in [
        r#"{assigned="false",fresh="true",healthy="false"} 0"#,
        r#"{assigned="false",fresh="true",healthy="true"} 2"#,
        r#"{assigned="true",fresh="true",healthy="false"} 0"#,
        r#"{assigned="true",fresh="true",healthy="true"} 0"#,
    ] {
        assert!(
            health_status_metrics.iter().any(|m| m.as_str() == expected),
            "Expected to find {}. Got {:?}",
            expected,
            health_status_metrics
        );
    }

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

    let mut txn = env.pool.begin().await.unwrap();
    let host_machine = Machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .unwrap();
    txn.rollback().await.unwrap();
    let _expected_state = ManagedHostState::DPUInit {
        dpu_states: carbide::model::machine::DpuInitStates {
            states: HashMap::from([(
                dpu_machine_id.clone(),
                DpuInitState::WaitingForNetworkConfig,
            )]),
        },
    };
    assert!(matches!(host_machine.current_state(), _expected_state));
    assert!(
        matches!(
            host_machine.current_state_iteration_outcome(),
            Some(PersistentStateHandlerOutcome::Transition)
        ),
        "Machine should have just transitioned into WaitingForNetworkConfig"
    );

    // Scout does its thing

    let _ = forge_agent_control(&env, dpu_machine_id.to_string().into()).await;

    // Now we're stuck waiting for DPU agent to run
    env.run_machine_state_controller_iteration().await;
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_state_sla(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (_dpu_machine_id, host_machine_id) = create_managed_host(&env).await;

    // When the Machine is in Ready state, there is no SLA
    let machine = env
        .find_machines(Some(host_machine_id.clone().into()), None, false)
        .await
        .machines
        .remove(0);
    let sla = machine.state_sla.as_ref().unwrap();
    assert!(!sla.time_in_state_above_sla);
    assert!(sla.sla.is_none());

    // Now do a Hack and move the Machine into a failed state - which has a SLA
    let mut txn = env.pool.begin().await.unwrap();
    Machine::update_state(
        &mut txn,
        &host_machine_id,
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: FailureCause::NoError,
                failed_at: chrono::Utc::now(),
                source: FailureSource::NoError,
            },
            machine_id: host_machine_id.clone(),
            retry_count: 1,
        },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let machine = env
        .find_machines(Some(host_machine_id.into()), None, false)
        .await
        .machines
        .remove(0);
    let sla = machine.state_sla.as_ref().unwrap();
    assert!(sla.time_in_state_above_sla);
    assert_eq!(
        sla.sla.clone().unwrap(),
        std::time::Duration::from_secs(0).into()
    );
}

/// test_measurement_failed_state_transition is used to test the state
/// machine changes surrounding measured boot, more specifically, making
/// sure the handle_measuring_state function works as expected, in terms
/// of being able to fluidly switch back and forth between Ready/Failed
/// states in reaction to measurement bundle management changes behind the
/// scenes via the API and/or CLI.
///
/// This includes the initial movement of a machine to Ready state after
/// initial attestation, "failure" of a machine (out of Ready state) into
/// a FailureCause::MeasurementsRetired state by retiring the bundle that
/// put it into Ready state, and then re-activating the bundle to move
/// the machine from ::Failed -> back to ::Ready.
#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_measurement_failed_state_transition(pool: sqlx::PgPool) {
    // For this test case, we'll flip on attestation, which will
    // introduce the measurement states into the state machine (which
    // also includes additional steps that happen during `create_managed_host`.
    let mut config = get_config();
    config.attestation_enabled = true;
    let env = create_test_env_with_config(pool, Some(config)).await;

    // add CA cert to pass attestation process
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    env.api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert");

    let (host_machine_id, _dpu_machine_id) =
        create_managed_host_with_ek(&env, &EK_CERT_SERIALIZED).await;

    env.run_machine_state_controller_iteration().await;

    // This is kind of redundant since `create_managed_host` returns a machine
    // in Ready state, but, just to be super explicit...
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();

    // At this point there is an attested/measured machine in Ready state,
    // so get its bundle, retire it, run another iteration, and make sure
    // it's retired.
    let bundles_response = env
        .api
        .show_measurement_bundles(Request::new(
            rpc::protos::measured_boot::ShowMeasurementBundlesRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(1, bundles_response.bundles.len());
    let bundle = MeasurementBundle::from_grpc(Some(&bundles_response.bundles[0])).unwrap();
    assert_eq!(bundle.state, MeasurementBundleState::Active);
    let mut txn = env.pool.begin().await.unwrap();
    let retired_bundle = MeasurementBundle::set_state_for_id(
        &mut txn,
        bundle.bundle_id,
        MeasurementBundleState::Retired,
    )
    .await
    .unwrap();
    assert_eq!(bundle.bundle_id, retired_bundle.bundle_id);
    assert_eq!(retired_bundle.state, MeasurementBundleState::Retired);
    txn.commit().await.unwrap();

    // .. and now flip it to retired.
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: carbide::model::machine::FailureCause::MeasurementsRetired { .. },
                ..
            },
            ..
        }
    ));
    txn.commit().await.unwrap();

    // ..and now reactivate the bundle.
    let mut txn = env.pool.begin().await.unwrap();
    let reactivated_bundle = MeasurementBundle::set_state_for_id(
        &mut txn,
        retired_bundle.bundle_id,
        MeasurementBundleState::Active,
    )
    .await
    .unwrap();
    assert_eq!(retired_bundle.bundle_id, reactivated_bundle.bundle_id);
    txn.commit().await.unwrap();

    // ..and now flip it back.
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();
}

// this is mostly copied from the one above
#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_measurement_no_ca_cert_failed_state_transition(pool: sqlx::PgPool) {
    // For this test case, we'll flip on attestation, which will
    // introduce the measurement states into the state machine (which
    // also includes additional steps that happen during `create_managed_host`.
    let mut config = get_config();
    config.attestation_enabled = true;
    let env = create_test_env_with_config(pool, Some(config)).await;

    // add CA cert to pass attestation process
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    let inserted_cert = env
        .api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert")
        .into_inner();

    let (host_machine_id, _dpu_machine_id) =
        create_managed_host_with_ek(&env, &EK_CERT_SERIALIZED).await;

    env.run_machine_state_controller_iteration().await;

    // This is kind of redundant since `create_managed_host` returns a machine
    // in Ready state, but, just to be super explicit...
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();

    // At this point there is an attested/measured machine in Ready state,
    // so get its bundle, retire it, run another iteration, and make sure
    // it's retired.

    // But before retiring the bundle, remove the ca cert, this will unmatch the ek
    // cert - this should have no effect on moving away from the ready state
    let delete_ca_certs_request = tonic::Request::new(TpmCaCertId {
        ca_cert_id: inserted_cert.id.unwrap().ca_cert_id,
    });
    env.api
        .tpm_delete_ca_cert(delete_ca_certs_request)
        .await
        .unwrap();

    // ... and now retire the bundle
    let bundles_response = env
        .api
        .show_measurement_bundles(Request::new(
            rpc::protos::measured_boot::ShowMeasurementBundlesRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(1, bundles_response.bundles.len());
    let bundle = MeasurementBundle::from_grpc(Some(&bundles_response.bundles[0])).unwrap();
    assert_eq!(bundle.state, MeasurementBundleState::Active);
    let mut txn = env.pool.begin().await.unwrap();
    let retired_bundle = MeasurementBundle::set_state_for_id(
        &mut txn,
        bundle.bundle_id,
        MeasurementBundleState::Retired,
    )
    .await
    .unwrap();
    assert_eq!(bundle.bundle_id, retired_bundle.bundle_id);
    assert_eq!(retired_bundle.state, MeasurementBundleState::Retired);
    txn.commit().await.unwrap();

    // now trigger the state transition
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    // and confirm that it is actually in the retired state
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: carbide::model::machine::FailureCause::MeasurementsRetired { .. },
                ..
            },
            ..
        }
    ));
    txn.commit().await.unwrap();

    // now, try to move into a ready state by reactivating the bundle - this will fail
    // due to the lack of ca cert
    let mut txn = env.pool.begin().await.unwrap();
    let reactivated_bundle = MeasurementBundle::set_state_for_id(
        &mut txn,
        retired_bundle.bundle_id,
        MeasurementBundleState::Active,
    )
    .await
    .unwrap();
    assert_eq!(retired_bundle.bundle_id, reactivated_bundle.bundle_id);
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration().await;

    // check that it has failed as intended due to the lack of ca cert
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: carbide::model::machine::FailureCause::MeasurementsCAValidationFailed { .. },
                ..
            },
            ..
        }
    ));
    txn.commit().await.unwrap();

    // ... and now re-insert the ca cert
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    env.api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert");

    // ... and trigger the state transition
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_update_reboot_requested_time_off(pool: sqlx::PgPool) {
    let mut config = get_config();
    config.attestation_enabled = true;
    let env = create_test_env_with_config(pool, Some(config)).await;

    // add CA cert to pass attestation process
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    env.api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert");

    let (host_machine_id, _dpu_machine_id) =
        create_managed_host_with_ek(&env, &EK_CERT_SERIALIZED).await;

    let mut txn = env.pool.begin().await.unwrap();
    let snapshot = db::managed_host::load_snapshot(&mut txn, &host_machine_id, Default::default())
        .await
        .unwrap()
        .unwrap();

    handler_host_power_control(
        &snapshot,
        &env.state_handler_services(),
        libredfish::SystemPowerControl::ForceOff,
        &mut txn,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();

    let snapshot1 = db::managed_host::load_snapshot(&mut txn, &host_machine_id, Default::default())
        .await
        .unwrap()
        .unwrap();

    for i in 0..snapshot.dpu_snapshots.len() {
        assert_ne!(
            snapshot.dpu_snapshots[i]
                .clone()
                .last_reboot_requested
                .map(|x| x.time)
                .unwrap_or_default(),
            snapshot1.dpu_snapshots[i]
                .clone()
                .last_reboot_requested
                .unwrap()
                .time
        );
    }

    let mut txn = env.pool.begin().await.unwrap();
    handler_host_power_control(
        &snapshot,
        &env.state_handler_services(),
        libredfish::SystemPowerControl::On,
        &mut txn,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let snapshot2 = db::managed_host::load_snapshot(&mut txn, &host_machine_id, Default::default())
        .await
        .unwrap()
        .unwrap();

    for i in 0..snapshot.dpu_snapshots.len() {
        assert_ne!(
            snapshot1.dpu_snapshots[i]
                .clone()
                .last_reboot_requested
                .map(|x| x.time)
                .unwrap_or_default(),
            snapshot2.dpu_snapshots[i]
                .clone()
                .last_reboot_requested
                .unwrap()
                .time
        );
    }

    let mut txn = env.pool.begin().await.unwrap();
    handler_host_power_control(
        &snapshot,
        &env.state_handler_services(),
        libredfish::SystemPowerControl::ForceRestart,
        &mut txn,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let snapshot3 = db::managed_host::load_snapshot(&mut txn, &host_machine_id, Default::default())
        .await
        .unwrap()
        .unwrap();

    for i in 0..snapshot.dpu_snapshots.len() {
        assert_eq!(
            snapshot2.dpu_snapshots[i]
                .clone()
                .last_reboot_requested
                .map(|x| x.time)
                .unwrap_or_default(),
            snapshot3.dpu_snapshots[i]
                .clone()
                .last_reboot_requested
                .unwrap()
                .time
        );
    }
}

async fn create_managed_host_with_ek(env: &TestEnv, ek_cert: &[u8]) -> (MachineId, MachineId) {
    let host_sim = ManagedHostSim {
        config: ManagedHostConfig {
            tpm_ek_cert: TpmEkCertificate::from(ek_cert.to_vec()),
            ..Default::default()
        },
    };

    let dpu_machine_id = create_dpu_machine(env, &host_sim.config).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_machine_id).unwrap();
    let host_machine_id = create_host_machine(env, &host_sim.config, &dpu_machine_id).await;

    (
        try_parse_machine_id(&host_machine_id).unwrap(),
        dpu_machine_id,
    )
}
