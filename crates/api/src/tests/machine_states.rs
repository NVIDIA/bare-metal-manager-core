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
use std::collections::HashMap;

use chrono::Duration;
use common::api_fixtures::dpu::{
    create_dpu_machine, create_dpu_machine_in_waiting_for_network_install,
};
use common::api_fixtures::host::{host_discover_dhcp, host_discover_machine, host_uefi_setup};
use common::api_fixtures::tpm_attestation::{CA_CERT_SERIALIZED, EK_CERT_SERIALIZED};
use common::api_fixtures::{
    TestManagedHost, create_managed_host, create_test_env, create_test_env_with_overrides,
    get_config,
};
use health_report::HealthReport;
use measured_boot::bundle::MeasurementBundle;
use measured_boot::pcr::PcrRegisterValue;
use measured_boot::records::MeasurementBundleState;
use measured_boot::report::MeasurementReport;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::hardware_info::TpmEkCertificate;
use model::machine::{
    DpuInitState, FailureCause, FailureDetails, FailureSource, LockdownMode, MachineState,
    MachineValidatingState, ManagedHostState, MeasuringState, ValidationState,
};
use rpc::forge::forge_server::Forge;
use rpc::forge::{HardwareHealthReport, TpmCaCert, TpmCaCertId};
use rpc::forge_agent_control_response::Action;
use tonic::Request;

use crate::state_controller::machine::handler::{
    MachineStateHandlerBuilder, handler_host_power_control,
};
use crate::tests::common;
use crate::tests::common::api_fixtures::dpu::{
    TEST_DOCA_HBN_VERSION, TEST_DOCA_TELEMETRY_VERSION, TEST_DPU_AGENT_VERSION,
};
use crate::tests::common::api_fixtures::managed_host::ManagedHostConfig;
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, create_managed_host_with_ek, discovery_completed, forge_agent_control,
    update_time_params,
};

#[crate::sqlx_test]
async fn test_dpu_and_host_till_ready(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.db_txn().await;
    let dpu = mh.dpu().db_machine(&mut txn).await;

    assert!(!mh.host().db_machine(&mut txn).await.dpf.used_for_ingestion);
    for i in 0..mh.dpu_ids.len() {
        let dpu = mh.dpu_n(i).db_machine(&mut txn).await;
        assert!(!dpu.dpf.used_for_ingestion);
    }

    assert!(matches!(dpu.current_state(), ManagedHostState::Ready));

    let carbide_machines_per_state = env.test_meter.parsed_metrics("carbide_machines_per_state");

    assert!(carbide_machines_per_state.contains(&(
        "{fresh=\"true\",state=\"ready\",substate=\"\"}".to_string(),
        "2".to_string()
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
        (r#"{state="hostnotready",substate="pollingbiossetup"}"#, 1),
        (
            r#"{state="hostnotready",substate="waitingforplatformconfiguration"}"#,
            1,
        ),
        (r#"{state="hostnotready",substate="waitingforlockdown"}"#, 4),
        (r#"{state="ready",substate=""}"#, 3),
    ];

    let states_entered = env
        .test_meter
        .parsed_metrics("carbide_machines_state_entered_total");

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
        ("{state=\"hostnotready\",substate=\"pollingbiossetup\"}", 1),
        (
            "{state=\"hostnotready\",substate=\"waitingforplatformconfiguration\"}",
            1,
        ),
        (
            "{state=\"hostnotready\",substate=\"waitingforlockdown\"}",
            4,
        ),
    ];

    let states_exited = env
        .test_meter
        .parsed_metrics("carbide_machines_state_exited_total");

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

#[crate::sqlx_test]
async fn test_failed_state_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    db::machine::update_failure_details(
        &host,
        &mut txn,
        FailureDetails {
            cause: model::machine::FailureCause::NVMECleanFailed {
                err: "failed in module xyz.".to_string(),
            },
            failed_at: chrono::Utc::now(),
            source: model::machine::FailureSource::Scout,
        },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    // let state machine check the failure condition.
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed { .. }
    ));
}

#[crate::sqlx_test]
async fn test_nvme_clean_failed_state_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let host = mh.host().db_machine(&mut txn).await;

    let clean_failed_req = tonic::Request::new(rpc::MachineCleanupInfo {
        machine_id: mh.id.into(),
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

    update_time_params(
        &env.pool,
        &host,
        1,
        Some(host.last_reboot_requested.as_ref().unwrap().time - Duration::seconds(59)),
    )
    .await;
    // let state machine check the failure condition.
    env.run_machine_state_controller_iteration().await;

    let host = mh.host().db_machine(&mut txn).await;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::NVMECleanFailed { .. },
                ..
            },
            retry_count: 0,
            ..
        }
    ));

    // Fail again
    let clean_failed_req = tonic::Request::new(rpc::MachineCleanupInfo {
        machine_id: mh.id.into(),
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
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::NVMECleanFailed { .. },
                ..
            },
            retry_count: 1,
            ..
        }
    ));
    // Now the host cleans up successfully.
    let clean_succeeded_req = tonic::Request::new(rpc::MachineCleanupInfo {
        machine_id: mh.id.into(),
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
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::WaitingForCleanup { .. }
    ));
}

/// If the DPU stops sending us health updates we eventually mark it unhealthy
#[crate::sqlx_test]
async fn test_dpu_heartbeat(pool: sqlx::PgPool) -> sqlx::Result<()> {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;

    // Ensure DPU network status is recorded
    mh.network_configured(&env).await;

    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;

    // create_dpu_machine runs record_dpu_network_status, so machine should be healthy
    let dpu_machine = mh.dpu().db_machine(&mut txn).await;
    assert!(
        dpu_machine
            .dpu_agent_health_report
            .as_ref()
            .as_ref()
            .unwrap()
            .alerts
            .is_empty()
    );

    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpus_up_count{fresh=\"true\"}")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpus_healthy_count{fresh=\"true\"}")
            .unwrap(),
        r#"1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpu_health_check_failed_count"),
        None
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_hosts_unhealthy_by_probe_id_count{fresh=\"true\",probe_id=\"HeartbeatTimeout\",probe_target=\"forge-dpu-agent\"}"),
        None,
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_hosts_unhealthy_by_probe_id_count{fresh=\"true\",probe_id=\"HeartbeatTimeout\",probe_target=\"hardware-health\"}"),
        None,
    );

    // Tell state handler to mark DPU as unhealthy after 1 second
    let handler = MachineStateHandlerBuilder::builder()
        .dpu_up_threshold(chrono::Duration::seconds(1))
        .reachability_params(env.reachability_params)
        .attestation_enabled(env.attestation_enabled)
        .hardware_models(env.config.get_firmware_config())
        .power_options_config(env.config.power_manager_options.clone().into())
        .build();
    env.override_machine_state_controller_handler(handler).await;
    env.run_machine_state_controller_iteration().await;

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Run the state state handler *twice* because metrics are reported before
    // state transitions occur in `handle_object_state`. Thus, we can only see
    // the updated metrics set in the first iteration by running another round.
    env.run_machine_state_controller_iteration().await;
    env.run_machine_state_controller_iteration().await;

    // Now the network should be marked unhealthy
    let dpu_machine = mh.dpu().db_machine(&mut txn).await;
    assert!(
        !dpu_machine
            .dpu_agent_health_report
            .as_ref()
            .as_ref()
            .unwrap()
            .alerts
            .is_empty(),
        "DPU is not healthy: {:?}",
        dpu_machine
            .dpu_agent_health_report
            .as_ref()
            .as_ref()
            .unwrap()
    );

    // The up count reflects the heartbeat timeout.
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpus_up_count{fresh=\"true\"}")
            .unwrap(),
        "0"
    );
    // The report now says heartbeat timeout, which is unhealthy.
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpus_healthy_count{fresh=\"true\"}")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpu_health_check_failed_count{failure=\"HeartbeatTimeout [Target: forge-dpu-agent]\",fresh=\"true\",probe_id=\"HeartbeatTimeout\",probe_target=\"forge-dpu-agent\"}")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_hosts_unhealthy_by_probe_id_count{fresh=\"true\",in_use=\"false\",probe_id=\"HeartbeatTimeout\",probe_target=\"forge-dpu-agent\"}")
            .unwrap(),
        "1",
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_hosts_unhealthy_by_probe_id_count{fresh=\"true\",in_use=\"false\",probe_id=\"HeartbeatTimeout\",probe_target=\"hardware-health\"}"),
        None,
    );
    assert_eq!(
        env.test_meter
            .formatted_metric(
                "carbide_hosts_health_status_count{fresh=\"true\",healthy=\"false\",in_use=\"false\"}"
            )
            .unwrap(),
        "1"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_failed_state_host_discovery_recovery(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    db::machine::update_failure_details(
        &host,
        &mut txn,
        FailureDetails {
            cause: model::machine::FailureCause::Discovery {
                err: "host discovery failed".to_string(),
            },
            failed_at: chrono::Utc::now(),
            source: model::machine::FailureSource::Scout,
        },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    // let state machine check the failure condition.

    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed { retry_count: 0, .. }
    ));
    txn.commit().await.unwrap();

    update_time_params(&env.pool, &host, 1, None).await;
    env.run_machine_state_controller_iteration().await;

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed { retry_count: 1, .. }
    ));

    txn.commit().await.unwrap();
    let pxe = env
        .api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: rpc::forge::MachineArchitecture::X86 as i32,
            interface_id: Some(host.interfaces[0].id),
            product: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(pxe.pxe_script.contains("scout.efi"));

    let response = forge_agent_control(&env, mh.id).await;
    assert_eq!(response.action, Action::Discovery as i32);

    discovery_completed(&env, mh.id).await;

    env.run_machine_state_controller_iteration().await;
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_reboot_attempts_in_failed_during_discovery_sum")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_reboot_attempts_in_failed_during_discovery_count")
            .unwrap(),
        "1"
    );

    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    assert!(host.last_reboot_requested.is_some());
    let last_reboot_requested_time = host.last_reboot_requested.as_ref().unwrap().time;

    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForLockdown { .. },
        }
    ));
    txn.commit().await.unwrap();

    // First wait for the lockdown state machine to reach WaitForDPUUp
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.id,
        5,
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForLockdown {
                lockdown_info: model::machine::LockdownInfo {
                    state: model::machine::LockdownState::WaitForDPUUp,
                    mode: model::machine::LockdownMode::Enable,
                },
            },
        },
    )
    .await;

    // We use dpu_agent's health reporting as a signal that
    // DPU has rebooted.
    mh.network_configured(&env).await;

    // Now wait for validation state after DPU is up
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.id,
        10,
        ManagedHostState::Validation {
            validation_state: ValidationState::MachineValidation {
                machine_validation: MachineValidatingState::MachineValidating {
                    context: "Discovery".to_string(),
                    id: uuid::Uuid::default(),
                    completed: 1,
                    total: 1,
                    is_enabled: true,
                },
            },
        },
    )
    .await;

    mh.machine_validation_completed().await;

    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.id,
        4,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered {
                skip_reboot_wait: false,
            },
        },
    )
    .await;
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;

    assert_ne!(
        last_reboot_requested_time,
        host.last_reboot_requested.as_ref().unwrap().time
    );
    txn.commit().await.unwrap();

    let response = forge_agent_control(&env, mh.id).await;
    assert_eq!(response.action, Action::Noop as i32);
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.id,
        1,
        ManagedHostState::Ready,
    )
    .await;
}

/// Check whether metrics that describe hardware/software versions of discovered machines
/// are emitted correctly
#[crate::sqlx_test]
async fn test_managed_host_version_metrics(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    common::api_fixtures::create_managed_host(&env).await;
    common::api_fixtures::create_managed_host(&env).await;

    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_gpus_in_use_count")
            .unwrap(),
        r#"{fresh="true"} 0"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_hosts_in_use_count")
            .unwrap(),
        r#"{fresh="true"} 0"#
    );
    // TODO: For some reason the 2nd created Host stays in state `Discovered`
    // and never becomes ready. Once it does, the test should be updated.
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_hosts_usable_count")
            .unwrap(),
        r#"{fresh="true"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_gpus_usable_count")
            .unwrap(),
        r#"{fresh="true"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_gpus_total_count")
            .unwrap(),
        r#"{fresh="true"} 2"#
    );

    let mut health_status_metrics = env
        .test_meter
        .formatted_metrics("carbide_hosts_health_status_count");
    health_status_metrics.sort();
    assert_eq!(health_status_metrics.len(), 4);

    for expected in [
        r#"{fresh="true",healthy="false",in_use="false"} 0"#,
        r#"{fresh="true",healthy="true",in_use="false"} 2"#,
        r#"{fresh="true",healthy="false",in_use="true"} 0"#,
        r#"{fresh="true",healthy="true",in_use="true"} 0"#,
    ] {
        assert!(
            health_status_metrics.iter().any(|m| m.as_str() == expected),
            "Expected to find {expected}. Got {health_status_metrics:?}"
        );
    }

    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpu_firmware_version_count")
            .unwrap(),
        r#"{firmware_version="24.42.1000",fresh="true"} 2"#,
    );

    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_dpu_agent_version_count")
            .unwrap(),
        format!(r#"{{fresh="true",version="{TEST_DPU_AGENT_VERSION}"}} 2"#)
    );

    let mut inventory_metrics = env
        .test_meter
        .formatted_metrics("carbide_machine_inventory_component_version_count");
    inventory_metrics.sort();

    for expected in &[
        format!(r#"{{fresh="true",name="doca-hbn",version="{TEST_DOCA_HBN_VERSION}"}} 2"#),
        format!(
            r#"{{fresh="true",name="doca-telemetry",version="{TEST_DOCA_TELEMETRY_VERSION}"}} 2"#
        ),
    ] {
        assert!(
            inventory_metrics
                .iter()
                .any(|m| m.as_str() == expected.as_str()),
            "Expected to find {expected}. Got {inventory_metrics:?}"
        );
    }

    // Now that we track all hosts (including those without SKU as "unknown"),
    // we should have SKU metrics for the created hosts
    let sku_metrics = env
        .test_meter
        .formatted_metric("carbide_hosts_by_sku_count");
    assert_eq!(
        sku_metrics.unwrap(),
        r#"{device_type="unknown",fresh="true",sku="unknown"} 2"#
    );
}

/// Check that controller state reason is correct as we work through the states
#[crate::sqlx_test]
async fn test_state_outcome(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let mh = create_dpu_machine_in_waiting_for_network_install(&env, &host_config).await;

    let mut txn = env.db_txn().await;
    let host_machine = mh.host().db_machine(&mut txn).await;
    txn.rollback().await.unwrap();
    let _expected_state = ManagedHostState::DPUInit {
        dpu_states: model::machine::DpuInitStates {
            states: HashMap::from([(mh.dpu().id, DpuInitState::WaitingForNetworkConfig)]),
        },
    };
    assert!(matches!(host_machine.current_state(), _expected_state));
    assert!(
        matches!(
            host_machine.controller_state_outcome,
            Some(PersistentStateHandlerOutcome::Transition { .. })
        ),
        "Machine should have just transitioned into WaitingForNetworkConfig"
    );

    // Scout does its thing

    let _ = mh.dpu().forge_agent_control().await;

    // Now we're stuck waiting for DPU agent to run
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;
    let host_machine = mh.host().db_machine(&mut txn).await;
    txn.rollback().await.unwrap();
    let outcome = host_machine.controller_state_outcome.unwrap();
    dbg!(&outcome);
    assert!(
        matches!(outcome, PersistentStateHandlerOutcome::Wait{ reason, source_ref: Some(source_ref) } if !reason.is_empty() && source_ref.file.ends_with("/handler.rs")),
        "Third iteration should be waiting for DPU agent, and include a wait reason and source reference",
    );
}

#[crate::sqlx_test]
async fn test_state_sla(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;

    // When the Machine is in Ready state, there is no SLA
    let machine = mh.host().rpc_machine().await;
    let sla = machine.state_sla.as_ref().unwrap();
    assert!(!sla.time_in_state_above_sla);
    assert!(sla.sla.is_none());

    // Now do a Hack and move the Machine into a failed state - which has a SLA
    let mut txn = env.db_txn().await;
    db::machine::update_state(
        &mut txn,
        &mh.id,
        &ManagedHostState::Failed {
            details: FailureDetails {
                cause: FailureCause::NoError,
                failed_at: chrono::Utc::now(),
                source: FailureSource::NoError,
            },
            machine_id: mh.id,
            retry_count: 1,
        },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let machine = mh.host().rpc_machine().await;
    let sla = machine.state_sla.as_ref().unwrap();
    assert!(sla.time_in_state_above_sla);
    assert_eq!(sla.sla.unwrap(), std::time::Duration::from_secs(0).into());
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
#[crate::sqlx_test]
async fn test_measurement_failed_state_transition(pool: sqlx::PgPool) {
    // For this test case, we'll flip on attestation, which will
    // introduce the measurement states into the state machine (which
    // also includes additional steps that happen during `create_managed_host`.
    let mut config = get_config();
    config.attestation_enabled = true;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    // add CA cert to pass attestation process
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    env.api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert");

    let mh = create_managed_host_with_ek(&env, &EK_CERT_SERIALIZED).await;

    env.run_machine_state_controller_iteration().await;

    // This is kind of redundant since `create_managed_host` returns a machine
    // in Ready state, but, just to be super explicit...
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
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
    let mut txn = env.db_txn().await;
    let retired_bundle = db::measured_boot::bundle::set_state_for_id(
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
    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    let mut txn = env.pool.begin().await.unwrap();
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::MeasurementsRetired { .. },
                ..
            },
            ..
        }
    ));
    txn.commit().await.unwrap();

    // ..and now reactivate the bundle.
    let mut txn = env.db_txn().await;
    let reactivated_bundle = db::measured_boot::bundle::set_state_for_id(
        &mut txn,
        retired_bundle.bundle_id,
        MeasurementBundleState::Active,
    )
    .await
    .unwrap();
    assert_eq!(retired_bundle.bundle_id, reactivated_bundle.bundle_id);
    txn.commit().await.unwrap();

    // ..and now flip it back.
    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();
}

// this is mostly copied from the one above
#[crate::sqlx_test]
async fn test_measurement_ready_to_retired_to_ca_fail_to_revoked_to_ready(pool: sqlx::PgPool) {
    // For this test case, we'll flip on attestation, which will
    // introduce the measurement states into the state machine (which
    // also includes additional steps that happen during `create_managed_host`.
    let mut config = get_config();
    config.attestation_enabled = true;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

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

    let mh = create_managed_host_with_ek(&env, &EK_CERT_SERIALIZED).await;

    env.run_machine_state_controller_iteration().await;

    // This is kind of redundant since `create_managed_host` returns a machine
    // in Ready state, but, just to be super explicit...
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
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
    let mut txn = env.db_txn().await;
    let retired_bundle = db::measured_boot::bundle::set_state_for_id(
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
    for _ in 0..5 {
        env.run_machine_state_controller_iteration().await;
    }

    // make sure the machine is in retired state
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    // and confirm that it is actually in the retired state
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::MeasurementsRetired { .. },
                ..
            },
            ..
        }
    ));
    txn.commit().await.unwrap();

    // now remove the ca cert and resurrect the bundle
    // and try to move forward - this will now fail due to the lack
    // of ca cert
    let delete_ca_certs_request = tonic::Request::new(TpmCaCertId {
        ca_cert_id: inserted_cert.id.unwrap().ca_cert_id,
    });
    env.api
        .tpm_delete_ca_cert(delete_ca_certs_request)
        .await
        .unwrap();
    // "resurrect" the bundle
    let mut txn = env.db_txn().await;
    let reactivated_bundle = db::measured_boot::bundle::set_state_for_id(
        &mut txn,
        retired_bundle.bundle_id,
        MeasurementBundleState::Active,
    )
    .await
    .unwrap();
    assert_eq!(retired_bundle.bundle_id, reactivated_bundle.bundle_id);
    txn.commit().await.unwrap();

    for _ in 0..5 {
        env.run_machine_state_controller_iteration().await;
    }

    // check that it has failed as intended due to the lack of ca cert
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::MeasurementsCAValidationFailed { .. },
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

    // before advancing the state, change the bundle state to revoked
    let mut txn = env.db_txn().await;
    let _revoked_bundle = db::measured_boot::bundle::set_state_for_id(
        &mut txn,
        bundle.bundle_id,
        MeasurementBundleState::Revoked,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    // ... and trigger the state transition
    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    // check we are in revoked state
    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::MeasurementsRevoked { .. },
                ..
            },
            ..
        }
    ));

    // and now reactivate the state so that it would get to ready
    let _reactivated_bundle = db::measured_boot::bundle::set_state_for_id(
        &mut txn,
        retired_bundle.bundle_id,
        MeasurementBundleState::Active,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    // ... and trigger the state transition
    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    let mut txn = env.db_txn().await;
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(host.current_state(), ManagedHostState::Ready));
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_measurement_host_init_failed_to_waiting_for_measurements_to_pending_bundle_to_ready(
    pool: sqlx::PgPool,
) {
    let mut config = get_config();
    config.attestation_enabled = true;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    // 1. create_dpu as usual
    // 2. start creating host until ca validation failure is encountered
    // 3. add ca certificate - we should recover from failure and go into Ready state

    let host_config = ManagedHostConfig {
        tpm_ek_cert: TpmEkCertificate::from(EK_CERT_SERIALIZED.to_vec()),
        ..Default::default()
    };

    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;

    //--------
    let env = &env;

    let machine_interface_id = host_discover_dhcp(env, &host_config, &dpu_machine_id).await;

    let host_machine_id = host_discover_machine(env, &host_config, machine_interface_id).await;
    let mh = TestManagedHost {
        id: host_machine_id,
        dpu_ids: vec![dpu_machine_id],
        api: env.api.clone(),
    };

    // ---------------
    // now, since the CA has not been added, we should be stuck in the failed state
    for _ in 0..11 {
        env.run_machine_state_controller_iteration().await;
    }

    let mut txn = env.db_txn().await;

    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::Failed {
            details: FailureDetails {
                cause: model::machine::FailureCause::MeasurementsCAValidationFailed { .. },
                ..
            },
            ..
        }
    ));
    // ----------
    // now add the CA cert, we should transition to waiting for measurements
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    let _inserted_cert = env
        .api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert")
        .into_inner();

    env.run_machine_state_controller_iteration().await;

    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostInit {
            machine_state: MachineState::Measuring {
                measuring_state: MeasuringState::WaitingForMeasurements
            }
        }
    ));
    //----------
    // now inject some measurement values

    let pcr_values: Vec<PcrRegisterValue> = vec![
        PcrRegisterValue {
            pcr_register: 0,
            sha_any: "aa".to_string(),
        },
        PcrRegisterValue {
            pcr_register: 1,
            sha_any: "bb".to_string(),
        },
    ];

    let _response = env
        .api
        .attest_candidate_machine(Request::new(
            rpc::protos::measured_boot::AttestCandidateMachineRequest {
                machine_id: host_machine_id.to_string(),
                pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }

    // now we should be in pending bundle state
    let host = mh.host().db_machine(&mut txn).await;
    assert!(matches!(
        host.current_state(),
        ManagedHostState::HostInit {
            machine_state: MachineState::Measuring {
                measuring_state: MeasuringState::PendingBundle
            }
        }
    ));

    // now promote report to bundle
    let reports_response = env
        .api
        .show_measurement_reports(Request::new(
            rpc::protos::measured_boot::ShowMeasurementReportsRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(1, reports_response.reports.len());
    let report = MeasurementReport::from_grpc(Some(&reports_response.reports[0])).unwrap();

    let _promotion_response = env
        .api
        .promote_measurement_report(Request::new(
            rpc::protos::measured_boot::PromoteMeasurementReportRequest {
                report_id: Some(report.report_id),
                pcr_registers: "0,1".to_string(),
            },
        ))
        .await
        .unwrap();
    txn.commit().await.unwrap();

    // ---------
    // after the measurements are in, we should proceed to ready state
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        5,
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForDiscovery,
        },
    )
    .await;

    env.api
        .record_hardware_health_report(Request::new(HardwareHealthReport {
            machine_id: host_machine_id.into(),
            report: Some(HealthReport::empty("hardware-health".to_string()).into()),
        }))
        .await
        .expect("Failed to add hardware health report to newly created machine");

    let response = mh.host().forge_agent_control().await;
    assert_eq!(response.action, Action::Discovery as i32);

    mh.host().discovery_completed().await;

    host_uefi_setup(env, &host_machine_id).await;

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        10,
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForLockdown {
                lockdown_info: model::machine::LockdownInfo {
                    state: model::machine::LockdownState::WaitForDPUUp,
                    mode: LockdownMode::Enable,
                },
            },
        },
    )
    .await;

    // We use forge_dpu_agent's health reporting as a signal that
    // DPU has rebooted.
    mh.network_configured(env).await;

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        10,
        ManagedHostState::Validation {
            validation_state: ValidationState::MachineValidation {
                machine_validation: MachineValidatingState::MachineValidating {
                    context: "Discovery".to_string(),
                    id: uuid::Uuid::default(),
                    completed: 1,
                    total: 1,
                    is_enabled: env.config.machine_validation_config.enabled,
                },
            },
        },
    )
    .await;

    mh.machine_validation_completed().await;

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        4,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered {
                skip_reboot_wait: false,
            },
        },
    )
    .await;

    // This is what simulates a reboot being completed.
    let response = mh.host().forge_agent_control().await;
    assert_eq!(response.action, Action::Noop as i32);

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        1,
        ManagedHostState::Ready,
    )
    .await;
}

#[crate::sqlx_test]
async fn test_update_reboot_requested_time_off(pool: sqlx::PgPool) {
    let mut config = get_config();
    config.attestation_enabled = true;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    // add CA cert to pass attestation process
    let add_ca_request = tonic::Request::new(TpmCaCert {
        ca_cert: CA_CERT_SERIALIZED.to_vec(),
    });

    env.api
        .tpm_add_ca_cert(add_ca_request)
        .await
        .expect("Failed to add CA cert");

    let mh = create_managed_host_with_ek(&env, &EK_CERT_SERIALIZED).await;

    let mut txn = env.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;
    handler_host_power_control(
        &snapshot,
        &env.state_handler_services(),
        libredfish::SystemPowerControl::ForceOff,
        &mut txn,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.db_txn().await;

    let snapshot1 = mh.snapshot(&mut txn).await;
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

    let mut txn = env.db_txn().await;
    handler_host_power_control(
        &snapshot,
        &env.state_handler_services(),
        libredfish::SystemPowerControl::On,
        &mut txn,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.db_txn().await;
    let snapshot2 = mh.snapshot(&mut txn).await;
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

    let mut txn = env.db_txn().await;
    handler_host_power_control(
        &snapshot,
        &env.state_handler_services(),
        libredfish::SystemPowerControl::ForceRestart,
        &mut txn,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.db_txn().await;
    let snapshot3 = mh.snapshot(&mut txn).await;

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
