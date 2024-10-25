/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide::{
    db::machine::Machine,
    model::machine::{
        machine_id::try_parse_machine_id, FailureCause, FailureDetails, FailureSource,
        MachineState, MachineValidationFilter, ManagedHostState,
    },
};
use config_version::ConfigVersion;
use rpc::forge::forge_server::Forge;
use std::{str::FromStr, time::SystemTime};

mod common;
use common::api_fixtures::{
    create_test_env, create_test_env_with_overrides, forge_agent_control, get_config,
    get_machine_validation_results, get_machine_validation_runs,
    host::create_host_with_machine_validation,
    instance::{create_instance, delete_instance, single_interface_network_config},
    machine_validation_completed,
    network_segment::FIXTURE_NETWORK_SEGMENT_ID,
    on_demand_machine_validation, reboot_completed, TestEnvOverrides,
};
use rpc::Timestamp;

use crate::common::api_fixtures::dpu::create_dpu_machine;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_machine_validation_complete_with_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let host_machine_id = create_host_with_machine_validation(
        &env,
        &host_sim.config,
        &dpu_machine_id,
        None,
        Some("Test Error".to_owned()),
    )
    .await;

    let mut txn = env.pool.begin().await?;

    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    match machine.current_state() {
        ManagedHostState::Failed {
            details,
            machine_id: _,
            retry_count: _,
        } => {
            let FailureDetails { cause, source, .. } = details;
            assert_eq!(
                cause,
                FailureCause::MachineValidation {
                    err: "Test Error".to_owned()
                }
            );
            assert_eq!(source, FailureSource::Scout);
        }
        s => {
            panic!("Incorrect state: {}", s);
        }
    }

    let machine = env
        .find_machines(Some(host_machine_id), None, false)
        .await
        .machines
        .remove(0);
    let health = machine.health.as_ref().unwrap();
    assert_eq!(health.alerts.len(), 1);
    let mut alert = health.alerts[0].clone();
    assert!(alert.in_alert_since.is_some());
    alert.in_alert_since = None;
    assert_eq!(
        alert,
        health_report::HealthProbeAlert {
            id: "FailedValidationTestCompletion".parse().unwrap(),
            target: None,
            in_alert_since: None,
            message: "Validation test failed to run to completion:\nTest Error".to_string(),
            tenant_message: None,
            classifications: vec![health_report::HealthAlertClassification::prevent_allocations()],
        }
        .into()
    );

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_machine_validation_with_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let machine_validation_result = rpc::forge::MachineValidationResult {
        validation_id: None,
        name: "test1".to_string(),
        description: "desc".to_string(),
        command: "echo".to_string(),
        args: "test".to_string(),
        std_out: "".to_string(),
        std_err: "Some Error".to_string(),
        context: "Discovery".to_string(),
        exit_code: -1,
        start_time: Some(Timestamp::from(SystemTime::now())),
        end_time: Some(Timestamp::from(SystemTime::now())),
    };

    let host_machine_id = create_host_with_machine_validation(
        &env,
        &host_sim.config,
        &dpu_machine_id,
        Some(machine_validation_result.clone()),
        None,
    )
    .await;

    let mut txn = env.pool.begin().await?;

    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    match machine.current_state() {
        ManagedHostState::Failed {
            details,
            machine_id: _,
            retry_count,
        } => {
            let FailureDetails { cause, source, .. } = details;
            assert_eq!(
                cause,
                FailureCause::MachineValidation {
                    err: format!("{} is failed", machine_validation_result.name),
                }
            );
            assert_eq!(source, FailureSource::Scout);
            // assert_eq!(machine_id, host_machine_id);
            assert_eq!(retry_count, 0);
        }
        s => {
            panic!("Incorrect state: {}", s);
        }
    }

    let machine = env
        .find_machines(Some(host_machine_id.clone()), None, false)
        .await
        .machines
        .remove(0);
    let health = machine.health.as_ref().unwrap();
    assert_eq!(health.alerts.len(), 1);
    let mut alert = health.alerts[0].clone();
    assert!(alert.in_alert_since.is_some());
    alert.in_alert_since = None;
    assert_eq!(
        alert,
        health_report::HealthProbeAlert {
            id: "FailedValidationTest".parse().unwrap(),
            target: Some("test1".to_string()),
            in_alert_since: None,
            message: "Failed validation test:\nName:test1\nCommand:echo\nArgs:test".to_string(),
            tenant_message: None,
            classifications: vec![health_report::HealthAlertClassification::prevent_allocations()],
        }
        .into()
    );

    let _ =
        on_demand_machine_validation(&env, machine.id.unwrap_or_default(), Vec::new(), Vec::new())
            .await;
    env.run_machine_state_controller_iteration_until_state_matches(
        &try_parse_machine_id(&host_machine_id.clone()).unwrap(),
        3,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::MachineValidating {
                context: "OnDemand".to_string(),
                id: uuid::Uuid::default(),
                completed: 1,
                total: 1,
                is_enabled: env.config.machine_validation_config.enabled,
            },
        },
    )
    .await;
    machine_validation_completed(&env, host_machine_id.clone(), None).await;
    env.run_machine_state_controller_iteration_until_state_matches(
        &try_parse_machine_id(&host_machine_id.clone()).unwrap(),
        1,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered,
        },
    )
    .await;

    let machine = env
        .find_machines(Some(host_machine_id.clone()), None, false)
        .await
        .machines
        .remove(0);
    let health = machine.health.as_ref().unwrap();
    assert_eq!(health.alerts.len(), 0);
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_machine_validation(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let machine_validation_result = rpc::forge::MachineValidationResult {
        validation_id: None,
        name: "test1".to_string(),
        description: "desc".to_string(),
        command: "echo".to_string(),
        args: "test".to_string(),
        std_out: "".to_string(),
        std_err: "".to_string(),
        context: "Discovery".to_string(),
        exit_code: 0,
        start_time: Some(Timestamp::from(SystemTime::now())),
        end_time: Some(Timestamp::from(SystemTime::now())),
    };

    let host_machine_id = create_host_with_machine_validation(
        &env,
        &host_sim.config,
        &dpu_machine_id,
        Some(machine_validation_result.clone()),
        None,
    )
    .await;

    let mut txn = env.pool.begin().await?;

    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    match machine.current_state() {
        ManagedHostState::Ready => {}
        s => {
            panic!("Incorrect state: {}", s);
        }
    }

    let machine = env
        .find_machines(Some(host_machine_id.clone()), None, false)
        .await
        .machines
        .remove(0);
    assert!(machine.health.as_ref().unwrap().alerts.is_empty());

    let _ =
        on_demand_machine_validation(&env, machine.id.unwrap_or_default(), Vec::new(), Vec::new())
            .await;
    env.run_machine_state_controller_iteration_until_state_matches(
        &try_parse_machine_id(&host_machine_id.clone()).unwrap(),
        3,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::MachineValidating {
                context: "OnDemand".to_string(),
                id: uuid::Uuid::default(),
                completed: 1,
                total: 1,
                is_enabled: env.config.machine_validation_config.enabled,
            },
        },
    )
    .await;
    machine_validation_completed(&env, host_machine_id.clone(), None).await;
    env.run_machine_state_controller_iteration_until_state_matches(
        &try_parse_machine_id(&host_machine_id.clone()).unwrap(),
        3,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered,
        },
    )
    .await;
    txn.commit().await.unwrap();
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_machine_validation_get_results(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let machine_validation_result = rpc::forge::MachineValidationResult {
        validation_id: None,
        name: "test1".to_string(),
        description: "desc".to_string(),
        command: "echo".to_string(),
        args: "test".to_string(),
        std_out: "".to_string(),
        std_err: "".to_string(),
        context: "Discovery".to_string(),
        exit_code: 0,
        start_time: Some(Timestamp::from(SystemTime::now())),
        end_time: Some(Timestamp::from(SystemTime::now())),
    };

    let host_remote_id = create_host_with_machine_validation(
        &env,
        &host_sim.config,
        &dpu_machine_id,
        Some(machine_validation_result.clone()),
        None,
    )
    .await;

    let host_machine_id = try_parse_machine_id(&host_remote_id).unwrap();
    let (instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        None,
        None,
        vec![],
    )
    .await;

    let runs = get_machine_validation_runs(&env, host_remote_id.clone(), false).await;
    assert_eq!(runs.runs.len(), 1);
    assert_eq!(
        runs.runs[0].context.clone().unwrap_or_default(),
        "Discovery".to_owned()
    );
    let discovery_validation_id = runs.runs[0].validation_id.clone();
    delete_instance(&env, instance_id, &dpu_machine_id, &host_machine_id).await;

    // one for cleanup and one for discovery
    let runs = get_machine_validation_runs(&env, host_remote_id.clone(), false).await;
    assert_eq!(runs.runs.len(), 2);

    let results =
        get_machine_validation_results(&env, Some(host_remote_id.clone()), true, None).await;
    assert_eq!(results.results.len(), 2);
    assert_eq!(results.results[0].name, machine_validation_result.name);
    assert_eq!(results.results[1].name, "instance".to_owned());
    let cleanup_validation_id = results.results[1].validation_id.clone();

    // find using validation id
    let results = get_machine_validation_results(&env, None, true, discovery_validation_id).await;
    assert_eq!(results.results.len(), 1);
    assert_eq!(results.results[0].name, machine_validation_result.name);

    // find using machine and validation id
    let results =
        get_machine_validation_results(&env, Some(host_remote_id), true, cleanup_validation_id)
            .await;
    assert_eq!(results.results.len(), 1);
    assert_eq!(results.results[0].name, "instance".to_owned());

    let machine = env
        .find_machines(Some(host_machine_id.to_string().into()), None, false)
        .await
        .machines
        .remove(0);
    assert!(machine.health.as_ref().unwrap().alerts.is_empty());

    Ok(())
}

#[sqlx::test]
async fn test_create_update_external_config(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let input = r#"
    {
        "ADDRESS": "shoreline.nvidia.com",
        "SECRET": "somesecret"
    }
    "#;
    let name = "shoreline";
    let desc = "shoreline description";
    env.api
        .add_update_machine_validation_external_config(tonic::Request::new(
            rpc::forge::AddUpdateMachineValidationExternalConfigRequest {
                name: name.to_string(),
                description: Some(desc.to_string()),
                config: input.as_bytes().to_vec(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let res = env
        .api
        .get_machine_validation_external_config(tonic::Request::new(
            rpc::forge::GetMachineValidationExternalConfigRequest {
                name: name.to_string(),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(res.config.clone().unwrap().name, name);
    assert_eq!(res.config.clone().unwrap().description.unwrap(), desc);
    assert_eq!(
        ConfigVersion::from_str(&res.config.clone().unwrap().version)?.version_nr(),
        1
    );
    assert_eq!(res.config.unwrap().config, input.as_bytes().to_vec());
    // Update one more time
    env.api
        .add_update_machine_validation_external_config(tonic::Request::new(
            rpc::forge::AddUpdateMachineValidationExternalConfigRequest {
                name: name.to_string(),
                description: Some(desc.to_string()),
                config: input.as_bytes().to_vec(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let res_next = env
        .api
        .get_machine_validation_external_config(tonic::Request::new(
            rpc::forge::GetMachineValidationExternalConfigRequest {
                name: name.to_string(),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(res_next.config.clone().unwrap().name, name);
    assert_eq!(res_next.config.clone().unwrap().description.unwrap(), desc);
    assert_eq!(
        ConfigVersion::from_str(&res_next.config.clone().unwrap().version)?.version_nr(),
        2
    );
    assert_eq!(res_next.config.unwrap().config, input.as_bytes().to_vec());
    let res_list = env
        .api
        .get_machine_validation_external_configs(tonic::Request::new(()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(res_list.names[0], "shoreline");
    assert_eq!(res_list.names.len(), 1);

    // remove
    env.api
        .remove_machine_validation_external_config(tonic::Request::new(
            rpc::forge::RemoveMachineValidationExternalConfigRequest {
                name: res_list.names[0].clone(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let remove_res_list = env
        .api
        .get_machine_validation_external_configs(tonic::Request::new(()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(remove_res_list.names.len(), 0);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_machine_validation_test_on_demand_filter(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let machine_validation_result = rpc::forge::MachineValidationResult {
        validation_id: None,
        name: "test1".to_string(),
        description: "desc".to_string(),
        command: "echo".to_string(),
        args: "test".to_string(),
        std_out: "".to_string(),
        std_err: "".to_string(),
        context: "Discovery".to_string(),
        exit_code: 0,
        start_time: Some(Timestamp::from(SystemTime::now())),
        end_time: Some(Timestamp::from(SystemTime::now())),
    };

    let host_machine_id = create_host_with_machine_validation(
        &env,
        &host_sim.config,
        &dpu_machine_id,
        Some(machine_validation_result.clone()),
        None,
    )
    .await;

    let mut txn = env.pool.begin().await?;

    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    match machine.current_state() {
        ManagedHostState::Ready => {}
        s => {
            panic!("Incorrect state: {}", s);
        }
    }

    let machine = env
        .find_machines(Some(host_machine_id.clone()), None, false)
        .await
        .machines
        .remove(0);
    assert!(machine.health.as_ref().unwrap().alerts.is_empty());
    let allowed_tests = vec!["test1".to_string(), "test2".to_string()];
    let on_demand_response = on_demand_machine_validation(
        &env,
        machine.id.unwrap_or_default(),
        Vec::new(),
        allowed_tests.clone(),
    )
    .await;

    env.run_machine_state_controller_iteration_until_state_matches(
        &try_parse_machine_id(&host_machine_id.clone()).unwrap(),
        1,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::MachineValidating {
                context: "OnDemand".to_string(),
                id: uuid::Uuid::try_from(on_demand_response.validation_id.unwrap_or_default())
                    .unwrap(),
                completed: 1,
                total: 1,
                is_enabled: env.config.machine_validation_config.enabled,
            },
        },
    )
    .await;
    let response = forge_agent_control(&env, host_machine_id.clone()).await;

    for item in response.data.unwrap().pair {
        if item.key == "MachineValidationFilter" {
            let machine_validation_filter: MachineValidationFilter =
                serde_json::from_str(&item.value)?;
            assert!(allowed_tests
                .clone()
                .iter()
                .all(|item| machine_validation_filter.allowed_tests.contains(item)));
        }
    }

    machine_validation_completed(&env, host_machine_id.clone(), None).await;
    env.run_machine_state_controller_iteration_until_state_matches(
        &try_parse_machine_id(&host_machine_id.clone()).unwrap(),
        3,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered,
        },
    )
    .await;
    txn.commit().await.unwrap();
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_machine_validation_disabled(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = {
        let mut config = get_config();
        config.machine_validation_config.enabled = false;
        create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await
    };

    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let host_machine_id =
        create_host_with_machine_validation(&env, &host_sim.config, &dpu_machine_id, None, None)
            .await;

    let runs = get_machine_validation_runs(&env, host_machine_id.clone(), true).await;
    let skipped_state_int =
        rpc::forge::machine_validation_status::MachineValidationState::Completed(
            rpc::forge::machine_validation_status::MachineValidationCompleted::Skipped.into(),
        );
    // let skipped_state_int: i32 = rpc::forge::MachineValidationState::Skipped.into();
    assert_eq!(
        runs.runs[0]
            .status
            .clone()
            .unwrap_or_default()
            .machine_validation_state
            .unwrap_or(skipped_state_int.clone()),
        skipped_state_int
    );

    let machine = env
        .find_machines(Some(host_machine_id.clone()), None, false)
        .await
        .machines
        .remove(0);
    assert!(machine.health.as_ref().unwrap().alerts.is_empty());

    let on_demand_response =
        on_demand_machine_validation(&env, machine.id.unwrap_or_default(), Vec::new(), Vec::new())
            .await;
    let mut txn = env.pool.begin().await?;

    env.run_machine_state_controller_iteration_until_state_matches(
        &try_parse_machine_id(&host_machine_id.clone()).unwrap(),
        3,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::MachineValidating {
                context: "OnDemand".to_string(),
                id: uuid::Uuid::default(),
                completed: 1,
                total: 1,
                is_enabled: env.config.machine_validation_config.enabled,
            },
        },
    )
    .await;
    txn.commit().await.unwrap();
    let _ = reboot_completed(&env, host_machine_id.clone()).await;

    let runs = get_machine_validation_runs(&env, host_machine_id.clone(), true).await;
    let started_state_int = rpc::forge::machine_validation_status::MachineValidationState::Started(
        rpc::forge::machine_validation_status::MachineValidationStarted::Started.into(),
    );
    let mut status_asserted = false;
    for run in runs.runs {
        if run.validation_id.unwrap_or_default()
            == on_demand_response.validation_id.clone().unwrap_or_default()
        {
            status_asserted = true;
            assert_eq!(
                run.status
                    .clone()
                    .unwrap_or_default()
                    .machine_validation_state
                    .unwrap_or(started_state_int.clone()),
                started_state_int
            );
        }
    }
    assert!(status_asserted);
    let mut txn = env.pool.begin().await?;

    env.run_machine_state_controller_iteration_until_state_matches(
        &try_parse_machine_id(&host_machine_id.clone()).unwrap(),
        3,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered,
        },
    )
    .await;
    txn.commit().await.unwrap();

    status_asserted = false;
    let runs = get_machine_validation_runs(&env, host_machine_id.clone(), true).await;
    for run in runs.runs {
        if run.validation_id.unwrap_or_default()
            == on_demand_response.validation_id.clone().unwrap_or_default()
        {
            status_asserted = true;
            assert_eq!(
                run.status
                    .clone()
                    .unwrap_or_default()
                    .machine_validation_state
                    .unwrap_or(skipped_state_int.clone()),
                skipped_state_int
            );
        }
    }
    assert!(status_asserted);
    Ok(())
}
