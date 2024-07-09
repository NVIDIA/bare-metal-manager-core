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

use std::time::SystemTime;

use carbide::{
    db::machine::Machine,
    model::machine::{
        machine_id::try_parse_machine_id, FailureCause, FailureDetails, FailureSource,
        ManagedHostState,
    },
};

mod common;
use common::api_fixtures::{
    create_test_env, get_machine_validation_results,
    host::create_host_with_machine_validation,
    instance::{create_instance, delete_instance, single_interface_network_config},
    network_segment::FIXTURE_NETWORK_SEGMENT_ID,
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
    let _ = create_host_with_machine_validation(
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

    let _ = create_host_with_machine_validation(
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
                    err: machine_validation_result.std_err,
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

    let _ = create_host_with_machine_validation(
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
        vec![],
    )
    .await;

    delete_instance(&env, instance_id, &dpu_machine_id, &host_machine_id).await;

    let results = get_machine_validation_results(&env, host_remote_id, true).await;
    assert_eq!(results.results.len(), 2);
    assert_eq!(results.results[0].name, machine_validation_result.name);
    assert_eq!(results.results[1].name, "instance".to_owned());
    Ok(())
}
