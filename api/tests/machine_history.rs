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
use carbide::db::{machine::Machine, machine_state_history::MachineStateHistory};
use carbide::model::config_version::ConfigVersion;
use carbide::model::machine::{machine_id::try_parse_machine_id, ManagedHostState};

mod common;
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_machine_state_history(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let dpu_machine_id = try_parse_machine_id(&create_dpu_machine(&env).await).unwrap();

    let mut txn = pool.begin().await?;

    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await?
    .unwrap();

    assert_eq!(
        text_history(machine.history()),
        vec![
            "{\"state\": \"dpunotready\", \"machine_state\": {\"state\": \"init\"}}",
            "{\"state\": \"dpunotready\", \"machine_state\": {\"state\": \"waitingfornetworkinstall\"}}",
            "{\"state\": \"dpunotready\", \"machine_state\": {\"state\": \"waitingfornetworkconfig\"}}",
            "{\"state\": \"hostnotready\", \"machine_state\": {\"state\": \"waitingfordiscovery\"}}"]
    );

    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await?
    .unwrap();
    assert!(machine.history().is_empty());

    for _ in 1..300 {
        machine
            .advance(&mut txn, ManagedHostState::Ready, None)
            .await
            .unwrap();
    }

    txn.commit().await?;

    let mut txn = pool.begin().await?;
    let result = MachineStateHistory::for_machine(&mut txn, &dpu_machine_id)
        .await
        .unwrap();

    // Count should not go beyond 250.
    assert_eq!(result.len(), 250);

    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await?
    .unwrap();

    assert_eq!(machine.history().len(), 250);
    Ok(())
}

/// Check that we can handle old / unknown states in the history.
/// This allows us to change MachineState enum.
#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_old_machine_state_history(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let dpu_machine_id = try_parse_machine_id(&create_dpu_machine(&env).await).unwrap();

    let mut txn = pool.begin().await?;

    let version = ConfigVersion::initial();
    let query =
        "INSERT INTO machine_state_history (machine_id, state, state_version) VALUES ($1, $2::jsonb, $3)";
    sqlx::query(query)
        .bind(dpu_machine_id.to_string())
        .bind(r#"{"state": "dpunotready", "machine_state": {"state": "nolongerarealstate"}}"#)
        .bind(version.to_string())
        .execute(&mut *txn)
        .await?;

    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await?
    .unwrap();

    let mut states: Vec<&str> = Vec::with_capacity(machine.history().len());
    for e in machine.history() {
        states.push(e.state.as_ref());
    }
    assert_eq!(
        states,
        vec![
            "{\"state\": \"dpunotready\", \"machine_state\": {\"state\": \"init\"}}",
            "{\"state\": \"dpunotready\", \"machine_state\": {\"state\": \"waitingfornetworkinstall\"}}",
            "{\"state\": \"dpunotready\", \"machine_state\": {\"state\": \"waitingfornetworkconfig\"}}",
            "{\"state\": \"hostnotready\", \"machine_state\": {\"state\": \"waitingfordiscovery\"}}",
            "{\"state\": \"dpunotready\", \"machine_state\": {\"state\": \"nolongerarealstate\"}}",
        ],
    );

    Ok(())
}

fn text_history(history: &Vec<MachineStateHistory>) -> Vec<&str> {
    // // Check that version numbers are always incrementing by 1
    if !history.is_empty() {
        let mut version = history[0].state_version.version_nr();
        for entry in &history[1..] {
            assert_eq!(entry.state_version.version_nr(), version + 1);
            version += 1;
        }
    }

    let mut states = Vec::with_capacity(history.len());
    for e in history {
        states.push(e.state.as_ref());
    }
    states
}
