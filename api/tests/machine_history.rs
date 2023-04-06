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
use log::LevelFilter;

use carbide::db::{machine::Machine, machine_state_history::MachineStateHistory};
use carbide::model::machine::{machine_id::try_parse_machine_id, ManagedHostState};

mod common;
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine};

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_machine_state_history(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone(), Default::default());
    let dpu_machine_id = try_parse_machine_id(&create_dpu_machine(&env).await).unwrap();

    let mut txn = pool.begin().await?;

    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
        },
    )
    .await?
    .unwrap();

    assert_eq!(
        text_history(machine.history()),
        vec!["dpunotready".to_string(), "hostnotready".to_string(),]
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
        },
    )
    .await?
    .unwrap();

    assert_eq!(machine.history().len(), 250);
    Ok(())
}

fn text_history(history: &Vec<MachineStateHistory>) -> Vec<String> {
    // // Check that version numbers are always incrementing by 1
    if !history.is_empty() {
        let mut version = history[0].state_version.version_nr();
        for entry in &history[1..] {
            assert_eq!(entry.state_version.version_nr(), version + 1);
            version += 1;
        }
    }

    history
        .iter()
        .map(|entry| {
            match entry.state {
                ManagedHostState::Created => "created",
                ManagedHostState::DPUNotReady(_) => "dpunotready",
                ManagedHostState::HostNotReady(_) => "hostnotready",
                ManagedHostState::Ready => "ready",
                ManagedHostState::Assigned(_) => "assigned",
                ManagedHostState::WaitingForCleanup(_) => "waitingforcleanup",
                ManagedHostState::ForceDeletion => "forcedeletion",
            }
            .to_string()
        })
        .collect()
}
