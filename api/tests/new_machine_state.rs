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
use log::LevelFilter;

use carbide::db::{machine::Machine, machine_state_history::MachineStateHistory};
use carbide::model::machine::ManagedHostState;

const FIXTURE_CREATED_MACHINE_ID: &str =
    "fm100dt37B6YIKCXOOKMSFIB3A3RSBKXTNS6437JFZVKX3S43LZQ3QSKUCA";

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_new_machine_state(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let machine = Machine::find_one(
        &mut txn,
        &FIXTURE_CREATED_MACHINE_ID.parse().unwrap(),
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
        },
    )
    .await?;

    assert!(matches!(
        machine,
        Some(x) if x.current_state() == ManagedHostState::Created));

    txn.commit().await?;

    Ok(())
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_new_machine_state_history(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let machine = Machine::find_one(
        &mut txn,
        &FIXTURE_CREATED_MACHINE_ID.parse().unwrap(),
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
        },
    )
    .await?
    .unwrap();

    assert!(machine.history().is_empty()); // No machine history is added during fixtures based
                                           // machine creation as this is just DB value update.

    let machine = Machine::find_one(
        &mut txn,
        &FIXTURE_CREATED_MACHINE_ID.parse().unwrap(),
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
    let result =
        MachineStateHistory::for_machine(&mut txn, &FIXTURE_CREATED_MACHINE_ID.parse().unwrap())
            .await
            .unwrap();

    // Count should not go beyond 250.
    assert_eq!(result.len(), 250);

    let machine = Machine::find_one(
        &mut txn,
        &FIXTURE_CREATED_MACHINE_ID.parse().unwrap(),
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
        },
    )
    .await?
    .unwrap();

    assert!(!machine.history().is_empty());
    Ok(())
}
