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
use carbide::db::machine::Machine;
use carbide::model::machine::MachineState;
use log::LevelFilter;

const FIXTURE_CREATED_MACHINE_ID: uuid::Uuid = uuid::uuid!("52dfecb4-8070-4f4b-ba95-f66d0f51fd98");

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
async fn state_machine_advance_from_db_events(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let machine = Machine::find_one(
        &mut txn,
        FIXTURE_CREATED_MACHINE_ID,
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await?
    .unwrap();

    // Insert some valid state changes into the db
    machine
        .advance(&mut txn, MachineState::Adopted)
        .await
        .unwrap();
    machine
        .advance(&mut txn, MachineState::Ready)
        .await
        .unwrap();
    machine
        .advance(&mut txn, MachineState::Assigned)
        .await
        .unwrap();

    let machine = Machine::find_one(
        &mut txn,
        FIXTURE_CREATED_MACHINE_ID,
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await?
    .unwrap();
    let state = machine.current_state();
    assert!(matches!(state, MachineState::Assigned));

    Ok(())
}
