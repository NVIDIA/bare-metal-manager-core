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
use carbide::db::machine_interface::MachineInterface;
use log::LevelFilter;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

const FIXTURE_CREATED_MACHINE_INTERFACE_ID: uuid::Uuid =
    uuid::uuid!("ad871735-efaa-406e-a83e-9ff63b1bc145");

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_machine_rename(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let new_hostname = "peppersmacker400";

    let mut machine_interface =
        MachineInterface::find_one(&mut txn, FIXTURE_CREATED_MACHINE_INTERFACE_ID).await?;

    assert_ne!(machine_interface.hostname(), new_hostname);

    machine_interface
        .update_hostname(&mut txn, new_hostname)
        .await?;

    txn.commit().await?;

    assert_eq!(machine_interface.hostname(), new_hostname);

    Ok(())
}
