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
use carbide::{db::expected_machine::ExpectedMachine, CarbideError};
use sqlx::Postgres;

pub mod common;

async fn get_expected_machine_1(
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Option<ExpectedMachine> {
    let fixture_mac_address = "0a:0b:0c:0d:0e:0f".parse().unwrap();

    ExpectedMachine::find_by_bmc_mac_address(txn, fixture_mac_address)
        .await
        .unwrap()
}

#[sqlx::test(fixtures("create_expected_machine"))]
async fn test_lookup_by_mac(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    assert_eq!(
        get_expected_machine_1(&mut txn)
            .await
            .expect("Expected machine not found")
            .serial_number,
        "VVG121GG"
    );
    Ok(())
}

#[sqlx::test(fixtures("create_expected_machine"))]
async fn test_duplicate_fail_create(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    let machine = get_expected_machine_1(&mut txn)
        .await
        .expect("Expected machine not found");

    let new_machine = ExpectedMachine::create(
        &mut txn,
        machine.bmc_mac_address,
        "ADMIN3".into(),
        "hmm".into(),
        "JFAKLJF".into(),
    )
    .await;

    assert!(matches!(
        new_machine,
        Err(CarbideError::ExpectedHostDuplicateMacAddress(_))
    ));

    Ok(())
}

#[sqlx::test(fixtures("create_expected_machine"))]
async fn test_update_bmc_credentials(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");
    let mut machine = get_expected_machine_1(&mut txn)
        .await
        .expect("Expected machine not found");

    assert_eq!(machine.serial_number, "VVG121GG");

    machine
        .update_bmc_credentials(&mut txn, "ADMIN2".to_string(), "wysiwyg".to_string())
        .await
        .expect("Error updating bmc username/password");

    txn.commit().await.expect("Failed to commit transaction");

    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    let machine = get_expected_machine_1(&mut txn)
        .await
        .expect("Expected machine not found");

    assert_eq!(machine.bmc_username, "ADMIN2");
    assert_eq!(machine.bmc_password, "wysiwyg");

    Ok(())
}

#[sqlx::test(fixtures("create_expected_machine"))]
async fn test_delete(pool: sqlx::PgPool) -> () {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");
    let machine = get_expected_machine_1(&mut txn)
        .await
        .expect("Expected machine not found");

    assert_eq!(machine.serial_number, "VVG121GG");

    machine
        .delete(&mut txn)
        .await
        .expect("Error deleting expected_machine");

    txn.commit().await.expect("Failed to commit transaction");
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    get_expected_machine_1(&mut txn).await;

    assert!(get_expected_machine_1(&mut txn).await.is_none())
}
