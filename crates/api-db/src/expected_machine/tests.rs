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

use model::expected_machine::ExpectedMachineData;
use model::metadata::Metadata;

use super::*;
use crate as db;

async fn get_expected_machine_1(txn: &mut PgConnection) -> Option<ExpectedMachine> {
    let fixture_mac_address = "0a:0b:0c:0d:0e:0f".parse().unwrap();

    db::expected_machine::find_by_bmc_mac_address(txn, fixture_mac_address)
        .await
        .unwrap()
}

async fn create_fixture_expected_machines(pool: &sqlx::PgPool) {
    let mut txn = pool.begin().await.unwrap();
    for (bmc_mac_address, serial_number, fallback_dpu_serial_numbers) in [
        ("0a:0b:0c:0d:0e:0f", "VVG121GG", vec![]),
        ("1a:1b:1c:1d:1e:1f", "VVG121GH", vec![]),
        ("2a:2b:2c:2d:2e:2f", "VVG121GI", vec![]),
        ("3a:3b:3c:3d:3e:3f", "VVG121GJ", vec!["dpu_serial1"]),
        (
            "4a:4b:4c:4d:4e:4f",
            "VVG121GK",
            vec!["dpu_serial2", "dpu_serial3"],
        ),
        ("5a:5b:5c:5d:5e:5f", "VVG121GL", vec![]),
    ] {
        db::expected_machine::create(
            &mut txn,
            ExpectedMachine {
                id: None,
                bmc_mac_address: bmc_mac_address.parse().unwrap(),
                data: ExpectedMachineData {
                    bmc_username: "ADMIN".into(),
                    bmc_password: "Pwd2023x0x0x0x0x7".into(),
                    serial_number: serial_number.into(),
                    fallback_dpu_serial_numbers: fallback_dpu_serial_numbers
                        .into_iter()
                        .map(ToString::to_string)
                        .collect(),
                    ..Default::default()
                },
            },
        )
        .await
        .unwrap();
    }
    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn test_lookup_by_mac(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    create_fixture_expected_machines(&pool).await;
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    assert_eq!(
        get_expected_machine_1(&mut txn)
            .await
            .expect("Expected machine not found")
            .data
            .serial_number,
        "VVG121GG"
    );
    Ok(())
}

#[crate::sqlx_test]
async fn test_duplicate_fail_create(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    create_fixture_expected_machines(&pool).await;
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    let machine = get_expected_machine_1(&mut txn)
        .await
        .expect("Expected machine not found");

    let new_machine = db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: machine.bmc_mac_address,
            data: ExpectedMachineData {
                bmc_username: "ADMIN3".into(),
                bmc_password: "hmm".into(),
                serial_number: "JFAKLJF".into(),
                fallback_dpu_serial_numbers: vec![],
                metadata: Metadata::new_with_default_name(),
                sku_id: None,
                default_pause_ingestion_and_poweron: None,
                host_nics: vec![],
                rack_id: None,
                dpf_enabled: Some(true),
                bmc_ip_address: None,
                bmc_retain_credentials: None,
                dpu_mode: Default::default(),
                host_lifecycle_profile: Default::default(),
            },
        },
    )
    .await;

    assert!(matches!(
        new_machine,
        Err(DatabaseError::ExpectedHostDuplicateMacAddress(_))
    ));

    Ok(())
}

#[crate::sqlx_test]
async fn test_update_bmc_credentials(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    create_fixture_expected_machines(&pool).await;
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");
    let mut machine = get_expected_machine_1(&mut txn)
        .await
        .expect("Expected machine not found");

    assert_eq!(machine.data.serial_number, "VVG121GG");

    db::expected_machine::update_bmc_credentials(
        &mut machine,
        &mut txn,
        "ADMIN2".to_string(),
        "wysiwyg".to_string(),
    )
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

    assert_eq!(machine.data.bmc_username, "ADMIN2");
    assert_eq!(machine.data.bmc_password, "wysiwyg");

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete(pool: sqlx::PgPool) -> () {
    create_fixture_expected_machines(&pool).await;
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");
    let machine = get_expected_machine_1(&mut txn)
        .await
        .expect("Expected machine not found");

    assert_eq!(machine.data.serial_number, "VVG121GG");

    db::expected_machine::delete_by_mac(&mut txn, machine.bmc_mac_address)
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

#[crate::sqlx_test]
async fn test_with_dpu_serial_numbers(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_fixture_expected_machines(&pool).await;

    let fixture_mac_address_0 = "0a:0b:0c:0d:0e:0f".parse().unwrap();
    let fixture_mac_address_3 = "3a:3b:3c:3d:3e:3f".parse().unwrap();
    let fixture_mac_address_4 = "4a:4b:4c:4d:4e:4f".parse().unwrap();

    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    let em0 = db::expected_machine::find_by_bmc_mac_address(txn.as_mut(), fixture_mac_address_0)
        .await
        .unwrap()
        .expect("Expected machine not found");
    assert!(em0.data.fallback_dpu_serial_numbers.is_empty());

    let em3 = db::expected_machine::find_by_bmc_mac_address(txn.as_mut(), fixture_mac_address_3)
        .await
        .unwrap()
        .expect("Expected machine not found");
    assert_eq!(em3.data.fallback_dpu_serial_numbers, vec!["dpu_serial1"]);

    let em4 = db::expected_machine::find_by_bmc_mac_address(txn.as_mut(), fixture_mac_address_4)
        .await
        .unwrap()
        .expect("Expected machine not found");

    assert_eq!(
        em4.data.fallback_dpu_serial_numbers,
        vec!["dpu_serial2", "dpu_serial3"]
    );

    Ok(())
}
