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

use model::expected_power_shelf::ExpectedPowerShelf;
use model::metadata::Metadata;

use super::*;
use crate as db;

fn expected_power_shelf_bmc_mac_address(index: u8) -> mac_address::MacAddress {
    mac_address::MacAddress::new([0x44, 0x44, 0x22, 0x22, 0x00, index])
}

/// create_expected_power_shelves seeds 6 expected power shelves into the
/// database, replacing the create_expected_power_shelf.sql fixture.
async fn create_expected_power_shelves(
    txn: &mut sqlx::PgConnection,
) -> Vec<model::expected_power_shelf::ExpectedPowerShelf> {
    use model::expected_power_shelf::ExpectedPowerShelf;
    use model::metadata::Metadata;

    let mut created = Vec::new();
    for i in 0..6 {
        let power_shelf = ExpectedPowerShelf {
            expected_power_shelf_id: None,
            bmc_mac_address: expected_power_shelf_bmc_mac_address(i),
            serial_number: format!("PS-SN-{:03}", i + 1),
            bmc_username: "ADMIN".into(),
            bmc_password: "Pwd2023x0x0x0x0x7".into(),
            bmc_ip_address: if (3..=4).contains(&i) {
                Some(format!("192.168.1.{}", 100 + i - 3).parse().unwrap())
            } else {
                None
            },
            metadata: Metadata::default(),
            rack_id: None,
            bmc_retain_credentials: None,
        };
        let result = db::expected_power_shelf::create(txn, power_shelf)
            .await
            .expect("unable to create expected power shelf");
        created.push(result);
    }
    created
}

#[crate::sqlx_test]
async fn test_lookup_by_mac(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");
    let shelves = create_expected_power_shelves(&mut txn).await;

    assert_eq!(shelves[0].serial_number, "PS-SN-001");
    Ok(())
}

#[crate::sqlx_test]
async fn test_duplicate_fail_create(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");
    let shelves = create_expected_power_shelves(&mut txn).await;

    let power_shelf = &shelves[0];

    let new_power_shelf = db::expected_power_shelf::create(
        &mut txn,
        ExpectedPowerShelf {
            expected_power_shelf_id: None,
            bmc_mac_address: power_shelf.bmc_mac_address,
            bmc_username: "ADMIN3".into(),
            bmc_password: "hmm".into(),
            serial_number: "DUPLICATE".into(),
            bmc_ip_address: None,
            metadata: Metadata::default(),
            rack_id: None,
            bmc_retain_credentials: None,
        },
    )
    .await;

    assert!(matches!(
        new_power_shelf,
        Err(DatabaseError::ExpectedHostDuplicateMacAddress(_))
    ));

    Ok(())
}

#[crate::sqlx_test]
async fn test_update_bmc_credentials(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");
    let shelves = create_expected_power_shelves(&mut txn).await;
    let mut power_shelf = shelves[0].clone();

    assert_eq!(power_shelf.serial_number, "PS-SN-001");
    assert_eq!(power_shelf.bmc_username, "ADMIN");
    assert_eq!(power_shelf.bmc_password, "Pwd2023x0x0x0x0x7");

    power_shelf.bmc_username = "ADMIN2".to_string();
    power_shelf.bmc_password = "wysiwyg".to_string();
    db::expected_power_shelf::update(&mut txn, &power_shelf)
        .await
        .expect("Error updating bmc username/password");

    txn.commit().await.expect("Failed to commit transaction");

    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    let power_shelf =
        db::expected_power_shelf::find_by_bmc_mac_address(&mut txn, shelves[0].bmc_mac_address)
            .await
            .unwrap()
            .expect("Expected power shelf not found");

    assert_eq!(power_shelf.bmc_username, "ADMIN2");
    assert_eq!(power_shelf.bmc_password, "wysiwyg");

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete(pool: sqlx::PgPool) -> () {
    let mut txn = pool.begin().await.unwrap();
    let shelves = create_expected_power_shelves(&mut txn).await;
    let mac = shelves[0].bmc_mac_address;
    txn.commit().await.expect("Failed to commit transaction");

    crate::test_support::expected_host::assert_delete_by_mac_removes_row(
        &pool,
        mac,
        async |txn, mac| db::expected_power_shelf::delete_by_mac(txn, mac).await,
        async |txn, mac| db::expected_power_shelf::find_by_bmc_mac_address(txn, mac).await,
    )
    .await;
}
