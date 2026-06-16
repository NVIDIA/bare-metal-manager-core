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

use std::collections::HashMap;

use model::expected_switch::ExpectedSwitch;
use model::metadata::Metadata;

use super::*;
use crate as db;

fn expected_switch_bmc_mac_address(index: u32) -> mac_address::MacAddress {
    mac_address::MacAddress::new([0x44, 0x44, 0x11, 0x11, 0x00, index as u8])
}

fn expected_switch_nvos_mac_address(index: u32) -> mac_address::MacAddress {
    mac_address::MacAddress::new([0x44, 0x44, 0x33, 0x33, 0x00, index as u8])
}

/// Seeds one expected switch into the database.
async fn create_expected_switch(
    txn: &mut sqlx::PgConnection,
    index: u32,
) -> model::expected_switch::ExpectedSwitch {
    use model::expected_switch::ExpectedSwitch;
    use model::metadata::Metadata;

    let i = index as usize;
    let switch = ExpectedSwitch {
        expected_switch_id: None,
        bmc_mac_address: expected_switch_bmc_mac_address(index),
        nvos_mac_addresses: vec![expected_switch_nvos_mac_address(index)],
        serial_number: format!("SW-SN-{:03}", index + 1),
        bmc_username: "ADMIN".into(),
        bmc_password: "Pwd2023x0x0x0x7".into(),
        nvos_username: if (3..=4).contains(&i) {
            Some(format!("nvos_admin{}", i - 2))
        } else {
            None
        },
        nvos_password: if (3..=4).contains(&i) {
            Some(format!("nvos_pass{}", i - 2))
        } else {
            None
        },
        bmc_ip_address: None,
        nvos_ip_address: None,
        metadata: Metadata {
            name: format!("Switch{}", index + 1),
            description: format!("Test Switch {}", index + 1),
            labels: HashMap::new(),
        },
        rack_id: None,
        bmc_retain_credentials: None,
    };
    db::expected_switch::create(txn, switch)
        .await
        .expect("unable to create expected switch")
}

/// create_expected_switches seeds 6 expected switches into the database,
/// replacing the create_expected_switch.sql fixture.
async fn create_expected_switches(
    txn: &mut sqlx::PgConnection,
) -> Vec<model::expected_switch::ExpectedSwitch> {
    let mut created = Vec::new();
    for i in 0..6 {
        created.push(create_expected_switch(txn, i).await);
    }
    created
}

#[crate::sqlx_test]
async fn test_lookup_by_mac(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await.unwrap();
    let switches = create_expected_switches(&mut txn).await;

    assert_eq!(switches[0].serial_number, "SW-SN-001");
    Ok(())
}

#[crate::sqlx_test]
async fn test_duplicate_fail_create(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await.unwrap();
    let switches = create_expected_switches(&mut txn).await;
    let switch = &switches[0];
    let new_switch = db::expected_switch::create(
        &mut txn,
        ExpectedSwitch {
            expected_switch_id: None,
            bmc_mac_address: switch.bmc_mac_address,
            nvos_mac_addresses: switch.nvos_mac_addresses.clone(),
            bmc_username: "ADMIN3".into(),
            bmc_password: "hmm".into(),
            serial_number: "DUPLICATE".into(),
            bmc_ip_address: None,
            metadata: Metadata::default(),
            rack_id: None,
            bmc_retain_credentials: None,
            nvos_ip_address: None,
            nvos_username: None,
            nvos_password: None,
        },
    )
    .await;

    assert!(matches!(
        new_switch,
        Err(DatabaseError::ExpectedHostDuplicateMacAddress(_))
    ));

    Ok(())
}

#[crate::sqlx_test]
async fn test_update_bmc_credentials(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await.unwrap();
    let switches = create_expected_switches(&mut txn).await;
    let mut switch = switches[0].clone();

    assert_eq!(switch.serial_number, "SW-SN-001");
    assert_eq!(switch.bmc_username, "ADMIN");
    assert_eq!(switch.bmc_password, "Pwd2023x0x0x0x7");
    switch.bmc_username = "ADMIN2".to_string();
    switch.bmc_password = "wysiwyg".to_string();
    db::expected_switch::update(&mut txn, &switch)
        .await
        .expect("Error updating bmc username/password");

    txn.commit().await.expect("Failed to commit transaction");

    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    let switch =
        db::expected_switch::find_by_bmc_mac_address(&mut txn, switches[0].bmc_mac_address)
            .await
            .unwrap()
            .expect("Expected switch not found");

    assert_eq!(switch.bmc_username, "ADMIN2");
    assert_eq!(switch.bmc_password, "wysiwyg");

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete(pool: sqlx::PgPool) -> () {
    let mut txn = pool.begin().await.unwrap();
    let switches = create_expected_switches(&mut txn).await;

    let switch = &switches[0];

    assert_eq!(switch.serial_number, "SW-SN-001");

    db::expected_switch::delete_by_mac(&mut txn, switch.bmc_mac_address)
        .await
        .expect("Error deleting expected_switch");

    txn.commit().await.expect("Failed to commit transaction");
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    assert!(
        db::expected_switch::find_by_bmc_mac_address(&mut txn, switches[0].bmc_mac_address)
            .await
            .unwrap()
            .is_none()
    )
}
