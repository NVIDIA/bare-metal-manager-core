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
use std::default::Default;

use carbide_uuid::rack::RackId;
use common::api_fixtures::create_test_env;
use db::DatabaseError;
use mac_address::MacAddress;
use model::expected_power_shelf::ExpectedPowerShelf;
use model::metadata::Metadata;
use rpc::forge::forge_server::Forge;
use rpc::forge::{ExpectedPowerShelfList, ExpectedPowerShelfRequest};
use sqlx::PgConnection;

use crate::tests::common;

// Test DB Functionality
async fn get_expected_power_shelf_1(txn: &mut PgConnection) -> Option<ExpectedPowerShelf> {
    let fixture_mac_address = "0a:0b:0c:0d:0e:0f".parse().unwrap();

    db::expected_power_shelf::find_by_bmc_mac_address(txn, fixture_mac_address)
        .await
        .unwrap()
}

#[crate::sqlx_test(fixtures("create_expected_power_shelf"))]
async fn test_lookup_by_mac(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    assert_eq!(
        get_expected_power_shelf_1(&mut txn)
            .await
            .expect("Expected power shelf not found")
            .serial_number,
        "PS-SN-001"
    );
    Ok(())
}

#[crate::sqlx_test(fixtures("create_expected_power_shelf"))]
async fn test_duplicate_fail_create(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    let power_shelf = get_expected_power_shelf_1(&mut txn)
        .await
        .expect("Expected power shelf not found");

    let new_power_shelf = db::expected_power_shelf::create(
        &mut txn,
        power_shelf.bmc_mac_address,
        "ADMIN3".into(),
        "hmm".into(),
        "DUPLICATE".into(),
        None,
        Metadata::default(),
        None,
    )
    .await;

    assert!(matches!(
        new_power_shelf,
        Err(DatabaseError::ExpectedHostDuplicateMacAddress(_))
    ));

    Ok(())
}

#[crate::sqlx_test(fixtures("create_expected_power_shelf"))]
async fn test_update_bmc_credentials(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");
    let mut power_shelf = get_expected_power_shelf_1(&mut txn)
        .await
        .expect("Expected power shelf not found");

    let serial_number = power_shelf.serial_number.clone();
    let ip_address = power_shelf.ip_address;
    let metadata = power_shelf.metadata.clone();
    assert_eq!(power_shelf.serial_number, "PS-SN-001");
    assert_eq!(power_shelf.bmc_username, "ADMIN");
    assert_eq!(power_shelf.bmc_password, "Pwd2023x0x0x0x0x7");

    db::expected_power_shelf::update(
        &mut power_shelf,
        &mut txn,
        "ADMIN2".to_string(),
        "wysiwyg".to_string(),
        serial_number,
        ip_address,
        metadata,
        None,
    )
    .await
    .expect("Error updating bmc username/password");

    txn.commit().await.expect("Failed to commit transaction");

    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    let power_shelf = get_expected_power_shelf_1(&mut txn)
        .await
        .expect("Expected power shelf not found");

    assert_eq!(power_shelf.bmc_username, "ADMIN2");
    assert_eq!(power_shelf.bmc_password, "wysiwyg");

    Ok(())
}

#[crate::sqlx_test(fixtures("create_expected_power_shelf"))]
async fn test_delete(pool: sqlx::PgPool) -> () {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");
    let power_shelf = get_expected_power_shelf_1(&mut txn)
        .await
        .expect("Expected power shelf not found");

    assert_eq!(power_shelf.serial_number, "PS-SN-001");

    db::expected_power_shelf::delete(power_shelf.bmc_mac_address, &mut txn)
        .await
        .expect("Error deleting expected_power_shelf");

    txn.commit().await.expect("Failed to commit transaction");
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    get_expected_power_shelf_1(&mut txn).await;

    assert!(get_expected_power_shelf_1(&mut txn).await.is_none())
}

// Test API functionality
#[crate::sqlx_test()]
async fn test_add_expected_power_shelf(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    for mut expected_power_shelf in [
        rpc::forge::ExpectedPowerShelf {
            bmc_mac_address: "3A:3B:3C:3D:3E:3F".to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            shelf_serial_number: "PS-TEST-001".into(),
            ip_address: "".into(),
            metadata: None,
            rack_id: None,
        },
        rpc::forge::ExpectedPowerShelf {
            bmc_mac_address: "3A:3B:3C:3D:3E:40".to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            shelf_serial_number: "PS-TEST-002".into(),
            ip_address: "192.168.1.200".into(),
            metadata: Some(rpc::forge::Metadata::default()),
            rack_id: None,
        },
        rpc::forge::ExpectedPowerShelf {
            bmc_mac_address: "3A:3B:3C:3D:3E:41".to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            shelf_serial_number: "PS-TEST-003".into(),
            ip_address: "192.168.1.201".into(),
            metadata: Some(rpc::forge::Metadata {
                name: "power-shelf-a".to_string(),
                description: "Test power shelf".to_string(),
                labels: vec![
                    rpc::forge::Label {
                        key: "location".to_string(),
                        value: Some("datacenter-1".to_string()),
                    },
                    rpc::forge::Label {
                        key: "rack".to_string(),
                        value: Some("A1".to_string()),
                    },
                ],
            }),
            rack_id: Some(RackId::from(uuid::Uuid::new_v4())),
        },
    ] {
        env.api
            .add_expected_power_shelf(tonic::Request::new(expected_power_shelf.clone()))
            .await
            .expect("unable to add expected power shelf ");

        let expected_power_shelf_query = rpc::forge::ExpectedPowerShelfRequest {
            bmc_mac_address: expected_power_shelf.bmc_mac_address.clone(),
        };

        let mut retrieved_expected_power_shelf = env
            .api
            .get_expected_power_shelf(tonic::Request::new(expected_power_shelf_query))
            .await
            .expect("unable to retrieve expected power shelf ")
            .into_inner();
        retrieved_expected_power_shelf
            .metadata
            .as_mut()
            .unwrap()
            .labels
            .sort_by(|l1, l2| l1.key.cmp(&l2.key));
        if expected_power_shelf.metadata.is_none() {
            expected_power_shelf.metadata = Some(Default::default());
        }

        assert_eq!(retrieved_expected_power_shelf, expected_power_shelf);
    }
}

#[crate::sqlx_test(fixtures("create_expected_power_shelf"))]
async fn test_delete_expected_power_shelf(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let expected_power_shelf_count = env
        .api
        .get_all_expected_power_shelves(tonic::Request::new(()))
        .await
        .expect("unable to get all expected power shelves")
        .into_inner()
        .expected_power_shelves
        .len();

    let expected_power_shelf_query = rpc::forge::ExpectedPowerShelfRequest {
        bmc_mac_address: "2A:2B:2C:2D:2E:2F".into(),
    };
    env.api
        .delete_expected_power_shelf(tonic::Request::new(expected_power_shelf_query))
        .await
        .expect("unable to delete expected power shelf ")
        .into_inner();

    let new_expected_power_shelf_count = env
        .api
        .get_all_expected_power_shelves(tonic::Request::new(()))
        .await
        .expect("unable to get all expected power shelves")
        .into_inner()
        .expected_power_shelves
        .len();

    assert_eq!(
        new_expected_power_shelf_count,
        expected_power_shelf_count - 1
    );
}

#[crate::sqlx_test()]
async fn test_delete_expected_power_shelf_error(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac_address: MacAddress = "2A:2B:2C:2D:2E:2F".parse().unwrap();
    let expected_power_shelf_request = rpc::forge::ExpectedPowerShelfRequest {
        bmc_mac_address: bmc_mac_address.to_string(),
    };

    let err = env
        .api
        .delete_expected_power_shelf(tonic::Request::new(expected_power_shelf_request))
        .await
        .unwrap_err();

    assert_eq!(
        err.message().to_string(),
        format!(
            "Failed to delete expected power shelf: expected_power_shelf not found: {}",
            bmc_mac_address
        )
    );
}

#[crate::sqlx_test(fixtures("create_expected_power_shelf"))]
async fn test_update_expected_power_shelf(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let bmc_mac_address: MacAddress = "2A:2B:2C:2D:2E:2F".parse().unwrap();
    for mut updated_power_shelf in [
        rpc::forge::ExpectedPowerShelf {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: "ADMIN_UPDATE".into(),
            bmc_password: "PASS_UPDATE".into(),
            shelf_serial_number: "PS-UPD-001".into(),
            ip_address: "".into(),
            metadata: None,
            rack_id: None,
        },
        rpc::forge::ExpectedPowerShelf {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: "ADMIN_UPDATE".into(),
            bmc_password: "PASS_UPDATE".into(),
            shelf_serial_number: "PS-UPD-002".into(),
            ip_address: "192.168.2.100".into(),
            metadata: Some(Default::default()),
            rack_id: None,
        },
        rpc::forge::ExpectedPowerShelf {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: "ADMIN_UPDATE1".into(),
            bmc_password: "PASS_UPDATE1".into(),
            shelf_serial_number: "PS-UPD-003".into(),
            ip_address: "192.168.2.101".into(),
            metadata: Some(rpc::forge::Metadata {
                name: "updated-shelf".to_string(),
                description: "Updated power shelf".to_string(),
                labels: vec![
                    rpc::forge::Label {
                        key: "env".to_string(),
                        value: Some("production".to_string()),
                    },
                    rpc::forge::Label {
                        key: "zone".to_string(),
                        value: Some("zone-a".to_string()),
                    },
                ],
            }),
            rack_id: Some(RackId::from(uuid::Uuid::new_v4())),
        },
    ] {
        env.api
            .update_expected_power_shelf(tonic::Request::new(updated_power_shelf.clone()))
            .await
            .expect("unable to update expected power shelf ")
            .into_inner();

        let mut retrieved_expected_power_shelf = env
            .api
            .get_expected_power_shelf(tonic::Request::new(ExpectedPowerShelfRequest {
                bmc_mac_address: bmc_mac_address.to_string(),
            }))
            .await
            .expect("unable to fetch expected power shelf ")
            .into_inner();
        retrieved_expected_power_shelf
            .metadata
            .as_mut()
            .unwrap()
            .labels
            .sort_by(|l1, l2| l1.key.cmp(&l2.key));
        if updated_power_shelf.metadata.is_none() {
            updated_power_shelf.metadata = Some(Default::default());
        }

        assert_eq!(retrieved_expected_power_shelf, updated_power_shelf);
    }
}

#[crate::sqlx_test()]
async fn test_update_expected_power_shelf_error(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac_address: MacAddress = "2A:2B:2C:2D:2E:2F".parse().unwrap();
    let expected_power_shelf = rpc::forge::ExpectedPowerShelf {
        bmc_mac_address: bmc_mac_address.to_string(),
        bmc_username: "ADMIN_UPDATE".into(),
        bmc_password: "PASS_UPDATE".into(),
        shelf_serial_number: "PS-UPD-001".into(),
        ip_address: "".into(),
        metadata: None,
        rack_id: None,
    };

    let err = env
        .api
        .update_expected_power_shelf(tonic::Request::new(expected_power_shelf.clone()))
        .await
        .unwrap_err();

    assert_eq!(
        err.message().to_string(),
        format!(
            "Expected power shelf with MAC address {} not found",
            bmc_mac_address
        )
    );
}

#[crate::sqlx_test(fixtures("create_expected_power_shelf"))]
async fn test_delete_all_expected_power_shelves(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mut expected_power_shelf_count = env
        .api
        .get_all_expected_power_shelves(tonic::Request::new(()))
        .await
        .expect("unable to get all expected power shelves")
        .into_inner()
        .expected_power_shelves
        .len();

    assert_eq!(expected_power_shelf_count, 6);

    env.api
        .delete_all_expected_power_shelves(tonic::Request::new(()))
        .await
        .expect("unable to delete all expected power shelves")
        .into_inner();

    expected_power_shelf_count = env
        .api
        .get_all_expected_power_shelves(tonic::Request::new(()))
        .await
        .expect("unable to get all expected power shelves")
        .into_inner()
        .expected_power_shelves
        .len();

    assert_eq!(expected_power_shelf_count, 0);
}

#[crate::sqlx_test(fixtures("create_expected_power_shelf"))]
async fn test_replace_all_expected_power_shelves(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let expected_power_shelf_count = env
        .api
        .get_all_expected_power_shelves(tonic::Request::new(()))
        .await
        .expect("unable to get all expected power shelves")
        .into_inner()
        .expected_power_shelves
        .len();

    assert_eq!(expected_power_shelf_count, 6);

    let mut expected_power_shelf_list = ExpectedPowerShelfList {
        expected_power_shelves: Vec::new(),
    };

    let expected_power_shelf_1 = rpc::forge::ExpectedPowerShelf {
        bmc_mac_address: "6A:6B:6C:6D:6E:6F".into(),
        bmc_username: "ADMIN_NEW".into(),
        bmc_password: "PASS_NEW".into(),
        shelf_serial_number: "PS-NEW-001".into(),
        ip_address: "192.168.100.1".into(),
        metadata: Some(rpc::Metadata::default()),
        rack_id: Some(RackId::from(uuid::Uuid::new_v4())),
    };

    let expected_power_shelf_2 = rpc::forge::ExpectedPowerShelf {
        bmc_mac_address: "7A:7B:7C:7D:7E:7F".into(),
        bmc_username: "ADMIN_NEW".into(),
        bmc_password: "PASS_NEW".into(),
        shelf_serial_number: "PS-NEW-002".into(),
        ip_address: "192.168.100.2".into(),
        metadata: Some(rpc::Metadata::default()),
        rack_id: Some(RackId::from(uuid::Uuid::new_v4())),
    };

    expected_power_shelf_list
        .expected_power_shelves
        .push(expected_power_shelf_1.clone());
    expected_power_shelf_list
        .expected_power_shelves
        .push(expected_power_shelf_2.clone());

    env.api
        .replace_all_expected_power_shelves(tonic::Request::new(expected_power_shelf_list))
        .await
        .expect("unable to replace all expected power shelves")
        .into_inner();

    let expected_power_shelves = env
        .api
        .get_all_expected_power_shelves(tonic::Request::new(()))
        .await
        .expect("unable to get all expected power shelves")
        .into_inner()
        .expected_power_shelves;

    assert_eq!(expected_power_shelves.len(), 2);
    assert!(expected_power_shelves.contains(&expected_power_shelf_1));
    assert!(expected_power_shelves.contains(&expected_power_shelf_2));
}

#[crate::sqlx_test()]
async fn test_get_expected_power_shelf_error(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac_address: MacAddress = "2A:2B:2C:2D:2E:2F".parse().unwrap();
    let expected_power_shelf_query = rpc::forge::ExpectedPowerShelfRequest {
        bmc_mac_address: bmc_mac_address.to_string(),
    };

    let err = env
        .api
        .get_expected_power_shelf(tonic::Request::new(expected_power_shelf_query))
        .await
        .unwrap_err();

    assert_eq!(
        err.message().to_string(),
        format!(
            "Expected power shelf with MAC address {} not found",
            bmc_mac_address
        )
    );
}

#[crate::sqlx_test(fixtures("create_expected_power_shelf"))]
async fn test_get_linked_expected_power_shelves_unseen(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let out = env
        .api
        .get_all_expected_power_shelves_linked(tonic::Request::new(()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(out.expected_power_shelves.len(), 6);
    // They are sorted by MAC server-side
    let eps = out.expected_power_shelves.first().unwrap();
    assert_eq!(eps.shelf_serial_number, "PS-SN-001");
    assert!(
        eps.power_shelf_id.is_none(),
        "expected_power_shelves fixture should have no linked power shelf"
    );
}

#[crate::sqlx_test()]
async fn test_add_expected_power_shelf_with_ip(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac_address: MacAddress = "3A:3B:3C:3D:3E:3F".parse().unwrap();
    let expected_power_shelf = rpc::forge::ExpectedPowerShelf {
        bmc_mac_address: bmc_mac_address.to_string(),
        bmc_username: "ADMIN".into(),
        bmc_password: "PASS".into(),
        shelf_serial_number: "PS-IP-001".into(),
        ip_address: "10.0.0.100".into(),
        metadata: Some(rpc::Metadata::default()),
        rack_id: Some(RackId::from(uuid::Uuid::new_v4())),
    };

    env.api
        .add_expected_power_shelf(tonic::Request::new(expected_power_shelf.clone()))
        .await
        .expect("unable to add expected power shelf ");

    let expected_power_shelf_query = rpc::forge::ExpectedPowerShelfRequest {
        bmc_mac_address: bmc_mac_address.to_string(),
    };

    let retrieved_expected_power_shelf = env
        .api
        .get_expected_power_shelf(tonic::Request::new(expected_power_shelf_query))
        .await
        .expect("unable to retrieve expected power shelf ")
        .into_inner();

    assert_eq!(retrieved_expected_power_shelf, expected_power_shelf);
    assert_eq!(retrieved_expected_power_shelf.ip_address, "10.0.0.100");
}

#[crate::sqlx_test(fixtures("create_expected_power_shelf"))]
async fn test_with_ip_addresses(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let fixture_mac_address_3 = "3a:3b:3c:3d:3e:3f".parse().unwrap();
    let fixture_mac_address_4 = "4a:4b:4c:4d:4e:4f".parse().unwrap();

    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    let eps3 = db::expected_power_shelf::find_by_bmc_mac_address(&mut txn, fixture_mac_address_3)
        .await
        .unwrap()
        .expect("Expected power shelf not found");
    assert_eq!(eps3.ip_address, Some("192.168.1.100".parse().unwrap()));

    let eps4 = db::expected_power_shelf::find_by_bmc_mac_address(&mut txn, fixture_mac_address_4)
        .await
        .unwrap()
        .expect("Expected power shelf not found");

    assert_eq!(eps4.ip_address, Some("192.168.1.101".parse().unwrap()));

    Ok(())
}

#[crate::sqlx_test(fixtures("create_expected_power_shelf"))]
async fn test_update_expected_power_shelf_ip_address(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let mut eps1 = env
        .api
        .get_expected_power_shelf(tonic::Request::new(rpc::forge::ExpectedPowerShelfRequest {
            bmc_mac_address: "2A:2B:2C:2D:2E:2F".into(),
        }))
        .await
        .expect("unable to get")
        .into_inner();

    eps1.ip_address = "172.16.0.50".to_string();

    env.api
        .update_expected_power_shelf(tonic::Request::new(eps1.clone()))
        .await
        .expect("unable to update")
        .into_inner();

    let eps2 = env
        .api
        .get_expected_power_shelf(tonic::Request::new(rpc::forge::ExpectedPowerShelfRequest {
            bmc_mac_address: "2A:2B:2C:2D:2E:2F".into(),
        }))
        .await
        .expect("unable to get")
        .into_inner();

    assert_eq!(eps1, eps2);
    assert_eq!(eps2.ip_address, "172.16.0.50");
}
