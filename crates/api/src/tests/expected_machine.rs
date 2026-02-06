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

use common::api_fixtures::create_test_env;
use db::{self};
use mac_address::MacAddress;
use model::expected_machine::{ExpectedMachine, ExpectedMachineData};
use model::metadata::Metadata;
use model::site_explorer::EndpointExplorationReport;
use rpc::forge::forge_server::Forge;
use rpc::forge::{ExpectedMachineList, ExpectedMachineRequest};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::tests::common;
use crate::{CarbideError, DatabaseError};

// Test DB Functionality
async fn get_expected_machine_1(txn: &mut PgConnection) -> Option<ExpectedMachine> {
    let fixture_mac_address = "0a:0b:0c:0d:0e:0f".parse().unwrap();

    db::expected_machine::find_by_bmc_mac_address(txn, fixture_mac_address)
        .await
        .unwrap()
}

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_lookup_by_mac(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
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

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_duplicate_fail_create(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    let machine = get_expected_machine_1(&mut txn)
        .await
        .expect("Expected machine not found");

    let new_machine = db::expected_machine::create(
        &mut txn,
        machine.bmc_mac_address,
        ExpectedMachineData {
            bmc_username: "ADMIN3".into(),
            bmc_password: "hmm".into(),
            serial_number: "JFAKLJF".into(),
            fallback_dpu_serial_numbers: vec![],
            metadata: Metadata::new_with_default_name(),
            sku_id: None,
            override_id: None,
            default_pause_ingestion_and_poweron: None,
            host_nics: vec![],
            rack_id: None,
            dpf_enabled: true,
        },
    )
    .await;

    assert!(matches!(
        new_machine,
        Err(DatabaseError::ExpectedHostDuplicateMacAddress(_))
    ));

    Ok(())
}

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_update_bmc_credentials(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
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

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_delete(pool: sqlx::PgPool) -> () {
    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");
    let machine = get_expected_machine_1(&mut txn)
        .await
        .expect("Expected machine not found");

    assert_eq!(machine.data.serial_number, "VVG121GG");

    db::expected_machine::delete(machine.bmc_mac_address, &mut txn)
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

// Test API functionality
/*
  // Expected Machine Management
  // Replace all expected machines in site
  rpc ReplaceAllExpectedMachines(ExpectedMachineList) returns (google.protobuf.Empty);
*/
#[crate::sqlx_test()]
async fn test_add_expected_machine(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    for (idx, expected_machine) in [
        rpc::forge::ExpectedMachine {
            bmc_mac_address: "3A:3B:3C:3D:3E:3F".to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "VVG121GI".into(),
            metadata: None,
            sku_id: None,
            id: Some(::rpc::common::Uuid {
                value: Uuid::new_v4().to_string(),
            }),
            default_pause_ingestion_and_poweron: Some(true),
            dpf_enabled: false,
            ..Default::default()
        },
        rpc::forge::ExpectedMachine {
            bmc_mac_address: "3A:3B:3C:3D:3E:40".to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "VVG121GI".into(),
            metadata: Some(rpc::forge::Metadata::default()),
            sku_id: Some("sku_id".to_string()),
            id: Some(::rpc::common::Uuid {
                value: Uuid::new_v4().to_string(),
            }),
            default_pause_ingestion_and_poweron: Some(false),
            dpf_enabled: true,
            ..Default::default()
        },
        rpc::forge::ExpectedMachine {
            bmc_mac_address: "3A:3B:3C:3D:3E:41".to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "VVG121GI".into(),
            metadata: Some(rpc::forge::Metadata {
                name: "a".to_string(),
                description: "desc".to_string(),
                labels: vec![
                    rpc::forge::Label {
                        key: "k1".to_string(),
                        value: None,
                    },
                    rpc::forge::Label {
                        key: "k2".to_string(),
                        value: Some("v2".to_string()),
                    },
                ],
            }),
            id: Some(::rpc::common::Uuid {
                value: Uuid::new_v4().to_string(),
            }),
            sku_id: Some("sku_id".to_string()),
            default_pause_ingestion_and_poweron: None,
            ..Default::default()
        },
    ]
    .iter_mut()
    .enumerate()
    {
        env.api
            .add_expected_machine(tonic::Request::new(expected_machine.clone()))
            .await
            .expect("unable to add expected machine ");

        let expected_machine_query = rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: expected_machine.bmc_mac_address.clone(),
            id: None,
        };

        let mut retrieved_expected_machine = env
            .api
            .get_expected_machine(tonic::Request::new(expected_machine_query))
            .await
            .expect("unable to retrieve expected machine ")
            .into_inner();
        retrieved_expected_machine
            .metadata
            .as_mut()
            .unwrap()
            .labels
            .sort_by(|l1, l2| l1.key.cmp(&l2.key));
        if expected_machine.metadata.is_none() {
            expected_machine.metadata = Some(Default::default());
        }
        if expected_machine
            .default_pause_ingestion_and_poweron
            .is_none()
        {
            expected_machine.default_pause_ingestion_and_poweron = Some(false);
        }
        assert_eq!(retrieved_expected_machine, expected_machine.clone());

        if idx != 1 {
            assert!(!retrieved_expected_machine.dpf_enabled);
        } else {
            assert!(retrieved_expected_machine.dpf_enabled);
        }
    }
}

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_delete_expected_machine(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let expected_machine_count = env
        .api
        .get_all_expected_machines(tonic::Request::new(()))
        .await
        .expect("unable to get all expected machines")
        .into_inner()
        .expected_machines
        .len();

    let expected_machine_query = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "2A:2B:2C:2D:2E:2F".into(),
        id: None,
    };
    env.api
        .delete_expected_machine(tonic::Request::new(expected_machine_query))
        .await
        .expect("unable to delete expected machine ")
        .into_inner();

    let new_expected_machine_count = env
        .api
        .get_all_expected_machines(tonic::Request::new(()))
        .await
        .expect("unable to get all expected machines")
        .into_inner()
        .expected_machines
        .len();

    assert_eq!(new_expected_machine_count, expected_machine_count - 1);
}

#[crate::sqlx_test()]
async fn test_delete_expected_machine_error(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac_address: MacAddress = "2A:2B:2C:2D:2E:2F".parse().unwrap();
    let expected_machine_request = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: bmc_mac_address.to_string(),
        id: None,
    };

    let err = env
        .api
        .delete_expected_machine(tonic::Request::new(expected_machine_request))
        .await
        .unwrap_err();

    assert_eq!(
        err.message().to_string(),
        CarbideError::NotFoundError {
            kind: "expected_machine",
            id: bmc_mac_address.to_string(),
        }
        .to_string()
    );
}

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_update_expected_machine(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let bmc_mac_address: MacAddress = "2A:2B:2C:2D:2E:2F".parse().unwrap();
    for mut updated_machine in [
        rpc::forge::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: "ADMIN_UPDATE".into(),
            bmc_password: "PASS_UPDATE".into(),
            chassis_serial_number: "VVG121GI".into(),
            metadata: None,
            default_pause_ingestion_and_poweron: Some(true),
            ..Default::default()
        },
        rpc::forge::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: "ADMIN_UPDATE".into(),
            bmc_password: "PASS_UPDATE".into(),
            chassis_serial_number: "VVG121GJ".into(),
            metadata: Some(Default::default()),
            default_pause_ingestion_and_poweron: Some(false),
            ..Default::default()
        },
        rpc::forge::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: "ADMIN_UPDATE1".into(),
            bmc_password: "PASS_UPDATE1".into(),
            chassis_serial_number: "VVG121GN".into(),
            metadata: Some(rpc::forge::Metadata {
                name: "a".to_string(),
                description: "desc".to_string(),
                labels: vec![
                    rpc::forge::Label {
                        key: "k1".to_string(),
                        value: None,
                    },
                    rpc::forge::Label {
                        key: "k2".to_string(),
                        value: Some("v2".to_string()),
                    },
                ],
            }),
            default_pause_ingestion_and_poweron: None,
            ..Default::default()
        },
    ] {
        // ensure MAC-based update; id is ignored by update path
        updated_machine.id = None;
        env.api
            .update_expected_machine(tonic::Request::new(updated_machine.clone()))
            .await
            .expect("unable to update expected machine ")
            .into_inner();

        let mut retrieved_expected_machine = env
            .api
            .get_expected_machine(tonic::Request::new(ExpectedMachineRequest {
                bmc_mac_address: bmc_mac_address.to_string(),
                id: None,
            }))
            .await
            .expect("unable to fetch expected machine ")
            .into_inner();
        retrieved_expected_machine
            .metadata
            .as_mut()
            .unwrap()
            .labels
            .sort_by(|l1, l2| l1.key.cmp(&l2.key));
        // Ignore id field in comparison; MAC-based update path doesn't care about id
        retrieved_expected_machine.id = None;
        if updated_machine.metadata.is_none() {
            updated_machine.metadata = Some(Default::default());
        }

        if updated_machine
            .default_pause_ingestion_and_poweron
            .is_none()
        {
            updated_machine.default_pause_ingestion_and_poweron = Some(false);
        }

        assert_eq!(retrieved_expected_machine, updated_machine);
    }
}

#[crate::sqlx_test()]
async fn test_update_expected_machine_error(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac_address: MacAddress = "2A:2B:2C:2D:2E:2F".parse().unwrap();
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: bmc_mac_address.to_string(),
        bmc_username: "ADMIN_UPDATE".into(),
        bmc_password: "PASS_UPDATE".into(),
        chassis_serial_number: "VVG121GI".into(),
        ..Default::default()
    };

    let err = env
        .api
        .update_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await
        .unwrap_err();

    assert_eq!(
        err.message().to_string(),
        CarbideError::NotFoundError {
            kind: "expected_machine",
            id: bmc_mac_address.to_string(),
        }
        .to_string()
    );
}

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_delete_all_expected_machines(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mut expected_machine_count = env
        .api
        .get_all_expected_machines(tonic::Request::new(()))
        .await
        .expect("unable to get all expected machines")
        .into_inner()
        .expected_machines
        .len();

    assert_eq!(expected_machine_count, 6);

    env.api
        .delete_all_expected_machines(tonic::Request::new(()))
        .await
        .expect("unable to get all expected machines")
        .into_inner();

    expected_machine_count = env
        .api
        .get_all_expected_machines(tonic::Request::new(()))
        .await
        .expect("unable to get all expected machines")
        .into_inner()
        .expected_machines
        .len();

    assert_eq!(expected_machine_count, 0);
}

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_replace_all_expected_machines(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let expected_machine_count = env
        .api
        .get_all_expected_machines(tonic::Request::new(()))
        .await
        .expect("unable to get all expected machines")
        .into_inner()
        .expected_machines
        .len();

    assert_eq!(expected_machine_count, 6);

    let mut expected_machine_list = ExpectedMachineList {
        expected_machines: Vec::new(),
    };

    let expected_machine_1 = rpc::forge::ExpectedMachine {
        bmc_mac_address: "4A:4B:4C:4D:4E:4F".into(),
        bmc_username: "ADMIN_NEW".into(),
        bmc_password: "PASS_NEW".into(),
        chassis_serial_number: "SERIAL_NEW".into(),
        metadata: Some(rpc::Metadata::default()),
        default_pause_ingestion_and_poweron: Some(true),
        ..Default::default()
    };

    let expected_machine_2 = rpc::forge::ExpectedMachine {
        bmc_mac_address: "5A:5B:5C:5D:5E:5F".into(),
        bmc_username: "ADMIN_NEW".into(),
        bmc_password: "PASS_NEW".into(),
        chassis_serial_number: "SERIAL_NEW".into(),
        metadata: Some(rpc::Metadata::default()),
        default_pause_ingestion_and_poweron: Some(false),
        ..Default::default()
    };

    let expected_machine_3 = rpc::forge::ExpectedMachine {
        bmc_mac_address: "6A:6B:6C:6D:6E:6F".into(),
        bmc_username: "ADMIN_NEW".into(),
        bmc_password: "PASS_NEW".into(),
        chassis_serial_number: "SERIAL_NEW".into(),
        metadata: Some(rpc::Metadata::default()),
        default_pause_ingestion_and_poweron: None,
        ..Default::default()
    };

    expected_machine_list
        .expected_machines
        .push(expected_machine_1.clone());
    expected_machine_list
        .expected_machines
        .push(expected_machine_2.clone());
    expected_machine_list
        .expected_machines
        .push(expected_machine_3.clone());

    env.api
        .replace_all_expected_machines(tonic::Request::new(expected_machine_list))
        .await
        .expect("unable to get all expected machines")
        .into_inner();

    let mut expected_machines = env
        .api
        .get_all_expected_machines(tonic::Request::new(()))
        .await
        .expect("unable to get all expected machines")
        .into_inner()
        .expected_machines;
    expected_machines.sort_by_key(|e| e.bmc_mac_address.clone());

    assert_eq!(expected_machines.len(), 3);
    let mut resulting_machine_1 = expected_machines[0].clone();
    resulting_machine_1.id = None;
    let mut resulting_machine_2 = expected_machines[1].clone();
    resulting_machine_2.id = None;
    let mut resulting_machine_3 = expected_machines[2].clone();
    resulting_machine_3.id = None;

    // None will become Some(false), so we have to make the adjustment
    let mut expected_machine_3_clone = expected_machine_3.clone();
    expected_machine_3_clone.default_pause_ingestion_and_poweron = Some(false);

    assert_eq!(expected_machine_1, resulting_machine_1);
    assert_eq!(expected_machine_2, resulting_machine_2);
    assert_eq!(expected_machine_3_clone, resulting_machine_3);
}

#[crate::sqlx_test()]
async fn test_get_expected_machine_error(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac_address: MacAddress = "2A:2B:2C:2D:2E:2F".parse().unwrap();
    let expected_machine_query = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: bmc_mac_address.to_string(),
        id: None,
    };

    let err = env
        .api
        .get_expected_machine(tonic::Request::new(expected_machine_query))
        .await
        .unwrap_err();

    assert_eq!(
        err.message().to_string(),
        CarbideError::NotFoundError {
            kind: "expected_machine",
            id: bmc_mac_address.to_string(),
        }
        .to_string()
    );
}

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_get_linked_expected_machines_unseen(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let out = env
        .api
        .get_all_expected_machines_linked(tonic::Request::new(()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(out.expected_machines.len(), 6);
    // They are sorted by MAC server-side
    let em = out.expected_machines.first().unwrap();
    assert_eq!(em.chassis_serial_number, "VVG121GG");
    assert!(
        em.interface_id.is_none(),
        "expected_machines fixture should have no linked interface"
    );
    assert!(
        em.explored_endpoint_address.is_none(),
        "expected_machines fixture should have no linked explored endpoint"
    );
    assert!(
        em.machine_id.is_none(),
        "expected_machines fixture should have no machine"
    );
    assert!(
        em.expected_machine_id.is_some(),
        "expected_machine_id should be populated from the expected_machines table"
    );
}

#[crate::sqlx_test]
async fn test_get_linked_expected_machines_completed(pool: sqlx::PgPool) {
    // Prep the data

    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, _dpu_machine_id) =
        common::api_fixtures::create_managed_host(&env).await.into();
    let host_machine = env.find_machine(host_machine_id).await.remove(0);
    let bmc_ip = host_machine.bmc_info.as_ref().unwrap().ip();
    let bmc_mac = host_machine.bmc_info.as_ref().unwrap().mac();

    let mut txn = pool.begin().await.unwrap();
    db::explored_endpoints::insert(
        bmc_ip.parse().unwrap(),
        &EndpointExplorationReport::default(),
        false,
        &mut txn,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let provided_id = Uuid::new_v4();
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: bmc_mac.to_string(),
        bmc_username: "ADMIN".into(),
        bmc_password: "PASS".into(),
        chassis_serial_number: "GKTEST".into(),
        id: Some(::rpc::common::Uuid {
            value: provided_id.to_string(),
        }),
        ..Default::default()
    };
    env.api
        .add_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await
        .expect("unable to add expected machine");

    // The test

    let mut out = env
        .api
        .get_all_expected_machines_linked(tonic::Request::new(()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(out.expected_machines.len(), 1);

    let mut em = out.expected_machines.remove(0);
    assert_eq!(em.chassis_serial_number, "GKTEST");
    assert!(em.interface_id.is_some(), "interface not found");
    assert_eq!(
        em.explored_endpoint_address.take().unwrap(),
        bmc_ip,
        "BMC MAC should match"
    );
    assert_eq!(
        em.machine_id.take().unwrap().to_string(),
        host_machine_id.to_string(),
        "machine id should match via bmc_mac"
    );
    assert!(
        em.expected_machine_id.is_some(),
        "expected_machine_id should be populated"
    );
    assert_eq!(
        em.expected_machine_id.unwrap().value,
        provided_id.to_string(),
        "expected_machine_id should match the ID we provided"
    );
}

#[crate::sqlx_test()]
async fn test_add_expected_machine_dpu_serials(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac_address: MacAddress = "3A:3B:3C:3D:3E:3F".parse().unwrap();
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: bmc_mac_address.to_string(),
        bmc_username: "ADMIN".into(),
        bmc_password: "PASS".into(),
        chassis_serial_number: "VVG121GI".into(),
        fallback_dpu_serial_numbers: vec!["dpu_serial1".to_string()],
        metadata: Some(rpc::Metadata::default()),
        sku_id: None,
        id: None,
        default_pause_ingestion_and_poweron: Some(true),
        host_nics: vec![],
        rack_id: None,
        dpf_enabled: true,
    };

    env.api
        .add_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await
        .expect("unable to add expected machine ");

    let expected_machine_query = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: bmc_mac_address.to_string(),
        id: None,
    };

    let mut retrieved_expected_machine = env
        .api
        .get_expected_machine(tonic::Request::new(expected_machine_query))
        .await
        .expect("unable to retrieve expected machine ")
        .into_inner();
    // Zero id for equality test
    retrieved_expected_machine.id = None;
    assert_eq!(retrieved_expected_machine, expected_machine);
}

#[crate::sqlx_test()]
async fn test_add_and_update_expected_machine_with_invalid_metadata(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac_address: MacAddress = "3A:3B:3C:3D:3E:3F".parse().unwrap();
    // Start adding an expected-machine with invalid metadata
    for (invalid_metadata, expected_err) in common::metadata::invalid_metadata_testcases(false) {
        let expected_machine = rpc::forge::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "VVG121GI".into(),
            fallback_dpu_serial_numbers: vec![],
            metadata: Some(invalid_metadata.clone()),
            sku_id: None,
            id: None,
            default_pause_ingestion_and_poweron: None,
            host_nics: vec![],
            rack_id: None,
            dpf_enabled: true,
        };

        let err = env
            .api
            .add_expected_machine(tonic::Request::new(expected_machine.clone()))
            .await
            .expect_err(&format!(
                "Invalid metadata of type should not be accepted: {invalid_metadata:?}"
            ));
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().contains(&expected_err),
            "Testcase: {:?}\nMessage is \"{}\".\nMessage should contain: \"{}\"",
            invalid_metadata,
            err.message(),
            expected_err
        );
    }

    // Create one with valid metadata, and try to update it to invalid
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: bmc_mac_address.to_string(),
        bmc_username: "ADMIN".into(),
        bmc_password: "PASS".into(),
        chassis_serial_number: "VVG121GI".into(),
        fallback_dpu_serial_numbers: vec![],
        metadata: None,
        sku_id: None,
        id: None,
        default_pause_ingestion_and_poweron: None,
        host_nics: vec![],
        rack_id: None,
        dpf_enabled: true,
    };

    env.api
        .add_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await
        .expect("Expected addition to succeed");

    for (invalid_metadata, expected_err) in common::metadata::invalid_metadata_testcases(false) {
        let expected_machine = rpc::forge::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "VVG121GI".into(),
            fallback_dpu_serial_numbers: vec![],
            metadata: Some(invalid_metadata.clone()),
            sku_id: None,
            id: None,
            default_pause_ingestion_and_poweron: None,
            host_nics: vec![],
            rack_id: None,
            dpf_enabled: true,
        };

        let err = env
            .api
            .update_expected_machine(tonic::Request::new(expected_machine.clone()))
            .await
            .expect_err(&format!(
                "Invalid metadata of type should not be accepted: {invalid_metadata:?}"
            ));
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().contains(&expected_err),
            "Testcase: {:?}\nMessage is \"{}\".\nMessage should contain: \"{}\"",
            invalid_metadata,
            err.message(),
            expected_err
        );
    }
}

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_with_dpu_serial_numbers(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture_mac_address_0 = "0a:0b:0c:0d:0e:0f".parse().unwrap();
    let fixture_mac_address_3 = "3a:3b:3c:3d:3e:3f".parse().unwrap();
    let fixture_mac_address_4 = "4a:4b:4c:4d:4e:4f".parse().unwrap();

    let mut txn = pool
        .begin()
        .await
        .expect("unable to create transaction on database pool");

    let em0 = db::expected_machine::find_by_bmc_mac_address(&mut txn, fixture_mac_address_0)
        .await
        .unwrap()
        .expect("Expected machine not found");
    assert!(em0.data.fallback_dpu_serial_numbers.is_empty());

    let em3 = db::expected_machine::find_by_bmc_mac_address(&mut txn, fixture_mac_address_3)
        .await
        .unwrap()
        .expect("Expected machine not found");
    assert_eq!(em3.data.fallback_dpu_serial_numbers, vec!["dpu_serial1"]);

    let em4 = db::expected_machine::find_by_bmc_mac_address(&mut txn, fixture_mac_address_4)
        .await
        .unwrap()
        .expect("Expected machine not found");

    assert_eq!(
        em4.data.fallback_dpu_serial_numbers,
        vec!["dpu_serial2", "dpu_serial3"]
    );

    Ok(())
}

#[crate::sqlx_test()]
async fn test_add_expected_machine_duplicate_dpu_serials(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac_address: MacAddress = "3A:3B:3C:3D:3E:3F".parse().unwrap();
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: bmc_mac_address.to_string(),
        bmc_username: "ADMIN".into(),
        bmc_password: "PASS".into(),
        chassis_serial_number: "VVG121GI".into(),
        fallback_dpu_serial_numbers: vec!["dpu_serial1".to_string(), "dpu_serial1".to_string()],
        metadata: None,
        sku_id: None,
        id: None,
        default_pause_ingestion_and_poweron: None,
        host_nics: vec![],
        rack_id: None,
        dpf_enabled: true,
    };

    assert!(
        env.api
            .add_expected_machine(tonic::Request::new(expected_machine.clone()))
            .await
            .is_err()
    );
}

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_update_expected_machine_add_dpu_serial(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let mut ee1 = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: "2A:2B:2C:2D:2E:2F".into(),
            id: None,
        }))
        .await
        .expect("unable to get")
        .into_inner();

    ee1.fallback_dpu_serial_numbers = vec!["dpu_serial".to_string()];

    env.api
        .update_expected_machine(tonic::Request::new(ee1.clone()))
        .await
        .expect("unable to update")
        .into_inner();

    let ee2 = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: "2A:2B:2C:2D:2E:2F".into(),
            id: None,
        }))
        .await
        .expect("unable to get")
        .into_inner();

    assert_eq!(ee1, ee2);
}
#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_update_expected_machine_add_duplicate_dpu_serial(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let mut ee1 = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: "2A:2B:2C:2D:2E:2F".into(),
            id: None,
        }))
        .await
        .expect("unable to get")
        .into_inner();

    ee1.fallback_dpu_serial_numbers = vec![
        "dpu_serial1".to_string(),
        "dpu_serial2".to_string(),
        "dpu_serial1".to_string(),
    ];

    assert!(
        env.api
            .update_expected_machine(tonic::Request::new(ee1.clone()))
            .await
            .is_err()
    );
}

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_update_expected_machine_add_sku(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let mut ee1 = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: "2A:2B:2C:2D:2E:2F".into(),
            id: None,
        }))
        .await
        .expect("unable to get")
        .into_inner();

    ee1.sku_id = Some("sku_id".to_string());

    env.api
        .update_expected_machine(tonic::Request::new(ee1.clone()))
        .await
        .expect("unable to update")
        .into_inner();

    let ee2 = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: "2A:2B:2C:2D:2E:2F".into(),
            id: None,
        }))
        .await
        .expect("unable to get")
        .into_inner();

    assert_eq!(ee1, ee2);
}

#[crate::sqlx_test()]
async fn test_add_expected_machine_with_id_and_get_by_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let provided_id = Uuid::new_v4().to_string();
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: "AA:BB:CC:DD:EE:01".to_string(),
        bmc_username: "ADMIN".into(),
        bmc_password: "PASS".into(),
        chassis_serial_number: "SERIAL-ID".into(),
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: provided_id.clone(),
        }),
        ..Default::default()
    };

    env.api
        .add_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await
        .expect("unable to add expected machine with id");

    // Get by id
    let get_req = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: provided_id.clone(),
        }),
    };
    let retrieved = env
        .api
        .get_expected_machine(tonic::Request::new(get_req))
        .await
        .expect("unable to retrieve by id")
        .into_inner();

    assert_eq!(
        retrieved.id,
        Some(::rpc::common::Uuid { value: provided_id })
    );
    assert_eq!(retrieved.bmc_mac_address, "AA:BB:CC:DD:EE:01");
}

#[crate::sqlx_test()]
async fn test_update_expected_machine_by_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // Create with id
    let provided_id = Uuid::new_v4().to_string();
    let mut expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: "AA:BB:CC:DD:EE:02".to_string(),
        bmc_username: "ADMIN".into(),
        bmc_password: "PASS".into(),
        chassis_serial_number: "SERIAL-1".into(),
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: provided_id.clone(),
        }),
        ..Default::default()
    };

    env.api
        .add_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await
        .expect("add with id");

    // Update by id (change username)
    expected_machine.bmc_username = "ADMIN_UPDATED".into();
    env.api
        .update_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await
        .expect("update by id");

    // Fetch by id and verify
    let get_req = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: provided_id.clone(),
        }),
    };
    let retrieved = env
        .api
        .get_expected_machine(tonic::Request::new(get_req))
        .await
        .expect("get after update by id")
        .into_inner();

    assert_eq!(
        retrieved.id,
        Some(::rpc::common::Uuid { value: provided_id })
    );
    assert_eq!(retrieved.bmc_username, "ADMIN_UPDATED");
}

#[crate::sqlx_test()]
async fn test_delete_expected_machine_by_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // Create with id
    let provided_id = Uuid::new_v4().to_string();
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: "AA:BB:CC:DD:EE:03".to_string(),
        bmc_username: "ADMIN".into(),
        bmc_password: "PASS".into(),
        chassis_serial_number: "SERIAL-DEL".into(),
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: provided_id.clone(),
        }),
        ..Default::default()
    };

    env.api
        .add_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await
        .expect("add with id");

    // Delete by id
    let del_req = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: provided_id.clone(),
        }),
    };
    env.api
        .delete_expected_machine(tonic::Request::new(del_req))
        .await
        .expect("delete by id");

    // Verify NotFound by id
    let get_req = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: provided_id.clone(),
        }),
    };
    let err = env
        .api
        .get_expected_machine(tonic::Request::new(get_req))
        .await
        .unwrap_err();
    assert_eq!(
        err.message().to_string(),
        CarbideError::NotFoundError {
            kind: "expected_machine",
            id: provided_id
        }
        .to_string()
    );
}

#[crate::sqlx_test()]
async fn test_batch_create_expected_machines_all_or_nothing_success(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();

    let request = rpc::forge::BatchExpectedMachineOperationRequest {
        expected_machines: Some(rpc::forge::ExpectedMachineList {
            expected_machines: vec![
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id1.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:01".to_string(),
                    bmc_username: "admin1".to_string(),
                    bmc_password: "pass1".to_string(),
                    chassis_serial_number: "SERIAL-001".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id2.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:02".to_string(),
                    bmc_username: "admin2".to_string(),
                    bmc_password: "pass2".to_string(),
                    chassis_serial_number: "SERIAL-002".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
            ],
        }),
        accept_partial_results: false,
    };

    let response = env
        .api
        .create_expected_machines(tonic::Request::new(request))
        .await
        .expect("batch create should succeed");

    let results = response.into_inner().results;
    assert_eq!(results.len(), 2);
    assert!(results[0].success);
    assert!(results[1].success);

    // Verify both machines were created
    let get_req1 = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: id1.to_string(),
        }),
    };
    let machine1 = env
        .api
        .get_expected_machine(tonic::Request::new(get_req1))
        .await
        .expect("should find machine 1");
    assert_eq!(machine1.into_inner().bmc_username, "admin1");

    let get_req2 = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: id2.to_string(),
        }),
    };
    let machine2 = env
        .api
        .get_expected_machine(tonic::Request::new(get_req2))
        .await
        .expect("should find machine 2");
    assert_eq!(machine2.into_inner().bmc_username, "admin2");
}

#[crate::sqlx_test()]
async fn test_batch_create_expected_machines_all_or_nothing_failure(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();

    let request = rpc::forge::BatchExpectedMachineOperationRequest {
        expected_machines: Some(rpc::forge::ExpectedMachineList {
            expected_machines: vec![
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id1.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:03".to_string(),
                    bmc_username: "admin1".to_string(),
                    bmc_password: "pass1".to_string(),
                    chassis_serial_number: "SERIAL-003".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id2.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:03".to_string(), // Duplicate MAC
                    bmc_username: "admin2".to_string(),
                    bmc_password: "pass2".to_string(),
                    chassis_serial_number: "SERIAL-004".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
            ],
        }),
        accept_partial_results: false,
    };

    let result = env
        .api
        .create_expected_machines(tonic::Request::new(request))
        .await;

    // Should fail due to duplicate MAC
    assert!(result.is_err());

    // Verify neither machine was created (transaction rollback)
    let get_req1 = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: id1.to_string(),
        }),
    };
    let result1 = env
        .api
        .get_expected_machine(tonic::Request::new(get_req1))
        .await;
    assert!(result1.is_err());
}

#[crate::sqlx_test()]
async fn test_batch_create_expected_machines_partial_results(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();
    let id3 = Uuid::new_v4();

    let request = rpc::forge::BatchExpectedMachineOperationRequest {
        expected_machines: Some(rpc::forge::ExpectedMachineList {
            expected_machines: vec![
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id1.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:05".to_string(),
                    bmc_username: "admin1".to_string(),
                    bmc_password: "pass1".to_string(),
                    chassis_serial_number: "SERIAL-005".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id2.to_string(),
                    }),
                    bmc_mac_address: "INVALID-MAC".to_string(), // Invalid MAC
                    bmc_username: "admin2".to_string(),
                    bmc_password: "pass2".to_string(),
                    chassis_serial_number: "SERIAL-006".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id3.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:07".to_string(),
                    bmc_username: "admin3".to_string(),
                    bmc_password: "pass3".to_string(),
                    chassis_serial_number: "SERIAL-007".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
            ],
        }),
        accept_partial_results: true,
    };

    let response = env
        .api
        .create_expected_machines(tonic::Request::new(request))
        .await
        .expect("batch create should succeed with partial results");

    let results = response.into_inner().results;
    assert_eq!(results.len(), 3);
    assert!(results[0].success, "First machine should succeed");
    assert!(!results[1].success, "Second machine should fail");
    assert!(results[2].success, "Third machine should succeed");

    // Verify first machine was created
    let get_req1 = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: id1.to_string(),
        }),
    };
    let machine1 = env
        .api
        .get_expected_machine(tonic::Request::new(get_req1))
        .await
        .expect("should find machine 1");
    assert_eq!(machine1.into_inner().bmc_username, "admin1");

    // Verify second machine was NOT created
    let get_req2 = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: id2.to_string(),
        }),
    };
    let result2 = env
        .api
        .get_expected_machine(tonic::Request::new(get_req2))
        .await;
    assert!(result2.is_err());

    // Verify third machine was created
    let get_req3 = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: id3.to_string(),
        }),
    };
    let machine3 = env
        .api
        .get_expected_machine(tonic::Request::new(get_req3))
        .await
        .expect("should find machine 3");
    assert_eq!(machine3.into_inner().bmc_username, "admin3");
}

#[crate::sqlx_test()]
async fn test_batch_create_missing_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let request = rpc::forge::BatchExpectedMachineOperationRequest {
        expected_machines: Some(rpc::forge::ExpectedMachineList {
            expected_machines: vec![rpc::forge::ExpectedMachine {
                id: None, // Missing ID
                bmc_mac_address: "AA:BB:CC:DD:EE:08".to_string(),
                bmc_username: "admin".to_string(),
                bmc_password: "pass".to_string(),
                chassis_serial_number: "SERIAL-008".to_string(),
                metadata: Some(rpc::forge::Metadata::default()),
                ..Default::default()
            }],
        }),
        accept_partial_results: false,
    };

    let result = env
        .api
        .create_expected_machines(tonic::Request::new(request))
        .await;

    assert!(result.is_err(), "Should fail when id is missing");
}

#[crate::sqlx_test()]
async fn test_batch_update_expected_machines_all_or_nothing_success(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();

    // Create initial machines
    let create_req = rpc::forge::BatchExpectedMachineOperationRequest {
        expected_machines: Some(rpc::forge::ExpectedMachineList {
            expected_machines: vec![
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id1.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:10".to_string(),
                    bmc_username: "admin1".to_string(),
                    bmc_password: "pass1".to_string(),
                    chassis_serial_number: "SERIAL-010".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id2.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:11".to_string(),
                    bmc_username: "admin2".to_string(),
                    bmc_password: "pass2".to_string(),
                    chassis_serial_number: "SERIAL-011".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
            ],
        }),
        accept_partial_results: false,
    };

    env.api
        .create_expected_machines(tonic::Request::new(create_req))
        .await
        .expect("create should succeed");

    // Update both machines
    let update_req = rpc::forge::BatchExpectedMachineOperationRequest {
        expected_machines: Some(rpc::forge::ExpectedMachineList {
            expected_machines: vec![
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id1.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:10".to_string(),
                    bmc_username: "admin1_updated".to_string(),
                    bmc_password: "pass1_updated".to_string(),
                    chassis_serial_number: "SERIAL-010".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id2.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:11".to_string(),
                    bmc_username: "admin2_updated".to_string(),
                    bmc_password: "pass2_updated".to_string(),
                    chassis_serial_number: "SERIAL-011".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
            ],
        }),
        accept_partial_results: false,
    };

    let response = env
        .api
        .update_expected_machines(tonic::Request::new(update_req))
        .await
        .expect("batch update should succeed");

    let results = response.into_inner().results;
    assert_eq!(results.len(), 2);
    assert!(results[0].success);
    assert!(results[1].success);

    // Verify both machines were updated
    let get_req1 = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: id1.to_string(),
        }),
    };
    let machine1 = env
        .api
        .get_expected_machine(tonic::Request::new(get_req1))
        .await
        .expect("should find machine 1");
    assert_eq!(machine1.into_inner().bmc_username, "admin1_updated");

    let get_req2 = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: id2.to_string(),
        }),
    };
    let machine2 = env
        .api
        .get_expected_machine(tonic::Request::new(get_req2))
        .await
        .expect("should find machine 2");
    assert_eq!(machine2.into_inner().bmc_username, "admin2_updated");
}

#[crate::sqlx_test()]
async fn test_batch_update_expected_machines_all_or_nothing_failure(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();

    // Create initial machines
    let create_req = rpc::forge::BatchExpectedMachineOperationRequest {
        expected_machines: Some(rpc::forge::ExpectedMachineList {
            expected_machines: vec![rpc::forge::ExpectedMachine {
                id: Some(::rpc::common::Uuid {
                    value: id1.to_string(),
                }),
                bmc_mac_address: "AA:BB:CC:DD:EE:12".to_string(),
                bmc_username: "admin1".to_string(),
                bmc_password: "pass1".to_string(),
                chassis_serial_number: "SERIAL-012".to_string(),
                metadata: Some(rpc::forge::Metadata::default()),
                ..Default::default()
            }],
        }),
        accept_partial_results: false,
    };

    env.api
        .create_expected_machines(tonic::Request::new(create_req))
        .await
        .expect("create should succeed");

    // Try to update with one valid and one invalid (non-existent id)
    let update_req = rpc::forge::BatchExpectedMachineOperationRequest {
        expected_machines: Some(rpc::forge::ExpectedMachineList {
            expected_machines: vec![
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id1.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:12".to_string(),
                    bmc_username: "admin1_updated".to_string(),
                    bmc_password: "pass1_updated".to_string(),
                    chassis_serial_number: "SERIAL-012".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id2.to_string(), // Non-existent ID
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:13".to_string(),
                    bmc_username: "admin2".to_string(),
                    bmc_password: "pass2".to_string(),
                    chassis_serial_number: "SERIAL-013".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
            ],
        }),
        accept_partial_results: false,
    };

    let result = env
        .api
        .update_expected_machines(tonic::Request::new(update_req))
        .await;

    // Should fail
    assert!(result.is_err());

    // Verify first machine was NOT updated (transaction rollback)
    let get_req1 = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: id1.to_string(),
        }),
    };
    let machine1 = env
        .api
        .get_expected_machine(tonic::Request::new(get_req1))
        .await
        .expect("should find machine 1");
    assert_eq!(
        machine1.into_inner().bmc_username,
        "admin1",
        "Should still have original username due to rollback"
    );
}

#[crate::sqlx_test()]
async fn test_batch_update_expected_machines_partial_results(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();
    let id3 = Uuid::new_v4();

    // Create initial machines
    let create_req = rpc::forge::BatchExpectedMachineOperationRequest {
        expected_machines: Some(rpc::forge::ExpectedMachineList {
            expected_machines: vec![
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id1.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:14".to_string(),
                    bmc_username: "admin1".to_string(),
                    bmc_password: "pass1".to_string(),
                    chassis_serial_number: "SERIAL-014".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id3.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:16".to_string(),
                    bmc_username: "admin3".to_string(),
                    bmc_password: "pass3".to_string(),
                    chassis_serial_number: "SERIAL-016".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
            ],
        }),
        accept_partial_results: false,
    };

    env.api
        .create_expected_machines(tonic::Request::new(create_req))
        .await
        .expect("create should succeed");

    // Try to update with partial results
    let update_req = rpc::forge::BatchExpectedMachineOperationRequest {
        expected_machines: Some(rpc::forge::ExpectedMachineList {
            expected_machines: vec![
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id1.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:14".to_string(),
                    bmc_username: "admin1_updated".to_string(),
                    bmc_password: "pass1_updated".to_string(),
                    chassis_serial_number: "SERIAL-014".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id2.to_string(), // Non-existent ID
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:15".to_string(),
                    bmc_username: "admin2".to_string(),
                    bmc_password: "pass2".to_string(),
                    chassis_serial_number: "SERIAL-015".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
                rpc::forge::ExpectedMachine {
                    id: Some(::rpc::common::Uuid {
                        value: id3.to_string(),
                    }),
                    bmc_mac_address: "AA:BB:CC:DD:EE:16".to_string(),
                    bmc_username: "admin3_updated".to_string(),
                    bmc_password: "pass3_updated".to_string(),
                    chassis_serial_number: "SERIAL-016".to_string(),
                    metadata: Some(rpc::forge::Metadata::default()),
                    ..Default::default()
                },
            ],
        }),
        accept_partial_results: true,
    };

    let response = env
        .api
        .update_expected_machines(tonic::Request::new(update_req))
        .await
        .expect("batch update should succeed with partial results");

    let results = response.into_inner().results;
    assert_eq!(results.len(), 3);
    assert!(results[0].success, "First update should succeed");
    assert!(!results[1].success, "Second update should fail");
    assert!(results[2].success, "Third update should succeed");

    // Verify first machine was updated
    let get_req1 = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: id1.to_string(),
        }),
    };
    let machine1 = env
        .api
        .get_expected_machine(tonic::Request::new(get_req1))
        .await
        .expect("should find machine 1");
    assert_eq!(machine1.into_inner().bmc_username, "admin1_updated");

    // Verify second machine does not exist
    let get_req2 = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: id2.to_string(),
        }),
    };
    let result2 = env
        .api
        .get_expected_machine(tonic::Request::new(get_req2))
        .await;
    assert!(result2.is_err());

    // Verify third machine was updated
    let get_req3 = rpc::forge::ExpectedMachineRequest {
        bmc_mac_address: "".to_string(),
        id: Some(::rpc::common::Uuid {
            value: id3.to_string(),
        }),
    };
    let machine3 = env
        .api
        .get_expected_machine(tonic::Request::new(get_req3))
        .await
        .expect("should find machine 3");
    assert_eq!(machine3.into_inner().bmc_username, "admin3_updated");
}
