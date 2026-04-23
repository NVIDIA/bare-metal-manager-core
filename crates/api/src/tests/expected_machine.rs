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

use common::api_fixtures::{
    TestEnvOverrides, create_test_env, create_test_env_with_overrides, get_config,
};
use db::{self};
use mac_address::MacAddress;
use model::expected_machine::{ExpectedMachine, ExpectedMachineData};
use model::metadata::Metadata;
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
            is_dpf_enabled: Some(false),
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
            is_dpf_enabled: Some(true),
            #[allow(deprecated)]
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
            is_dpf_enabled: Some(false),
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
            assert!(
                !retrieved_expected_machine
                    .is_dpf_enabled
                    .unwrap_or_default()
            );
        } else {
            assert!(
                retrieved_expected_machine
                    .is_dpf_enabled
                    .unwrap_or_default()
            );
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
        is_dpf_enabled: Some(false),
        ..Default::default()
    };

    let expected_machine_2 = rpc::forge::ExpectedMachine {
        bmc_mac_address: "5A:5B:5C:5D:5E:5F".into(),
        bmc_username: "ADMIN_NEW".into(),
        bmc_password: "PASS_NEW".into(),
        chassis_serial_number: "SERIAL_NEW".into(),
        metadata: Some(rpc::Metadata::default()),
        default_pause_ingestion_and_poweron: Some(false),
        is_dpf_enabled: Some(false),
        ..Default::default()
    };

    let expected_machine_3 = rpc::forge::ExpectedMachine {
        bmc_mac_address: "6A:6B:6C:6D:6E:6F".into(),
        bmc_username: "ADMIN_NEW".into(),
        bmc_password: "PASS_NEW".into(),
        chassis_serial_number: "SERIAL_NEW".into(),
        metadata: Some(rpc::Metadata::default()),
        default_pause_ingestion_and_poweron: None,
        is_dpf_enabled: Some(false),
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
    let host_config = common::api_fixtures::managed_host::ManagedHostConfig::default();
    let bmc_mac = host_config.bmc_mac_address;

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

    let (host_machine_id, _dpu_machine_id) =
        common::api_fixtures::create_managed_host_with_config(&env, host_config)
            .await
            .into();
    let host_machine = env.find_machine(host_machine_id).await.remove(0);
    let bmc_ip = host_machine.bmc_info.as_ref().unwrap().ip();

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
        is_dpf_enabled: Some(true),
        bmc_ip_address: None,
        bmc_retain_credentials: None,
        dpu_mode: None,
        #[allow(deprecated)]
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
            is_dpf_enabled: Some(true),
            ..Default::default()
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
        is_dpf_enabled: Some(true),
        ..Default::default()
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
            is_dpf_enabled: Some(true),
            ..Default::default()
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
        is_dpf_enabled: Some(true),
        ..Default::default()
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

// test_patch_dpf_enabled_null_stays_null verifies that when dpf_enabled is NULL
// in the DB and an update is applied with is_dpf_enabled: None, the value remains NULL.
#[crate::sqlx_test()]
async fn test_patch_dpf_enabled_none_to_false(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac_address = "AA:BB:CC:DD:EE:F0";

    // Create machine with dpf_enabled = null (is_dpf_enabled: None)
    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "SN-DPF-NULL".into(),
            metadata: Some(rpc::forge::Metadata::default()),
            is_dpf_enabled: None,
            ..Default::default()
        }))
        .await
        .expect("unable to add expected machine");

    // Patch (update) with is_dpf_enabled: None — should keep dpf_enabled as NULL
    let mut updated = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: bmc_mac_address.to_string(),
            id: None,
        }))
        .await
        .expect("unable to fetch expected machine")
        .into_inner();

    // default should be updated as false
    assert_eq!(updated.is_dpf_enabled, Some(false),);

    updated.id = None;
    updated.bmc_username = "ADMIN_PATCHED".into();
    updated.is_dpf_enabled = None;

    env.api
        .update_expected_machine(tonic::Request::new(updated))
        .await
        .expect("unable to update expected machine");

    let retrieved = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: bmc_mac_address.to_string(),
            id: None,
        }))
        .await
        .expect("unable to fetch expected machine after update")
        .into_inner();

    assert_eq!(retrieved.is_dpf_enabled, Some(false),);
}

// test_patch_dpf_enabled_true_stays_true_when_patched_with_null verifies that when
// dpf_enabled is true in the DB and an update is applied with is_dpf_enabled: None,
// the value remains true (not overwritten to NULL).
#[crate::sqlx_test()]
async fn test_patch_dpf_enabled_true_stays_true_when_patched_with_null(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac_address = "AA:BB:CC:DD:EE:F1";

    // Create machine with dpf_enabled = true
    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "SN-DPF-TRUE".into(),
            metadata: Some(rpc::forge::Metadata::default()),
            is_dpf_enabled: Some(true),
            ..Default::default()
        }))
        .await
        .expect("unable to add expected machine");

    // Patch (update) with is_dpf_enabled: None — should preserve dpf_enabled = true
    let mut updated = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: bmc_mac_address.to_string(),
            id: None,
        }))
        .await
        .expect("unable to fetch expected machine")
        .into_inner();

    assert_eq!(updated.is_dpf_enabled, Some(true),);

    updated.id = None;
    updated.bmc_username = "ADMIN_PATCHED".into();
    updated.is_dpf_enabled = None;

    env.api
        .update_expected_machine(tonic::Request::new(updated))
        .await
        .expect("unable to update expected machine");

    let retrieved = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: bmc_mac_address.to_string(),
            id: None,
        }))
        .await
        .expect("unable to fetch expected machine after update")
        .into_inner();

    assert_eq!(retrieved.is_dpf_enabled, Some(true),);
}

// --- Optional `ExpectedMachine.bmc_ip_address`: persists configured BMC IP and exercises API
// pre-allocation (`preallocate_machine_interface` / `update_preallocated_machine_interface`). ---
#[crate::sqlx_test()]
async fn test_add_expected_machine_with_static_ip(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: "5A:5B:5C:5D:5E:60".to_string(),
        bmc_username: "root".into(),
        bmc_password: "testpass".into(),
        chassis_serial_number: "STATIC-IP-TEST".into(),
        bmc_ip_address: Some("10.0.0.100".to_string()),
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: uuid::Uuid::new_v4().to_string(),
        }),
        ..Default::default()
    };

    env.api
        .add_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await
        .expect("unable to add expected machine with static IP");

    let retrieved_machine = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: "5A:5B:5C:5D:5E:60".to_string(),
            id: None,
        }))
        .await
        .expect("unable to retrieve expected machine")
        .into_inner();

    assert_eq!(
        retrieved_machine.bmc_ip_address,
        Some("10.0.0.100".to_string())
    );
    assert_eq!(retrieved_machine.bmc_username, "root");
}

#[crate::sqlx_test()]
async fn test_update_expected_machine_add_static_ip(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // Create machine without static IP
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: "5A:5B:5C:5D:5E:62".to_string(),
        bmc_username: "root".into(),
        bmc_password: "testpass".into(),
        chassis_serial_number: "UPDATE-STATIC-IP".into(),
        bmc_ip_address: None,
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: uuid::Uuid::new_v4().to_string(),
        }),
        ..Default::default()
    };

    env.api
        .add_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await
        .expect("unable to add expected machine");

    // Update to add static IP
    let mut updated_machine = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: "5A:5B:5C:5D:5E:62".to_string(),
            id: None,
        }))
        .await
        .expect("unable to retrieve expected machine")
        .into_inner();

    updated_machine.id = None;
    updated_machine.bmc_ip_address = Some("192.168.1.50".to_string());

    env.api
        .update_expected_machine(tonic::Request::new(updated_machine.clone()))
        .await
        .expect("unable to update expected machine with static IP");

    let retrieved_machine = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: "5A:5B:5C:5D:5E:62".to_string(),
            id: None,
        }))
        .await
        .expect("unable to retrieve expected machine after update")
        .into_inner();

    assert_eq!(
        retrieved_machine.bmc_ip_address,
        Some("192.168.1.50".to_string())
    );
}

#[crate::sqlx_test()]
async fn test_update_expected_machine_change_static_ip(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // Create machine with static IP
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: "5A:5B:5C:5D:5E:63".to_string(),
        bmc_username: "root".into(),
        bmc_password: "testpass".into(),
        chassis_serial_number: "CHANGE-STATIC-IP".into(),
        bmc_ip_address: Some("10.0.0.200".to_string()),
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: uuid::Uuid::new_v4().to_string(),
        }),
        ..Default::default()
    };

    env.api
        .add_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await
        .expect("unable to add expected machine");

    // Update to change static IP
    let mut updated_machine = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: "5A:5B:5C:5D:5E:63".to_string(),
            id: None,
        }))
        .await
        .expect("unable to retrieve expected machine")
        .into_inner();

    updated_machine.id = None;
    updated_machine.bmc_ip_address = Some("10.0.0.201".to_string());

    env.api
        .update_expected_machine(tonic::Request::new(updated_machine.clone()))
        .await
        .expect("unable to update expected machine IP");

    let retrieved_machine = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: "5A:5B:5C:5D:5E:63".to_string(),
            id: None,
        }))
        .await
        .expect("unable to retrieve expected machine after IP change")
        .into_inner();

    assert_eq!(
        retrieved_machine.bmc_ip_address,
        Some("10.0.0.201".to_string())
    );
}

#[crate::sqlx_test()]
async fn test_add_expected_machine_with_invalid_static_ip(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: "5A:5B:5C:5D:5E:64".to_string(),
        bmc_username: "root".into(),
        bmc_password: "testpass".into(),
        chassis_serial_number: "INVALID-IP".into(),
        bmc_ip_address: Some("not-a-valid-ip".to_string()),
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: uuid::Uuid::new_v4().to_string(),
        }),
        ..Default::default()
    };

    let result = env
        .api
        .add_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await;

    assert!(
        result.is_err(),
        "Should fail when adding machine with invalid IP address"
    );
}

/// Adding an expected machine with host_nics[].fixed_ip should
/// pre-allocate a machine_interface with a static address.
#[crate::sqlx_test]
async fn test_add_with_host_nic_fixed_ip_creates_interface(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let bmc_mac: MacAddress = "7A:7B:7C:7D:7E:01".parse().unwrap();
    let nic_mac: MacAddress = "7A:7B:7C:7D:7E:02".parse().unwrap();
    let fixed_ip = "192.0.2.230";

    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            id: None,
            bmc_mac_address: bmc_mac.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "EM-FIXEDIP-001".into(),
            host_nics: vec![rpc::forge::ExpectedHostNic {
                mac_address: nic_mac.to_string(),
                nic_type: Some("onboard".into()),
                fixed_ip: Some(fixed_ip.into()),
                fixed_mask: None,
                fixed_gateway: None,
                primary: None,
            }],
            ..Default::default()
        }))
        .await?;

    // Verify a machine_interface was created for the host NIC MAC.
    let mut txn = env.pool.begin().await?;
    let interfaces = db::machine_interface::find_by_mac_address(&mut *txn, nic_mac).await?;
    assert_eq!(
        interfaces.len(),
        1,
        "should have one interface for the host NIC MAC"
    );
    assert!(
        interfaces[0].addresses.contains(&fixed_ip.parse().unwrap()),
        "interface should have the fixed IP"
    );

    let addrs =
        db::machine_interface_address::find_for_interface(&mut txn, interfaces[0].id).await?;
    assert_eq!(addrs.len(), 1);
    assert_eq!(
        addrs[0].allocation_type,
        model::allocation_type::AllocationType::Static
    );

    Ok(())
}

/// When a device DHCPs with a MAC that has a fixed_ip in the expected
/// machine's host_nics, it should get the fixed IP (not a pool allocation).
#[crate::sqlx_test]
async fn test_dhcp_discover_uses_fixed_ip_from_host_nics(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let bmc_mac: MacAddress = "7A:7B:7C:7D:7E:03".parse().unwrap();
    let nic_mac: MacAddress = "7A:7B:7C:7D:7E:04".parse().unwrap();
    let fixed_ip = "192.0.2.231";

    // Register expected machine with host NIC fixed_ip.
    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            id: None,
            bmc_mac_address: bmc_mac.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "EM-DHCP-001".into(),
            host_nics: vec![rpc::forge::ExpectedHostNic {
                mac_address: nic_mac.to_string(),
                nic_type: Some("onboard".into()),
                fixed_ip: Some(fixed_ip.into()),
                fixed_mask: None,
                fixed_gateway: None,
                primary: None,
            }],
            ..Default::default()
        }))
        .await?;

    // DHCP discover with the host NIC MAC -- should get the fixed IP.
    let nic_mac_str = nic_mac.to_string();
    let response = env
        .api
        .discover_dhcp(
            common::rpc_builder::DhcpDiscovery::builder(
                &nic_mac_str,
                common::api_fixtures::FIXTURE_DHCP_RELAY_ADDRESS,
            )
            .tonic_request(),
        )
        .await?
        .into_inner();

    assert_eq!(
        response.address, fixed_ip,
        "DHCP should return the fixed IP from host_nics"
    );

    Ok(())
}

/// When `bmc_retain_credentials` is set to true, the value should persist through
/// add -> get round-trip via the RPC API.
#[crate::sqlx_test()]
async fn test_add_expected_machine_with_bmc_retain_credentials(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let bmc_mac: MacAddress = "5A:5B:5C:5D:5E:70".parse().unwrap();

    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: bmc_mac.to_string(),
        bmc_username: "ADMIN".into(),
        bmc_password: "PASS".into(),
        chassis_serial_number: "RETAIN-CREDS-001".into(),
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: Uuid::new_v4().to_string(),
        }),
        bmc_retain_credentials: Some(true),
        ..Default::default()
    };

    env.api
        .add_expected_machine(tonic::Request::new(expected_machine.clone()))
        .await
        .expect("unable to add expected machine");

    let retrieved = env
        .api
        .get_expected_machine(tonic::Request::new(ExpectedMachineRequest {
            bmc_mac_address: bmc_mac.to_string(),
            id: None,
        }))
        .await
        .expect("unable to retrieve expected machine")
        .into_inner();

    assert_eq!(
        retrieved.bmc_retain_credentials,
        Some(true),
        "bmc_retain_credentials should be true after round-trip"
    );
}

/// Verify that updating an expected machine without specifying `bmc_retain_credentials`
/// preserves the existing value (and making sure COALESCE works).
#[crate::sqlx_test()]
async fn test_update_preserves_bmc_retain_credentials(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let bmc_mac: MacAddress = "5A:5B:5C:5D:5E:71".parse().unwrap();

    // Create with bmc_retain_credentials = true.
    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            bmc_mac_address: bmc_mac.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "RETAIN-UPDATE-001".into(),
            metadata: Some(rpc::forge::Metadata::default()),
            id: Some(::rpc::common::Uuid {
                value: Uuid::new_v4().to_string(),
            }),
            bmc_retain_credentials: Some(true),
            ..Default::default()
        }))
        .await?;

    // Update without setting bmc_retain_credentials (None).
    env.api
        .update_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            bmc_mac_address: bmc_mac.to_string(),
            bmc_username: "NEW-ADMIN".into(),
            bmc_password: "NEW-PASS".into(),
            chassis_serial_number: "RETAIN-UPDATE-001".into(),
            metadata: Some(rpc::forge::Metadata::default()),
            bmc_retain_credentials: None,
            ..Default::default()
        }))
        .await?;

    let retrieved = env
        .api
        .get_expected_machine(tonic::Request::new(ExpectedMachineRequest {
            bmc_mac_address: bmc_mac.to_string(),
            id: None,
        }))
        .await?
        .into_inner();

    assert_eq!(
        retrieved.bmc_retain_credentials,
        Some(true),
        "bmc_retain_credentials should be preserved after update with None"
    );

    Ok(())
}

/// When an ExpectedMachine's host_nics entry is flagged `primary: true`,
/// the matching NIC's DHCP should land as `machine_interfaces.primary_interface=true`.
#[crate::sqlx_test]
async fn test_dhcp_honors_primary_host_nic(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // rack_management_enabled is required for discover_dhcp to consult
    // ExpectedMachine records for unknown MACs -- that's the path that
    // reads the matched host_nic's `primary` flag.
    let env = {
        let mut config = get_config();
        config.rack_management_enabled = true;
        create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await
    };
    let bmc_mac: MacAddress = "9A:9B:9C:9D:9E:01".parse().unwrap();
    let primary_mac: MacAddress = "9A:9B:9C:9D:9E:02".parse().unwrap();

    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            id: None,
            bmc_mac_address: bmc_mac.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "EM-PRIMARY-001".into(),
            host_nics: vec![rpc::forge::ExpectedHostNic {
                mac_address: primary_mac.to_string(),
                nic_type: Some("onboard".into()),
                fixed_ip: None,
                fixed_mask: None,
                fixed_gateway: None,
                primary: Some(true),
            }],
            ..Default::default()
        }))
        .await?;

    // DHCP discover with the declared primary MAC.
    let primary_mac_str = primary_mac.to_string();
    env.api
        .discover_dhcp(
            common::rpc_builder::DhcpDiscovery::builder(
                &primary_mac_str,
                common::api_fixtures::FIXTURE_DHCP_RELAY_ADDRESS,
            )
            .tonic_request(),
        )
        .await?;

    // Verify the created machine_interface is flagged primary=true.
    let mut txn = env.pool.begin().await?;
    let ifaces = db::machine_interface::find_by_mac_address(&mut *txn, primary_mac).await?;
    assert_eq!(ifaces.len(), 1);
    assert!(
        ifaces[0].primary_interface,
        "host_nic primary=true should flow to machine_interfaces.primary_interface"
    );

    Ok(())
}

/// When one host_nics entry is flagged `primary: true`, a DHCP from a
/// *different* MAC on the same host should land as `primary_interface: false`.
/// Verifies the "operator declared some other NIC primary, so this one
/// must not inherit the default primary=true" branch, protecting the DB's
/// one_primary_interface_per_machine unique constraint once the primary
/// MAC's interface eventually lands.
#[crate::sqlx_test]
async fn test_dhcp_marks_non_primary_mac_as_non_primary(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = {
        let mut config = get_config();
        config.rack_management_enabled = true;
        create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await
    };
    let bmc_mac: MacAddress = "9A:9B:9C:9D:9E:10".parse().unwrap();
    let primary_mac: MacAddress = "9A:9B:9C:9D:9E:11".parse().unwrap();
    let other_mac: MacAddress = "9A:9B:9C:9D:9E:12".parse().unwrap();

    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            id: None,
            bmc_mac_address: bmc_mac.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "EM-PRIMARY-002".into(),
            host_nics: vec![
                rpc::forge::ExpectedHostNic {
                    mac_address: primary_mac.to_string(),
                    nic_type: Some("onboard".into()),
                    fixed_ip: None,
                    fixed_mask: None,
                    fixed_gateway: None,
                    primary: Some(true),
                },
                rpc::forge::ExpectedHostNic {
                    mac_address: other_mac.to_string(),
                    nic_type: Some("onboard".into()),
                    fixed_ip: None,
                    fixed_mask: None,
                    fixed_gateway: None,
                    primary: None,
                },
            ],
            ..Default::default()
        }))
        .await?;

    // DHCP for the non-primary MAC on this machine.
    let other_mac_str = other_mac.to_string();
    env.api
        .discover_dhcp(
            common::rpc_builder::DhcpDiscovery::builder(
                &other_mac_str,
                common::api_fixtures::FIXTURE_DHCP_RELAY_ADDRESS,
            )
            .tonic_request(),
        )
        .await?;

    let mut txn = env.pool.begin().await?;
    let ifaces = db::machine_interface::find_by_mac_address(&mut *txn, other_mac).await?;
    assert_eq!(ifaces.len(), 1);
    assert!(
        !ifaces[0].primary_interface,
        "a MAC that isn't the declared primary should not land as primary_interface=true"
    );

    Ok(())
}

/// An ExpectedMachine with two host_nics entries both flagged `primary: true`
/// must be rejected at the API boundary -- the handler enforces at most one
/// primary NIC per machine (anchoring the DB's `one_primary_interface_per_machine`
/// unique constraint to a single declaration).
#[crate::sqlx_test]
async fn test_add_rejects_multiple_primary_host_nics(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let bmc_mac: MacAddress = "9A:9B:9C:9D:9E:20".parse().unwrap();
    let mac_a: MacAddress = "9A:9B:9C:9D:9E:21".parse().unwrap();
    let mac_b: MacAddress = "9A:9B:9C:9D:9E:22".parse().unwrap();

    let result = env
        .api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            id: None,
            bmc_mac_address: bmc_mac.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "EM-DUPLICATE-PRIMARY-001".into(),
            host_nics: vec![
                rpc::forge::ExpectedHostNic {
                    mac_address: mac_a.to_string(),
                    nic_type: Some("onboard".into()),
                    fixed_ip: None,
                    fixed_mask: None,
                    fixed_gateway: None,
                    primary: Some(true),
                },
                rpc::forge::ExpectedHostNic {
                    mac_address: mac_b.to_string(),
                    nic_type: Some("onboard".into()),
                    fixed_ip: None,
                    fixed_mask: None,
                    fixed_gateway: None,
                    primary: Some(true),
                },
            ],
            ..Default::default()
        }))
        .await;

    let err = result.expect_err("multi-primary ExpectedMachine should be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    Ok(())
}

/// Simple test to have some round-trip coverage for `ExpectedMachine.dpu_mode`
/// to make sure a `NicMode` setting makes it from the API to the DB and back
/// correctly. Verifies:
/// - The RPC carrying `Some(DpuMode::NicMode)` persists.
/// - The re-read RPC response replies `dpu_mode = Some(NicMode)` back
/// - Other `dpu_mode` values do the same.
#[crate::sqlx_test]
async fn test_dpu_mode_round_trip_for_non_default_values(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    for (idx, mode) in [rpc::forge::DpuMode::NicMode, rpc::forge::DpuMode::NoDpu]
        .iter()
        .enumerate()
    {
        let mac = format!("5A:5B:5C:5D:5E:{idx:02X}");
        let request = rpc::forge::ExpectedMachine {
            bmc_mac_address: mac.clone(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: format!("EM-DPU-MODE-{idx}"),
            dpu_mode: Some(*mode as i32),
            ..Default::default()
        };

        env.api
            .add_expected_machine(tonic::Request::new(request))
            .await?;

        let retrieved = env
            .api
            .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
                bmc_mac_address: mac.clone(),
                id: None,
            }))
            .await?
            .into_inner();

        assert_eq!(
            retrieved.dpu_mode,
            Some(*mode as i32),
            "DPU mode {mode:?} should survive DB round-trip unchanged"
        );
    }

    Ok(())
}

/// Also have some "round trip" coverage for the dpu_mode default case,
/// when the operator didn't set `dpu_mode` on the wire. In this case,
/// we should persist the Postgrs default (`DpuMode::DpuMode`) and return
/// `None` on the wire (so old clients see the same thing they sent).
#[crate::sqlx_test]
async fn test_dpu_mode_default_value_omitted_on_wire(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mac = "5A:5B:5C:5D:5E:FF";
    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            bmc_mac_address: mac.into(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "EM-DPU-DEFAULT".into(),
            dpu_mode: None,
            ..Default::default()
        }))
        .await?;

    let retrieved = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: mac.into(),
            id: None,
        }))
        .await?
        .into_inner();

    assert_eq!(
        retrieved.dpu_mode, None,
        "default DpuMode should not be emitted on the wire for stable round-trips"
    );

    Ok(())
}
