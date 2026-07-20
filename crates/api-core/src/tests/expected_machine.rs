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
use rpc::forge::forge_server::Forge;
use rpc::forge::{ExpectedMachineList, ExpectedMachineRequest};
use uuid::Uuid;

use crate::CarbideError;
use crate::test_support::fixture_config::FixtureDefault as _;
use crate::tests::common;

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

#[crate::sqlx_test]
async fn test_delete_expected_machine(pool: sqlx::PgPool) {
    create_fixture_expected_machines(&pool).await;
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

#[crate::sqlx_test]
async fn test_update_expected_machine(pool: sqlx::PgPool) {
    create_fixture_expected_machines(&pool).await;
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
            is_dpf_enabled: Some(false),
            ..Default::default()
        },
        rpc::forge::ExpectedMachine {
            bmc_mac_address: bmc_mac_address.to_string(),
            bmc_username: "ADMIN_UPDATE".into(),
            bmc_password: "PASS_UPDATE".into(),
            chassis_serial_number: "VVG121GJ".into(),
            metadata: Some(Default::default()),
            default_pause_ingestion_and_poweron: Some(false),
            is_dpf_enabled: Some(false),
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
            is_dpf_enabled: Some(false),
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

#[crate::sqlx_test]
async fn test_delete_all_expected_machines(pool: sqlx::PgPool) {
    create_fixture_expected_machines(&pool).await;
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

#[crate::sqlx_test]
async fn test_replace_all_expected_machines(pool: sqlx::PgPool) {
    create_fixture_expected_machines(&pool).await;
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

#[crate::sqlx_test]
async fn test_get_linked_expected_machines_unseen(pool: sqlx::PgPool) {
    create_fixture_expected_machines(&pool).await;
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
    let host_config = model::test_support::ManagedHostConfig::default();
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
        bmc_ip_allocation: None,
        host_lifecycle_profile: None,
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

#[crate::sqlx_test]
async fn test_update_expected_machine_add_dpu_serial(pool: sqlx::PgPool) {
    create_fixture_expected_machines(&pool).await;

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
#[crate::sqlx_test]
async fn test_update_expected_machine_add_duplicate_dpu_serial(pool: sqlx::PgPool) {
    create_fixture_expected_machines(&pool).await;
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

#[crate::sqlx_test]
async fn test_update_expected_machine_add_sku(pool: sqlx::PgPool) {
    create_fixture_expected_machines(&pool).await;
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

// test_patch_dpf_enabled_none_to_true verifies that when an expected machine is
// added with is_dpf_enabled: None, the value defaults to true on insert, and a
// subsequent update with is_dpf_enabled: None preserves that value.
#[crate::sqlx_test()]
async fn test_patch_dpf_enabled_none_to_true(pool: sqlx::PgPool) {
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

    // default should be true
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

#[test]
fn test_expected_machine_data_accepts_ipv6_host_nic_fixed_ip() {
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: "5A:5B:5C:5D:5E:65".to_string(),
        bmc_username: "root".into(),
        bmc_password: "testpass".into(),
        chassis_serial_number: "IPV6-HOST-NIC-FIXED-IP".into(),
        host_nics: vec![rpc::forge::ExpectedHostNic {
            mac_address: "5A:5B:5C:5D:5E:66".to_string(),
            fixed_ip: Some("2001:db8::66".to_string()),
            ..Default::default()
        }],
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: uuid::Uuid::new_v4().to_string(),
        }),
        ..Default::default()
    };

    let data = ExpectedMachineData::try_from(expected_machine).unwrap();

    assert_eq!(
        data.host_nics[0].fixed_ip,
        Some("2001:db8::66".parse().unwrap())
    );
}

#[test]
fn test_expected_machine_data_rejects_invalid_host_nic_fixed_ip() {
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: "5A:5B:5C:5D:5E:65".to_string(),
        bmc_username: "root".into(),
        bmc_password: "testpass".into(),
        chassis_serial_number: "INVALID-HOST-NIC-FIXED-IP".into(),
        host_nics: vec![rpc::forge::ExpectedHostNic {
            mac_address: "5A:5B:5C:5D:5E:66".to_string(),
            fixed_ip: Some("not-a-valid-ip".to_string()),
            ..Default::default()
        }],
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: uuid::Uuid::new_v4().to_string(),
        }),
        ..Default::default()
    };

    let err = match ExpectedMachineData::try_from(expected_machine) {
        Ok(_) => panic!("invalid host NIC fixed IP should fail conversion"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("Invalid fixed IP"));
}

#[test]
fn test_expected_machine_data_accepts_ipv6_host_nic_fixed_gateway() {
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: "5A:5B:5C:5D:5E:65".to_string(),
        bmc_username: "root".into(),
        bmc_password: "testpass".into(),
        chassis_serial_number: "IPV6-HOST-NIC-FIXED-GATEWAY".into(),
        host_nics: vec![rpc::forge::ExpectedHostNic {
            mac_address: "5A:5B:5C:5D:5E:66".to_string(),
            fixed_gateway: Some("2001:db8::1".to_string()),
            ..Default::default()
        }],
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: uuid::Uuid::new_v4().to_string(),
        }),
        ..Default::default()
    };

    let data = ExpectedMachineData::try_from(expected_machine).unwrap();

    assert_eq!(
        data.host_nics[0].fixed_gateway,
        Some("2001:db8::1".parse().unwrap())
    );
}

#[test]
fn test_expected_machine_data_rejects_invalid_host_nic_fixed_gateway() {
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: "5A:5B:5C:5D:5E:65".to_string(),
        bmc_username: "root".into(),
        bmc_password: "testpass".into(),
        chassis_serial_number: "INVALID-HOST-NIC-FIXED-GATEWAY".into(),
        host_nics: vec![rpc::forge::ExpectedHostNic {
            mac_address: "5A:5B:5C:5D:5E:66".to_string(),
            fixed_gateway: Some("not-a-valid-ip".to_string()),
            ..Default::default()
        }],
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: uuid::Uuid::new_v4().to_string(),
        }),
        ..Default::default()
    };

    let err = match ExpectedMachineData::try_from(expected_machine) {
        Ok(_) => panic!("invalid host NIC fixed gateway should fail conversion"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("Invalid fixed gateway"));
}

#[test]
fn test_expected_machine_data_rejects_invalid_host_nic_mac_address() {
    let expected_machine = rpc::forge::ExpectedMachine {
        bmc_mac_address: "5A:5B:5C:5D:5E:65".to_string(),
        bmc_username: "root".into(),
        bmc_password: "testpass".into(),
        chassis_serial_number: "INVALID-HOST-NIC-MAC".into(),
        host_nics: vec![rpc::forge::ExpectedHostNic {
            mac_address: "not-a-mac".to_string(),
            fixed_ip: Some("192.0.2.66".to_string()),
            ..Default::default()
        }],
        metadata: Some(rpc::forge::Metadata::default()),
        id: Some(::rpc::common::Uuid {
            value: uuid::Uuid::new_v4().to_string(),
        }),
        ..Default::default()
    };

    let err = match ExpectedMachineData::try_from(expected_machine) {
        Ok(_) => panic!("invalid host NIC MAC should fail conversion"),
        Err(err) => err,
    };

    assert!(
        matches!(
            &err,
            ::rpc::errors::RpcDataConversionError::InvalidMacAddress(mac)
                if mac == "not-a-mac"
        ),
        "got: {err}"
    );
}

/// Adding an expected machine with `host_nics[].fixed_ip` should result in a static
/// `machine_interface` for that NIC. The materialization is deferred: site-explorer's
/// reconciliation pass (or the DHCP discover hook) is what creates the row. The test
/// triggers that reconciliation after add to verify the end-to-end flow.
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
                network_segment_type: None,
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

    // Add doesn't preallocate inline; mimic what site-explorer does on the next iteration --
    // materialize the host NIC's static fixed_ip.
    carbide_site_explorer::try_preallocate_one(
        &env.pool,
        nic_mac,
        fixed_ip.parse().unwrap(),
        model::machine_interface::InterfaceType::Data,
        "expected_machine host NIC",
        None,
    )
    .await;

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
                network_segment_type: None,
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

/// First DHCPDISCOVER for an `expected_machines` BMC: discover() consults
/// `find_by_bmc_mac_address`, preallocates from `bmc_ip_address`, and the existing
/// find_or_create path serves that static IP. Add-time doesn't preallocate; row materialization
/// is deferred until this hook fires (for in-network MACs that DHCPDISCOVER) or until
/// site-explorer's reconciliation pass runs (for everything, including external
/// static-assignments IPs).
#[crate::sqlx_test]
async fn test_dhcp_discover_preallocates_bmc_ip_for_unknown_mac(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let bmc_mac: MacAddress = "7A:7B:7C:7D:7E:41".parse().unwrap();
    let bmc_ip = "192.0.2.245";

    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            id: None,
            bmc_mac_address: bmc_mac.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "EM-RECOVERY-001".into(),
            bmc_ip_address: Some(bmc_ip.into()),
            ..Default::default()
        }))
        .await?;

    // Add no longer preallocates -- the row should be absent until DHCPDISCOVER fires.
    let mut txn = env.db_txn().await;
    let before = db::machine_interface::find_by_mac_address(txn.as_mut(), bmc_mac).await?;
    assert!(
        before.is_empty(),
        "add does not preallocate inline; the interface should only appear after discover()"
    );
    txn.commit().await?;

    let bmc_mac_str = bmc_mac.to_string();
    let response = env
        .api
        .discover_dhcp(
            common::rpc_builder::DhcpDiscovery::builder(
                &bmc_mac_str,
                common::api_fixtures::FIXTURE_DHCP_RELAY_ADDRESS,
            )
            .tonic_request(),
        )
        .await?
        .into_inner();

    assert_eq!(
        response.address, bmc_ip,
        "BMC DHCP should serve the configured bmc_ip_address, not a dynamic-pool allocation"
    );

    let mut txn = env.db_txn().await;
    let after = db::machine_interface::find_by_mac_address(txn.as_mut(), bmc_mac).await?;
    assert_eq!(after.len(), 1, "interface should be created by discover()");
    assert!(
        after[0].addresses.contains(&bmc_ip.parse().unwrap()),
        "preallocated interface should carry the configured static IP"
    );
    assert_eq!(
        after[0].interface_type,
        model::machine_interface::InterfaceType::Bmc,
        "BMC discover hook should mark the interface as InterfaceType::Bmc, not Data"
    );

    Ok(())
}

/// First DHCPDISCOVER for an `ExpectedHostNic.fixed_ip`. discover() passes the matched NIC
/// through to `validate_existing_mac_and_create`, which honors `fixed_ip` via
/// `AddressSelectionStrategy::StaticAddress`. Pins the deferred preallocation path for host NICs.
#[crate::sqlx_test]
async fn test_dhcp_discover_preallocates_host_nic_fixed_ip_for_unknown_mac(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let bmc_mac: MacAddress = "7A:7B:7C:7D:7E:51".parse().unwrap();
    let nic_mac: MacAddress = "7A:7B:7C:7D:7E:52".parse().unwrap();
    let fixed_ip = "192.0.2.246";

    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            id: None,
            bmc_mac_address: bmc_mac.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "EM-RECOVERY-002".into(),
            host_nics: vec![rpc::forge::ExpectedHostNic {
                network_segment_type: None,
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

    let mut txn = env.db_txn().await;
    let before = db::machine_interface::find_by_mac_address(txn.as_mut(), nic_mac).await?;
    assert!(
        before.is_empty(),
        "add does not preallocate inline; the interface should only appear after discover()"
    );
    txn.commit().await?;

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
        "host NIC re-DHCP should serve the configured fixed_ip"
    );

    let mut txn = env.db_txn().await;
    let after = db::machine_interface::find_by_mac_address(txn.as_mut(), nic_mac).await?;
    assert_eq!(after.len(), 1, "interface should be created by discover()");
    assert_eq!(
        after[0].interface_type,
        model::machine_interface::InterfaceType::Data,
        "host NIC discover hook should mark the interface as InterfaceType::Data, not Bmc"
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
                network_segment_type: None,
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
                    network_segment_type: None,
                    mac_address: primary_mac.to_string(),
                    nic_type: Some("onboard".into()),
                    fixed_ip: None,
                    fixed_mask: None,
                    fixed_gateway: None,
                    primary: Some(true),
                },
                rpc::forge::ExpectedHostNic {
                    network_segment_type: None,
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
                    network_segment_type: None,
                    mac_address: mac_a.to_string(),
                    nic_type: Some("onboard".into()),
                    fixed_ip: None,
                    fixed_mask: None,
                    fixed_gateway: None,
                    primary: Some(true),
                },
                rpc::forge::ExpectedHostNic {
                    network_segment_type: None,
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

/// The declared primary survives whichever order its NICs DHCP in: leasing the
/// non-primary NIC first, then the declared primary, still lands the declared
/// primary as `primary_interface` and the other as non-primary.
#[crate::sqlx_test]
async fn test_declared_primary_survives_dhcp_arrival_order(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = {
        let mut config = get_config();
        config.rack_management_enabled = true;
        create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await
    };
    let bmc_mac: MacAddress = "9A:9B:9C:9D:9F:10".parse().unwrap();
    let primary_mac: MacAddress = "9A:9B:9C:9D:9F:11".parse().unwrap();
    let other_mac: MacAddress = "9A:9B:9C:9D:9F:12".parse().unwrap();

    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            id: None,
            bmc_mac_address: bmc_mac.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "EM-PRIMARY-003".into(),
            host_nics: vec![
                rpc::forge::ExpectedHostNic {
                    network_segment_type: None,
                    mac_address: primary_mac.to_string(),
                    nic_type: Some("onboard".into()),
                    fixed_ip: None,
                    fixed_mask: None,
                    fixed_gateway: None,
                    primary: Some(true),
                },
                rpc::forge::ExpectedHostNic {
                    network_segment_type: None,
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

    // The non-primary NIC leases first, then the declared primary.
    for mac in [other_mac, primary_mac] {
        let mac_str = mac.to_string();
        env.api
            .discover_dhcp(
                common::rpc_builder::DhcpDiscovery::builder(
                    &mac_str,
                    common::api_fixtures::FIXTURE_DHCP_RELAY_ADDRESS,
                )
                .tonic_request(),
            )
            .await?;
    }

    let mut txn = env.pool.begin().await?;
    let primary = db::machine_interface::find_by_mac_address(&mut *txn, primary_mac).await?;
    let other = db::machine_interface::find_by_mac_address(&mut *txn, other_mac).await?;
    assert_eq!(primary.len(), 1);
    assert_eq!(other.len(), 1);
    assert!(
        primary[0].primary_interface,
        "the declared primary NIC should be primary even when it leases last"
    );
    assert!(
        !other[0].primary_interface,
        "the non-declared NIC should not be primary"
    );

    Ok(())
}

/// The stable Forge DPU policy field round-trips through the database.
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
            "DPU policy mode {mode:?} should survive DB round-trip unchanged"
        );
    }

    Ok(())
}

/// The default host DPU policy is omitted on the wire, preserving existing
/// clients' absent-field behavior.
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
        "default HostDpuPolicy should not be emitted on the Forge compatibility field"
    );

    Ok(())
}

/// Verify the update RPC (for update/patch flows) changes the DPU policy.
#[crate::sqlx_test]
async fn test_update_changes_dpu_mode(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mac = "5A:5B:5C:5D:5E:80";
    let base = rpc::forge::ExpectedMachine {
        bmc_mac_address: mac.into(),
        bmc_username: "ADMIN".into(),
        bmc_password: "PASS".into(),
        chassis_serial_number: "EM-DPU-UPDATE".into(),
        metadata: Some(rpc::forge::Metadata::default()),
        ..Default::default()
    };

    env.api
        .add_expected_machine(tonic::Request::new(base.clone()))
        .await?;

    for mode in [
        rpc::forge::DpuMode::NicMode,
        rpc::forge::DpuMode::NoDpu,
        rpc::forge::DpuMode::DpuMode,
    ] {
        env.api
            .update_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
                dpu_mode: Some(mode as i32),
                ..base.clone()
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

        // Manage is the column default and the wire-default; the model
        // collapses it to `None` on the way out (see `From<ExpectedMachine>
        // for rpc::forge::ExpectedMachine`), so compare accordingly.
        let expected_wire = match mode {
            rpc::forge::DpuMode::DpuMode | rpc::forge::DpuMode::Unspecified => None,
            other => Some(other as i32),
        };
        assert_eq!(
            retrieved.dpu_mode, expected_wire,
            "update to {mode:?} should persist and round-trip on the wire"
        );
    }

    Ok(())
}

/// `ExpectedMachine.bmc_ip_allocation` round-trips through the API: a non-default
/// value (`Dynamic`, `Retained`) set on the wire persists to the DB and reads back
/// unchanged (the default/unset case is covered separately below). `Dynamic`/`Retained`
/// are used here because they're valid with no `bmc_ip_address` (which these requests
/// omit); `Fixed` requires an address and is exercised by the validation tests.
#[crate::sqlx_test]
async fn test_bmc_ip_allocation_round_trip_for_non_default_values(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    for (idx, mode) in [
        rpc::forge::BmcIpAllocationType::Dynamic,
        rpc::forge::BmcIpAllocationType::Retained,
    ]
    .iter()
    .enumerate()
    {
        let mac = format!("5A:5B:5C:5D:5F:{idx:02X}");
        let request = rpc::forge::ExpectedMachine {
            bmc_mac_address: mac.clone(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: format!("EM-BMC-ALLOC-{idx}"),
            bmc_ip_allocation: Some(*mode as i32),
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
            retrieved.bmc_ip_allocation,
            Some(*mode as i32),
            "bmc_ip_allocation {mode:?} should survive DB round-trip unchanged"
        );
    }

    Ok(())
}

/// Default-case round-trip for `bmc_ip_allocation`: when the operator omits it on
/// the wire, the server persists the Postgres default (`Auto`) and returns `None`
/// on the wire, so old clients see exactly what they sent.
#[crate::sqlx_test]
async fn test_bmc_ip_allocation_default_value_omitted_on_wire(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let mac = "5A:5B:5C:5D:5F:FF";
    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            bmc_mac_address: mac.into(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "EM-BMC-ALLOC-DEFAULT".into(),
            bmc_ip_allocation: None,
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
        retrieved.bmc_ip_allocation, None,
        "default bmc_ip_allocation should not be emitted on the wire for stable round-trips"
    );

    Ok(())
}

/// Every `bmc_ip_allocation` x `bmc_ip_address` combination driven through the
/// real handlers: `add_expected_machine` accepts the six valid pairings and
/// refuses the three invalid ones, and `update_expected_machine` refuses the
/// same invalid pairings on an existing machine. Rejection is `InvalidArgument`
/// and names `bmc_ip_allocation` so the operator knows which knob to fix, and a
/// rejected update leaves the stored machine untouched. The combination table
/// itself is unit-tested in api-model -- these rows pin the handler wiring that
/// enforces it at the API boundary.
#[crate::sqlx_test]
async fn test_bmc_ip_allocation_combinations_enforced_at_the_api_boundary(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    use carbide_test_support::Outcome::{FailsWith, Yields};
    use carbide_test_support::{Case, check_cases_async};
    use rpc::forge::BmcIpAllocationType::{Auto, Dynamic, Fixed, Retained};

    let env = create_test_env(pool).await;

    /// One `add_expected_machine` request: the allocation/address pairing under
    /// test, plus the unique per-machine identity the API requires.
    struct AddRequest {
        mode: Option<rpc::forge::BmcIpAllocationType>,
        bmc_ip_address: Option<&'static str>,
        mac: &'static str,
        serial: &'static str,
    }

    // Rejections are projected to (status code, "the error names
    // bmc_ip_allocation") so each failing row pins both.
    check_cases_async(
        [
            Case {
                scenario: "add: unset with no address is accepted (defaults to auto)",
                input: AddRequest {
                    mode: None,
                    bmc_ip_address: None,
                    mac: "5A:5B:5C:5D:61:01",
                    serial: "EM-BMC-ALLOC-API-01",
                },
                expect: Yields(()),
            },
            Case {
                scenario: "add: auto with no address is accepted (retains)",
                input: AddRequest {
                    mode: Some(Auto),
                    bmc_ip_address: None,
                    mac: "5A:5B:5C:5D:61:02",
                    serial: "EM-BMC-ALLOC-API-02",
                },
                expect: Yields(()),
            },
            Case {
                scenario: "add: auto with an address is accepted (fixed)",
                input: AddRequest {
                    mode: Some(Auto),
                    bmc_ip_address: Some("192.0.2.61"),
                    mac: "5A:5B:5C:5D:61:03",
                    serial: "EM-BMC-ALLOC-API-03",
                },
                expect: Yields(()),
            },
            Case {
                scenario: "add: dynamic with no address is accepted",
                input: AddRequest {
                    mode: Some(Dynamic),
                    bmc_ip_address: None,
                    mac: "5A:5B:5C:5D:61:04",
                    serial: "EM-BMC-ALLOC-API-04",
                },
                expect: Yields(()),
            },
            Case {
                scenario: "add: fixed with an address is accepted",
                input: AddRequest {
                    mode: Some(Fixed),
                    bmc_ip_address: Some("192.0.2.62"),
                    mac: "5A:5B:5C:5D:61:05",
                    serial: "EM-BMC-ALLOC-API-05",
                },
                expect: Yields(()),
            },
            Case {
                scenario: "add: retained with no address is accepted",
                input: AddRequest {
                    mode: Some(Retained),
                    bmc_ip_address: None,
                    mac: "5A:5B:5C:5D:61:06",
                    serial: "EM-BMC-ALLOC-API-06",
                },
                expect: Yields(()),
            },
            Case {
                scenario: "add: fixed with no address is rejected",
                input: AddRequest {
                    mode: Some(Fixed),
                    bmc_ip_address: None,
                    mac: "5A:5B:5C:5D:61:07",
                    serial: "EM-BMC-ALLOC-API-07",
                },
                expect: FailsWith((tonic::Code::InvalidArgument, true)),
            },
            Case {
                scenario: "add: dynamic with an address is rejected",
                input: AddRequest {
                    mode: Some(Dynamic),
                    bmc_ip_address: Some("192.0.2.63"),
                    mac: "5A:5B:5C:5D:61:08",
                    serial: "EM-BMC-ALLOC-API-08",
                },
                expect: FailsWith((tonic::Code::InvalidArgument, true)),
            },
            Case {
                scenario: "add: retained with an address is rejected",
                input: AddRequest {
                    mode: Some(Retained),
                    bmc_ip_address: Some("192.0.2.64"),
                    mac: "5A:5B:5C:5D:61:09",
                    serial: "EM-BMC-ALLOC-API-09",
                },
                expect: FailsWith((tonic::Code::InvalidArgument, true)),
            },
        ],
        |req| {
            let env = &env;
            async move {
                env.api
                    .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
                        bmc_mac_address: req.mac.into(),
                        bmc_username: "ADMIN".into(),
                        bmc_password: "PASS".into(),
                        chassis_serial_number: req.serial.into(),
                        bmc_ip_allocation: req.mode.map(|m| m as i32),
                        bmc_ip_address: req.bmc_ip_address.map(Into::into),
                        ..Default::default()
                    }))
                    .await
                    .map(|_| ())
                    .map_err(|status| {
                        (
                            status.code(),
                            status.message().contains("bmc_ip_allocation"),
                        )
                    })
            }
        },
    )
    .await;

    // The same invalid pairings through update_expected_machine, against one
    // existing machine.
    let mac = "5A:5B:5C:5D:61:10";
    let base = rpc::forge::ExpectedMachine {
        bmc_mac_address: mac.into(),
        bmc_username: "ADMIN".into(),
        bmc_password: "PASS".into(),
        chassis_serial_number: "EM-BMC-ALLOC-API-10".into(),
        metadata: Some(rpc::forge::Metadata::default()),
        ..Default::default()
    };
    env.api
        .add_expected_machine(tonic::Request::new(base.clone()))
        .await?;

    /// One `update_expected_machine` request: the invalid pairing sent for the
    /// machine created above.
    struct UpdateRequest {
        mode: rpc::forge::BmcIpAllocationType,
        bmc_ip_address: Option<&'static str>,
    }

    check_cases_async(
        [
            Case {
                scenario: "update: fixed with no address is rejected",
                input: UpdateRequest {
                    mode: Fixed,
                    bmc_ip_address: None,
                },
                expect: FailsWith((tonic::Code::InvalidArgument, true)),
            },
            Case {
                scenario: "update: dynamic with an address is rejected",
                input: UpdateRequest {
                    mode: Dynamic,
                    bmc_ip_address: Some("192.0.2.65"),
                },
                expect: FailsWith((tonic::Code::InvalidArgument, true)),
            },
            Case {
                scenario: "update: retained with an address is rejected",
                input: UpdateRequest {
                    mode: Retained,
                    bmc_ip_address: Some("192.0.2.66"),
                },
                expect: FailsWith((tonic::Code::InvalidArgument, true)),
            },
        ],
        |req| {
            let env = &env;
            let base = &base;
            async move {
                env.api
                    .update_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
                        bmc_ip_allocation: Some(req.mode as i32),
                        bmc_ip_address: req.bmc_ip_address.map(Into::into),
                        ..base.clone()
                    }))
                    .await
                    .map(|_| ())
                    .map_err(|status| {
                        (
                            status.code(),
                            status.message().contains("bmc_ip_allocation"),
                        )
                    })
            }
        },
    )
    .await;

    // Every rejected update happened before any write: the stored machine still
    // has the default allocation and no address.
    let retrieved = env
        .api
        .get_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachineRequest {
            bmc_mac_address: mac.into(),
            id: None,
        }))
        .await?
        .into_inner();
    assert_eq!(
        retrieved.bmc_ip_allocation, None,
        "rejected updates should leave the stored allocation untouched"
    );
    assert_eq!(
        retrieved.bmc_ip_address, None,
        "rejected updates should not store a bmc_ip_address"
    );

    Ok(())
}

/// Make sure expected_machines.json, which uses create_missing_from,
/// follows the shared codepath for handling interface allocation.
#[crate::sqlx_test]
async fn test_create_missing_from_preallocates_interfaces(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let bmc_mac: MacAddress = "AA:BB:CC:DD:EE:01".parse().unwrap();
    let nic_mac: MacAddress = "AA:BB:CC:DD:EE:02".parse().unwrap();
    let bmc_ip: std::net::IpAddr = "192.0.2.240".parse().unwrap();
    let host_ip: std::net::IpAddr = "192.0.2.241".parse().unwrap();

    let machine = ExpectedMachine {
        id: None,
        bmc_mac_address: bmc_mac,
        data: ExpectedMachineData {
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            serial_number: "EM-JSON-SEED-001".into(),
            bmc_ip_address: Some(bmc_ip),
            host_nics: vec![model::expected_machine::ExpectedHostNic {
                network_segment_type: None,
                mac_address: nic_mac,
                nic_type: Some("onboard".into()),
                fixed_ip: Some(host_ip),
                fixed_mask: None,
                fixed_gateway: None,
                primary: Some(true),
            }],
            ..Default::default()
        },
    };

    let mut txn = env.pool.begin().await?;
    crate::handlers::expected_machine::create_missing_from(
        &mut txn,
        std::slice::from_ref(&machine),
    )
    .await?;
    txn.commit().await?;

    // Mimic site-explorer's per-row materialization: one preallocate per static IP on the
    // entity we just inserted.
    carbide_site_explorer::try_preallocate_one(
        &env.pool,
        bmc_mac,
        bmc_ip,
        model::machine_interface::InterfaceType::Bmc,
        "expected_machine BMC",
        None,
    )
    .await;
    carbide_site_explorer::try_preallocate_one(
        &env.pool,
        nic_mac,
        host_ip,
        model::machine_interface::InterfaceType::Data,
        "expected_machine host NIC",
        None,
    )
    .await;

    let mut txn = env.pool.begin().await?;
    for (mac, expected_ip) in [(bmc_mac, bmc_ip), (nic_mac, host_ip)] {
        let interfaces = db::machine_interface::find_by_mac_address(&mut *txn, mac).await?;
        assert_eq!(
            interfaces.len(),
            1,
            "expected one machine_interface for MAC {mac}"
        );
        assert!(
            interfaces[0].addresses.contains(&expected_ip),
            "machine_interface for MAC {mac} should carry static IP {expected_ip}, got {:?}",
            interfaces[0].addresses,
        );
    }

    // Re-running create_missing_from with the same input must be a no-op (idempotent).
    let mut txn = env.pool.begin().await?;
    crate::handlers::expected_machine::create_missing_from(
        &mut txn,
        std::slice::from_ref(&machine),
    )
    .await?;
    txn.commit().await?;

    Ok(())
}
