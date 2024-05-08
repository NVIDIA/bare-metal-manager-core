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

use crate::common::api_fixtures;
use rpc::forge::forge_server::Forge;
use rpc::{forge::MachineIdList, MachineId};

pub mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_managed_hosts"))]
async fn test_find_connected_devices_by_machine_ids_single_id(pool: sqlx::PgPool) {
    let expected_machine_id = "fm100dsbiu5ckus880v8407u0mkcensa39cule26im5gnpvmuufckacguc0";
    let env = api_fixtures::create_test_env(pool).await;
    let response = env
        .api
        .find_connected_devices_by_dpu_machine_ids(tonic::Request::new(MachineIdList {
            machine_ids: vec![MachineId {
                id: String::from(expected_machine_id),
            }],
        }))
        .await
        .expect("Response should have been successful");
    let connected_devices = response.into_inner().connected_devices;
    assert_eq!(
        connected_devices.len(),
        3,
        "Response should have returned 3 results"
    );

    for connected_device in connected_devices.iter() {
        let id = connected_device
            .id
            .as_ref()
            .expect("All returned connected_devices should have an id");
        assert_eq!(
            id.id, expected_machine_id,
            "All returned connected_devices should match the requested machine ID"
        );
        assert!(
            connected_device.network_device_id.is_some(),
            "network_device_id should be set"
        );
    }
}

#[sqlx::test(fixtures("create_managed_hosts"))]
async fn test_find_connected_devices_by_machine_ids_no_ids(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let response = env
        .api
        .find_connected_devices_by_dpu_machine_ids(tonic::Request::new(MachineIdList {
            machine_ids: vec![],
        }))
        .await
        .expect("Response should have been successful");
    let connected_devices = response.into_inner().connected_devices;
    assert_eq!(
        connected_devices.len(),
        0,
        "Response should have returned zero results"
    );
}

#[sqlx::test(fixtures("create_managed_hosts"))]
async fn test_find_connected_devices_by_machine_ids_missing_id(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let response = env
        .api
        .find_connected_devices_by_dpu_machine_ids(tonic::Request::new(MachineIdList {
            machine_ids: vec![MachineId {
                // Is a host, not a DPU.
                id: String::from("fm100htkod0q440bpcnjnsp50qsl3l5sr4htnhckhhb596r0qm3btnqt63g"),
            }],
        }))
        .await
        .expect("Response should have been successful");
    let connected_devices = response.into_inner().connected_devices;
    assert_eq!(
        connected_devices.len(),
        0,
        "Response should have returned zero results"
    );
}
