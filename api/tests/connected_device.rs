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

use crate::common::api_fixtures::{create_test_env, managed_host::create_managed_host_multi_dpu};
use rpc::forge::forge_server::Forge;
use rpc::{common::MachineIdList, MachineId};

pub mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_connected_devices_by_machine_ids_single_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_machine_id = create_managed_host_multi_dpu(&env, 1).await;
    let host_machine = env
        .api
        .get_machine(tonic::Request::new(MachineId {
            id: host_machine_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    let expected_machine_id = host_machine
        .associated_dpu_machine_ids
        .into_iter()
        .next()
        .expect("created managed_host from fixture must have a dpu");
    let response = env
        .api
        .find_connected_devices_by_dpu_machine_ids(tonic::Request::new(MachineIdList {
            machine_ids: vec![expected_machine_id.clone()],
        }))
        .await
        .expect("Response should have been successful");
    let connected_devices = response.into_inner().connected_devices;
    assert_eq!(
        connected_devices.len(),
        3,
        "Response should have returned 3 results"
    );

    for connected_device in connected_devices.into_iter() {
        let id = connected_device
            .id
            .expect("All returned connected_devices should have an id");
        assert_eq!(
            id, expected_machine_id,
            "All returned connected_devices should match the requested machine ID"
        );
        assert!(
            connected_device.network_device_id.is_some(),
            "network_device_id should be set"
        );
    }
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_connected_devices_by_machine_ids_no_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    _ = create_managed_host_multi_dpu(&env, 1).await;
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_connected_devices_by_machine_ids_missing_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    _ = create_managed_host_multi_dpu(&env, 1).await;
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
