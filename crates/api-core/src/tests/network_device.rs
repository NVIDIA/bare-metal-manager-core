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

use rpc::forge::NetworkDeviceIdList;
use rpc::forge::forge_server::Forge;

use crate::tests::common::api_fixtures::{create_managed_host_multi_dpu, create_test_env};

#[crate::sqlx_test]
async fn test_find_network_devices_by_device_ids_single_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    _ = create_managed_host_multi_dpu(&env, 1).await;
    let expected_id = "mac=a1:b1:c1:00:00:01";
    let response = env
        .api
        .find_network_devices_by_device_ids(tonic::Request::new(NetworkDeviceIdList {
            network_device_ids: vec![String::from(expected_id)],
        }))
        .await
        .expect("Response should have been successful");
    let network_devices = response.into_inner().network_devices;
    assert_eq!(
        network_devices.len(),
        1,
        "Response should have returned 1 result"
    );

    let network_device = network_devices
        .first()
        .expect("Response should have N>0 devices");
    assert_eq!(
        network_device.id, expected_id,
        "All returned connected_devices should match the requested machine ID"
    );
    assert!(
        network_device.description.is_some(),
        "description should be set"
    );
}

#[crate::sqlx_test]
async fn test_find_network_devices_by_device_ids_multiple_ids(pool: sqlx::PgPool) {
    let expected_ids = vec![
        "mac=a1:b1:c1:00:00:01",
        "mac=a2:b2:c2:00:00:02",
        "mac=a3:b3:c3:00:00:03",
    ];
    let env = create_test_env(pool).await;
    _ = create_managed_host_multi_dpu(&env, 1).await;
    let response = env
        .api
        .find_network_devices_by_device_ids(tonic::Request::new(NetworkDeviceIdList {
            network_device_ids: expected_ids.clone().into_iter().map(String::from).collect(),
        }))
        .await
        .expect("Response should have been successful");
    let network_devices = response.into_inner().network_devices;
    assert_eq!(
        network_devices.len(),
        3,
        "Response should have returned 3 results"
    );

    for (index, expected_id) in expected_ids.iter().enumerate() {
        let found_device = network_devices
            .get(index)
            .unwrap_or_else(|| panic!("No network_device at index {index}"));
        assert_eq!(
            &found_device.id, expected_id,
            "Returned device at index {} should have id {}, got {}",
            index, expected_id, found_device.id
        );
        assert!(
            found_device.description.is_some(),
            "description should be set"
        );
    }
}

#[crate::sqlx_test]
async fn test_find_network_devices_by_device_ids_no_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    _ = create_managed_host_multi_dpu(&env, 1).await;
    let response = env
        .api
        .find_network_devices_by_device_ids(tonic::Request::new(NetworkDeviceIdList {
            network_device_ids: vec![],
        }))
        .await
        .expect("Response should have been successful");
    let network_devices = response.into_inner().network_devices;
    assert_eq!(
        network_devices.len(),
        0,
        "Response should have returned 0 results"
    );
}
