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

use rpc::common::MachineIdList;
use rpc::forge::forge_server::Forge;

use super::common::api_fixtures::{create_managed_host_multi_dpu, create_test_env};

#[crate::sqlx_test]
async fn test_find_connected_devices_by_machine_ids_single_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host_multi_dpu(&env, 1).await;
    let host_machine = mh.host().rpc_machine().await;
    let expected_machine_id = host_machine
        .associated_dpu_machine_ids
        .into_iter()
        .next()
        .expect("created managed_host from fixture must have a dpu");
    let response = env
        .api
        .find_connected_devices_by_dpu_machine_ids(tonic::Request::new(MachineIdList {
            machine_ids: vec![expected_machine_id],
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

#[crate::sqlx_test]
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

#[crate::sqlx_test]
async fn test_find_connected_devices_by_machine_ids_missing_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    _ = create_managed_host_multi_dpu(&env, 1).await;
    let response = env
        .api
        .find_connected_devices_by_dpu_machine_ids(tonic::Request::new(MachineIdList {
            machine_ids: vec![
                // Is a host, not a DPU.
                "fm100htkod0q440bpcnjnsp50qsl3l5sr4htnhckhhb596r0qm3btnqt63g"
                    .parse()
                    .unwrap(),
            ],
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
