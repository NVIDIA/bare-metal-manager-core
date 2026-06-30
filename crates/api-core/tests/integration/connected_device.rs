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

use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::{
    FixtureDefault as _, ManagedHostConfigExt as _,
};
use model::test_support::ManagedHostConfig;
use rpc::common::MachineIdList;
use rpc::forge::forge_server::Forge;

async fn init(pool: PgPool) -> (TestHarness, TestManagedHost) {
    let env = TestHarness::builder(pool)
        .with_resource_pools(
            ResourcePoolBuilder::default()
                .with_secondary_vtep_ip("192.0.7.0/24")
                .build(),
        )
        .build()
        .await;
    let network_controller = env.network_controller();
    let domain = env.test_domain().await;
    let underlay_segment = network_controller.create_underlay_segment(&domain).await;
    let admin_segment = network_controller.create_admin_segment(&domain).await;
    let site_explorer = env.default_test_site_explorer();
    let (mh, _) = env
        .managed_host_builder(&site_explorer, underlay_segment)
        .with_config(ManagedHostConfig::default().with_dpu_count(1))
        .build()
        .await;
    mh.first_dpu().discover_oob_iface(admin_segment).await;
    (env, mh)
}

#[sqlx_test]
async fn test_find_connected_devices_by_machine_ids_single_id(pool: PgPool) {
    let (env, mh) = init(pool).await;

    let host_machine = mh.host.rpc_machine().await;
    let expected_machine_id = host_machine
        .associated_dpu_machine_ids
        .into_iter()
        .next()
        .expect("created managed_host from fixture must have a dpu");
    let response = env
        .api()
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

#[sqlx_test]
async fn test_find_connected_devices_by_machine_ids_no_ids(pool: PgPool) {
    let (env, _) = init(pool).await;
    let response = env
        .api()
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

#[sqlx_test]
async fn test_find_connected_devices_by_machine_ids_host_id(pool: PgPool) {
    // `init` populates DPU mappings so a zero result proves the host ID is rejected, rather than
    // merely observing an empty DPU-to-network-device mapping table.
    let (env, mh) = init(pool).await;

    let response = env
        .api()
        .find_connected_devices_by_dpu_machine_ids(tonic::Request::new(MachineIdList {
            machine_ids: vec![mh.host.id],
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
