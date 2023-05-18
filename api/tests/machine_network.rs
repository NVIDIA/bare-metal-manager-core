/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::time::SystemTime;

use ::rpc::forge::{
    ManagedHostNetworkConfigRequest, ManagedHostNetworkStatusObservation,
    ManagedHostNetworkStatusRequest, NetworkHealth,
};
use rpc::forge::forge_server::Forge;

pub mod common;
use common::api_fixtures;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_managed_host_network_config(pool: sqlx::PgPool) {
    let test = api_fixtures::create_test_env(pool.clone(), Default::default()).await;
    let dpu_machine_id = api_fixtures::dpu::create_dpu_machine(&test).await;

    // Fetch a Machines network config
    let response = test
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            machine_id: Some(dpu_machine_id),
        }))
        .await;

    assert!(response.is_err());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_managed_host_network_status(pool: sqlx::PgPool) {
    let test = api_fixtures::create_test_env(pool.clone(), Default::default()).await;
    let dpu_machine_id = api_fixtures::dpu::create_dpu_machine(&test).await;

    // At first there are no network status
    let response = test
        .api
        .get_all_managed_host_network_status(tonic::Request::new(
            ManagedHostNetworkStatusRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(response.all.is_empty());

    // Update the machine's status to healthy
    let hs = NetworkHealth {
        is_healthy: true,
        passed: vec!["ContainerExists".to_string(), "checkTwo".to_string()],
        failed: vec!["".to_string()],
        message: None,
    };
    test.api
        .record_managed_host_network_status(tonic::Request::new(
            ManagedHostNetworkStatusObservation {
                dpu_machine_id: Some(dpu_machine_id),
                observed_at: Some(SystemTime::now().into()),
                health: Some(hs),
            },
        ))
        .await
        .unwrap();

    // And query again
    let response = test
        .api
        .get_all_managed_host_network_status(tonic::Request::new(
            ManagedHostNetworkStatusRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.all.len(), 1);
    let status = response.all[0].health.as_ref().unwrap();
    assert!(status.is_healthy);
    assert_eq!(status.passed[0], "ContainerExists");
}
