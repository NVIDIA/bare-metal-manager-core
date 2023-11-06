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

use common::api_fixtures::dpu;
use common::api_fixtures::instance::{create_instance, single_interface_network_config};
use common::api_fixtures::network_segment::FIXTURE_NETWORK_SEGMENT_ID;
use common::api_fixtures::{
    create_managed_host, create_test_env, TestEnv, FIXTURE_DHCP_RELAY_ADDRESS,
};
use rpc::forge::forge_server::Forge;
use rpc::forge::IpType;

mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

/// Test searching for an IP address. Tests all the cases in a single
/// test so that we only need to create and populate the DB once.
#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_ip_finder(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    // Setup
    let env = create_test_env(db_pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
    let host_machine = env
        .find_machines(Some(host_machine_id.to_string().into()), None, true)
        .await
        .machines
        .remove(0);

    let (_instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config(FIXTURE_NETWORK_SEGMENT_ID)),
        None,
        vec!["keyset1".to_string(), "keyset2".to_string()],
    )
    .await;

    test_not_found(&env).await;
    test_inner(
        FIXTURE_DHCP_RELAY_ADDRESS,
        IpType::StaticDataDhcpServer,
        &env,
        "test_dhcp_server",
    )
    .await;
    test_inner(
        "172.20.0.10",
        IpType::ResourcePool,
        &env,
        "test_resource_pool",
    )
    .await;
    test_inner(
        "192.0.2.3",
        IpType::InstanceAddress,
        &env,
        "test_instance_address",
    )
    .await;
    test_inner(
        "192.0.2.4",
        IpType::MachineAddress,
        &env,
        "test_machine_address",
    )
    .await;

    test_inner(
        host_machine.bmc_info.as_ref().unwrap().ip(),
        IpType::BmcIp,
        &env,
        "test_bmc_ip",
    )
    .await;

    test_inner(
        "192.0.3.1",
        IpType::NetworkSegment,
        &env,
        "test_network_segment",
    )
    .await;

    // Loopback IP is assigned at random from pool, so we need to search for the correct one
    let mut txn = db_pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let loopback_ip = dpu::loopback_ip(&mut txn, &dpu_machine_id).await;
    test_inner(
        &loopback_ip.to_string(),
        IpType::LoopbackIp,
        &env,
        "test_loopback_ip",
    )
    .await;

    Ok(())
}

async fn test_not_found(env: &TestEnv) {
    let req = rpc::forge::FindIpAddressRequest {
        ip: "10.0.0.1".to_string(),
    };
    let res = env.api.find_ip_address(tonic::Request::new(req)).await;
    assert!(
        matches!(res, Err(status) if status.code() == tonic::Code::NotFound),
        "test_not_found"
    );
}

async fn test_inner(ip: &str, ip_type: IpType, env: &TestEnv, caller: &str) {
    let req = rpc::forge::FindIpAddressRequest { ip: ip.to_string() };
    let res = env
        .api
        .find_ip_address(tonic::Request::new(req))
        .await
        .expect(caller)
        .into_inner();
    assert!(!res.matches.is_empty(), "{caller} not found");
    // In integration testing DHCP relay is in a network segment,
    // so we get multiple matches. Wouldn't happen in live.
    for m in res.matches {
        if m.ip_type == ip_type as i32 {
            return; // success
        }
    }
    panic!("{caller} did not have correct IPType");
}
