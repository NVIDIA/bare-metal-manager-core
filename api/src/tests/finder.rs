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

use crate::db::network_segment::NetworkSegment;
use common::api_fixtures::create_managed_host_with_config;
use common::api_fixtures::dpu;
use common::api_fixtures::instance::{create_instance, single_interface_network_config};
use common::api_fixtures::managed_host::ManagedHostConfig;
use common::api_fixtures::{
    create_managed_host, create_test_env, TestEnv, FIXTURE_DHCP_RELAY_ADDRESS,
};
use rpc::forge::forge_server::Forge;
use rpc::forge::IpType;

use crate::tests::common;

/// Test searching for an IP address. Tests all the cases in a single
/// test so that we only need to create and populate the DB once.
#[crate::sqlx_test]
async fn test_ip_finder(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    // Setup
    let env = create_test_env(db_pool.clone()).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
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
        Some(single_interface_network_config(segment_id)),
        None,
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
        "192.0.4.3",
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
        "192.0.4.1",
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

#[crate::sqlx_test]
async fn test_identify_uuid(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    // Setup
    let env = create_test_env(db_pool.clone()).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let (instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        Some(single_interface_network_config(segment_id)),
        None,
        None,
        vec!["keyset1".to_string(), "keyset2".to_string()],
    )
    .await;
    let res = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![host_machine_id.to_string().into()],
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0);
    let interface_id = &res.interfaces[0].id;

    // Network segment
    let req = rpc::forge::IdentifyUuidRequest {
        uuid: Some((segment_id).into()),
    };
    let res = env
        .api
        .identify_uuid(tonic::Request::new(req))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(res.object_type, rpc::forge::UuidType::NetworkSegment as i32);

    // Instance
    let req = rpc::forge::IdentifyUuidRequest {
        uuid: Some(instance_id.into()),
    };
    let res = env
        .api
        .identify_uuid(tonic::Request::new(req))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(res.object_type, rpc::forge::UuidType::Instance as i32);

    // Machine interface
    let req = rpc::forge::IdentifyUuidRequest {
        uuid: interface_id.clone(),
    };
    let res = env
        .api
        .identify_uuid(tonic::Request::new(req))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        res.object_type,
        rpc::forge::UuidType::MachineInterface as i32
    );

    // VPC
    let mut txn = db_pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let segment = NetworkSegment::find_by_name(&mut txn, "TENANT")
        .await
        .unwrap();
    let req = rpc::forge::IdentifyUuidRequest {
        uuid: Some(segment.vpc_id.unwrap().into()),
    };
    let res = env
        .api
        .identify_uuid(tonic::Request::new(req))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(res.object_type, rpc::forge::UuidType::Vpc as i32);

    // Domain
    let req = rpc::forge::IdentifyUuidRequest {
        uuid: Some(env.domain.into()),
    };
    let res = env
        .api
        .identify_uuid(tonic::Request::new(req))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(res.object_type, rpc::forge::UuidType::Domain as i32);

    Ok(())
}

#[crate::sqlx_test]
async fn test_identify_mac(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    // Setup
    let env = create_test_env(db_pool.clone()).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let res = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![host_machine_id.to_string().into()],
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0);
    let interface_id = res.interfaces[0].id.as_ref().unwrap().to_string();
    let mac_address = &res.interfaces[0].mac_address;

    let req = rpc::forge::IdentifyMacRequest {
        mac_address: mac_address.to_string(),
    };
    let res = env
        .api
        .identify_mac(tonic::Request::new(req))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(res.primary_key, *interface_id);
    assert_eq!(
        res.object_type,
        rpc::forge::MacOwner::MachineInterface as i32
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_identify_serial(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    // Setup
    let env = create_test_env(db_pool.clone()).await;
    let config = ManagedHostConfig::default();
    let dpu_config = config.get_and_assert_single_dpu().clone();
    let (host_machine_id, dpu_machine_id) = create_managed_host_with_config(&env, config).await;

    let res = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![dpu_machine_id[0].to_string().into()],
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0);
    assert_eq!(
        res.discovery_info.unwrap().dmi_data.unwrap().product_serial,
        dpu_config.serial
    );

    // Host

    let req = rpc::forge::IdentifySerialRequest {
        // src/model/hardware_info/test_data/x86_info.json
        serial_number: "HostBoard123".to_string(),
    };
    let res = env
        .api
        .identify_serial(tonic::Request::new(req))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        res.machine_id.unwrap().to_string(),
        host_machine_id.to_string()
    );

    // DPU

    let req = rpc::forge::IdentifySerialRequest {
        serial_number: dpu_config.serial,
    };
    let res = env
        .api
        .identify_serial(tonic::Request::new(req))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        res.machine_id.unwrap().to_string(),
        dpu_machine_id[0].to_string()
    );

    Ok(())
}
