/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::ops::DerefMut;

use ::rpc::forge::ManagedHostNetworkConfigRequest;
use forge::forge_server::Forge;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use model::machine::ManagedHostStateSnapshot;
use rpc::forge;

use crate::tests::common;
use crate::tests::common::api_fixtures;
use crate::tests::common::api_fixtures::managed_host::ManagedHostConfig;
use crate::tests::common::api_fixtures::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_2, FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS,
    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY, create_admin_network_segment,
    create_host_inband_network_segment, create_network_segment, create_tenant_network_segment,
    create_underlay_network_segment,
};
use crate::tests::common::api_fixtures::{TestEnv, TestEnvOverrides};
use crate::tests::common::mac_address_pool::HOST_NON_DPU_MAC_ADDRESS_POOL;
use crate::tests::common::rpc_builder::VpcCreationRequest;

#[derive(Debug, Default)]
struct TestEnvOptions {
    host_inband_segments_in_different_vpcs: bool,
}

/// Create a test_env for tests in this file, with:
/// - An admin network
/// - A DPU underlay network segment
/// - 2 tenant overlay networks
/// - 2 tenant HostInband networks
/// - 2 VPC's
async fn create_test_env_for_instance_allocation(
    pool: sqlx::PgPool,
    options: Option<TestEnvOptions>,
) -> TestEnv {
    let options = options.unwrap_or_default();
    let site_prefixes = vec![
        IpNetwork::new(
            FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
            FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.network(),
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_2.network(),
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_2.prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.network(),
            FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[0].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[0].prefix(),
        )
        .unwrap(),
        IpNetwork::new(
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[1].network(),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[1].prefix(),
        )
        .unwrap(),
    ];

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            allow_zero_dpu_hosts: Some(true),
            site_prefixes: Some(site_prefixes),
            create_network_segments: Some(false),
            ..Default::default()
        },
    )
    .await;

    let vpc_1 = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("test vpc 1", "2829bbe3-c169-4cd9-8b2a-19a8b1618a93")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    let vpc_2 = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("test vpc 2", "2829bbe3-c169-4cd9-8b2a-19a8b1618a93")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    create_underlay_network_segment(&env.api).await;
    create_admin_network_segment(&env.api).await;

    create_tenant_network_segment(
        &env.api,
        vpc_1.id,
        FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[0],
        "TENANT",
        true,
    )
    .await;

    create_tenant_network_segment(
        &env.api,
        vpc_2.id,
        FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[1],
        "TENANT_2",
        true,
    )
    .await;

    create_host_inband_network_segment(&env.api, vpc_1.id).await;
    // Make sure second host_inband network segment has the same VPC ID
    create_network_segment(
        &env.api,
        "HOST_INBAND_2",
        &format!(
            "{}/{}",
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_2.network(),
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_2.prefix()
        ),
        &FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_2
            .ip()
            .to_string(),
        forge::NetworkSegmentType::HostInband,
        // One test asserts that allocation should fail if each segment is in a different VPC
        if options.host_inband_segments_in_different_vpcs {
            vpc_2.id
        } else {
            vpc_1.id
        },
        true,
    )
    .await;

    // Get the tenant segment into ready state
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    env
}

#[crate::sqlx_test]
async fn test_zero_dpu_instance_allocation_explicit_network_config(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig::with_dpus(vec![]);

    // Ingest zero DPU host
    let zero_dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;

    let host_inband_segment =
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "HOST_INBAND")
            .await?;

    // Allocate an instance by explicitly specifying an interface that is on the HOST_INBAND network
    let instance = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: "2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string(), // from sql fixture
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                network_security_group_id: None,
                os: Some(forge::OperatingSystem {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::operating_system::Variant::Ipxe(forge::InlineIpxe {
                        ipxe_script: "exit".to_string(),
                        user_data: None,
                    })),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![forge::InstanceInterfaceConfig {
                        function_type: forge::InterfaceFunctionType::Physical as i32,
                        network_segment_id: Some(host_inband_segment.id),
                        network_details: None,
                        device: None,
                        device_instance: 0u32,
                        virtual_function_id: None,
                    }],
                }),
                infiniband: None,
                dpu_extension_services: None,
                nvlink: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await
    .expect("Instance allocation with no network config should have been successful")
    .into_inner();

    // Make sure getting the Machine over RPC has the correct instance network restrictions. While
    // not strictly testing instance allocation, it's very related, because cloud-api will be using
    // the static_vpc_id field to determine where allocation should happen.
    let rpc_machine: forge::Machine = env
        .find_machine(zero_dpu_host.host_snapshot.id)
        .await
        .remove(0);

    let instance_network_restrictions = rpc_machine.instance_network_restrictions.unwrap();
    assert_eq!(
        instance_network_restrictions.network_segment_membership_type,
        forge::InstanceNetworkSegmentMembershipType::Static as i32,
        "Machine that was just ingested should have a static network membership type in its instance network restrictions, since it has zero DPUs",
    );
    assert_eq!(
        instance_network_restrictions.network_segment_ids,
        vec![host_inband_segment.id],
        "Machine that was just ingested should have instance network restrictions listing its network segment ID's",
    );

    let interfaces = instance.config.unwrap().network.unwrap().interfaces;
    assert_eq!(
        interfaces.len(),
        1,
        "New instance should have one interface"
    );
    assert_eq!(
        interfaces[0].network_segment_id,
        Some(host_inband_segment.id),
        "New instance should have an interface on the HOST_INBAND network"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_zero_dpu_instance_allocation_no_network_config(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig::with_dpus(vec![]);

    // Ingest zero DPU host
    let zero_dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;

    let host_inband_segment =
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "HOST_INBAND")
            .await?;

    // Allocate an instance without specifying a network config
    let instance = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: "2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string(), // from sql fixture
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::OperatingSystem {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::operating_system::Variant::Ipxe(forge::InlineIpxe {
                        ipxe_script: "exit".to_string(),
                        user_data: None,
                    })),
                }),
                network: None, // code under test: Network config is None
                infiniband: None,
                nvlink: None,
                network_security_group_id: None,
                dpu_extension_services: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await
    .expect("Instance allocation with no network config should have been successful")
    .into_inner();

    let interfaces = instance.config.unwrap().network.unwrap().interfaces;
    assert_eq!(
        interfaces.len(),
        1,
        "New instance should have one interface"
    );
    assert_eq!(
        interfaces[0].network_segment_id,
        Some(host_inband_segment.id),
        "New instance should have an interface on the HOST_INBAND network"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_zero_dpu_instance_allocation_multi_segment_no_network_config(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig {
        dpus: vec![],
        non_dpu_macs: vec![
            HOST_NON_DPU_MAC_ADDRESS_POOL.allocate(),
            HOST_NON_DPU_MAC_ADDRESS_POOL.allocate(),
        ],
        ..Default::default()
    };

    // Ingest zero DPU host with custom behavior in the finish callback...
    let zero_dpu_host = api_fixtures::site_explorer::new_mock_host(&env, config)
        .await?
        .discover_dhcp_host_secondary_iface(
            1,
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_2
                .ip()
                .to_string(),
            |result, _| {
                assert!(result.is_ok());
                Ok(())
            },
        )
        .await?
        .finish(|mock| async move {
            let machine_id = mock.discovered_machine_id().unwrap();

            Ok::<ManagedHostStateSnapshot, eyre::Report>(
                db::managed_host::load_snapshot(
                    mock.test_env.pool.begin().await?.deref_mut(),
                    &machine_id,
                    Default::default(),
                )
                .await
                .transpose()
                .unwrap()?,
            )
        })
        .await?;

    let instance = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: "2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string(), // from sql fixture
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::OperatingSystem {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::operating_system::Variant::Ipxe(forge::InlineIpxe {
                        ipxe_script: "exit".to_string(),
                        user_data: None,
                    })),
                }),
                network: None, // code under test: Network config is None
                infiniband: None,
                nvlink: None,
                network_security_group_id: None,
                dpu_extension_services: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await
    .expect("Instance allocation with no network config should have been successful")
    .into_inner();

    let (host_inband_segment_1, host_inband_segment_2) = (
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "HOST_INBAND")
            .await?,
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "HOST_INBAND_2")
            .await?,
    );

    let interfaces = instance.config.unwrap().network.unwrap().interfaces;
    assert_eq!(
        interfaces.len(),
        2,
        "New instance should have two interface"
    );

    let host_snapshot_after_allocate = db::managed_host::load_snapshot(
        env.pool.begin().await?.deref_mut(),
        &zero_dpu_host.host_snapshot.id,
        Default::default(),
    )
    .await
    .transpose()
    .unwrap()?;

    let instance_snapshot = host_snapshot_after_allocate
        .instance
        .expect("zero-dpu host snapshot should have an assigned instance");

    assert_eq!(
        instance_snapshot.config.network.interfaces.len(),
        2,
        "Instance should have 2 interfaces"
    );

    let interface_in_segment_1 = instance_snapshot
        .config
        .network
        .interfaces
        .iter()
        .find(|i| i.network_segment_id == Some(host_inband_segment_1.id))
        .expect("One of the instance interfaces should have been in the HOST_INBAND segment");
    let interface_in_segment_2 = instance_snapshot
        .config
        .network
        .interfaces
        .iter()
        .find(|i| i.network_segment_id == Some(host_inband_segment_2.id))
        .expect("One of the instance interfaces should have been in the HOST_INBAND_2 segment");

    assert!(
        !interface_in_segment_1.ip_addrs.is_empty(),
        "Instance interface in segment 1 should have IP addresses assigned"
    );
    assert!(
        !interface_in_segment_2.ip_addrs.is_empty(),
        "Instance interface in segment 2 should have IP addresses assigned"
    );

    assert!(
        interface_in_segment_1
            .ip_addrs
            .iter()
            .all(
                |(prefix_id, addr)| host_inband_segment_1.prefixes[0].prefix.contains(*addr)
                    && prefix_id.eq(&host_inband_segment_1.prefixes[0].id)
            )
    );

    assert!(
        interface_in_segment_2
            .ip_addrs
            .iter()
            .all(
                |(prefix_id, addr)| host_inband_segment_2.prefixes[0].prefix.contains(*addr)
                    && prefix_id.eq(&host_inband_segment_2.prefixes[0].id)
            )
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_reject_single_dpu_instance_allocation_no_network_config(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;

    // Create single DPU host
    let single_dpu_host = api_fixtures::site_explorer::new_host(&env, Default::default()).await?;

    // Create an instance on a host with DPUs, without specifying a network config, which is not allowed
    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(single_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: "2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string(), // from sql fixture
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::OperatingSystem {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::operating_system::Variant::Ipxe(forge::InlineIpxe {
                        ipxe_script: "exit".to_string(),
                        user_data: None,
                    })),
                }),
                network: None,
                infiniband: None,
                nvlink: None,
                network_security_group_id: None,
                dpu_extension_services: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await;

    match result {
        Err(e) if e.code() == tonic::Code::InvalidArgument => {}
        _ => panic!(
            "Creating an instance on a dpu host without specifying a network segment should throw an error, got {result:?}"
        ),
    };

    Ok(())
}

#[crate::sqlx_test]
async fn test_reject_single_dpu_instance_allocation_host_inband_network_config(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;

    // Create single DPU host
    let single_dpu_host = api_fixtures::site_explorer::new_host(&env, Default::default()).await?;

    let host_inband_segment =
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "HOST_INBAND")
            .await?;

    // Create an instance on a host with DPUs, but try to configure it on a host_inband network,
    // which is not allowed
    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(single_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: "2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string(), // from sql fixture
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::OperatingSystem {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::operating_system::Variant::Ipxe(forge::InlineIpxe {
                        ipxe_script: "exit".to_string(),
                        user_data: None,
                    })),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![forge::InstanceInterfaceConfig {
                        function_type: forge::InterfaceFunctionType::Physical as i32,
                        network_segment_id: Some(host_inband_segment.id),
                        network_details: None,
                        device: None,
                        device_instance: 0u32,
                        virtual_function_id: None,
                    }],
                }),
                network_security_group_id: None,
                dpu_extension_services: None,
                infiniband: None,
                nvlink: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await;

    match result {
        Err(e) if e.code() == tonic::Code::InvalidArgument => {}
        _ => panic!(
            "Creating an instance on a dpu host while specifying a host_inband network segment should throw an error, got {result:?}"
        ),
    };

    Ok(())
}

/// Make sure that if a host exists in two different network segments each with different VPC ID's,
/// we don't allow instance allocation.
#[crate::sqlx_test]
async fn test_reject_zero_dpu_instance_allocation_multiple_vpcs(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(
        pool.clone(),
        Some(TestEnvOptions {
            host_inband_segments_in_different_vpcs: true,
        }),
    )
    .await;

    let config = ManagedHostConfig {
        dpus: vec![],
        non_dpu_macs: vec![
            HOST_NON_DPU_MAC_ADDRESS_POOL.allocate(),
            HOST_NON_DPU_MAC_ADDRESS_POOL.allocate(),
        ],
        ..Default::default()
    };

    // Ingest zero DPU host
    let zero_dpu_host = api_fixtures::site_explorer::new_mock_host(&env, config)
        .await?
        .discover_dhcp_host_secondary_iface(
            1,
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_2
                .ip()
                .to_string(),
            |dhcp_result, _| {
                assert!(
                    dhcp_result.is_ok(),
                    "DHCP failed on second interface: {dhcp_result:?}"
                );
                Ok(())
            },
        )
        .await?
        .finish(|mock| async move {
            let machine_id = mock.discovered_machine_id().unwrap();
            let mut txn = mock.test_env.pool.begin().await.unwrap();
            Ok::<ManagedHostStateSnapshot, eyre::Report>(
                db::managed_host::load_snapshot(&mut txn, &machine_id, Default::default())
                    .await
                    .transpose()
                    .unwrap()?,
            )
        })
        .await?;

    let host_snapshot_rpc: forge::Machine = zero_dpu_host.host_snapshot.clone().into();

    let host_inband_segment =
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "HOST_INBAND")
            .await?;
    let host_inband_2_segment =
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "HOST_INBAND_2")
            .await?;

    let instance_network_restrictions = host_snapshot_rpc.instance_network_restrictions.unwrap();
    assert_eq!(
        instance_network_restrictions.network_segment_membership_type,
        forge::InstanceNetworkSegmentMembershipType::Static as i32,
        "Instance network segment membership should be Static since the host has zero DPUs"
    );
    assert_eq!(
        instance_network_restrictions.network_segment_ids.len(),
        2,
        "Instance network segment restrictions should show both network segment ID's"
    );
    assert!(
        instance_network_restrictions
            .network_segment_ids
            .iter()
            .contains(&host_inband_segment.id),
        "Machine that was just ingested should have instance network restrictions showing host_inband_segment {}",
        host_inband_segment.id,
    );
    assert!(
        instance_network_restrictions
            .network_segment_ids
            .iter()
            .contains(&host_inband_2_segment.id),
        "Machine that was just ingested should have instance network restrictions showing host_inband_2_segment {}",
        host_inband_2_segment.id,
    );

    // Allocate an instance without specifying a network config
    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                network_security_group_id: None,
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: "2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string(), // from sql fixture
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::OperatingSystem {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::operating_system::Variant::Ipxe(forge::InlineIpxe {
                        ipxe_script: "exit".to_string(),
                        user_data: None,
                    })),
                }),
                network: None,
                infiniband: None,
                dpu_extension_services: None,
                nvlink: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await;

    match result {
        Err(e) if e.code() == tonic::Code::InvalidArgument => {}
        _ => panic!(
            "Creating an instance on a zero-dpu host that is a member of multiple VPC's should fail, got {result:?}"
        ),
    }

    Ok(())
}

// Create a machine with a single DPU, and create an instance on that machine.
// Call GetManagedHostNetworkConfig and make sure instance metadata matches
// expected results.
#[crate::sqlx_test]
async fn test_single_dpu_instance_allocation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;

    // Create single DPU host
    let single_dpu_host = api_fixtures::site_explorer::new_host(&env, Default::default()).await?;

    let tenant_segment =
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "TENANT").await?;

    // Create an instance on a host with DPUs, without specifying a network config, which is not allowed
    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(single_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: "2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string(), // from sql fixture
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::OperatingSystem {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::operating_system::Variant::Ipxe(forge::InlineIpxe {
                        ipxe_script: "exit".to_string(),
                        user_data: None,
                    })),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![forge::InstanceInterfaceConfig {
                        function_type: forge::InterfaceFunctionType::Physical as i32,
                        network_segment_id: Some(tenant_segment.id),
                        network_details: None,
                        device: None,
                        device_instance: 0,
                        virtual_function_id: Some(0),
                    }],
                }),
                infiniband: None,
                nvlink: None,
                network_security_group_id: None,
                dpu_extension_services: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await
    .expect("Instance allocation with no network config should have been successful")
    .into_inner();

    let instid = result.id.unwrap();
    let mid = result.machine_id.unwrap();

    let mut machine = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![mid],
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0);

    let dpu_machine_id = machine.associated_dpu_machine_ids.remove(0).into();

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id,
        }))
        .await
        .unwrap();

    let resp = response.into_inner();

    let inst = resp.instance.unwrap();

    assert_eq!(inst.machine_id, Some(mid));
    assert_eq!(inst.id, Some(instid));

    Ok(())
}
