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
use std::collections::HashMap;
use std::ops::DerefMut;

use ::rpc::forge::ManagedHostNetworkConfigRequest;
use carbide_redfish::libredfish::test_support::RedfishSimAction;
use carbide_uuid::vpc::VpcId;
use forge::forge_server::Forge;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use model::machine::{ManagedHostState, ManagedHostStateSnapshot};
use model::test_support::ManagedHostConfig;
use rpc::{Metadata, forge};

use crate::cfg::file::{FnnConfig, FnnRoutingProfileConfig, PrefixFilterPolicyEntry};
use crate::test_support::fixture_config::{FixtureDefault as _, ManagedHostConfigExt as _};
use crate::test_support::mac_address_pool::HOST_NON_DPU_MAC_ADDRESS_POOL;
use crate::test_support::network_segment::{FIXTURE_TENANT_ORG_ID, create_default_flat_vpc};
use crate::tests::common;
use crate::tests::common::api_fixtures;
use crate::tests::common::api_fixtures::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_2, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_3,
    FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS, FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY,
    create_admin_network_segment, create_host_inband_network_segment, create_network_segment,
    create_tenant_network_segment, create_underlay_network_segment,
};
use crate::tests::common::api_fixtures::{TestEnv, TestEnvOverrides};
use crate::tests::common::rpc_builder::{DhcpDiscovery, VpcCreationRequest};

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
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_3.network(),
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_3.prefix(),
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
            site_prefixes: Some(site_prefixes),
            create_network_segments: Some(false),
            ..Default::default()
        },
    )
    .await;

    let vpc_1 = env
        .api
        .create_vpc(
            VpcCreationRequest::builder(FIXTURE_TENANT_ORG_ID)
                .metadata(Metadata {
                    name: "test vpc 1".to_string(),
                    ..Default::default()
                })
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    let vpc_2 = env
        .api
        .create_vpc(
            VpcCreationRequest::builder(FIXTURE_TENANT_ORG_ID)
                .metadata(Metadata {
                    name: "test vpc 2".to_string(),
                    ..Default::default()
                })
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    // Create Flat VPCs for zero-DPU allocation. In the normal path the
    // HostInband segments are unbound and the instance address carries the
    // logical VPC. The "different VPCs" variant deliberately binds segments
    // to conflicting VPCs so allocation is rejected.
    let flat_vpc_1_id =
        common::api_fixtures::network_segment::create_default_flat_vpc(&env.api, "test flat vpc 1")
            .await;
    let flat_vpc_2_id =
        common::api_fixtures::network_segment::create_default_flat_vpc(&env.api, "test flat vpc 2")
            .await;

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

    create_host_inband_network_segment(
        &env.api,
        options
            .host_inband_segments_in_different_vpcs
            .then_some(flat_vpc_1_id),
    )
    .await;
    // Second HostInband segment is normally unbound too, or bound to a
    // different Flat VPC if the test wants to assert allocation rejection.
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
        options
            .host_inband_segments_in_different_vpcs
            .then_some(flat_vpc_2_id),
        true,
    )
    .await;

    // Get the tenant segment into ready state
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    env
}

async fn vpc_id_by_name(env: &TestEnv, name: &str) -> VpcId {
    let mut txn = env.db_txn().await;
    let vpcs = db::vpc::find_by_name(txn.as_mut(), name).await.unwrap();
    assert_eq!(vpcs.len(), 1, "expected exactly one VPC named {name}");
    vpcs[0].id
}

async fn default_flat_vpc_id(env: &TestEnv) -> VpcId {
    vpc_id_by_name(env, "test flat vpc 1").await
}

#[crate::sqlx_test]
async fn test_allocate_instance_rejects_interface_anycast_prefix_outside_vpc_profile(
    pool: sqlx::PgPool,
) {
    let profile_type = "ANYCAST_ALLOC_TEST";
    let tenant_org = "anycast-alloc-test";

    // Configure the operator-owned VPC profile with one allowed anycast prefix.
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::default().with_fnn_config(Some(FnnConfig {
            admin_vpc: None,
            common_internal_route_target: None,
            additional_route_target_imports: vec![],
            routing_profiles: HashMap::from([(
                profile_type.to_string(),
                FnnRoutingProfileConfig {
                    internal: true,
                    access_tier: 0,
                    allowed_anycast_prefixes: vec![PrefixFilterPolicyEntry {
                        prefix: "192.0.2.0/24".parse().unwrap(),
                    }],
                    ..Default::default()
                },
            )]),
            use_vpc_vrf_loopback: false,
        })),
    )
    .await;

    // Create a tenant and FNN VPC that use that routing profile.
    env.api
        .create_tenant(tonic::Request::new(forge::CreateTenantRequest {
            organization_id: tenant_org.to_string(),
            routing_profile_type: Some(profile_type.to_string()),
            metadata: Some(forge::Metadata {
                name: tenant_org.to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap();
    let segment_id = env
        .create_vpc_and_tenant_segment_with_vpc_details(
            VpcCreationRequest::builder(tenant_org)
                .metadata(Metadata {
                    name: "anycast allocation vpc".to_string(),
                    ..Default::default()
                })
                .network_virtualization_type(forge::VpcVirtualizationType::Fnn as i32)
                .routing_profile_type(profile_type.to_string())
                .rpc(),
        )
        .await;

    // Request an interface anycast prefix outside the owning VPC profile.
    let mut network_config =
        common::api_fixtures::instance::single_interface_network_config(segment_id);
    network_config.interfaces[0].routing_profile = Some(forge::InstanceInterfaceRoutingProfile {
        allowed_anycast_prefixes: vec![forge::PrefixFilterPolicyEntry {
            prefix: "198.51.100.0/24".to_string(),
        }],
    });

    // Allocate the instance and verify invalid tenant input is rejected before persistence.
    let mh = api_fixtures::create_managed_host(&env).await;
    let err = env
        .api
        .allocate_instance(tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(mh.host().id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: tenant_org.to_string(),
                    tenant_keyset_ids: vec![],
                    hostname: None,
                }),
                os: Some(common::api_fixtures::instance::default_os_config()),
                network: Some(network_config),
                infiniband: None,
                network_security_group_id: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }))
        .await
        .expect_err("interface anycast prefix outside VPC profile should be rejected");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message()
            .contains("routing_profile.allowed_anycast_prefixes")
    );
}

/// Zero-DPU instance allocation that supplies explicit interfaces (instead
/// of `auto: true`) must be rejected. The requirement on zero-DPU hosts is
/// to send auto:true with empty interfaces, and we populate them. There's
/// no supported path for a tenant to configure interfaces on their own.
#[crate::sqlx_test]
async fn test_zero_dpu_instance_allocation_rejects_explicit_interfaces(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig::zero_dpu();

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
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                network_security_group_id: None,
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![forge::InstanceInterfaceConfig {
                        function_type: forge::InterfaceFunctionType::Physical as i32,
                        network_segment_id: Some(host_inband_segment.id),
                        network_details: None,
                        device: None,
                        device_instance: 0u32,
                        virtual_function_id: None,
                        ip_address: None,
                        ipv6_interface_config: None,
                        routing_profile: None,
                    }],
                    #[allow(deprecated)]
                    auto: false,
                    auto_config: None,
                }),
                infiniband: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await;

    let err = instance.expect_err("zero-DPU allocation without auto: true must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "got: {err}");
    assert!(
        err.message().contains("auto"),
        "error should mention auto, got: {}",
        err.message()
    );
    Ok(())
}

/// The `auto: true` path: a zero-DPU host with one HostInband segment, allocated
/// with empty interfaces and `auto: true`. NICo resolves the segment from the
/// host snapshot and stores the resolved interface internally. What the caller
/// sees on the wire is stripped back to `{ auto: true, vpc_id, interfaces: [] }`,
/// while `instance.status.network.interfaces` reflects the resolved details.
#[crate::sqlx_test]
async fn test_zero_dpu_instance_allocation_auto(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig::zero_dpu();

    // Ingest zero DPU host
    let zero_dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;
    let flat_vpc_id = default_flat_vpc_id(&env).await;

    let host_inband_segment =
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "HOST_INBAND")
            .await?;

    let instance = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                network_security_group_id: None,
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![],
                    #[allow(deprecated)]
                    auto: true,
                    auto_config: Some(forge::InstanceNetworkAutoConfig {
                        vpc_id: Some(flat_vpc_id),
                    }),
                }),
                infiniband: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await
    .expect("zero-DPU instance allocation with auto: true should succeed")
    .into_inner();
    let instance_id = instance.id.expect("allocated instance should have an id");

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

    // Flat VPCs are operator-managed; tenant status should not wait for a NICo
    // data-plane readiness signal after allocation.
    let tenant_status = instance
        .status
        .as_ref()
        .and_then(|status| status.tenant.as_ref())
        .expect("allocated instance should include tenant status");
    assert_eq!(
        forge::TenantState::try_from(tenant_status.state).unwrap(),
        forge::TenantState::Ready
    );

    // On the wire: `auto: true` with empty interfaces. The resolved
    // interface lives in status, not config, which takes place as
    // part of `into_external_view()`.
    let network = instance.config.unwrap().network.unwrap();
    #[allow(deprecated)]
    let auto = network.auto;
    assert!(auto, "auto must round-trip back to the caller as true");
    assert_eq!(
        network.auto_config.as_ref().unwrap().vpc_id,
        Some(flat_vpc_id)
    );
    assert!(
        network.interfaces.is_empty(),
        "external view of an auto config must have empty interfaces, got: {:?}",
        network.interfaces
    );

    let status_interfaces = instance.status.unwrap().network.unwrap().interfaces;
    assert_eq!(
        status_interfaces.len(),
        1,
        "status should reflect one resolved interface for the single HostInband segment"
    );
    assert_eq!(status_interfaces[0].vpc_id, Some(flat_vpc_id));

    let mut txn = env.db_txn().await;
    let address = db::instance_address::find_by_instance_id_and_segment_id(
        txn.as_mut(),
        &instance_id,
        &host_inband_segment.id,
    )
    .await?
    .expect("zero-DPU allocation should persist an instance address");
    assert_eq!(address.vpc_id, flat_vpc_id);
    Ok(())
}

#[crate::sqlx_test]
async fn test_zero_dpu_auto_update_rejects_host_inband_segment_bound_to_different_vpc(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let zero_dpu_host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::zero_dpu()).await?;
    let flat_vpc_id = default_flat_vpc_id(&env).await;

    let host_inband_segment =
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "HOST_INBAND")
            .await?;

    let instance = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                network_security_group_id: None,
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![],
                    #[allow(deprecated)]
                    auto: true,
                    auto_config: Some(forge::InstanceNetworkAutoConfig {
                        vpc_id: Some(flat_vpc_id),
                    }),
                }),
                infiniband: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
            }),
            instance_id: None,
            metadata: Some(Metadata {
                name: "zero-dpu-auto-update".to_string(),
                ..Default::default()
            }),
            allow_unhealthy_machine: false,
        }),
    )
    .await
    .expect("initial zero-DPU auto allocation should succeed")
    .into_inner();

    let conflicting_vpc_id = vpc_id_by_name(&env, "test flat vpc 2").await;
    env.api
        .attach_network_segment_to_vpc(tonic::Request::new(
            forge::AttachNetworkSegmentToVpcRequest {
                network_segment_id: Some(host_inband_segment.id),
                vpc_id: Some(conflicting_vpc_id),
                allow_replace: false,
            },
        ))
        .await
        .expect("operator should be able to bind the HostInband segment after allocation");

    let result = env
        .api
        .update_instance_config(tonic::Request::new(forge::InstanceConfigUpdateRequest {
            instance_id: instance.id,
            if_version_match: None,
            config: instance.config,
            metadata: instance.metadata,
        }))
        .await;

    let err = result
        .expect_err("auto-network update must reject HostInband segments bound to a different VPC");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(
        err.message()
            .contains("shared flat segments must be left unbound"),
        "unexpected error message: {}",
        err.message()
    );

    Ok(())
}

/// Zero-DPU instance allocation without `auto: true` (and without any network
/// config at all) is the previous "send nothing" path, which was mainly because
/// it worked, not because it was decided to be that way. Lets make sure it
/// doesn't work anymore by accident.
#[crate::sqlx_test]
async fn test_zero_dpu_instance_allocation_rejects_missing_auto(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig::zero_dpu();

    let zero_dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;

    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: None,
                infiniband: None,
                nvlink: None,
                spxconfig: None,
                network_security_group_id: None,
                dpu_extension_services: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await;

    let err = result
        .expect_err("zero-DPU allocation with no network config (no auto signal) must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "got: {err}");
    Ok(())
}

/// `auto: true` on a zero-DPU host also needs a logical Flat VPC ID. The
/// HostInband segment may be unbound, so the instance address needs this
/// request-level VPC to preserve tenant intent.
#[crate::sqlx_test]
async fn test_zero_dpu_instance_allocation_rejects_missing_vpc_id(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig::zero_dpu();

    let zero_dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;

    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![],
                    #[allow(deprecated)]
                    auto: true,
                    auto_config: Some(forge::InstanceNetworkAutoConfig { vpc_id: None }),
                }),
                infiniband: None,
                nvlink: None,
                spxconfig: None,
                network_security_group_id: None,
                dpu_extension_services: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await;

    let err = result.expect_err("zero-DPU auto allocation without VPC ID must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "got: {err}");
    assert!(
        err.message().contains("vpc_id"),
        "error should mention vpc_id, got: {}",
        err.message()
    );
    Ok(())
}

#[crate::sqlx_test]
async fn test_zero_dpu_instance_allocation_rejects_non_flat_vpc_id(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig::zero_dpu();

    let zero_dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;
    let etv_vpc_id = vpc_id_by_name(&env, "test vpc 1").await;

    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![],
                    #[allow(deprecated)]
                    auto: true,
                    auto_config: Some(forge::InstanceNetworkAutoConfig {
                        vpc_id: Some(etv_vpc_id),
                    }),
                }),
                infiniband: None,
                nvlink: None,
                spxconfig: None,
                network_security_group_id: None,
                dpu_extension_services: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await;

    let err = result.expect_err("zero-DPU auto allocation into non-Flat VPC must be rejected");
    assert_eq!(err.code(), tonic::Code::FailedPrecondition, "got: {err}");
    assert!(
        err.message().contains("flat"),
        "error should mention Flat VPC requirement, got: {}",
        err.message()
    );
    Ok(())
}

/// `auto: true` on a multi-NIC zero-DPU host must resolve to one resolved
/// interface per HostInband segment, with each interface inheriting the
/// host's already-assigned IP for that segment.
#[crate::sqlx_test]
async fn test_zero_dpu_instance_allocation_auto_multi_segment(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig {
        dpus: vec![],
        non_dpu_macs: vec![
            HOST_NON_DPU_MAC_ADDRESS_POOL.allocate(),
            HOST_NON_DPU_MAC_ADDRESS_POOL.allocate(),
        ],
        ..ManagedHostConfig::default()
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
    let flat_vpc_id = default_flat_vpc_id(&env).await;

    let instance = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![],
                    #[allow(deprecated)]
                    auto: true,
                    auto_config: Some(forge::InstanceNetworkAutoConfig {
                        vpc_id: Some(flat_vpc_id),
                    }),
                }),
                infiniband: None,
                nvlink: None,
                spxconfig: None,
                network_security_group_id: None,
                dpu_extension_services: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await
    .expect("zero-DPU instance allocation with auto: true should succeed on a multi-NIC host")
    .into_inner();

    let (host_inband_segment_1, host_inband_segment_2) = (
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "HOST_INBAND")
            .await?,
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "HOST_INBAND_2")
            .await?,
    );

    // On the wire: auto: true with empty interfaces, regardless of how many
    // HostInband segments resolved. The resolved-per-interface details
    // surface in status, not config.
    let rpc_network = instance.config.unwrap().network.unwrap();
    #[allow(deprecated)]
    let auto = rpc_network.auto;
    assert!(auto, "auto must round-trip back as true");
    assert_eq!(
        rpc_network.auto_config.as_ref().unwrap().vpc_id,
        Some(flat_vpc_id)
    );
    assert!(
        rpc_network.interfaces.is_empty(),
        "external view of an auto config must have empty interfaces, got: {:?}",
        rpc_network.interfaces
    );

    let status_interfaces = instance.status.unwrap().network.unwrap().interfaces;
    assert_eq!(
        status_interfaces.len(),
        2,
        "status should reflect both resolved HostInband interfaces"
    );
    assert!(
        status_interfaces
            .iter()
            .all(|interface| interface.vpc_id == Some(flat_vpc_id)),
        "all resolved HostInband status interfaces should expose the requested Flat VPC"
    );

    // Internal model: the persisted config has the fully-resolved interfaces.
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

    assert!(
        instance_snapshot.config.network.auto_config.is_some(),
        "internal model must preserve auto: true through resolution"
    );
    assert_eq!(
        instance_snapshot.config.network.interfaces.len(),
        2,
        "internal model must hold the fully-resolved interfaces, not just the wire-stripped view"
    );
    assert_eq!(
        instance_snapshot.config.network.auto_config.unwrap().vpc_id,
        flat_vpc_id
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
    assert_eq!(interface_in_segment_1.vpc_id, Some(flat_vpc_id));
    assert!(
        !interface_in_segment_2.ip_addrs.is_empty(),
        "Instance interface in segment 2 should have IP addresses assigned"
    );
    assert_eq!(interface_in_segment_2.vpc_id, Some(flat_vpc_id));

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

    let mut txn = env.db_txn().await;
    for segment_id in [host_inband_segment_1.id, host_inband_segment_2.id] {
        let address = db::instance_address::find_by_instance_id_and_segment_id(
            txn.as_mut(),
            &instance_snapshot.id,
            &segment_id,
        )
        .await?
        .expect("zero-DPU allocation should persist an instance address per HostInband segment");
        assert_eq!(address.vpc_id, flat_vpc_id);
    }

    Ok(())
}

/// Updating an auto-networked instance re-resolves its interface set from the
/// host's current HostInband segments, so an operator-added segment (with the
/// host DHCP'ing a NIC on it) flows into the instance on its next config
/// update. The re-resolved multi-interface config must pass validation: a
/// resolved auto interface is identified by its segment, not by a shared
/// per-device function-id bucket.
#[crate::sqlx_test]
async fn test_zero_dpu_auto_update_absorbs_added_host_inband_segment(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig {
        dpus: vec![],
        non_dpu_macs: vec![
            HOST_NON_DPU_MAC_ADDRESS_POOL.allocate(),
            HOST_NON_DPU_MAC_ADDRESS_POOL.allocate(),
            HOST_NON_DPU_MAC_ADDRESS_POOL.allocate(),
        ],
        ..ManagedHostConfig::default()
    };

    // Ingest a zero-DPU host with NICs on both fixture HostInband segments.
    // The third NIC stays segment-less for now; its segment arrives mid-test.
    let zero_dpu_host = api_fixtures::site_explorer::new_mock_host(&env, config.clone())
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
    let flat_vpc_id = default_flat_vpc_id(&env).await;

    let instance = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![],
                    #[allow(deprecated)]
                    auto: true,
                    auto_config: Some(forge::InstanceNetworkAutoConfig {
                        vpc_id: Some(flat_vpc_id),
                    }),
                }),
                infiniband: None,
                nvlink: None,
                spxconfig: None,
                network_security_group_id: None,
                dpu_extension_services: None,
            }),
            instance_id: None,
            metadata: Some(Metadata {
                name: "zero-dpu-auto-absorbs-segment".to_string(),
                ..Default::default()
            }),
            allow_unhealthy_machine: false,
        }),
    )
    .await
    .expect("initial zero-DPU auto allocation should succeed on a multi-NIC host")
    .into_inner();
    let instance_id = instance.id.expect("allocated instance should have an id");

    // Network config updates only run against a Ready instance.
    env.run_machine_state_controller_iteration_until_state_matches(
        &zero_dpu_host.host_snapshot.id,
        30,
        ManagedHostState::Assigned {
            instance_state: model::machine::InstanceState::Ready,
        },
    )
    .await;

    // The operator adds a third HostInband segment, and the host gets a
    // lease on it with its spare NIC.
    let host_inband_3_id = create_network_segment(
        &env.api,
        "HOST_INBAND_3",
        &format!(
            "{}/{}",
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_3.network(),
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_3.prefix()
        ),
        &FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_3
            .ip()
            .to_string(),
        forge::NetworkSegmentType::HostInband,
        None,
        true,
    )
    .await;
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    env.api
        .discover_dhcp(
            DhcpDiscovery::builder(
                config.non_dpu_macs[2],
                FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_3.ip(),
            )
            .vendor_string("Bluefield")
            .tonic_request(),
        )
        .await
        .expect("the spare host NIC should get a lease on the new HostInband segment");

    // Re-send the instance's own external-view config (`auto` + empty
    // interfaces); the update re-resolves it from the host's current
    // segments and stages the three-interface config.
    env.api
        .update_instance_config(tonic::Request::new(forge::InstanceConfigUpdateRequest {
            instance_id: instance.id,
            if_version_match: None,
            config: instance.config.clone(),
            metadata: instance.metadata.clone(),
        }))
        .await
        .expect("the auto update must absorb the added HostInband segment");

    let mut txn = env.db_txn().await;
    let db_instance = db::instance::find_by_id(txn.as_mut(), instance_id)
        .await?
        .expect("instance should still exist after the update");
    let pending = db_instance
        .update_network_config_request
        .expect("the auto update should stage a re-resolved network config");
    assert_eq!(
        pending.new_config.interfaces.len(),
        3,
        "the staged config should resolve one interface per HostInband segment"
    );
    let (host_inband_segment_1, host_inband_segment_2) = (
        db::network_segment::find_by_name(txn.as_mut(), "HOST_INBAND").await?,
        db::network_segment::find_by_name(txn.as_mut(), "HOST_INBAND_2").await?,
    );
    for segment_id in [
        host_inband_segment_1.id,
        host_inband_segment_2.id,
        host_inband_3_id,
    ] {
        assert_eq!(
            pending
                .new_config
                .interfaces
                .iter()
                .filter(|i| i.network_segment_id == Some(segment_id))
                .count(),
            1,
            "the staged config should hold exactly one interface for segment {segment_id}"
        );
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_reject_single_dpu_instance_allocation_no_network_config(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;

    // Create single DPU host
    let single_dpu_host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default()).await?;

    // Create an instance on a host with DPUs, without specifying a network config, which is not allowed
    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(single_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: None,
                infiniband: None,
                nvlink: None,
                spxconfig: None,
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
    let single_dpu_host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default()).await?;

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
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![forge::InstanceInterfaceConfig {
                        function_type: forge::InterfaceFunctionType::Physical as i32,
                        network_segment_id: Some(host_inband_segment.id),
                        network_details: None,
                        device: None,
                        device_instance: 0u32,
                        virtual_function_id: None,
                        ip_address: None,
                        ipv6_interface_config: None,
                        routing_profile: None,
                    }],
                    #[allow(deprecated)]
                    auto: false,
                    auto_config: None,
                }),
                network_security_group_id: None,
                dpu_extension_services: None,
                infiniband: None,
                nvlink: None,
                spxconfig: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await;

    match result {
        // The rejection can come from two distinct gates:
        //   - InvalidArgument from segment-type rules
        //   - FailedPrecondition from the DPU-host-vs-Flat-VPC gate
        // Both are valid rejections of "DPU host instance referencing a
        // HostInband segment"; the test only cares that allocation fails.
        Err(e)
            if matches!(
                e.code(),
                tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition
            ) => {}
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
        ..ManagedHostConfig::default()
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
            Ok::<ManagedHostStateSnapshot, eyre::Report>(
                db::managed_host::load_snapshot(
                    &mut mock.test_env.db_reader(),
                    &machine_id,
                    Default::default(),
                )
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
    let flat_vpc_id = default_flat_vpc_id(&env).await;

    // Allocate an auto-networked instance into the first Flat VPC. The second
    // HostInband segment is deliberately bound to a different Flat VPC, so
    // the shared-segment allocation path must reject the conflict.
    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                network_security_group_id: None,
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![],
                    #[allow(deprecated)]
                    auto: true,
                    auto_config: Some(forge::InstanceNetworkAutoConfig {
                        vpc_id: Some(flat_vpc_id),
                    }),
                }),
                infiniband: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await;

    match result {
        Err(e) if e.code() == tonic::Code::FailedPrecondition => {}
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
    let single_dpu_host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default()).await?;

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
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![forge::InstanceInterfaceConfig {
                        function_type: forge::InterfaceFunctionType::Physical as i32,
                        network_segment_id: Some(tenant_segment.id),
                        network_details: None,
                        device: None,
                        device_instance: 0,
                        virtual_function_id: Some(0),
                        ip_address: None,
                        ipv6_interface_config: None,
                        routing_profile: None,
                    }],
                    #[allow(deprecated)]
                    auto: false,
                    auto_config: None,
                }),
                infiniband: None,
                nvlink: None,
                spxconfig: None,
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

/// Make sure we take care of setting the boot order for zero DPU hosts.
/// This test ingests a zero-DPU host and drives things forward. We record
/// each Redfish `is_boot_order_setup` call, and then then assert at least
/// one such call was made. If something happens, we'll dump all recorded
/// Redfish actions to provide some feedback about where the state machine
/// left off/got stuck.
#[crate::sqlx_test]
async fn test_zero_dpu_host_verifies_boot_order_during_platform_configuration(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;

    let timepoint = env.redfish_sim.timepoint();

    // Ingest zero-DPU host. site-explorer runs it through the machine state
    // controller, which hits HostInit -> HostPlatformConfiguration, where
    // `CheckHostConfig` lives.
    let config = ManagedHostConfig::zero_dpu();
    let zero_dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;

    // Advance the state controller until the host converges on Ready.
    // `new_host` itself drives most of the transitions through HostInit
    // (including SetBootOrder to CheckBootOrder, where `is_boot_order_setup`
    // is called).
    env.run_machine_state_controller_iteration_until_state_matches(
        &zero_dpu_host.host_snapshot.id,
        10,
        ManagedHostState::Ready,
    )
    .await;

    let actions = env.redfish_sim.actions_since(&timepoint);
    let all_actions = actions.all_hosts();

    assert!(
        all_actions
            .iter()
            .any(|a| matches!(a, RedfishSimAction::IsBootOrderSetup { .. })),
        "Expected at least one Redfish is_boot_order_setup call during the zero DPU host HostPlatformConfiguration flow. host id: {}. Recorded actions: {:?}",
        zero_dpu_host.host_snapshot.id,
        all_actions,
    );

    Ok(())
}

/// a zero-DPU host has no DPU to handle overlay/tenant networking, so an
/// instance allocation request that puts a non-DPU (zero-DPU) host NIC
/// interface on a tenant (DPU-managed) segment must be rejected up front.
#[crate::sqlx_test]
async fn test_reject_zero_dpu_instance_with_tenant_network_segment(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig::zero_dpu();

    let zero_dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;

    let tenant_segment =
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "TENANT").await?;

    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                network_security_group_id: None,
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![forge::InstanceInterfaceConfig {
                        function_type: forge::InterfaceFunctionType::Physical as i32,
                        network_segment_id: Some(tenant_segment.id),
                        network_details: None,
                        device: None,
                        device_instance: 0u32,
                        virtual_function_id: None,
                        ip_address: None,
                        ipv6_interface_config: None,
                        routing_profile: None,
                    }],
                    #[allow(deprecated)]
                    auto: false,
                    auto_config: None,
                }),
                infiniband: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
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
            "Expected zero-DPU host to reject tenant-segment instance allocation (no DPU to manage overlay networking), got: {result:?}"
        ),
    };

    Ok(())
}

// A zero-DPU instance must surface its underlay IP, MAC, and gateway/prefix
// to the tenant via the standard `Instance::status::network::interfaces`
// path.
//
// This works because, behind the scenes, instance allocation auto-populates
// `config.network.interfaces` with the host's HostInband segment when the
// tenant submits no network config (`add_inband_interfaces_to_config`) and
// allocates IPs into `ip_addrs` (`with_allocated_ips`). When the Instance
// is read, `InstanceNetworkStatus::from_config_and_observations` sees no
// DPU observations + `config.is_host_inband()` and falls into
// `synchronized_from_host_interfaces`, which synthesizes per-interface
// status from the config. So the same `status.network.interfaces[i]`
// tenant machines with DPUs read from also carries the underlay IP for
// zero-DPU tenants.
#[crate::sqlx_test]
async fn test_zero_dpu_instance_surfaces_underlay_ip_in_status(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig::zero_dpu();
    let zero_dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;
    let flat_vpc_id = default_flat_vpc_id(&env).await;

    crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                network_security_group_id: None,
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                // Tenant signals `auto: true` with no interfaces; NICo
                // resolves the HostInband segment from the host snapshot.
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![],
                    #[allow(deprecated)]
                    auto: true,
                    auto_config: Some(forge::InstanceNetworkAutoConfig {
                        vpc_id: Some(flat_vpc_id),
                    }),
                }),
                infiniband: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await
    .expect("instance allocation should have succeeded")
    .into_inner();

    let response = env
        .api
        .find_instance_by_machine_id(tonic::Request::new(zero_dpu_host.host_snapshot.id))
        .await?
        .into_inner();
    let instance = response
        .instances
        .first()
        .expect("zero-DPU host should have one allocated instance");

    let status = instance
        .status
        .as_ref()
        .expect("instance.status should be set");
    let net_status = status
        .network
        .as_ref()
        .expect("status.network should be set");

    assert_eq!(
        net_status.configs_synced,
        forge::SyncState::Synced as i32,
        "host-inband interfaces don't need DPU-agent observations, so the status should be synthesized from config and report Synced immediately"
    );

    assert_eq!(
        net_status.interfaces.len(),
        1,
        "expected one synthesized interface mirroring the auto-filled HostInband config entry",
    );
    assert_eq!(net_status.interfaces[0].vpc_id, Some(flat_vpc_id));
    let iface = &net_status.interfaces[0];
    assert!(
        !iface.addresses.is_empty(),
        "underlay IP must be visible to the tenant via status.network.interfaces[0].addresses; got: {iface:?}",
    );
    assert!(
        iface.mac_address.is_some(),
        "underlay MAC must be visible to the tenant via status.network.interfaces[0].mac_address; got: {iface:?}",
    );
    assert_eq!(
        iface.gateways.len(),
        iface.addresses.len(),
        "one gateway should be reported per address; got: {iface:?}",
    );
    assert_eq!(
        iface.prefixes.len(),
        iface.addresses.len(),
        "one prefix should be reported per address; got: {iface:?}",
    );

    // On-the-wire contract for auto: config.interfaces is empty (preserved
    // verbatim from the request), while status.interfaces carries the
    // resolved per-interface details. The HostInband segment that drove
    // resolution shows up in `instance_network_restrictions` rather than the
    // config.
    let cfg_network = instance
        .config
        .as_ref()
        .and_then(|c| c.network.as_ref())
        .expect("instance.config.network should be set");
    #[allow(deprecated)]
    let auto = cfg_network.auto;
    assert!(auto, "auto must round-trip back to the caller as true");
    assert_eq!(
        cfg_network.auto_config.as_ref().unwrap().vpc_id,
        Some(flat_vpc_id)
    );
    assert!(
        cfg_network.interfaces.is_empty(),
        "external view of an auto config must have empty interfaces; got: {:?}",
        cfg_network.interfaces,
    );

    Ok(())
}

// Extension services run on the DPU agent; on a zero-DPU host there's no DPU
// to schedule them on, so the allocation should be rejected up front (rather
// than letting the instance get stuck reporting "Unknown" extension service
// status forever).
#[crate::sqlx_test]
async fn test_reject_zero_dpu_instance_with_extension_services(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let config = ManagedHostConfig::zero_dpu();

    let zero_dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;

    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                network_security_group_id: None,
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: None,
                infiniband: None,
                dpu_extension_services: Some(forge::InstanceDpuExtensionServicesConfig {
                    service_configs: vec![forge::InstanceDpuExtensionServiceConfig {
                        service_id: "test-service".to_string(),
                        version: "1.0.0".to_string(),
                    }],
                }),
                nvlink: None,
                spxconfig: None,
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
            "Expected zero-DPU host to reject instance allocation with dpu_extension_services (no DPU to schedule them on), got: {result:?}"
        ),
    };

    Ok(())
}

/// `auto: true` combined with a non-empty `interfaces` list is structurally
/// invalid: auto is mutually exclusive with caller-supplied interfaces.
#[crate::sqlx_test]
async fn test_instance_allocation_rejects_auto_with_explicit_interfaces(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let vpc_id = create_default_flat_vpc(&env.api, "flat-vpc").await;
    let config = ManagedHostConfig::zero_dpu();

    let zero_dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;
    let host_inband_segment =
        db::network_segment::find_by_name(env.pool.begin().await?.deref_mut(), "HOST_INBAND")
            .await?;

    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(zero_dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                network_security_group_id: None,
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![forge::InstanceInterfaceConfig {
                        function_type: forge::InterfaceFunctionType::Physical as i32,
                        network_segment_id: Some(host_inband_segment.id),
                        network_details: None,
                        device: None,
                        device_instance: 0u32,
                        virtual_function_id: None,
                        ip_address: None,
                        ipv6_interface_config: None,
                        routing_profile: None,
                    }],
                    #[allow(deprecated)]
                    auto: true,
                    auto_config: Some(forge::InstanceNetworkAutoConfig {
                        vpc_id: Some(vpc_id),
                    }),
                }),
                infiniband: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await;

    let err = result.expect_err("auto: true + non-empty interfaces must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "got: {err}");
    assert!(
        err.message().contains("auto"),
        "error should mention auto, got: {}",
        err.message()
    );
    Ok(())
}

/// `auto: true` is rejected on a host that has DPUs. The auto-resolution path
/// is specifically for zero-DPU hosts; DPU-managed hosts are expected to
/// enumerate their tenant overlay interfaces explicitly.
#[crate::sqlx_test]
async fn test_instance_allocation_rejects_auto_on_dpu_host(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_for_instance_allocation(pool.clone(), None).await;
    let vpc_id = create_default_flat_vpc(&env.api, "flat-vpc").await;
    // Default ManagedHostConfig has one DPU.
    let config = ManagedHostConfig::default().with_dpu_count(1);

    let dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;

    let result = crate::handlers::instance::allocate(
        env.api.as_ref(),
        tonic::Request::new(forge::InstanceAllocationRequest {
            machine_id: Some(dpu_host.host_snapshot.id),
            instance_type_id: None,
            config: Some(forge::InstanceConfig {
                tenant: Some(forge::TenantConfig {
                    tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
                    hostname: None,
                    tenant_keyset_ids: vec![],
                }),
                network_security_group_id: None,
                os: Some(forge::InstanceOperatingSystemConfig {
                    phone_home_enabled: false,
                    run_provisioning_instructions_on_every_boot: false,
                    user_data: None,
                    variant: Some(forge::instance_operating_system_config::Variant::Ipxe(
                        forge::InlineIpxe {
                            ipxe_script: "exit".to_string(),
                        },
                    )),
                }),
                network: Some(forge::InstanceNetworkConfig {
                    interfaces: vec![],
                    #[allow(deprecated)]
                    auto: true,
                    auto_config: Some(forge::InstanceNetworkAutoConfig {
                        vpc_id: Some(vpc_id),
                    }),
                }),
                infiniband: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }),
    )
    .await;

    let err = result.expect_err("auto: true on a DPU host must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "got: {err}");
    assert!(
        err.message().contains("DPU") || err.message().contains("zero-DPU"),
        "error should mention DPU semantics, got: {}",
        err.message()
    );
    Ok(())
}
