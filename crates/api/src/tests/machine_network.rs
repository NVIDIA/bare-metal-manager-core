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
use std::time::SystemTime;

use ::rpc::forge::{
    CreateDpuExtensionServiceRequest, DpuExtensionServiceType, DpuNetworkStatus,
    InstanceDpuExtensionServiceConfig, InstanceDpuExtensionServicesConfig,
    ManagedHostNetworkConfigRequest, ManagedHostNetworkStatusRequest,
};
use common::api_fixtures::network_segment::{
    FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS, create_network_segment, create_tenant_network_segment,
};
use common::api_fixtures::{self, create_managed_host, dpu, network_configured_with_health};
use forge_secrets::credentials::{BgpCredentialType, CredentialKey, Credentials};
use mac_address::MacAddress;
use model::address_selection_strategy::AddressSelectionStrategy;
use model::allocation_type::AllocationType;
use model::machine::network::ManagedHostQuarantineMode;
use model::machine_interface_address::MachineInterfaceAssociation;
use model::network_segment::NetworkSegmentType;
use rpc::Metadata;
use rpc::forge::forge_server::Forge;

use crate::cfg::file::{
    AdminFnnConfig, FnnConfig, FnnRoutingProfileConfig, PrefixFilterPolicyEntry, RouteTargetConfig,
};
use crate::tests::common;
use crate::tests::common::api_fixtures::TestEnvOverrides;
use crate::tests::common::api_fixtures::site_explorer::MockExploredHost;
use crate::tests::common::rpc_builder::VpcCreationRequest;

#[crate::sqlx_test]
async fn test_managed_host_network_config(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let mh = dpu::create_dpu_machine_in_waiting_for_network_install(&env, &host_config).await;
    let dpu_machine_id = mh.dpu().id;

    // Fetch a Machines network config
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await;

    assert!(response.is_ok());
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_with_sitewide_bgp_password(pool: sqlx::PgPool) {
    // Enable site-wide DPU BGP passwords in runtime config.
    let mut config = api_fixtures::get_config();
    config.bgp_leaf_session_password = Some(crate::cfg::file::BgpLeafSessionPassword::SiteWide);

    let env =
        api_fixtures::create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config))
            .await;

    // Seed the site-wide DPU BGP credential.
    env.api
        .credential_manager
        .set_credentials(
            &CredentialKey::Bgp {
                credential_type: BgpCredentialType::SiteWideLeafPassword,
            },
            &Credentials::UsernamePassword {
                username: "".to_string(),
                password: "test-bgp-password".to_string(),
            },
        )
        .await
        .unwrap();

    // Create a DPU that can request managed host network config.
    let host_config = env.managed_host_config();
    let dpu_machine_id = dpu::create_dpu_machine(&env, &host_config).await;

    // Verify the handler returns the configured site-wide BGP password.
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        response.bgp_leaf_session_password,
        Some("test-bgp-password".to_string())
    );
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_includes_routing_profile_prefix_lists(
    pool: sqlx::PgPool,
) {
    let profile_type = "ROUTE_LEAK_TEST";
    let expected_leaks = vec!["10.42.0.0/24".to_string(), "2001:db8:42::/64".to_string()];
    let expected_allowed_anycast_prefixes =
        vec!["192.0.2.0/24".to_string(), "2001:db8:99::/64".to_string()];

    // Configure an FNN routing profile with explicit accepted underlay leaks.
    let env = api_fixtures::create_test_env_with_overrides(
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
                    accepted_leaks_from_underlay: expected_leaks
                        .iter()
                        .map(|prefix| PrefixFilterPolicyEntry {
                            prefix: prefix.parse().unwrap(),
                        })
                        .collect(),
                    allowed_anycast_prefixes: expected_allowed_anycast_prefixes
                        .iter()
                        .map(|prefix| PrefixFilterPolicyEntry {
                            prefix: prefix.parse().unwrap(),
                        })
                        .collect(),
                    ..Default::default()
                },
            )]),
            use_vpc_vrf_loopback: false,
        })),
    )
    .await;

    // Create a tenant and FNN VPC using that routing profile.
    let tenant = env
        .api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: "route-leak-test".to_string(),
            routing_profile_type: Some(profile_type.to_string()),
            metadata: Some(rpc::forge::Metadata {
                name: "route-leak-test".to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .tenant
        .unwrap();

    let segment_id = env
        .create_vpc_and_tenant_segment_with_vpc_details(
            VpcCreationRequest::builder(tenant.organization_id.as_str())
                .metadata(Metadata {
                    name: "route leak vpc".to_string(),
                    ..Default::default()
                })
                .network_virtualization_type(rpc::forge::VpcVirtualizationType::Fnn as i32)
                .routing_profile_type(profile_type.to_string())
                .rpc(),
        )
        .await;

    // Allocate an instance on the VPC so the DPU receives tenant network config.
    let mh = create_managed_host(&env).await;
    mh.instance_builer(&env)
        .tenant_org(tenant.organization_id)
        .single_interface_network_config(segment_id)
        .build()
        .await;

    // Fetch the DPU network config and extract its per-VPC routing profile.
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(mh.dpu().id),
        }))
        .await
        .unwrap()
        .into_inner();
    let routing_profile = response.tenant_interfaces[0]
        .vpc_routing_profile
        .clone()
        .unwrap();
    assert!(
        response.tenant_interfaces[0]
            .interface_routing_profile
            .is_none()
    );

    // Verify the configured leak prefixes are preserved in the gRPC response.
    let actual_leaks: Vec<_> = routing_profile
        .accepted_leaks_from_underlay
        .into_iter()
        .map(|leak| leak.prefix)
        .collect();
    assert_eq!(actual_leaks, expected_leaks);

    // Verify anycast prefixes are preserved in the gRPC response.
    let actual_allowed_anycast_prefixes: Vec<_> = routing_profile
        .allowed_anycast_prefixes
        .into_iter()
        .map(|prefix| prefix.prefix)
        .collect();
    assert_eq!(
        actual_allowed_anycast_prefixes,
        expected_allowed_anycast_prefixes
    );

    // Verify the deprecated top-level field is still populated for rollout compatibility.
    assert!(response.routing_profile.is_some());
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_narrows_interface_anycast_prefixes(pool: sqlx::PgPool) {
    let profile_type = "ANYCAST_SUBSET_TEST";
    let vpc_allowed_anycast_prefixes = ["192.0.2.0/24".to_string(), "2001:db8:99::/48".to_string()];
    let interface_allowed_anycast_prefixes = vec![
        "192.0.2.64/26".to_string(),
        "2001:db8:99:1::/64".to_string(),
    ];
    let inherited_import = RouteTargetConfig {
        asn: 65001,
        vni: 123,
    };

    // Configure an FNN routing profile with anycast prefixes broad enough for the interface.
    let env = api_fixtures::create_test_env_with_overrides(
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
                    leak_default_route_from_underlay: true,
                    route_target_imports: vec![inherited_import.clone()],
                    allowed_anycast_prefixes: vpc_allowed_anycast_prefixes
                        .iter()
                        .map(|prefix| PrefixFilterPolicyEntry {
                            prefix: prefix.parse().unwrap(),
                        })
                        .collect(),
                    ..Default::default()
                },
            )]),
            use_vpc_vrf_loopback: false,
        })),
    )
    .await;

    // Create a tenant and FNN VPC using that VPC-level routing profile.
    let tenant = env
        .api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: "anycast-subset-test".to_string(),
            routing_profile_type: Some(profile_type.to_string()),
            metadata: Some(rpc::forge::Metadata {
                name: "anycast-subset-test".to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .tenant
        .unwrap();

    let segment_id = env
        .create_vpc_and_tenant_segment_with_vpc_details(
            VpcCreationRequest::builder(tenant.organization_id.as_str())
                .metadata(Metadata {
                    name: "anycast subset vpc".to_string(),
                    ..Default::default()
                })
                .network_virtualization_type(rpc::forge::VpcVirtualizationType::Fnn as i32)
                .routing_profile_type(profile_type.to_string())
                .rpc(),
        )
        .await;

    // Allocate an instance with a per-interface anycast prefix subset.
    let mut network_config =
        common::api_fixtures::instance::single_interface_network_config(segment_id);
    network_config.interfaces[0].routing_profile =
        Some(rpc::forge::InstanceInterfaceRoutingProfile {
            allowed_anycast_prefixes: interface_allowed_anycast_prefixes
                .iter()
                .map(|prefix| rpc::forge::PrefixFilterPolicyEntry {
                    prefix: prefix.to_string(),
                })
                .collect(),
        });
    let mh = create_managed_host(&env).await;
    mh.instance_builer(&env)
        .tenant_org(tenant.organization_id)
        .network(network_config)
        .build()
        .await;

    // Fetch the DPU network config and extract its split routing profiles.
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(mh.dpu().id),
        }))
        .await
        .unwrap()
        .into_inner();
    let vpc_routing_profile = response.tenant_interfaces[0]
        .vpc_routing_profile
        .clone()
        .unwrap();
    let interface_routing_profile = response.tenant_interfaces[0]
        .interface_routing_profile
        .clone()
        .unwrap();

    // Verify the VPC-level anycast prefixes remain unchanged.
    let actual_vpc_allowed_anycast_prefixes: Vec<_> = vpc_routing_profile
        .allowed_anycast_prefixes
        .clone()
        .into_iter()
        .map(|prefix| prefix.prefix)
        .collect();
    assert_eq!(
        actual_vpc_allowed_anycast_prefixes,
        vpc_allowed_anycast_prefixes.to_vec()
    );

    // Verify the interface-level anycast prefixes are sent separately.
    let actual_interface_allowed_anycast_prefixes: Vec<_> = interface_routing_profile
        .allowed_anycast_prefixes
        .into_iter()
        .map(|prefix| prefix.prefix)
        .collect();
    assert_eq!(
        actual_interface_allowed_anycast_prefixes,
        interface_allowed_anycast_prefixes
    );

    // Verify non-interface profile fields remain on the VPC profile.
    assert!(vpc_routing_profile.leak_default_route_from_underlay);
    assert_eq!(vpc_routing_profile.route_target_imports.len(), 1);
    assert_eq!(vpc_routing_profile.route_target_imports[0].asn, 65001);
    assert_eq!(vpc_routing_profile.route_target_imports[0].vni, 123);
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_includes_per_vpc_routing_profiles(pool: sqlx::PgPool) {
    let internal_import = RouteTargetConfig {
        asn: 65001,
        vni: 111,
    };
    let external_export = RouteTargetConfig {
        asn: 65002,
        vni: 222,
    };

    // Configure two distinguishable FNN routing profiles.
    let env = api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::default().with_fnn_config(Some(FnnConfig {
            admin_vpc: None,
            common_internal_route_target: None,
            additional_route_target_imports: vec![],
            routing_profiles: HashMap::from([
                (
                    "INTERNAL".to_string(),
                    FnnRoutingProfileConfig {
                        internal: true,
                        access_tier: 1,
                        leak_default_route_from_underlay: true,
                        route_target_imports: vec![internal_import.clone()],
                        ..Default::default()
                    },
                ),
                (
                    "EXTERNAL".to_string(),
                    FnnRoutingProfileConfig {
                        internal: false,
                        access_tier: 2,
                        leak_tenant_host_routes_to_underlay: true,
                        route_targets_on_exports: vec![external_export.clone()],
                        ..Default::default()
                    },
                ),
            ]),
            use_vpc_vrf_loopback: false,
        })),
    )
    .await;

    // Create a tenant that can use both routing profiles.
    let tenant = env
        .api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: "per-vpc-routing-profile".to_string(),
            routing_profile_type: Some("INTERNAL".to_string()),
            metadata: Some(rpc::forge::Metadata {
                name: "per-vpc-routing-profile".to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .tenant
        .unwrap();

    // Create two FNN VPCs with different routing profiles.
    let internal_vpc = env
        .api
        .create_vpc(tonic::Request::new(
            VpcCreationRequest::builder(tenant.organization_id.as_str())
                .metadata(Metadata {
                    name: "internal profile vpc".to_string(),
                    ..Default::default()
                })
                .network_virtualization_type(rpc::forge::VpcVirtualizationType::Fnn as i32)
                .routing_profile_type("INTERNAL".to_string())
                .rpc(),
        ))
        .await
        .unwrap()
        .into_inner();
    let internal_segment_id = create_tenant_network_segment(
        &env.api,
        internal_vpc.id,
        FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[0],
        "TENANT_INTERNAL",
        true,
    )
    .await;
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    let external_vpc = env
        .api
        .create_vpc(tonic::Request::new(
            VpcCreationRequest::builder(tenant.organization_id.as_str())
                .metadata(Metadata {
                    name: "external profile vpc".to_string(),
                    ..Default::default()
                })
                .network_virtualization_type(rpc::forge::VpcVirtualizationType::Fnn as i32)
                .routing_profile_type("EXTERNAL".to_string())
                .rpc(),
        ))
        .await
        .unwrap()
        .into_inner();
    let external_segment_id = create_tenant_network_segment(
        &env.api,
        external_vpc.id,
        FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[1],
        "TENANT_EXTERNAL",
        true,
    )
    .await;
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    // Allocate an instance spanning both VPCs so each interface carries its own profile.
    let mh = create_managed_host(&env).await;
    mh.instance_builer(&env)
        .tenant_org(tenant.organization_id)
        .network(
            api_fixtures::instance::single_interface_network_config_with_vfs(vec![
                internal_segment_id,
                external_segment_id,
            ]),
        )
        .build()
        .await;

    // Fetch the DPU config and index profiles by the interface's actual VPC VNI.
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(mh.dpu().id),
        }))
        .await
        .unwrap()
        .into_inner();
    let mut txn = env.db_txn().await;
    let internal_vpc = db::vpc::find_by_segment(txn.as_mut(), internal_segment_id)
        .await
        .unwrap();
    let external_vpc = db::vpc::find_by_segment(txn.as_mut(), external_segment_id)
        .await
        .unwrap();
    let internal_vni = internal_vpc.status.unwrap().vni.unwrap() as u32;
    let external_vni = external_vpc.status.unwrap().vni.unwrap() as u32;
    let profiles_by_vni = response
        .tenant_interfaces
        .into_iter()
        .map(|interface| {
            (
                interface.vpc_vni,
                interface
                    .vpc_routing_profile
                    .expect("FNN interface should include a routing profile"),
            )
        })
        .collect::<HashMap<_, _>>();
    assert_eq!(profiles_by_vni.len(), 2);

    // Verify each VPC receives the profile resolved from that VPC, not the first VPC.
    let internal_profile = profiles_by_vni.get(&internal_vni).unwrap();
    assert!(internal_profile.leak_default_route_from_underlay);
    assert_eq!(
        internal_profile.route_target_imports,
        vec![rpc::common::RouteTarget {
            asn: internal_import.asn,
            vni: internal_import.vni,
        }]
    );

    let external_profile = profiles_by_vni.get(&external_vni).unwrap();
    assert!(external_profile.leak_tenant_host_routes_to_underlay);
    assert_eq!(
        external_profile.route_targets_on_exports,
        vec![rpc::common::RouteTarget {
            asn: external_export.asn,
            vni: external_export.vni,
        }]
    );
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_omits_fnn_vrf_loopback_by_default(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::default().with_fnn_config(None),
    )
    .await;

    // Create a tenant and FNN segment with the default disabled loopback setting.
    let tenant = env
        .api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: "fnn-loopback-default".to_string(),
            routing_profile_type: Some("INTERNAL".to_string()),
            metadata: Some(rpc::forge::Metadata {
                name: "fnn-loopback-default".to_string(),
                ..Default::default()
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .tenant
        .unwrap();

    let segment_id = env
        .create_vpc_and_tenant_segment_with_vpc_details(
            VpcCreationRequest::builder(tenant.organization_id.as_str())
                .metadata(Metadata {
                    name: "fnn loopback default vpc".to_string(),
                    ..Default::default()
                })
                .network_virtualization_type(rpc::forge::VpcVirtualizationType::Fnn as i32)
                .routing_profile_type("INTERNAL".to_string())
                .rpc(),
        )
        .await;

    // Allocate a managed host on the FNN segment.
    let mh = create_managed_host(&env).await;
    let dpu_machine_id = mh.dpu().id;
    mh.instance_builer(&env)
        .tenant_org(tenant.organization_id)
        .single_interface_network_config(segment_id)
        .build()
        .await;

    // Fetch the DPU config and verify no tenant VRF loopback is sent.
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(!response.tenant_interfaces.is_empty());
    assert!(
        response
            .tenant_interfaces
            .iter()
            .all(|iface| iface.tenant_vrf_loopback_ip.is_none())
    );

    // Verify the DB did not allocate a VPC/DPU loopback row.
    let mut txn = env.db_txn().await;
    let vpc = db::vpc::find_by_segment(txn.as_mut(), segment_id)
        .await
        .unwrap();
    let loopback = db::vpc_dpu_loopback::find(txn.as_mut(), &dpu_machine_id, &vpc.id)
        .await
        .unwrap();
    assert!(loopback.is_none());
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_includes_fnn_vrf_loopback_when_enabled(
    pool: sqlx::PgPool,
) {
    let mut overrides = TestEnvOverrides::default().with_fnn_config(None);
    overrides.fnn_config.as_mut().unwrap().use_vpc_vrf_loopback = true;

    let env = api_fixtures::create_test_env_with_overrides(pool, overrides).await;

    // Create a tenant and FNN segment with loopback allocation enabled.
    let tenant = env
        .api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: "fnn-loopback-enabled".to_string(),
            routing_profile_type: Some("INTERNAL".to_string()),
            metadata: Some(rpc::forge::Metadata {
                name: "fnn-loopback-enabled".to_string(),
                ..Default::default()
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .tenant
        .unwrap();

    let segment_id = env
        .create_vpc_and_tenant_segment_with_vpc_details(
            VpcCreationRequest::builder(tenant.organization_id.as_str())
                .metadata(Metadata {
                    name: "fnn loopback enabled vpc".to_string(),
                    ..Default::default()
                })
                .network_virtualization_type(rpc::forge::VpcVirtualizationType::Fnn as i32)
                .routing_profile_type("INTERNAL".to_string())
                .rpc(),
        )
        .await;

    // Allocate a managed host on the FNN segment.
    let mh = create_managed_host(&env).await;
    let dpu_machine_id = mh.dpu().id;
    mh.instance_builer(&env)
        .tenant_org(tenant.organization_id)
        .single_interface_network_config(segment_id)
        .build()
        .await;

    // Fetch the DPU config and verify the tenant VRF loopback is sent.
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .unwrap()
        .into_inner();
    let loopback_ip = response.tenant_interfaces[0]
        .tenant_vrf_loopback_ip
        .clone()
        .expect("loopback should be present when enabled");

    // Verify the DB allocation matches the response.
    let mut txn = env.db_txn().await;
    let vpc = db::vpc::find_by_segment(txn.as_mut(), segment_id)
        .await
        .unwrap();
    let loopback = db::vpc_dpu_loopback::find(txn.as_mut(), &dpu_machine_id, &vpc.id)
        .await
        .unwrap()
        .expect("loopback allocation should be persisted");
    assert_eq!(loopback.loopback_ip.to_string(), loopback_ip);
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_omits_admin_fnn_vrf_loopback_by_default(
    pool: sqlx::PgPool,
) {
    let mut overrides = TestEnvOverrides::default().with_fnn_config(None);
    overrides.fnn_config.as_mut().unwrap().admin_vpc = Some(AdminFnnConfig {
        enabled: true,
        vpc_vni: Some(10000),
        routing_profile: FnnRoutingProfileConfig {
            leak_default_route_from_underlay: true,
            route_target_imports: vec![RouteTargetConfig {
                asn: 64512,
                vni: 10000,
            }],
            ..Default::default()
        },
    });

    let env = api_fixtures::create_test_env_with_overrides(pool, overrides).await;

    // Attach the FNN admin VPC because test env setup does not run production setup hooks.
    crate::db_init::create_admin_vpc(&env.pool, Some(10000))
        .await
        .unwrap();
    crate::db_init::update_network_segments_svi_ip(&env.pool)
        .await
        .unwrap();

    // Create a managed host that stays on the admin network.
    let mh = create_managed_host(&env).await;
    let dpu_machine_id = mh.dpu().id;

    // Fetch the DPU config and verify the FNN admin interface has no loopback.
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .unwrap()
        .into_inner();
    let admin_interface = response
        .admin_interface
        .as_ref()
        .expect("admin interface should be present");

    assert!(response.use_admin_network);
    assert_eq!(admin_interface.vpc_vni, 10000);
    assert!(admin_interface.tenant_vrf_loopback_ip.is_none());
    assert!(response.routing_profile.is_some());

    let routing_profile = admin_interface
        .vpc_routing_profile
        .as_ref()
        .expect("admin interface should include per-VPC routing profile");
    assert!(admin_interface.interface_routing_profile.is_none());
    assert!(routing_profile.leak_default_route_from_underlay);
    assert_eq!(routing_profile.route_target_imports.len(), 1);
    assert_eq!(routing_profile.route_target_imports[0].asn, 64512);
    assert_eq!(routing_profile.route_target_imports[0].vni, 10000);

    // Verify the admin VPC also did not allocate a VPC/DPU loopback row.
    let mut txn = env.db_txn().await;
    let admin_segment = db::network_segment::admin(txn.as_mut())
        .await
        .unwrap()
        .remove(0);
    let admin_vpc_id = admin_segment
        .config
        .vpc_id
        .expect("admin segment should be attached to an FNN VPC");
    let loopback = db::vpc_dpu_loopback::find(txn.as_mut(), &dpu_machine_id, &admin_vpc_id)
        .await
        .unwrap();
    assert!(loopback.is_none());
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_errors_when_sitewide_bgp_password_missing(
    pool: sqlx::PgPool,
) {
    // Enable site-wide DPU BGP passwords in runtime config without creating the credential.
    let mut config = api_fixtures::get_config();
    config.bgp_leaf_session_password = Some(crate::cfg::file::BgpLeafSessionPassword::SiteWide);

    let env =
        api_fixtures::create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config))
            .await;

    // Create a DPU without advancing to the point where the fixture fetches network config.
    // We'll fetch config next to validate the failure case.
    let host_config = env.managed_host_config();
    api_fixtures::site_explorer::register_expected_machine(&env, &host_config, None).await;

    let mock_explored_host = MockExploredHost::new(&env, host_config)
        .discover_dhcp_dpu_bmc(0, |_, _| Ok(()))
        .await
        .unwrap()
        .discover_dhcp_dpu_primary_iface(0)
        .await
        // Discover the host BMC and persist the exploration results.
        .discover_dhcp_host_bmc(|_, _| Ok(()))
        .await
        .unwrap()
        .insert_site_exploration_results()
        .unwrap()
        .run_site_explorer_iteration()
        .await
        .mark_preingestion_complete()
        .await
        .unwrap()
        .run_site_explorer_iteration()
        .await;

    let dpu_machine_id = mock_explored_host.dpu_machine_ids[&0];

    // Verify the handler fails when the site-wide BGP credential is missing.
    let err = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .expect_err("missing site-wide BGP password should fail");

    assert_eq!(err.code(), tonic::Code::Internal);
    assert!(err.message().contains("Could not find BGP credential"));
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_multi_dpu(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;

    // Given: A managed host with 2 DPUs.
    let mh = api_fixtures::create_managed_host_multi_dpu(&env, 2).await;

    let host_machine = mh.host().rpc_machine().await;
    let dpu_1_id = host_machine.associated_dpu_machine_ids[0];
    let dpu_2_id = host_machine.associated_dpu_machine_ids[1];

    // And: Multiple admin segments exist when the DPU network config is rendered.
    let _second_admin_segment = create_network_segment(
        &env.api,
        "ADMIN_2",
        "192.0.12.0/24",
        "192.0.12.1",
        rpc::forge::NetworkSegmentType::Admin,
        None,
        true,
    )
    .await;

    // Then: Get the managed host network config version via DPU 1's ID and DPU 2's ID
    let dpu_1_network_config = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_1_id),
        }))
        .await
        .expect("Error getting DPU1 network config")
        .into_inner();
    let dpu_2_network_config = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_2_id),
        }))
        .await
        .expect("Error getting DPU1 network config")
        .into_inner();

    let configs = [&dpu_1_network_config, &dpu_2_network_config];

    // Check that reconciliation left exactly one DHCP admin address on
    // the host, and normalized the dormant admin interface.
    let mut txn = env.pool.begin().await.unwrap();
    let mut interface_map = db::machine_interface::find_by_machine_ids(&mut txn, &[mh.id])
        .await
        .unwrap();
    let interfaces = interface_map.remove(&mh.id).unwrap();
    let admin_interfaces = interfaces
        .iter()
        .filter(|interface| {
            interface.network_segment_type == Some(NetworkSegmentType::Admin)
                && interface.attached_dpu_machine_id.is_some()
        })
        .collect::<Vec<_>>();
    assert_eq!(admin_interfaces.len(), 2);

    let primary_interface = admin_interfaces
        .iter()
        .copied()
        .find(|interface| interface.primary_interface)
        .unwrap();
    let dormant_interface = admin_interfaces
        .iter()
        .copied()
        .find(|interface| !interface.primary_interface)
        .unwrap();
    let mut dhcp_address_count = 0;
    for interface in &admin_interfaces {
        let addresses = db::machine_interface_address::find_for_interface(&mut txn, interface.id)
            .await
            .unwrap();
        dhcp_address_count += addresses
            .iter()
            .filter(|address| address.allocation_type == AllocationType::Dhcp)
            .count();
    }
    assert_eq!(dhcp_address_count, 1);
    assert_eq!(primary_interface.addresses.len(), 1);
    assert!(dormant_interface.addresses.is_empty());
    assert!(dormant_interface.domain_id.is_none());
    assert!(dormant_interface.hostname.starts_with("noip-"));
    txn.commit().await.unwrap();

    // Assert: Both DPUs are still on the singular admin-interface path.
    for config in configs {
        assert!(config.use_admin_network);
        assert!(config.admin_interface.is_some());
        assert!(config.tenant_interfaces.is_empty());
    }

    // Assert: Only the primary DPU is active on the admin network.
    assert_eq!(
        configs
            .iter()
            .filter(|config| config.is_primary_dpu)
            .count(),
        1,
    );

    // Assert: Both DPUs report the same managed_host_config_version, because
    // it's the host's network_config_version and group-sync keeps every member
    // of the host's machine group at the same version.
    assert_eq!(
        dpu_1_network_config.managed_host_config_version,
        dpu_2_network_config.managed_host_config_version,
    );

    // Assert: The admin config uses the primary address for both DPUs, but
    // still reports the requesting DPU's own host interface identity.
    let dpu_1_admin = dpu_1_network_config.admin_interface.as_ref().unwrap();
    let dpu_2_admin = dpu_2_network_config.admin_interface.as_ref().unwrap();
    assert_eq!(dpu_1_admin.ip, dpu_2_admin.ip);
    assert_eq!(dpu_1_admin.fqdn, dpu_2_admin.fqdn);
    assert_ne!(
        dpu_1_network_config.host_interface_id,
        dpu_2_network_config.host_interface_id,
    );
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_uses_non_dpu_primary_admin_interface(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;

    // Given: A managed host with 2 DPUs and a separate host admin NIC marked primary.
    let mh = api_fixtures::create_managed_host_multi_dpu(&env, 2).await;
    let host_machine = mh.host().rpc_machine().await;
    let dpu_1_id = host_machine.associated_dpu_machine_ids[0];
    let dpu_2_id = host_machine.associated_dpu_machine_ids[1];

    let mut txn = env.pool.begin().await.unwrap();
    let admin_segment = db::network_segment::admin(&mut txn)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let mut interface_map = db::machine_interface::find_by_machine_ids(&mut txn, &[mh.id])
        .await
        .unwrap();
    let interfaces = interface_map.remove(&mh.id).unwrap();
    for interface in interfaces
        .iter()
        .filter(|interface| interface.primary_interface)
    {
        db::machine_interface::set_primary_interface(&interface.id, false, &mut txn)
            .await
            .unwrap();
    }

    let active_mac: MacAddress = "9a:9b:9c:9d:9e:b1".parse().unwrap();
    let active_interface = db::machine_interface::create(
        &mut txn,
        std::slice::from_ref(&admin_segment),
        &active_mac,
        true,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await
    .unwrap();
    db::machine_interface::associate_interface_with_machine(
        &active_interface.id,
        MachineInterfaceAssociation::Machine(mh.id),
        &mut txn,
    )
    .await
    .unwrap();
    db::machine_interface::reconcile_admin_addresses_for_host(&mut txn, &mh.id)
        .await
        .unwrap();

    let mut interface_map = db::machine_interface::find_by_machine_ids(&mut txn, &[mh.id])
        .await
        .unwrap();
    let interfaces = interface_map.remove(&mh.id).unwrap();
    let active_interface = interfaces
        .iter()
        .find(|interface| interface.id == active_interface.id)
        .unwrap();
    let active_ip = active_interface
        .addresses
        .iter()
        .find(|address| address.is_ipv4())
        .unwrap()
        .to_string();
    let dpu_1_host_interface_id = interfaces
        .iter()
        .find(|interface| {
            interface.attached_dpu_machine_id == Some(dpu_1_id)
                && interface.network_segment_type == Some(NetworkSegmentType::Admin)
        })
        .unwrap()
        .id
        .to_string();
    let dpu_2_host_interface_id = interfaces
        .iter()
        .find(|interface| {
            interface.attached_dpu_machine_id == Some(dpu_2_id)
                && interface.network_segment_type == Some(NetworkSegmentType::Admin)
        })
        .unwrap()
        .id
        .to_string();
    txn.commit().await.unwrap();

    // Then: DPU network config uses the non-DPU primary admin IP, but each response
    // still reports the requesting DPU's own DPU-backed host interface ID.
    let dpu_1_network_config = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_1_id),
        }))
        .await
        .expect("Error getting DPU1 network config")
        .into_inner();
    let dpu_2_network_config = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_2_id),
        }))
        .await
        .expect("Error getting DPU2 network config")
        .into_inner();

    assert_eq!(
        dpu_1_network_config.admin_interface.as_ref().unwrap().ip,
        active_ip
    );
    assert_eq!(
        dpu_2_network_config.admin_interface.as_ref().unwrap().ip,
        active_ip
    );
    assert_eq!(
        dpu_1_network_config.admin_interface.as_ref().unwrap().fqdn,
        dpu_2_network_config.admin_interface.as_ref().unwrap().fqdn
    );
    assert_eq!(
        dpu_1_network_config.host_interface_id.as_deref(),
        Some(dpu_1_host_interface_id.as_str())
    );
    assert_eq!(
        dpu_2_network_config.host_interface_id.as_deref(),
        Some(dpu_2_host_interface_id.as_str())
    );
    assert!(!dpu_1_network_config.is_primary_dpu);
    assert!(!dpu_2_network_config.is_primary_dpu);
}

#[crate::sqlx_test]
async fn test_managed_host_network_status(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    // Add an instance
    let instance_network = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(segment_id),
            network_details: None,
            device: None,
            device_instance: 0u32,
            virtual_function_id: None,
            ip_address: None,
            ipv6_interface_config: None,
            routing_profile: None,
        }],
        auto: false,
    };

    mh.instance_builer(&env)
        .network(instance_network)
        .build()
        .await;

    let response = env
        .api
        .get_all_managed_host_network_status(tonic::Request::new(
            ManagedHostNetworkStatusRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.all.len(), 1);

    // Tell API about latest network config and machine health
    let dpu_health = rpc::health::HealthReport {
        source: "should-get-updated".to_string(),
        triggered_by: None,
        observed_at: None,
        successes: vec![
            rpc::health::HealthProbeSuccess {
                id: "ContainerExists".to_string(),
                target: Some("c1".to_string()),
            },
            rpc::health::HealthProbeSuccess {
                id: "checkTwo".to_string(),
                target: None,
            },
        ],
        alerts: vec![],
    };
    network_configured_with_health(&env, &mh.dpu().id, Some(dpu_health.clone())).await;

    // Query the aggregate health.
    let reported_health = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![mh.dpu().id],
            include_history: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0)
        .health;
    let mut reported_health = reported_health.unwrap();
    assert!(reported_health.observed_at.is_some());
    reported_health.observed_at = None;
    reported_health.source = "should-get-updated".to_string();
    assert_eq!(reported_health, dpu_health);

    // Now fetch the instance and check that knows its configs have synced
    let response = env
        .api
        .find_instance_by_machine_id(tonic::Request::new(mh.id))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.instances.len(), 1);
    let instance = &response.instances[0];
    tracing::info!(
        "instance_network_config_version: {}",
        instance.network_config_version
    );
    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced,
        rpc::SyncState::Synced as i32
    );
}

fn create_extension_service_data(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {}\nspec:\n  containers:\n    - name: app\n      image: nginx:1.27",
        name
    )
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_with_extension_services(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;
    let dpu_1_id = mh.dpu_ids[0];

    // Add an instance
    let instance_network = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(segment_id),
            network_details: None,
            device: None,
            device_instance: 0u32,
            virtual_function_id: None,
            ip_address: None,
            ipv6_interface_config: None,
            routing_profile: None,
        }],
        auto: false,
    };

    let default_tenant_org = "best_org";
    let _ = env
        .api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: default_tenant_org.to_string(),
            routing_profile_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: default_tenant_org.to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap();

    // Create extension services and add them to the instance
    let extension_service1 = env
        .api
        .create_dpu_extension_service(tonic::Request::new(CreateDpuExtensionServiceRequest {
            service_id: None,
            service_name: "test1".to_string(),
            service_type: DpuExtensionServiceType::KubernetesPod as i32,
            tenant_organization_id: "best_org".to_string(),
            description: None,
            data: create_extension_service_data("test"),
            credential: None,
            observability: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let service1_version = extension_service1
        .latest_version_info
        .as_ref()
        .unwrap()
        .version
        .clone();

    let extension_service2 = env
        .api
        .create_dpu_extension_service(tonic::Request::new(CreateDpuExtensionServiceRequest {
            service_id: None,
            service_name: "test2".to_string(),
            service_type: DpuExtensionServiceType::KubernetesPod as i32,
            tenant_organization_id: "best_org".to_string(),
            description: None,
            data: create_extension_service_data("test2"),
            credential: None,
            observability: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let service2_version = extension_service2
        .latest_version_info
        .as_ref()
        .unwrap()
        .version
        .clone();

    let es_config = InstanceDpuExtensionServicesConfig {
        service_configs: vec![
            InstanceDpuExtensionServiceConfig {
                service_id: extension_service1.service_id.clone(),
                version: service1_version.clone(),
            },
            InstanceDpuExtensionServiceConfig {
                service_id: extension_service2.service_id.clone(),
                version: service2_version.clone(),
            },
        ],
    };

    let _ = mh
        .instance_builer(&env)
        .network(instance_network)
        .extension_services(es_config)
        .build()
        .await;

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_1_id),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.dpu_extension_services.len(), 2);
    assert_eq!(
        response.dpu_extension_services[0].service_id,
        extension_service1.service_id
    );
    assert_eq!(
        response.dpu_extension_services[0].version,
        service1_version.clone()
    );
    assert_eq!(response.dpu_extension_services[0].removed, None);

    assert_eq!(
        response.dpu_extension_services[1].service_id,
        extension_service2.service_id
    );
    assert_eq!(
        response.dpu_extension_services[1].version,
        service2_version.clone()
    );
    assert_eq!(response.dpu_extension_services[1].removed, None);
}

#[crate::sqlx_test]
async fn test_dpu_health_is_required(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let (_host_machine_id, dpu_machine_id) = create_managed_host(&env).await.into();

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .unwrap()
        .into_inner();

    let admin_if = response.admin_interface.as_ref().unwrap();

    // dpu-health is not updated here
    let err = env
        .api
        .record_dpu_network_status(tonic::Request::new(DpuNetworkStatus {
            dpu_machine_id: Some(dpu_machine_id),
            dpu_agent_version: Some(dpu::TEST_DPU_AGENT_VERSION.to_string()),
            observed_at: Some(SystemTime::now().into()),
            dpu_health: None,
            network_config_version: Some(response.managed_host_config_version.clone()),
            instance_id: None,
            instance_config_version: None,
            instance_network_config_version: None,
            interfaces: vec![rpc::InstanceInterfaceStatusObservation {
                function_type: admin_if.function_type,
                virtual_function_id: None,
                mac_address: None,
                addresses: vec![admin_if.ip.clone()],
                prefixes: vec![admin_if.interface_prefix.clone()],
                gateways: vec![admin_if.gateway.clone()],
                network_security_group: None,
                internal_uuid: None,
            }],
            network_config_error: None,
            client_certificate_expiry_unix_epoch_secs: None,
            fabric_interfaces: vec![],
            last_dhcp_requests: vec![],
            dpu_extension_service_version: Some("V1-T1".to_string()),
            dpu_extension_services: vec![],
        }))
        .await
        .expect_err("Should fail");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(err.message(), "dpu_health");
}

/// Tests whether the in_alert_since field will be correctly populated
/// in case the DPU sends multiple reports using the same alarm
#[crate::sqlx_test]
async fn test_retain_in_alert_since(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let (_host_machine_id, dpu_machine_id) = create_managed_host(&env).await.into();

    let dpu_health = rpc::health::HealthReport {
        source: "should-get-updated".to_string(),
        triggered_by: None,
        observed_at: None,
        successes: vec![rpc::health::HealthProbeSuccess {
            id: "SuccessA".to_string(),
            target: None,
        }],
        alerts: vec![rpc::health::HealthProbeAlert {
            id: "AlertA".to_string(),
            target: None,
            in_alert_since: None,
            message: "AlertA".to_string(),
            tenant_message: None,
            classifications: vec![
                health_report::HealthAlertClassification::prevent_host_state_changes().to_string(),
            ],
        }],
    };

    network_configured_with_health(&env, &dpu_machine_id, Some(dpu_health.clone())).await;

    // Query the new HealthReport format
    let reported_health = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![dpu_machine_id],
            include_history: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0)
        .health;

    let reported_health = reported_health.unwrap();
    assert!(reported_health.observed_at.is_some());
    assert_eq!(reported_health.successes.len(), 1);
    assert_eq!(reported_health.alerts.len(), 1);
    let mut reported_alert = reported_health.alerts[0].clone();
    assert!(reported_alert.in_alert_since.is_some());
    let in_alert_since = reported_alert.in_alert_since.unwrap();
    reported_alert.in_alert_since = None;
    assert_eq!(reported_alert, dpu_health.alerts[0].clone());

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Report health again. The in_alert_since date should not have been updated
    network_configured_with_health(&env, &dpu_machine_id, Some(dpu_health.clone())).await;
    let reported_health = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![dpu_machine_id],
            include_history: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0)
        .health;
    let reported_health = reported_health.unwrap();
    assert!(reported_health.observed_at.is_some());
    assert_eq!(reported_health.successes.len(), 1);
    assert_eq!(reported_health.alerts.len(), 1);
    let mut reported_alert = reported_health.alerts[0].clone();
    assert_eq!(reported_alert.in_alert_since.unwrap(), in_alert_since);
    reported_alert.in_alert_since = None;
    assert_eq!(reported_alert, dpu_health.alerts[0].clone());
}

#[crate::sqlx_test]
async fn test_quarantine_state_crud(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

    let network_config_version =
        db::machine::get_network_config(env.pool.begin().await?.deref_mut(), &host_machine_id)
            .await?
            .version;

    // Get, make sure it's not set yet
    {
        let quarantine_state = env
            .api
            .get_managed_host_quarantine_state(tonic::Request::new(
                rpc::forge::GetManagedHostQuarantineStateRequest {
                    machine_id: Some(host_machine_id),
                },
            ))
            .await?
            .into_inner()
            .quarantine_state;

        assert!(
            quarantine_state.is_none(),
            "new host should not be quarantined"
        );
    }

    // Make sure finding machine ID's in quarantine state does not include anything yet
    {
        let ids = env
            .api
            .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
                only_quarantine: true,
                ..Default::default()
            }))
            .await?
            .into_inner()
            .machine_ids;
        assert!(
            ids.is_empty(),
            "No machine ID's should be found in quarantine state yet"
        );
    }

    // Set it, make sure we get None back for prior state
    {
        let set_result = env
            .api
            .set_managed_host_quarantine_state(tonic::Request::new(
                rpc::forge::SetManagedHostQuarantineStateRequest {
                    machine_id: Some(host_machine_id),
                    quarantine_state: Some(rpc::forge::ManagedHostQuarantineState {
                        mode: rpc::forge::ManagedHostQuarantineMode::BlockAllTraffic as i32,
                        reason: Some("test reason 1".to_string()),
                    }),
                },
            ))
            .await?
            .into_inner();

        assert!(
            set_result.prior_quarantine_state.is_none(),
            "prior quarantine state should be None"
        );
    }

    // Make sure finding machine ID's in quarantine state includes the machine ID
    {
        let ids = env
            .api
            .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
                only_quarantine: true,
                ..Default::default()
            }))
            .await?
            .into_inner()
            .machine_ids;
        assert_eq!(
            ids,
            vec![host_machine_id],
            "Finding machine ID's with only_quarantine should have returned the quarantined host"
        );
    }

    // Make sure the version got bumped
    let network_config =
        db::machine::get_network_config(env.pool.begin().await?.deref_mut(), &host_machine_id)
            .await?;
    assert_eq!(
        network_config.version.version_nr(),
        network_config_version.version_nr() + 1,
        "Setting quarantine should have bumped the network config version"
    );
    let network_config_version = network_config.version;

    // Make sure the DPU will see a mode saying to block all traffic
    assert_eq!(
        network_config.quarantine_state.as_ref().unwrap().mode,
        ManagedHostQuarantineMode::BlockAllTraffic
    );

    // Make sure we get back what we just set
    {
        let quarantine_state = env
            .api
            .get_managed_host_quarantine_state(tonic::Request::new(
                rpc::forge::GetManagedHostQuarantineStateRequest {
                    machine_id: Some(host_machine_id),
                },
            ))
            .await?
            .into_inner()
            .quarantine_state;

        assert_eq!(
            quarantine_state
                .expect("we should get a quarantine state back after setting")
                .reason
                .expect("reason should be set")
                .as_str(),
            "test reason 1",
            "getting quarantine state should return the value we just set"
        );
    }

    // Set again, make sure the prior version matches what we set last time
    {
        let set_result = env
            .api
            .set_managed_host_quarantine_state(tonic::Request::new(
                rpc::forge::SetManagedHostQuarantineStateRequest {
                    machine_id: Some(host_machine_id),
                    quarantine_state: Some(rpc::forge::ManagedHostQuarantineState {
                        mode: rpc::forge::ManagedHostQuarantineMode::BlockAllTraffic as i32,
                        reason: Some("test reason 2".to_string()),
                    }),
                },
            ))
            .await?
            .into_inner();

        assert_eq!(
            set_result
                .prior_quarantine_state
                .expect("prior quarantine state should now be set")
                .reason,
            Some("test reason 1".to_string()),
            "prior quarantine state should match the first state we set"
        );
    }

    // Make sure the version got bumped again
    let network_config =
        db::machine::get_network_config(env.pool.begin().await?.deref_mut(), &host_machine_id)
            .await?;
    assert_eq!(
        network_config.version.version_nr(),
        network_config_version.version_nr() + 1,
        "Setting quarantine should have bumped the network config version"
    );
    let network_config_version = network_config.version;

    // Make sure the DPU will (still) see a mode saying to block all traffic
    assert_eq!(
        network_config.quarantine_state.as_ref().unwrap().mode,
        ManagedHostQuarantineMode::BlockAllTraffic
    );

    // Make sure we get back what we set again
    {
        let quarantine_state = env
            .api
            .get_managed_host_quarantine_state(tonic::Request::new(
                rpc::forge::GetManagedHostQuarantineStateRequest {
                    machine_id: Some(host_machine_id),
                },
            ))
            .await?
            .into_inner()
            .quarantine_state;

        assert_eq!(
            quarantine_state
                .expect("we should get a quarantine state back after setting")
                .reason
                .expect("reason should be set")
                .as_str(),
            "test reason 2",
            "getting quarantine state should return the value we just set"
        );
    }

    // Clear, making sure we got back what we set last time
    {
        let clear_result = env
            .api
            .clear_managed_host_quarantine_state(tonic::Request::new(
                rpc::forge::ClearManagedHostQuarantineStateRequest {
                    machine_id: Some(host_machine_id),
                },
            ))
            .await?
            .into_inner();

        assert_eq!(
            clear_result
                .prior_quarantine_state
                .expect("prior quarantine state should be set when clearing")
                .reason,
            Some("test reason 2".to_string()),
            "prior quarantine state should match the second state we set"
        );
    }

    // Make sure the network config version bumps again on clear
    let network_config =
        db::machine::get_network_config(env.pool.begin().await?.deref_mut(), &host_machine_id)
            .await?;
    assert_eq!(
        network_config.version.version_nr(),
        network_config_version.version_nr() + 1,
        "Clearing quarantine should have bumped the network config version"
    );

    // Make sure the DPU no longer sees a quarantine state
    assert!(network_config.quarantine_state.is_none());

    // Make sure finding machine ID's in quarantine state does not include anything any more
    {
        let ids = env
            .api
            .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
                only_quarantine: true,
                ..Default::default()
            }))
            .await?
            .into_inner()
            .machine_ids;
        assert!(
            ids.is_empty(),
            "No machine ID's should be found in quarantine state after clearing"
        );
    }

    Ok(())
}
