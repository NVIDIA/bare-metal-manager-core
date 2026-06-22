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

use carbide_uuid::machine::MachineId;
use carbide_uuid::vpc::VpcId;
use carbide_uuid::vpc_peering::VpcPeeringId;
use model::metadata::Metadata;
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    ManagedHostNetworkConfigRequest, VpcPeeringCreationRequest, VpcPeeringDeletionRequest,
    VpcPeeringList, VpcPeeringSearchFilter, VpcPeeringsByIdsRequest, VpcVirtualizationType,
};
use sqlx::PgPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use super::common::api_fixtures::{self, TestEnv};
use crate::tests::common::api_fixtures::instance::default_tenant_config;
use crate::tests::common::api_fixtures::network_segment::{
    FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS, create_network_segment, create_tenant_network_segment,
};
use crate::tests::common::api_fixtures::tenant::create_fixture_tenant;
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, create_managed_host, create_test_env, create_test_env_with_overrides,
};
use crate::tests::common::rpc_builder::VpcCreationRequest;

async fn create_test_vpcs(
    env: &TestEnv,
    count: i32,
    vtype: Option<VpcVirtualizationType>,
) -> Result<MachineId, Box<dyn std::error::Error>> {
    let default_tenant = default_tenant_config();
    let tenant_organization_id =
        if matches!(vtype, Some(VpcVirtualizationType::Fnn)) && env.config.fnn.is_some() {
            create_fixture_tenant(env, default_tenant.tenant_organization_id.clone()).await?;
            default_tenant.tenant_organization_id
        } else {
            String::new()
        };

    let mut first_segment_id = None;
    for i in 0..count {
        let name = format!("test vpc {}", i + 1); // start from 1 for readability

        let vpc = match vtype {
            Some(vtype) => env
                .api
                .create_vpc(
                    VpcCreationRequest::builder(tenant_organization_id.clone())
                        .metadata(Metadata {
                            name,
                            ..Default::default()
                        })
                        .network_virtualization_type(vtype)
                        .tonic_request(),
                )
                .await
                .unwrap()
                .into_inner(),
            None => env
                .api
                .create_vpc(
                    VpcCreationRequest::builder("")
                        .metadata(Metadata {
                            name,
                            ..Default::default()
                        })
                        .tonic_request(),
                )
                .await
                .unwrap()
                .into_inner(),
        };

        let vpc_id = vpc.id.expect("Expected vpc_id to be present");
        let segment_id = create_tenant_network_segment(
            &env.api,
            Some(vpc_id),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[i as usize],
            &format!("TENANT{}", i + 1),
            true,
        )
        .await;

        if i == 0 {
            first_segment_id = Some(segment_id);
        }

        env.run_network_segment_controller_iteration().await;
    }

    // Create an instance on the first VPC
    let mh = create_managed_host(env).await;
    let instance_network = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(
                first_segment_id.expect("Expected first segment id to be present"),
            ),
            network_details: None,
            device: None,
            device_instance: 0,
            virtual_function_id: None,
            ip_address: None,
            ipv6_interface_config: None,
            routing_profile: None,
        }],
        auto: false,
    };
    mh.instance_builer(env)
        .network(instance_network)
        .build()
        .await;

    Ok(mh.dpu().id)
}

async fn find_vpc_id_by_name(
    env: &TestEnv,
    vpc_name: &str,
) -> Result<VpcId, Box<dyn std::error::Error>> {
    let vpc_id = db::vpc::find_by_name(&env.pool, vpc_name)
        .await?
        .into_iter()
        .next()
        .unwrap()
        .id;
    Ok(vpc_id)
}

async fn get_vpc_peerings(
    env: &TestEnv,
    vpc_id: VpcId,
) -> Result<Response<VpcPeeringList>, Status> {
    let find_ids_request = Request::new(VpcPeeringSearchFilter {
        vpc_id: Some(vpc_id),
    });
    let ids = env
        .api
        .find_vpc_peering_ids(find_ids_request)
        .await?
        .into_inner()
        .vpc_peering_ids;

    let find_by_ids_request = Request::new(VpcPeeringsByIdsRequest {
        vpc_peering_ids: ids,
    });
    env.api.find_vpc_peerings_by_ids(find_by_ids_request).await
}

#[crate::sqlx_test]

async fn test_create_vpc_peering(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    create_test_vpcs(&env, 2, None).await?;

    let vpc_id_1 = find_vpc_id_by_name(&env, "test vpc 1").await?;
    let vpc_id_2 = find_vpc_id_by_name(&env, "test vpc 2").await?;

    let vpc_peering_request = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_1),
        peer_vpc_id: Some(vpc_id_2),
        id: None,
    });

    let response = env.api.create_vpc_peering(vpc_peering_request).await;

    assert!(response.is_ok());

    Ok(())
}

#[crate::sqlx_test]
// Test creation, get, and deletion of vpc_peer
async fn test_vpc_peering_full(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    create_test_vpcs(&env, 3, None).await?;

    let vpc_id_1 = find_vpc_id_by_name(&env, "test vpc 1").await?;
    let vpc_id_2 = find_vpc_id_by_name(&env, "test vpc 2").await?;
    let vpc_id_3 = find_vpc_id_by_name(&env, "test vpc 3").await?;

    let id = Some(VpcPeeringId::from(Uuid::new_v4()));
    let vpc_peering_request_12 = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_1),
        peer_vpc_id: Some(vpc_id_2),
        id,
    });
    let response_12 = env.api.create_vpc_peering(vpc_peering_request_12).await;
    assert!(response_12.is_ok());
    let vpc_peering_12_id = response_12.unwrap().into_inner().id;

    // Recreate should fail
    let vpc_peering_request_12 = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_1),
        peer_vpc_id: Some(vpc_id_2),
        id: None,
    });
    let response_12 = env.api.create_vpc_peering(vpc_peering_request_12).await;
    assert!(response_12.is_err());

    // This should fail because the id is already in use
    let vpc_peering_request_same_id = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_3),
        peer_vpc_id: Some(vpc_id_1),
        id,
    });
    let response_same_id = env
        .api
        .create_vpc_peering(vpc_peering_request_same_id)
        .await;
    assert!(response_same_id.is_err());
    println!("response_same_id: {:?}", response_same_id);

    let vpc_peering_request_13 = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_1),
        peer_vpc_id: Some(vpc_id_3),
        id: None,
    });
    let response_13 = env.api.create_vpc_peering(vpc_peering_request_13).await;
    assert!(response_13.is_ok());
    let vpc_peering_13_id = response_13.unwrap().into_inner().id;

    let get_response = get_vpc_peerings(&env, vpc_id_1).await;
    assert!(get_response.is_ok());
    let vpc_peering_list = get_response.unwrap().into_inner();
    assert_eq!(vpc_peering_list.vpc_peerings.len(), 2);

    let vpc_peering_delete_request = Request::new(VpcPeeringDeletionRequest {
        id: vpc_peering_12_id,
    });
    let delete_response = env.api.delete_vpc_peering(vpc_peering_delete_request).await;
    assert!(delete_response.is_ok());

    let get_response = get_vpc_peerings(&env, vpc_id_1).await;
    assert!(get_response.is_ok());
    let vpc_peering_list = get_response.unwrap().into_inner();
    assert_eq!(vpc_peering_list.vpc_peerings.len(), 1);

    let vpc_peering_delete_request = Request::new(VpcPeeringDeletionRequest {
        id: vpc_peering_13_id,
    });
    let delete_response = env.api.delete_vpc_peering(vpc_peering_delete_request).await;
    assert!(delete_response.is_ok());

    let get_response = get_vpc_peerings(&env, vpc_id_1).await;
    assert!(get_response.is_ok());
    let vpc_peering_list = get_response.unwrap().into_inner();
    assert_eq!(vpc_peering_list.vpc_peerings.len(), 0);

    // Recreate
    let vpc_peering_request_12 = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_1),
        peer_vpc_id: Some(vpc_id_2),
        id: None,
    });
    let response_12 = env.api.create_vpc_peering(vpc_peering_request_12).await;
    assert!(response_12.is_ok());

    let vpc_peering_request_13 = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_1),
        peer_vpc_id: Some(vpc_id_3),
        id: None,
    });
    let _ = env.api.create_vpc_peering(vpc_peering_request_13).await;

    let vpc_peering_list = get_vpc_peerings(&env, vpc_id_1).await.unwrap().into_inner();
    assert_eq!(vpc_peering_list.vpc_peerings.len(), 2);

    let vpc_delete_response = env
        .api
        .delete_vpc(tonic::Request::new(rpc::forge::VpcDeletionRequest {
            id: Some(vpc_id_1),
        }))
        .await;
    assert!(vpc_delete_response.is_ok());

    let get_response = get_vpc_peerings(&env, vpc_id_1).await;
    assert!(get_response.is_ok());

    let vpc_peering_list = get_response.unwrap().into_inner();
    assert_eq!(vpc_peering_list.vpc_peerings.len(), 0);

    Ok(())
}

#[crate::sqlx_test]
// Test creation, get, and deletion of vpc_peering
async fn test_vpc_peering_constraint(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    create_test_vpcs(&env, 3, None).await?;

    let vpc_id_1 = find_vpc_id_by_name(&env, "test vpc 1").await?;
    let vpc_id_2 = find_vpc_id_by_name(&env, "test vpc 2").await?;

    let vpc_peering_request_12 = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_1),
        peer_vpc_id: Some(vpc_id_2),
        id: Some(VpcPeeringId::from(Uuid::new_v4())),
    });
    let response_12 = env.api.create_vpc_peering(vpc_peering_request_12).await;
    assert!(response_12.is_ok());

    // Create should fail for same pair of VPC in different order
    let vpc_peering_request_21 = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_2),
        peer_vpc_id: Some(vpc_id_1),
        id: None,
    });
    let response_21 = env.api.create_vpc_peering(vpc_peering_request_21).await;
    assert!(response_21.is_err());

    let fake_vpc_id: VpcId = "deadbeef-dead-beef-dead-beefdeadbeef".parse().unwrap();

    // Create should fail if two VPC ids provided are identical
    let dup_vpc_id_request = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_1),
        peer_vpc_id: Some(vpc_id_1),
        id: None,
    });
    let response = env.api.create_vpc_peering(dup_vpc_id_request).await;
    assert!(response.is_err());

    // Test foreign key constraint: create should fail if either VPC id does not exist in 'vpcs' table
    let fake_vpc_id_request = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_1),
        peer_vpc_id: Some(fake_vpc_id),
        id: None,
    });
    let response = env.api.create_vpc_peering(fake_vpc_id_request).await;
    assert!(response.is_err());

    Ok(())
}

async fn create_vpc_peering(
    env: &TestEnv,
    vtype1: VpcVirtualizationType,
    vtype2: VpcVirtualizationType,
) -> Result<(VpcId, VpcId, u32, u32, MachineId), Box<dyn std::error::Error>> {
    let default_tenant = default_tenant_config();
    let peer_tenant_organization_id = "Tenant2";
    let use_fixture_tenants = env.config.fnn.is_some()
        && (vtype1 == VpcVirtualizationType::Fnn || vtype2 == VpcVirtualizationType::Fnn);

    if use_fixture_tenants {
        create_fixture_tenant(env, default_tenant.tenant_organization_id.clone()).await?;
        create_fixture_tenant(env, peer_tenant_organization_id).await?;
    }

    let (vpc_id, vpc_vni, segment_id, peer_vpc_id, peer_vpc_vni, _peer_segment_id) =
        if use_fixture_tenants {
            env.create_vpc_and_peer_vpc_with_tenant_segments_for_tenants(
                &default_tenant.tenant_organization_id,
                vtype1,
                peer_tenant_organization_id,
                vtype2,
            )
            .await
        } else {
            env.create_vpc_and_peer_vpc_with_tenant_segments(vtype1, vtype2)
                .await
        };
    let vpc_id = vpc_id.expect("Expected vpc_id to be Some, but was None");
    let peer_vpc_id = peer_vpc_id.expect("Expected peer_vpc_id to be Some, but was None");
    let vpc_vni = vpc_vni.expect("Expected vpc_vni to be Some, but was None");
    let peer_vpc_vni = peer_vpc_vni.expect("Expected vpc_vni to be Some, but was None");

    let mh = create_managed_host(env).await;

    // Creating VPC peering between two VPCs
    let vpc_peering_request = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id),
        peer_vpc_id: Some(peer_vpc_id),
        id: None,
    });
    let _ = env.api.create_vpc_peering(vpc_peering_request).await?;

    // Add an instance
    let instance_network = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(segment_id),
            network_details: None,
            device: None,
            device_instance: 0,
            virtual_function_id: None,
            ip_address: None,
            ipv6_interface_config: None,
            routing_profile: None,
        }],
        auto: false,
    };

    mh.instance_builer(env)
        .network(instance_network)
        .build()
        .await;

    Ok((vpc_id, peer_vpc_id, vpc_vni, peer_vpc_vni, mh.dpu().id))
}

#[crate::sqlx_test]
async fn test_vpc_peering_network_config(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool, TestEnvOverrides::default().with_fnn_config(None))
            .await;
    let (_, _, _, peer_vpc_vni, dpu_machine_id) =
        create_vpc_peering(&env, VpcVirtualizationType::Fnn, VpcVirtualizationType::Fnn).await?;

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.tenant_interfaces.len(), 1);
    assert_eq!(response.tenant_interfaces[0].vpc_peer_prefixes.len(), 1);
    assert_eq!(response.tenant_interfaces[0].vpc_peer_vnis.len(), 1);
    assert_eq!(response.tenant_interfaces[0].vpc_peer_vnis[0], peer_vpc_vni);

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_peering_network_config_mixed(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;

    let response = create_vpc_peering(
        &env,
        VpcVirtualizationType::Fnn,
        VpcVirtualizationType::EthernetVirtualizer,
    )
    .await;

    assert!(response.is_err());

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_peering_network_config_exclusive_etv(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;

    let (_, _, _, _, dpu_machine_id) = create_vpc_peering(
        &env,
        VpcVirtualizationType::EthernetVirtualizer,
        VpcVirtualizationType::EthernetVirtualizer,
    )
    .await?;

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.tenant_interfaces.len(), 1);
    assert_eq!(response.tenant_interfaces[0].vpc_peer_prefixes.len(), 1);
    assert_eq!(response.tenant_interfaces[0].vpc_peer_vnis.len(), 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_peering_network_config_exclusive_etv_with_nvue(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;

    let (_, _, _, _, dpu_machine_id) = create_vpc_peering(
        &env,
        VpcVirtualizationType::EthernetVirtualizer,
        VpcVirtualizationType::EthernetVirtualizer,
    )
    .await?;

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.tenant_interfaces.len(), 1);
    assert_eq!(response.tenant_interfaces[0].vpc_peer_prefixes.len(), 1);
    assert_eq!(response.tenant_interfaces[0].vpc_peer_vnis.len(), 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_peering_deletion_upon_vpc_deletion(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;
    let (vpc_id, peer_vpc_id, _, _, dpu_machine_id) = create_vpc_peering(
        &env,
        VpcVirtualizationType::EthernetVirtualizer,
        VpcVirtualizationType::EthernetVirtualizer,
    )
    .await?;

    let get_response = get_vpc_peerings(&env, vpc_id).await;
    assert!(get_response.is_ok());
    let vpc_peering_list = get_response.unwrap().into_inner();
    assert_eq!(vpc_peering_list.vpc_peerings.len(), 1);

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.tenant_interfaces.len(), 1);
    assert_eq!(response.tenant_interfaces[0].vpc_peer_prefixes.len(), 1);
    assert_eq!(response.tenant_interfaces[0].vpc_peer_vnis.len(), 0);

    let vpc_delete_response = env
        .api
        .delete_vpc(tonic::Request::new(rpc::forge::VpcDeletionRequest {
            id: Some(peer_vpc_id),
        }))
        .await;
    assert!(vpc_delete_response.is_ok());

    let get_response = get_vpc_peerings(&env, vpc_id).await;
    assert!(get_response.is_ok());
    let vpc_peering_list = get_response.unwrap().into_inner();
    assert_eq!(vpc_peering_list.vpc_peerings.len(), 0);

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.tenant_interfaces.len(), 1);
    assert_eq!(response.tenant_interfaces[0].vpc_peer_prefixes.len(), 0);
    assert_eq!(response.tenant_interfaces[0].vpc_peer_vnis.len(), 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_peering_network_config_ordered_peerings(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool, TestEnvOverrides::default().with_fnn_config(None))
            .await;

    let dpu_machine_id = create_test_vpcs(&env, 4, Some(VpcVirtualizationType::Fnn)).await?;
    let vpc_id_1 = find_vpc_id_by_name(&env, "test vpc 1").await?;
    let vpc_id_2 = find_vpc_id_by_name(&env, "test vpc 2").await?;
    let vpc_id_3 = find_vpc_id_by_name(&env, "test vpc 3").await?;
    let vpc_id_4 = find_vpc_id_by_name(&env, "test vpc 4").await?;

    let peer_vpc_vni_2 = db::vpc::find_by_name(&env.pool, "test vpc 2")
        .await?
        .into_iter()
        .next()
        .and_then(|vpc| vpc.status.vni)
        .expect("Expected peer vpc 2 vni to be present") as u32;
    let peer_vpc_vni_3 = db::vpc::find_by_name(&env.pool, "test vpc 3")
        .await?
        .into_iter()
        .next()
        .and_then(|vpc| vpc.status.vni)
        .expect("Expected peer vpc 3 vni to be present") as u32;
    let peer_vpc_vni_4 = db::vpc::find_by_name(&env.pool, "test vpc 4")
        .await?
        .into_iter()
        .next()
        .and_then(|vpc| vpc.status.vni)
        .expect("Expected peer vpc 4 vni to be present") as u32;

    // Create VPC Peering between VPC 1 and VPC 2
    let vpc_peering_request_12 = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_1),
        peer_vpc_id: Some(vpc_id_2),
        id: None,
    });
    let _ = env.api.create_vpc_peering(vpc_peering_request_12).await?;

    // Create VPC Peering between VPC 1 and VPC 3
    let vpc_peering_request_13 = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_1),
        peer_vpc_id: Some(vpc_id_3),
        id: None,
    });
    let _ = env.api.create_vpc_peering(vpc_peering_request_13).await?;

    // Create VPC Peering between VPC 1 and VPC 4
    let vpc_peering_request_14 = Request::new(VpcPeeringCreationRequest {
        vpc_id: Some(vpc_id_1),
        peer_vpc_id: Some(vpc_id_4),
        id: None,
    });
    let _ = env.api.create_vpc_peering(vpc_peering_request_14).await?;

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await?
        .into_inner();

    assert_eq!(response.tenant_interfaces.len(), 1);
    let peer_vnis = &response.tenant_interfaces[0].vpc_peer_vnis;
    assert_eq!(peer_vnis.len(), 3);
    assert!(peer_vnis.contains(&peer_vpc_vni_2));
    assert!(peer_vnis.contains(&peer_vpc_vni_3));
    assert!(peer_vnis.contains(&peer_vpc_vni_4));

    let mut expected_peer_vnis = peer_vnis.clone();
    expected_peer_vnis.sort_unstable();
    assert_eq!(*peer_vnis, expected_peer_vnis);

    let peer_prefixes = &response.tenant_interfaces[0].vpc_peer_prefixes;
    assert_eq!(peer_prefixes.len(), 3);
    let mut expected_peer_prefixes = peer_prefixes.clone();
    expected_peer_prefixes.sort_unstable();
    assert_eq!(*peer_prefixes, expected_peer_prefixes);

    Ok(())
}

#[crate::sqlx_test]
async fn flat_vpc_can_peer_with_etv_under_exclusive_policy(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Flat VPCs short-circuit the ETV<->FNN exclusion under Exclusive policy
    // because Flat VPCs do not own a Carbide-managed data plane.
    let env = api_fixtures::create_test_env(pool).await;

    let (_, etv_vpc) = api_fixtures::vpc::create_vpc(
        &env,
        "etv".to_string(),
        Some("2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string()),
        None,
    )
    .await;
    let (_, flat_vpc) = api_fixtures::vpc::create_flat_vpc(
        &env,
        "flat".to_string(),
        Some("2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string()),
    )
    .await;

    env.api
        .create_vpc_peering(Request::new(VpcPeeringCreationRequest {
            vpc_id: etv_vpc.id,
            peer_vpc_id: flat_vpc.id,
            id: None,
        }))
        .await
        .expect("Flat <-> ETV peering must be allowed under Exclusive policy");

    Ok(())
}

#[crate::sqlx_test]
async fn flat_vpc_can_peer_with_fnn_under_exclusive_policy(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Same short-circuit as the ETV case, but on the FNN side: Flat VPCs are
    // peer-policy-neutral.
    let env = api_fixtures::create_test_env(pool).await;

    let fnn_vpc = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("2829bbe3-c169-4cd9-8b2a-19a8b1618a93")
                .metadata(Metadata {
                    name: "fnn".to_string(),
                    ..Default::default()
                })
                .network_virtualization_type(VpcVirtualizationType::Fnn)
                .tonic_request(),
        )
        .await?
        .into_inner();
    let (_, flat_vpc) = api_fixtures::vpc::create_flat_vpc(
        &env,
        "flat".to_string(),
        Some("2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string()),
    )
    .await;

    env.api
        .create_vpc_peering(Request::new(VpcPeeringCreationRequest {
            vpc_id: fnn_vpc.id,
            peer_vpc_id: flat_vpc.id,
            id: None,
        }))
        .await
        .expect("Flat <-> FNN peering must be allowed under Exclusive policy");

    Ok(())
}

#[crate::sqlx_test]
async fn flat_vpc_can_peer_with_flat_under_exclusive_policy(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Flat <-> Flat is structurally identical: no overlay state to mediate.
    let env = api_fixtures::create_test_env(pool).await;

    let (_, flat_a) = api_fixtures::vpc::create_flat_vpc(
        &env,
        "flat-a".to_string(),
        Some("2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string()),
    )
    .await;
    let (_, flat_b) = api_fixtures::vpc::create_flat_vpc(
        &env,
        "flat-b".to_string(),
        Some("2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string()),
    )
    .await;

    env.api
        .create_vpc_peering(Request::new(VpcPeeringCreationRequest {
            vpc_id: flat_a.id,
            peer_vpc_id: flat_b.id,
            id: None,
        }))
        .await
        .expect("Flat <-> Flat peering must be allowed under Exclusive policy");

    Ok(())
}

/// Coverage for the capability-driven peer-filter in `tenant_network`
/// with an FNN VPC peered to a Flat VPC:
///
/// - Flat VPC's HostInband segment prefix appears in the FNN
///   instance's `vpc_peer_prefixes`.
/// - Flat VPC's VNI appears in the FNN instance's `vpc_peer_vnis` --
///   Flat advertises its VNI for peer consumption (pluggable SDN
///   integrations on the operator's fabric may use it), even though
///   Flat itself doesn't run an overlay. The FNN DPU imports it on
///   the self side via `imports_peer_vnis_into_overlay`.
#[crate::sqlx_test]
async fn test_fnn_vpc_with_flat_peer_exchanges_prefixes_and_vnis(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool, TestEnvOverrides::default().with_fnn_config(None))
            .await;
    let default_tenant = default_tenant_config();
    create_fixture_tenant(&env, default_tenant.tenant_organization_id.clone()).await?;

    // FNN VPC + Tenant segment (the side the instance allocates on).
    let fnn_vpc = env
        .api
        .create_vpc(
            VpcCreationRequest::builder(default_tenant.tenant_organization_id.clone())
                .metadata(Metadata {
                    name: "test fnn vpc".to_string(),
                    ..Default::default()
                })
                .network_virtualization_type(VpcVirtualizationType::Fnn)
                .tonic_request(),
        )
        .await?
        .into_inner();
    let fnn_vpc_id = fnn_vpc.id.expect("FNN VPC must have id");
    let fnn_segment_id = create_tenant_network_segment(
        &env.api,
        Some(fnn_vpc_id),
        FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[2],
        "FNN_TENANT",
        true,
    )
    .await;

    // Flat VPC + HostInband segment (the peer side).
    let (flat_vpc_id, _) = api_fixtures::vpc::create_flat_vpc(
        &env,
        "test flat vpc".to_string(),
        Some(default_tenant.tenant_organization_id),
    )
    .await;
    // Use a different fixture-tenant gateway than the FNN side so the
    // peer-prefix assertion is unambiguous.
    let flat_gateway = FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[3];
    let flat_prefix = format!("{}/{}", flat_gateway.network(), flat_gateway.prefix());
    let _flat_segment_id = create_network_segment(
        &env.api,
        "FLAT_HOST_INBAND",
        &flat_prefix,
        &flat_gateway.ip().to_string(),
        rpc::forge::NetworkSegmentType::HostInband,
        Some(flat_vpc_id),
        true,
    )
    .await;

    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    // Peer the VPCs and allocate an instance in the FNN VPC.
    let mh = create_managed_host(&env).await;
    env.api
        .create_vpc_peering(Request::new(VpcPeeringCreationRequest {
            vpc_id: Some(fnn_vpc_id),
            peer_vpc_id: Some(flat_vpc_id),
            id: None,
        }))
        .await?;

    let instance_network = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(fnn_segment_id),
            network_details: None,
            device: None,
            device_instance: 0,
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

    // Pull the Flat VPC's VNI so we can assert it shows up.
    let flat_vpc = env
        .api
        .find_vpcs_by_ids(Request::new(rpc::forge::VpcsByIdsRequest {
            vpc_ids: vec![flat_vpc_id],
        }))
        .await?
        .into_inner();
    let flat_vni = flat_vpc.vpcs[0]
        .status
        .as_ref()
        .and_then(|s| s.vni)
        .expect("Flat VPC must have a VNI allocated") as u32;

    let response = env
        .api
        .get_managed_host_network_config(Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(mh.dpu().id),
        }))
        .await?
        .into_inner();

    assert_eq!(response.tenant_interfaces.len(), 1);
    let iface = &response.tenant_interfaces[0];

    // The Flat VPC's HostInband prefix shows up.
    assert_eq!(
        iface.vpc_peer_prefixes.len(),
        1,
        "FNN instance's vpc_peer_prefixes should include the Flat VPC's prefix; got {:?}",
        iface.vpc_peer_prefixes,
    );
    assert!(
        iface.vpc_peer_prefixes.contains(&flat_prefix),
        "expected Flat VPC's prefix {flat_prefix} in vpc_peer_prefixes, got {:?}",
        iface.vpc_peer_prefixes,
    );

    // The Flat VPC's VNI shows up too -- Flat advertises its VNI for
    // pluggable SDN integrations on the network operator's fabric.
    assert_eq!(
        iface.vpc_peer_vnis,
        vec![flat_vni],
        "FNN instance's vpc_peer_vnis should contain the Flat VPC's VNI ({flat_vni}); got {:?}",
        iface.vpc_peer_vnis,
    );

    Ok(())
}
