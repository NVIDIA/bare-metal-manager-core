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
use crate::tests::common::api_fixtures::{create_managed_host, create_test_env};
use crate::tests::common::rpc_builder::VpcCreationRequest;

async fn create_test_vpcs(env: &TestEnv, count: i32) -> Result<(), Box<dyn std::error::Error>> {
    for i in 0..count {
        let name = format!("test vpc {}", i + 1); // start from 1 for readability

        let _ = env
            .api
            .create_vpc(
                VpcCreationRequest::builder(&name, "")
                    .metadata(Metadata {
                        name,
                        ..Default::default()
                    })
                    .tonic_request(),
            )
            .await
            .unwrap()
            .into_inner();
    }

    Ok(())
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

    create_test_vpcs(&env, 2).await?;

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
    create_test_vpcs(&env, 3).await?;

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
    create_test_vpcs(&env, 3).await?;

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
    let (vpc_id, vpc_vni, segment_id, peer_vpc_id, peer_vpc_vni, _peer_segment_id) = env
        .create_vpc_and_peer_vpc_with_tenant_segments(vtype1, vtype2)
        .await;
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
        }],
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
    let env = api_fixtures::create_test_env(pool).await;
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
        VpcVirtualizationType::EthernetVirtualizerWithNvue,
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
        VpcVirtualizationType::EthernetVirtualizerWithNvue,
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
