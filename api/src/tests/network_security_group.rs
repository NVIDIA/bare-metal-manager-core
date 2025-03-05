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

use config_version::ConfigVersion;
use rpc::forge::forge_server::Forge;
use tonic::Code;

use crate::cfg::file::default_max_network_security_group_size;
use crate::tests::common::api_fixtures::{
    create_test_env,
    instance::{default_os_config, default_tenant_config, single_interface_network_config},
    managed_host::ManagedHostConfig,
    populate_network_security_groups, site_explorer,
};

#[crate::sqlx_test]
async fn test_network_security_group_create(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let id = "can_i_see_some_id?";

    // Create tenant orgs
    let default_tenant_org = "Tenant1";
    let _ = env
        .api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: default_tenant_org.to_string(),
            metadata: Some(rpc::forge::Metadata {
                name: default_tenant_org.to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap();

    let tenant_org2 = "create_nsg_tenant2";
    let _ = env
        .api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: tenant_org2.to_string(),
            metadata: Some(rpc::forge::Metadata {
                name: tenant_org2.to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap();

    // Prepare some bad attributes for testing NSG size limits
    let too_many_src_ports = Some(rpc::forge::NetworkSecurityGroupAttributes {
        rules: vec![rpc::forge::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                .into(),
            ipv6: false,
            src_port_start: Some(80),
            src_port_end: Some(32768),
            dst_port_start: None,
            dst_port_end: None,
            protocol: rpc::forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
            action: rpc::forge::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
            priority: 9001,
            source_net: Some(
                rpc::forge::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
            destination_net: Some(
                rpc::forge::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
        }],
    });

    let too_many_dst_ports = Some(rpc::forge::NetworkSecurityGroupAttributes {
        rules: vec![rpc::forge::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                .into(),
            ipv6: false,
            src_port_start: None,
            src_port_end: None,
            dst_port_start: Some(80),
            dst_port_end: Some(32768),
            protocol: rpc::forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
            action: rpc::forge::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
            priority: 9001,
            source_net: Some(
                rpc::forge::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
            destination_net: Some(
                rpc::forge::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
        }],
    });

    let too_many_rules =
        Some(rpc::forge::NetworkSecurityGroupAttributes {
            rules: vec![rpc::forge::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                .into(),
            ipv6: false,
            src_port_start: Some(80),
            src_port_end: Some(80),
            dst_port_start: Some(80),
            dst_port_end: Some(80),
            protocol: rpc::forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
            action: rpc::forge::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
            priority: 9001,
            source_net: Some(
                rpc::forge::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
            destination_net: Some(
                rpc::forge::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
        }; (default_max_network_security_group_size()+1) as usize],
        });

    // Prepare some attributes for creation and comparison later
    let network_security_group_attributes = Some(rpc::forge::NetworkSecurityGroupAttributes {
        rules: vec![rpc::forge::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                .into(),
            ipv6: false,
            src_port_start: Some(80),
            src_port_end: Some(80),
            dst_port_start: Some(90),
            dst_port_end: Some(90),
            protocol: rpc::forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
            action: rpc::forge::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
            priority: 9001,
            source_net: Some(
                rpc::forge::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
            destination_net: Some(
                rpc::forge::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
        }],
    });

    let metadata = Some(rpc::forge::Metadata {
        name: "the best NSG".to_string(),
        description: "".to_string(),
        labels: vec![],
    });

    // First, attempt to create a new NSG that's too big
    // because it will expand into too many rules.
    let _ = env
        .api
        .create_network_security_group(tonic::Request::new(
            rpc::forge::CreateNetworkSecurityGroupRequest {
                id: Some(id.to_string()),
                tenant_organization_id: default_tenant_org.to_string(),
                metadata: metadata.clone(),
                network_security_group_attributes: too_many_src_ports,
            },
        ))
        .await
        .unwrap_err();

    let _ = env
        .api
        .create_network_security_group(tonic::Request::new(
            rpc::forge::CreateNetworkSecurityGroupRequest {
                id: Some(id.to_string()),
                tenant_organization_id: default_tenant_org.to_string(),
                metadata: metadata.clone(),
                network_security_group_attributes: too_many_dst_ports,
            },
        ))
        .await
        .unwrap_err();

    // Then, attempt to create a new NSG that's too big because
    // it just has too many explicit rules.
    let _ = env
        .api
        .create_network_security_group(tonic::Request::new(
            rpc::forge::CreateNetworkSecurityGroupRequest {
                id: Some(id.to_string()),
                tenant_organization_id: default_tenant_org.to_string(),
                metadata: metadata.clone(),
                network_security_group_attributes: too_many_rules,
            },
        ))
        .await
        .unwrap_err();

    // Next, successfully create a new NSG
    let forge_network_security_group = env
        .api
        .create_network_security_group(tonic::Request::new(
            rpc::forge::CreateNetworkSecurityGroupRequest {
                id: Some(id.to_string()),
                tenant_organization_id: default_tenant_org.to_string(),
                metadata: metadata.clone(),
                network_security_group_attributes: network_security_group_attributes.clone(),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .network_security_group
        .unwrap();

    // Check that we're on our first version.
    let version: ConfigVersion = forge_network_security_group.version.parse()?;
    assert_eq!(version.version_nr(), 1);

    // Verify that the attributes we sent in are the attributes we got back out.
    assert_eq!(
        forge_network_security_group.attributes,
        network_security_group_attributes
    );

    //Verify the metadata
    assert_eq!(forge_network_security_group.metadata, metadata);

    // Next, try to create a duplicate with a new ID but the same name.
    // This should fail.
    let _ = env
        .api
        .create_network_security_group(tonic::Request::new(
            rpc::forge::CreateNetworkSecurityGroupRequest {
                id: Some("any_other_id".to_string()),
                tenant_organization_id: default_tenant_org.to_string(),
                metadata: metadata.clone(),
                network_security_group_attributes: network_security_group_attributes.clone(),
            },
        ))
        .await
        .unwrap_err();

    // Next, try to create a duplicate with a new ID and the same name
    // but for a different tenant.
    // This should pass.
    let _ = env
        .api
        .create_network_security_group(tonic::Request::new(
            rpc::forge::CreateNetworkSecurityGroupRequest {
                id: Some("any_other_id".to_string()),
                tenant_organization_id: tenant_org2.to_string(),
                metadata: metadata.clone(),
                network_security_group_attributes: network_security_group_attributes.clone(),
            },
        ))
        .await
        .unwrap();

    // Next, we'll find all the network security group IDs in the system.
    // There should two: one for each tenant.
    let forge_network_security_group_ids = env
        .api
        .find_network_security_group_ids(tonic::Request::new(
            rpc::forge::FindNetworkSecurityGroupIdsRequest {
                name: None,
                tenant_organization_id: None,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .network_security_group_ids;

    // We should have exactly two new ones
    assert_eq!(forge_network_security_group_ids.len(), 2);

    // Next, we'll use query options to search for our specific
    // network security group.
    let forge_network_security_group_ids = env
        .api
        .find_network_security_group_ids(tonic::Request::new(
            rpc::forge::FindNetworkSecurityGroupIdsRequest {
                name: Some("the best NSG".to_string()),
                tenant_organization_id: Some(default_tenant_org.to_string()),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .network_security_group_ids;

    // We should have exactly one.
    assert_eq!(forge_network_security_group_ids.len(), 1);

    // Next, we'll retrieve the previously created network security group
    // and make sure everything still matches.
    let forge_network_security_groups = env
        .api
        .find_network_security_groups_by_ids(tonic::Request::new(
            rpc::forge::FindNetworkSecurityGroupsByIdsRequest {
                network_security_group_ids: vec![id.to_string()],
                tenant_organization_id: None,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .network_security_groups;

    // We should have exactly one.
    assert_eq!(forge_network_security_groups.len(), 1);

    let network_security_group = forge_network_security_groups[0].clone();

    // The ID should be the one we started with.
    assert_eq!(network_security_group.id, id);

    // Verify that the attributes we sent in are the attributes we got back out.
    assert_eq!(
        network_security_group.attributes,
        network_security_group_attributes
    );

    //Verify the metadata
    assert_eq!(network_security_group.metadata, metadata);

    Ok(())
}

#[crate::sqlx_test]
async fn test_network_security_group_update(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    populate_network_security_groups(env.api.clone()).await;

    let existing_network_security_groups = env
        .api
        .find_network_security_groups_by_ids(tonic::Request::new(
            rpc::forge::FindNetworkSecurityGroupsByIdsRequest {
                // Provided by fixtures
                network_security_group_ids: vec![
                    "fd3ab096-d811-11ef-8fe9-7be4b2483448".to_string(),
                    "b65b13d6-d81c-11ef-9252-b346dc360bd4".to_string(),
                ],
                tenant_organization_id: None,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .network_security_groups;

    let id = existing_network_security_groups[0].id.clone();
    let version = existing_network_security_groups[0].version.clone();

    // Provided by fixtures
    let default_tenant_org = "Tenant1";

    // Prepare some bad attributes for testing NSG size limits
    let too_many_ports = Some(rpc::forge::NetworkSecurityGroupAttributes {
        rules: vec![rpc::forge::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                .into(),
            ipv6: false,
            src_port_start: Some(80),
            src_port_end: Some(32768),
            dst_port_start: Some(80),
            dst_port_end: Some(32768),
            protocol: rpc::forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
            action: rpc::forge::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
            priority: 9001,
            source_net: Some(
                rpc::forge::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
            destination_net: Some(
                rpc::forge::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
        }],
    });

    let too_many_rules =
        Some(rpc::forge::NetworkSecurityGroupAttributes {
            rules: vec![rpc::forge::NetworkSecurityGroupRuleAttributes {
                id: Some("anything".to_string()),
                direction: rpc::forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                    .into(),
                ipv6: false,
                src_port_start: Some(80),
                src_port_end: Some(80),
                dst_port_start: Some(80),
                dst_port_end: Some(80),
                protocol: rpc::forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                action: rpc::forge::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                priority: 9001,
                source_net: Some(
                    rpc::forge::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                        "0.0.0.0/0".to_string(),
                    ),
                ),
                destination_net: Some(
                    rpc::forge::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                        "0.0.0.0/0".to_string(),
                    ),
                ),
            }; (default_max_network_security_group_size()+1) as usize],
        });

    let update_network_security_group_attributes =
        Some(rpc::forge::NetworkSecurityGroupAttributes {
            rules: vec![rpc::forge::NetworkSecurityGroupRuleAttributes {
                id: Some("anything".to_string()),
                direction: rpc::forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                    .into(),
                ipv6: false,
                src_port_start: None,
                src_port_end: None,
                dst_port_start: Some(800),
                dst_port_end: Some(900),
                protocol: rpc::forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                action: rpc::forge::NetworkSecurityGroupRuleAction::NsgRuleActionPermit.into(),
                priority: 9002,
                source_net: Some(
                    rpc::forge::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                        "1.1.1.1/1".to_string(),
                    ),
                ),
                destination_net: Some(
                    rpc::forge::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                        "2.2.2.2/2".to_string(),
                    ),
                ),
            }],
        });

    let metadata = Some(rpc::forge::Metadata {
        name: "fixture_test_network_security_group_1".to_string(),
        description: "".to_string(),
        labels: vec![],
    });

    // Try to update the network security group with the wrong tenant org.  This should fail.
    let _ = env
        .api
        .update_network_security_group(tonic::Request::new(
            rpc::forge::UpdateNetworkSecurityGroupRequest {
                id: id.to_string(),
                tenant_organization_id: "this_is_a_bad_org".to_string(),
                metadata: metadata.clone(),
                network_security_group_attributes: update_network_security_group_attributes.clone(),
                if_version_match: None,
            },
        ))
        .await
        .unwrap_err();

    // Now update the network security group again.  This time it should
    // fail because we are trying to add too many implicit rules
    let _ = env
        .api
        .update_network_security_group(tonic::Request::new(
            rpc::forge::UpdateNetworkSecurityGroupRequest {
                id: id.to_string(),
                tenant_organization_id: default_tenant_org.to_string(),
                metadata: metadata.clone(),
                network_security_group_attributes: too_many_ports,
                if_version_match: None,
            },
        ))
        .await
        .unwrap_err();

    // One more update, and this time it should
    // fail because we are trying to add too many explicit rules
    let _ = env
        .api
        .update_network_security_group(tonic::Request::new(
            rpc::forge::UpdateNetworkSecurityGroupRequest {
                id: id.to_string(),
                tenant_organization_id: default_tenant_org.to_string(),
                metadata: metadata.clone(),
                network_security_group_attributes: too_many_rules,
                if_version_match: None,
            },
        ))
        .await
        .unwrap_err();

    // Now update the network security group again.  This time it should
    // pass because the tenant org is correct and we are adding a valid
    // amount of rules.
    let forge_network_security_group = env
        .api
        .update_network_security_group(tonic::Request::new(
            rpc::forge::UpdateNetworkSecurityGroupRequest {
                id: id.to_string(),
                tenant_organization_id: default_tenant_org.to_string(),
                metadata: metadata.clone(),
                network_security_group_attributes: update_network_security_group_attributes.clone(),
                if_version_match: None,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .network_security_group
        .unwrap();

    // Make sure we didn't somehow end up with a new id.
    assert_eq!(forge_network_security_group.id, id.to_string());

    // Check that we're on the second version.
    let next_version: ConfigVersion = forge_network_security_group.version.parse()?;
    assert_eq!(next_version.version_nr(), 2);

    // Verify that the attributes we sent in are the attributes we got back out.
    assert_eq!(
        forge_network_security_group.attributes,
        update_network_security_group_attributes
    );

    //Verify the metadata
    assert_eq!(forge_network_security_group.metadata, metadata);

    // Now update the network security group again but only if it's still on the first version.
    // This should fail.
    let _ = env
        .api
        .update_network_security_group(tonic::Request::new(
            rpc::forge::UpdateNetworkSecurityGroupRequest {
                id: id.to_string(),
                tenant_organization_id: default_tenant_org.to_string(),
                metadata: metadata.clone(),
                network_security_group_attributes: update_network_security_group_attributes.clone(),
                if_version_match: Some(version.to_string()),
            },
        ))
        .await
        .unwrap_err();

    // Now update the network security group AGAIN but only if its on the second version.
    // This should pass.
    let forge_network_security_group = env
        .api
        .update_network_security_group(tonic::Request::new(
            rpc::forge::UpdateNetworkSecurityGroupRequest {
                id: id.to_string(),
                tenant_organization_id: default_tenant_org.to_string(),
                metadata: metadata.clone(),
                network_security_group_attributes: update_network_security_group_attributes.clone(),
                if_version_match: Some(next_version.to_string()),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .network_security_group
        .unwrap();

    // Check that we're on the third version.
    let next_version: ConfigVersion = forge_network_security_group.version.parse()?;

    // Make sure we didn't somehow end up with a new id.
    assert_eq!(forge_network_security_group.id, id.to_string());

    assert_eq!(next_version.version_nr(), 3);
    // Verify that the attributes we sent in are the attributes we got back out.
    assert_eq!(
        forge_network_security_group.attributes,
        update_network_security_group_attributes
    );

    //Verify the metadata
    assert_eq!(forge_network_security_group.metadata, metadata);

    // Next, we'll retrieve the updated network security group
    // and make sure everything still matches and that we
    // didn't screw-up the DB update and lie to ourselves.
    let forge_network_security_groups = env
        .api
        .find_network_security_groups_by_ids(tonic::Request::new(
            rpc::forge::FindNetworkSecurityGroupsByIdsRequest {
                network_security_group_ids: vec![forge_network_security_group.id.to_string()],
                tenant_organization_id: Some(default_tenant_org.to_string()),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .network_security_groups;

    // We should have exactly one.
    assert_eq!(forge_network_security_groups.len(), 1);

    let network_security_group = forge_network_security_groups[0].clone();

    // The ID should be the one we started with.
    assert_eq!(network_security_group.id, id.to_string());

    // Verify that the attributes we sent in are the attributes we got back out.
    assert_eq!(
        network_security_group.attributes,
        update_network_security_group_attributes
    );

    //Verify the metadata
    assert_eq!(network_security_group.metadata, metadata);

    // Now update the network security group again, but use
    // the name of an existing type.  This should fail.
    let _ = env
        .api
        .update_network_security_group(tonic::Request::new(
            rpc::forge::UpdateNetworkSecurityGroupRequest {
                id: id.to_string(),
                tenant_organization_id: default_tenant_org.to_string(),
                metadata: Some(rpc::forge::Metadata {
                    name: existing_network_security_groups[1]
                        .metadata
                        .clone()
                        .unwrap()
                        .name,
                    description: "".to_string(),
                    labels: vec![],
                }),
                network_security_group_attributes: update_network_security_group_attributes.clone(),
                if_version_match: None,
            },
        ))
        .await
        .unwrap_err();

    Ok(())
}

#[crate::sqlx_test]
async fn test_network_security_group_delete(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    populate_network_security_groups(env.api.clone()).await;

    // Provided by fixtures
    let default_tenant_org = "Tenant1";

    // Our known fixture network security group
    let good_network_security_group_id = "fd3ab096-d811-11ef-8fe9-7be4b2483448".to_string();
    let bad_network_security_group_id = "ddfcabc4-92dc-41e2-874e-2c7eeb9fa156".to_string();

    // Create a VPC
    let vpc = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "".to_string(),
            tenant_organization_id: default_tenant_org.to_string(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            network_security_group_id: Some(good_network_security_group_id.clone()),
            metadata: Some(rpc::forge::Metadata {
                name: "Forge".to_string(),
                description: "".to_string(),
                labels: Vec::new(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    // Create a new managed host in the DB and get the snapshot.
    let mh = site_explorer::new_host(&env, ManagedHostConfig::default())
        .await
        .unwrap();

    let segment_id = env.create_vpc_and_tenant_segment().await;

    // Create an Instance
    let instance = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: mh.host_snapshot.id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                storage: None,
                network_security_group_id: Some(good_network_security_group_id.clone()),
            }),
            instance_id: None,
            instance_type_id: None,
            metadata: Some(rpc::forge::Metadata {
                name: "newinstance".to_string(),
                description: "desc".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    // Try to delete the NSG.  This should fail
    // because it's in use.
    let _ = env
        .api
        .delete_network_security_group(tonic::Request::new(
            rpc::forge::DeleteNetworkSecurityGroupRequest {
                id: good_network_security_group_id.to_string(),
                tenant_organization_id: default_tenant_org.to_string(),
            },
        ))
        .await
        .unwrap_err();

    // Delete the VPC and Instance
    let _ = env
        .api
        .release_instance(tonic::Request::new(rpc::forge::InstanceReleaseRequest {
            id: instance.id,
        }))
        .await
        .unwrap();

    let _ = env
        .api
        .delete_vpc(tonic::Request::new(rpc::forge::VpcDeletionRequest {
            id: vpc.id,
        }))
        .await
        .unwrap();

    // Try to delete the network security group again.
    // This time it should pass because there are no
    // associated objects.
    let _ = env
        .api
        .delete_network_security_group(tonic::Request::new(
            rpc::forge::DeleteNetworkSecurityGroupRequest {
                id: good_network_security_group_id.to_string(),
                tenant_organization_id: default_tenant_org.to_string(),
            },
        ))
        .await
        .unwrap();

    // Next, we'll try to retrieve the deleted network security group
    let forge_network_security_groups = env
        .api
        .find_network_security_groups_by_ids(tonic::Request::new(
            rpc::forge::FindNetworkSecurityGroupsByIdsRequest {
                network_security_group_ids: vec![good_network_security_group_id.to_string()],
                tenant_organization_id: None,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .network_security_groups;

    // We shouldn't find it.
    assert_eq!(forge_network_security_groups.len(), 0);

    // Now try to delete it AGAIN
    // This should be a no-op that returns without error.
    let _ = env
        .api
        .delete_network_security_group(tonic::Request::new(
            rpc::forge::DeleteNetworkSecurityGroupRequest {
                id: good_network_security_group_id.to_string(),
                tenant_organization_id: default_tenant_org.to_string(),
            },
        ))
        .await
        .unwrap();

    // Now try to delete a network security group with a blank ID.
    let _ = env
        .api
        .delete_network_security_group(tonic::Request::new(
            rpc::forge::DeleteNetworkSecurityGroupRequest {
                id: "".to_string(),
                tenant_organization_id: default_tenant_org.to_string(),
            },
        ))
        .await
        .unwrap_err();

    // Now try to delete a network security group of a different tenant.
    // This should fail because of the tenant mismatch.
    let _ = env
        .api
        .delete_network_security_group(tonic::Request::new(
            rpc::forge::DeleteNetworkSecurityGroupRequest {
                id: bad_network_security_group_id.to_string(),
                tenant_organization_id: default_tenant_org.to_string(),
            },
        ))
        .await
        .unwrap_err();

    Ok(())
}

#[crate::sqlx_test]
async fn test_network_security_group_propagation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    populate_network_security_groups(env.api.clone()).await;

    // Provided by fixtures
    let default_tenant_org = "Tenant1";

    // Our known fixture network security group
    let good_network_security_group_id = "fd3ab096-d811-11ef-8fe9-7be4b2483448";

    let vpc_id = "2ff5ba26-da6a-11ef-9c48-5b78e547a5e7";
    let instance_id = "46c555e0-da6a-11ef-b86d-db132142d068";

    let good_network_security_group = env
        .api
        .find_network_security_groups_by_ids(tonic::Request::new(
            rpc::forge::FindNetworkSecurityGroupsByIdsRequest {
                // Provided by fixtures
                network_security_group_ids: vec![good_network_security_group_id.to_string()],
                tenant_organization_id: None,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .network_security_groups
        .pop()
        .unwrap();

    // Check propagation status before doing anything else,
    // but make a bad request.
    let err = env
        .api
        .get_network_security_group_propagation_status(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupPropagationStatusRequest {
                network_security_group_ids: None,
                vpc_ids: vec![],
                instance_ids: vec![],
            },
        ))
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("at least one"));

    // Check propagation status again before doing anything else.
    // There should be no objects with any attached NSG
    // and no status should have been reported yet,
    // so there should be no results for any instance or VPC.
    // The results should be empty arrays.
    let prop_status = env
        .api
        .get_network_security_group_propagation_status(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupPropagationStatusRequest {
                network_security_group_ids: None,
                vpc_ids: vec![vpc_id.to_string()],
                instance_ids: vec![instance_id.to_string()],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let expected_results = rpc::forge::GetNetworkSecurityGroupPropagationStatusResponse {
        vpcs: vec![],
        instances: vec![],
    };

    assert_eq!(prop_status, expected_results);

    // Now create some objects with NSGs attached.

    let segment_id = env
        .create_vpc_and_tenant_segment_with_vpc_details(rpc::forge::VpcCreationRequest {
            id: Some(rpc::Uuid {
                value: vpc_id.to_string(),
            }),
            name: "Tenant1".to_string(),
            tenant_organization_id: default_tenant_org.to_string(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: None,
            network_security_group_id: Some(good_network_security_group_id.to_string()),
        })
        .await;

    // Create a new managed host in the DB and get the snapshot.
    let mh = site_explorer::new_host(&env, ManagedHostConfig::default())
        .await
        .unwrap();

    // Create an Instance
    let _ = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: mh.host_snapshot.id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                storage: None,
                network_security_group_id: Some(good_network_security_group_id.to_string()),
            }),
            instance_id: Some(rpc::Uuid {
                value: instance_id.to_string(),
            }),
            instance_type_id: None,
            metadata: Some(rpc::forge::Metadata {
                name: "newinstance".to_string(),
                description: "desc".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap();

    let prop_status = env
        .api
        .get_network_security_group_propagation_status(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupPropagationStatusRequest {
                network_security_group_ids: None,
                vpc_ids: vec![vpc_id.to_string()],
                instance_ids: vec![instance_id.to_string()],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    // No status should have been reported yet, so we
    // should see the instance as having no propagation.
    let expected_results = rpc::forge::GetNetworkSecurityGroupPropagationStatusResponse {
        vpcs: vec![],
        instances: vec![rpc::forge::NetworkSecurityGroupPropagationObjectStatus {
            id: instance_id.to_string(),
            status: rpc::forge::NetworkSecurityGroupPropagationStatus::NsgPropStatusNone.into(),
            details: None,
            related_instance_ids: vec![instance_id.to_string()],
            unpropagated_instance_ids: vec![instance_id.to_string()],
        }],
    };

    assert_eq!(prop_status, expected_results);

    // Now make a call to report status.
    let _ = env
        .api
        .record_observed_instance_network_status(tonic::Request::new(
            rpc::forge::InstanceNetworkStatusObservation {
                instance_id: Some(rpc::Uuid {
                    value: instance_id.to_string(),
                }),
                config_version: "V1-T1".to_string(),
                observed_at: Some(SystemTime::now().into()),
                interfaces: vec![rpc::forge::InstanceInterfaceStatusObservation {
                    gateways: vec!["10.180.125.1/27".to_string()],
                    prefixes: vec![],
                    addresses: vec!["10.180.125.5".to_string()],
                    function_type: rpc::forge::InterfaceFunctionType::Physical.into(),
                    mac_address: Some("A0:88:C2:4E:9B:78".to_string()),
                    virtual_function_id: None,
                    network_security_group: Some(rpc::forge::NetworkSecurityGroupStatus {
                        id: good_network_security_group_id.to_string(),
                        source: rpc::forge::NetworkSecurityGroupSource::NsgSourceInstance.into(),
                        version: good_network_security_group.version.to_string(),
                    }),
                }],
            },
        ))
        .await
        .unwrap();

    // Now that DPU status has been reported,
    // check propagation status again.
    let prop_status = env
        .api
        .get_network_security_group_propagation_status(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupPropagationStatusRequest {
                network_security_group_ids: None,
                vpc_ids: vec![vpc_id.to_string()],
                instance_ids: vec![instance_id.to_string()],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    // Up to now, the VPC and instance both have an NSG configured.
    // The instance should take precedence, so we should only see
    // that in the list, and the VPC has no children who need propagation.
    let expected_results = rpc::forge::GetNetworkSecurityGroupPropagationStatusResponse {
        vpcs: vec![],
        instances: vec![rpc::forge::NetworkSecurityGroupPropagationObjectStatus {
            id: instance_id.to_string(),
            status: rpc::forge::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull.into(),
            details: None,
            related_instance_ids: vec![instance_id.to_string()],
            unpropagated_instance_ids: vec![],
        }],
    };

    assert_eq!(prop_status, expected_results);

    // Now update the instance to remove the NSG attachment
    let instance = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                if_version_match: None,
                config: Some(rpc::InstanceConfig {
                    tenant: Some(default_tenant_config()),
                    os: Some(default_os_config()),
                    network: Some(single_interface_network_config(segment_id)),
                    infiniband: None,
                    storage: None,
                    network_security_group_id: None,
                }),
                instance_id: Some(rpc::Uuid {
                    value: instance_id.to_string(),
                }),
                metadata: Some(rpc::forge::Metadata {
                    name: "newinstance".to_string(),
                    description: "desc".to_string(),
                    labels: vec![],
                }),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    // Confirm that the security ID has been removed from the instance.
    assert_eq!(instance.config.unwrap().network_security_group_id, None);

    // Now check status again and we should see the VPC reported with
    // no propagation
    let prop_status = env
        .api
        .get_network_security_group_propagation_status(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupPropagationStatusRequest {
                network_security_group_ids: None,
                vpc_ids: vec![vpc_id.to_string()],
                instance_ids: vec![],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let expected_results = rpc::forge::GetNetworkSecurityGroupPropagationStatusResponse {
        vpcs: vec![rpc::forge::NetworkSecurityGroupPropagationObjectStatus {
            id: vpc_id.to_string(),
            status: rpc::forge::NetworkSecurityGroupPropagationStatus::NsgPropStatusNone.into(),
            details: None,
            related_instance_ids: vec![instance_id.to_string()],
            unpropagated_instance_ids: vec![instance_id.to_string()],
        }],
        instances: vec![],
    };

    assert_eq!(prop_status, expected_results);

    // Now send an observation update to make it look like
    // the DPU updated and has the NSG with the VPC source
    let _ = env
        .api
        .record_observed_instance_network_status(tonic::Request::new(
            rpc::forge::InstanceNetworkStatusObservation {
                instance_id: Some(rpc::Uuid {
                    value: instance_id.to_string(),
                }),
                config_version: "V1-T1".to_string(),
                observed_at: Some(SystemTime::now().into()),
                interfaces: vec![rpc::forge::InstanceInterfaceStatusObservation {
                    gateways: vec!["10.180.125.1/27".to_string()],
                    prefixes: vec![],
                    addresses: vec!["10.180.125.5".to_string()],
                    function_type: rpc::forge::InterfaceFunctionType::Physical.into(),
                    mac_address: Some("A0:88:C2:4E:9B:78".to_string()),
                    virtual_function_id: None,
                    network_security_group: Some(rpc::forge::NetworkSecurityGroupStatus {
                        id: good_network_security_group_id.to_string(),
                        source: rpc::forge::NetworkSecurityGroupSource::NsgSourceVpc.into(),
                        version: good_network_security_group.version.to_string(),
                    }),
                }],
            },
        ))
        .await
        .unwrap();

    // Now check status again, and we should see the VPC with full propagation.
    let prop_status = env
        .api
        .get_network_security_group_propagation_status(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupPropagationStatusRequest {
                network_security_group_ids: None,
                vpc_ids: vec![vpc_id.to_string()],
                instance_ids: vec![],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let expected_results = rpc::forge::GetNetworkSecurityGroupPropagationStatusResponse {
        vpcs: vec![rpc::forge::NetworkSecurityGroupPropagationObjectStatus {
            id: vpc_id.to_string(),
            status: rpc::forge::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull.into(),
            details: None,
            related_instance_ids: vec![instance_id.to_string()],
            unpropagated_instance_ids: vec![],
        }],
        instances: vec![],
    };

    assert_eq!(prop_status, expected_results);

    // Now add another machine and instance with no NSG
    // attached for the same VPC.
    let mh2 = site_explorer::new_host(&env, ManagedHostConfig::default())
        .await
        .unwrap();

    let instance_id2 = "16faf95e-dcb9-11ef-96b1-d3941046d310";
    // Create an Instance
    let _ = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: mh2.host_snapshot.id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                storage: None,
                network_security_group_id: None,
            }),
            instance_id: Some(rpc::Uuid {
                value: instance_id2.to_string(),
            }),
            instance_type_id: None,
            metadata: Some(rpc::forge::Metadata {
                name: "newinstance2".to_string(),
                description: "desc2".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap();

    // Now check status again and we should see the VPC with partial propagation
    let mut prop_status = env
        .api
        .get_network_security_group_propagation_status(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupPropagationStatusRequest {
                network_security_group_ids: None,
                vpc_ids: vec![vpc_id.to_string()],
                instance_ids: vec![],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let mut both_instances_sorted = vec![instance_id.to_string(), instance_id2.to_string()];
    both_instances_sorted.sort();

    let expected_results = rpc::forge::GetNetworkSecurityGroupPropagationStatusResponse {
        vpcs: vec![rpc::forge::NetworkSecurityGroupPropagationObjectStatus {
            id: vpc_id.to_string(),
            status: rpc::forge::NetworkSecurityGroupPropagationStatus::NsgPropStatusPartial.into(),
            details: None,
            related_instance_ids: both_instances_sorted.clone(),
            unpropagated_instance_ids: vec![instance_id2.to_string()],
        }],
        instances: vec![],
    };

    prop_status.vpcs[0].related_instance_ids.sort();
    prop_status.vpcs[0].unpropagated_instance_ids.sort();

    assert_eq!(prop_status, expected_results);

    // Now send an observation update to make it look like
    // the DPU of the other instance updated and has the NSG
    // with the VPC source.
    let _ = env
        .api
        .record_observed_instance_network_status(tonic::Request::new(
            rpc::forge::InstanceNetworkStatusObservation {
                instance_id: Some(rpc::Uuid {
                    value: instance_id2.to_string(),
                }),
                config_version: "V1-T1".to_string(),
                observed_at: Some(SystemTime::now().into()),
                interfaces: vec![rpc::forge::InstanceInterfaceStatusObservation {
                    gateways: vec!["10.180.125.1/27".to_string()],
                    prefixes: vec![],
                    addresses: vec!["10.180.125.6".to_string()],
                    function_type: rpc::forge::InterfaceFunctionType::Physical.into(),
                    mac_address: Some("AB:C8:D2:4E:9B:78".to_string()),
                    virtual_function_id: None,
                    network_security_group: Some(rpc::forge::NetworkSecurityGroupStatus {
                        id: good_network_security_group_id.to_string(),
                        source: rpc::forge::NetworkSecurityGroupSource::NsgSourceVpc.into(),
                        version: good_network_security_group.version.to_string(),
                    }),
                }],
            },
        ))
        .await
        .unwrap();

    // Now check status again and we should see the VPC with full propagation again.
    let mut prop_status = env
        .api
        .get_network_security_group_propagation_status(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupPropagationStatusRequest {
                network_security_group_ids: None,
                vpc_ids: vec![vpc_id.to_string()],
                instance_ids: vec![],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    prop_status.vpcs[0].related_instance_ids.sort();
    prop_status.vpcs[0].unpropagated_instance_ids.sort();

    let expected_results = rpc::forge::GetNetworkSecurityGroupPropagationStatusResponse {
        vpcs: vec![rpc::forge::NetworkSecurityGroupPropagationObjectStatus {
            id: vpc_id.to_string(),
            status: rpc::forge::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull.into(),
            details: None,
            related_instance_ids: both_instances_sorted.clone(),
            unpropagated_instance_ids: vec![],
        }],
        instances: vec![],
    };

    assert_eq!(prop_status, expected_results);

    // Now we update the NSG itself, and this should send everything
    // back into an unpropagated state.

    let nsg_version = env
        .api
        .update_network_security_group(tonic::Request::new(
            rpc::forge::UpdateNetworkSecurityGroupRequest {
                id: good_network_security_group_id.to_string(),
                if_version_match: None,
                tenant_organization_id: default_tenant_org.to_string(),
                metadata: Some(rpc::forge::Metadata {
                    name: "irrelevant".to_string(),
                    description: String::new(),
                    labels: vec![],
                }),
                network_security_group_attributes: Some(
                    rpc::forge::NetworkSecurityGroupAttributes {
                        rules: vec![rpc::forge::NetworkSecurityGroupRuleAttributes {
                id: Some("anything".to_string()),
                direction: rpc::forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                    .into(),
                ipv6: false,
                src_port_start: None,
                src_port_end: None,
                dst_port_start: Some(800),
                dst_port_end: Some(900),
                protocol: rpc::forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                action: rpc::forge::NetworkSecurityGroupRuleAction::NsgRuleActionPermit.into(),
                priority: 9002,
                source_net: Some(
                    rpc::forge::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                        "1.1.1.1/1".to_string(),
                    ),
                ),
                destination_net: Some(
                    rpc::forge::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                        "2.2.2.2/2".to_string(),
                    ),
                ),
            }],
                    },
                ),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .network_security_group
        .unwrap()
        .version;

    // Now check status again and we should see the VPC with no propagation again.
    let mut prop_status = env
        .api
        .get_network_security_group_propagation_status(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupPropagationStatusRequest {
                network_security_group_ids: None,
                vpc_ids: vec![vpc_id.to_string()],
                instance_ids: vec![],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    prop_status.vpcs[0].related_instance_ids.sort();
    prop_status.vpcs[0].unpropagated_instance_ids.sort();

    let expected_results = rpc::forge::GetNetworkSecurityGroupPropagationStatusResponse {
        vpcs: vec![rpc::forge::NetworkSecurityGroupPropagationObjectStatus {
            id: vpc_id.to_string(),
            status: rpc::forge::NetworkSecurityGroupPropagationStatus::NsgPropStatusNone.into(),
            details: None,
            related_instance_ids: both_instances_sorted.clone(),
            unpropagated_instance_ids: both_instances_sorted.clone(),
        }],
        instances: vec![],
    };

    assert_eq!(prop_status, expected_results);

    // Now another observation with the new version.
    let _ = env
        .api
        .record_observed_instance_network_status(tonic::Request::new(
            rpc::forge::InstanceNetworkStatusObservation {
                instance_id: Some(rpc::Uuid {
                    value: instance_id.to_string(),
                }),
                config_version: "V1-T1".to_string(),
                observed_at: Some(SystemTime::now().into()),
                interfaces: vec![rpc::forge::InstanceInterfaceStatusObservation {
                    gateways: vec!["10.180.125.1/27".to_string()],
                    prefixes: vec![],
                    addresses: vec!["10.180.125.6".to_string()],
                    function_type: rpc::forge::InterfaceFunctionType::Physical.into(),
                    mac_address: Some("AB:C8:D2:4E:9B:78".to_string()),
                    virtual_function_id: None,
                    network_security_group: Some(rpc::forge::NetworkSecurityGroupStatus {
                        id: good_network_security_group_id.to_string(),
                        source: rpc::forge::NetworkSecurityGroupSource::NsgSourceVpc.into(),
                        version: nsg_version.clone(),
                    }),
                }],
            },
        ))
        .await
        .unwrap();

    // Now check status again and we should see the VPC with partial propagation again.
    let mut prop_status = env
        .api
        .get_network_security_group_propagation_status(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupPropagationStatusRequest {
                network_security_group_ids: None,
                vpc_ids: vec![vpc_id.to_string()],
                instance_ids: vec![],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    prop_status.vpcs[0].related_instance_ids.sort();
    prop_status.vpcs[0].unpropagated_instance_ids.sort();

    let expected_results = rpc::forge::GetNetworkSecurityGroupPropagationStatusResponse {
        vpcs: vec![rpc::forge::NetworkSecurityGroupPropagationObjectStatus {
            id: vpc_id.to_string(),
            status: rpc::forge::NetworkSecurityGroupPropagationStatus::NsgPropStatusPartial.into(),
            details: None,
            related_instance_ids: both_instances_sorted.clone(),
            unpropagated_instance_ids: vec![instance_id2.to_string()],
        }],
        instances: vec![],
    };

    assert_eq!(prop_status, expected_results);

    // Now send an observation update for the second instance
    let _ = env
        .api
        .record_observed_instance_network_status(tonic::Request::new(
            rpc::forge::InstanceNetworkStatusObservation {
                instance_id: Some(rpc::Uuid {
                    value: instance_id2.to_string(),
                }),
                config_version: "V1-T1".to_string(),
                observed_at: Some(SystemTime::now().into()),
                interfaces: vec![rpc::forge::InstanceInterfaceStatusObservation {
                    gateways: vec!["10.180.125.1/27".to_string()],
                    prefixes: vec![],
                    addresses: vec!["10.180.125.5".to_string()],
                    function_type: rpc::forge::InterfaceFunctionType::Physical.into(),
                    mac_address: Some("A0:88:C2:4E:9B:78".to_string()),
                    virtual_function_id: None,
                    network_security_group: Some(rpc::forge::NetworkSecurityGroupStatus {
                        id: good_network_security_group_id.to_string(),
                        source: rpc::forge::NetworkSecurityGroupSource::NsgSourceVpc.into(),
                        version: nsg_version,
                    }),
                }],
            },
        ))
        .await
        .unwrap();

    // Now check status again and we should see the VPC with full propagation.
    let mut prop_status = env
        .api
        .get_network_security_group_propagation_status(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupPropagationStatusRequest {
                network_security_group_ids: None,
                vpc_ids: vec![vpc_id.to_string()],
                instance_ids: vec![],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    prop_status.vpcs[0].related_instance_ids.sort();
    prop_status.vpcs[0].unpropagated_instance_ids.sort();

    let expected_results = rpc::forge::GetNetworkSecurityGroupPropagationStatusResponse {
        vpcs: vec![rpc::forge::NetworkSecurityGroupPropagationObjectStatus {
            id: vpc_id.to_string(),
            status: rpc::forge::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull.into(),
            details: None,
            related_instance_ids: both_instances_sorted.clone(),
            unpropagated_instance_ids: vec![],
        }],
        instances: vec![],
    };

    assert_eq!(prop_status, expected_results);

    Ok(())
}

#[crate::sqlx_test]
async fn test_network_security_group_get_attachments(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    populate_network_security_groups(env.api.clone()).await;

    // Provided by fixtures
    let default_tenant_org = "Tenant1";

    // Our known fixture network security group
    let good_network_security_group_id = "fd3ab096-d811-11ef-8fe9-7be4b2483448";

    let vpc_id = "2ff5ba26-da6a-11ef-9c48-5b78e547a5e7";
    let instance_id = "46c555e0-da6a-11ef-b86d-db132142d068";

    // Check attachments before doing anything else.
    // There should be no objects with any attached NSG.
    let prop_status = env
        .api
        .get_network_security_group_attachments(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupAttachmentsRequest {
                network_security_group_ids: vec![good_network_security_group_id.to_string()],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let expected_results = rpc::forge::GetNetworkSecurityGroupAttachmentsResponse {
        attachments: vec![rpc::forge::NetworkSecurityGroupAttachments {
            network_security_group_id: good_network_security_group_id.to_string(),
            vpc_ids: vec![],
            instance_ids: vec![],
        }],
    };

    assert_eq!(prop_status, expected_results);

    // Now create some objects with NSGs attached.

    // Create a VPC
    let segment_id = env
        .create_vpc_and_tenant_segment_with_vpc_details(rpc::forge::VpcCreationRequest {
            id: Some(rpc::Uuid {
                value: vpc_id.to_string(),
            }),
            name: "Tenant1".to_string(),
            tenant_organization_id: default_tenant_org.to_string(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: None,
            network_security_group_id: Some(good_network_security_group_id.to_string()),
        })
        .await;

    // Create a new managed host in the DB and get the snapshot.
    let mh = site_explorer::new_host(&env, ManagedHostConfig::default())
        .await
        .unwrap();

    // Create an Instance
    let _ = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: mh.host_snapshot.id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                storage: None,
                network_security_group_id: Some(good_network_security_group_id.to_string()),
            }),
            instance_id: Some(rpc::Uuid {
                value: instance_id.to_string(),
            }),
            instance_type_id: None,
            metadata: Some(rpc::forge::Metadata {
                name: "newinstance".to_string(),
                description: "desc".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap();

    // Check attachments
    let prop_status = env
        .api
        .get_network_security_group_attachments(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupAttachmentsRequest {
                network_security_group_ids: vec![good_network_security_group_id.to_string()],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let expected_results = rpc::forge::GetNetworkSecurityGroupAttachmentsResponse {
        attachments: vec![rpc::forge::NetworkSecurityGroupAttachments {
            network_security_group_id: good_network_security_group_id.to_string(),
            vpc_ids: vec![vpc_id.to_string()],
            instance_ids: vec![instance_id.to_string()],
        }],
    };

    assert_eq!(prop_status, expected_results);

    // Delete the instance
    env.api
        .release_instance(tonic::Request::new(rpc::forge::InstanceReleaseRequest {
            id: Some(rpc::Uuid {
                value: instance_id.to_string(),
            }),
        }))
        .await
        .unwrap();
    // Delete the VPC
    env.api
        .delete_vpc(tonic::Request::new(rpc::forge::VpcDeletionRequest {
            id: Some(rpc::Uuid {
                value: vpc_id.to_string(),
            }),
        }))
        .await
        .unwrap();

    // Check attachments.  We should see none again.
    let prop_status = env
        .api
        .get_network_security_group_attachments(tonic::Request::new(
            rpc::forge::GetNetworkSecurityGroupAttachmentsRequest {
                network_security_group_ids: vec![good_network_security_group_id.to_string()],
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let expected_results = rpc::forge::GetNetworkSecurityGroupAttachmentsResponse {
        attachments: vec![rpc::forge::NetworkSecurityGroupAttachments {
            network_security_group_id: good_network_security_group_id.to_string(),
            vpc_ids: vec![],
            instance_ids: vec![],
        }],
    };

    assert_eq!(prop_status, expected_results);

    Ok(())
}
