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

use config_version::ConfigVersion;
use rpc::forge::forge_server::Forge;

use crate::tests::common::api_fixtures::{create_managed_host, create_test_env};

#[crate::sqlx_test]
async fn test_instance_type_create(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let existing_instance_type_ids = env
        .api
        .find_instance_type_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypeIdsRequest {},
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_type_ids;

    let id = "can_i_see_some_id?";

    // Prepare some attributes for creation and comparison later
    let instance_type_attributes = Some(rpc::forge::InstanceTypeAttributes {
        desired_capabilities: vec![rpc::forge::InstanceTypeMachineCapabilityAttributes {
            capability_type: rpc::forge::InstanceTypeMachineCapabilityType::CapTypeCpu.into(),
            name: Some("pentium 4 HT".to_string()),
            frequency: Some("1.3 GHz".to_string()),
            capacity: None,
            vendor: Some("intel".to_string()),
            count: Some(1),
            hardware_revision: None,
            cores: Some(1),
            threads: Some(2),
        }],
    });

    let metadata = Some(rpc::forge::Metadata {
        name: "the best type".to_string(),
        description: "".to_string(),
        labels: vec![],
    });

    // First, we'll create a new instance type
    let forge_instance_type = env
        .api
        .create_instance_type(tonic::Request::new(rpc::forge::CreateInstanceTypeRequest {
            id: Some(id.to_string()),
            metadata: metadata.clone(),
            instance_type_attributes: instance_type_attributes.clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .instance_type
        .unwrap();

    // Check that we're on our first version.
    let version: ConfigVersion = forge_instance_type.version.parse()?;
    assert_eq!(version.version_nr(), 1);

    // Verify that the attributes we sent in are the attributes we got back out.
    assert_eq!(forge_instance_type.attributes, instance_type_attributes);

    //Verify the metadata
    assert_eq!(forge_instance_type.metadata, metadata);

    // Next, try to create a duplicate with a new ID but the same name.
    // This should fail.
    let _ = env
        .api
        .create_instance_type(tonic::Request::new(rpc::forge::CreateInstanceTypeRequest {
            id: Some("any_other_id".to_string()),
            metadata: metadata.clone(),
            instance_type_attributes: instance_type_attributes.clone(),
        }))
        .await
        .unwrap_err();

    // Next, we'll find all the instance type IDs in the system.
    // There should only be one.

    let forge_instance_type_ids = env
        .api
        .find_instance_type_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypeIdsRequest {},
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_type_ids;

    // We should have exactly one new one.
    assert_eq!(
        forge_instance_type_ids.len(),
        existing_instance_type_ids.len() + 1
    );

    // Next, we'll retrieve the previously created instance type
    // and make sure everything still matches.
    let forge_instance_types = env
        .api
        .find_instance_types_by_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypesByIdsRequest {
                instance_type_ids: vec![id.to_string()],
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_types;

    // We should have exactly one.
    assert_eq!(forge_instance_types.len(), 1);

    let instance_type = forge_instance_types[0].clone();

    // The ID should be the one we started with.
    assert_eq!(instance_type.id, id);

    // Verify that the attributes we sent in are the attributes we got back out.
    assert_eq!(instance_type.attributes, instance_type_attributes);

    //Verify the metadata
    assert_eq!(instance_type.metadata, metadata);

    Ok(())
}

#[crate::sqlx_test]
async fn test_instance_type_update(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // Find the existing instance types in the test env
    let existing_instance_type_ids = env
        .api
        .find_instance_type_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypeIdsRequest {},
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_type_ids;

    let existing_instance_types = env
        .api
        .find_instance_types_by_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypesByIdsRequest {
                instance_type_ids: existing_instance_type_ids,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_types;

    let id = existing_instance_types[0].id.clone();
    let version = existing_instance_types[0].version.clone();

    let update_instance_type_attributes = Some(rpc::forge::InstanceTypeAttributes {
        desired_capabilities: vec![rpc::forge::InstanceTypeMachineCapabilityAttributes {
            capability_type: rpc::forge::InstanceTypeMachineCapabilityType::CapTypeCpu.into(),
            name: Some("pentium 9000".to_string()),
            frequency: Some("100.3 GHz".to_string()),
            capacity: None,
            vendor: Some("intel".to_string()),
            count: Some(1),
            hardware_revision: None,
            cores: Some(1),
            threads: Some(2),
        }],
    });

    let metadata = Some(rpc::forge::Metadata {
        name: "fixture_test_instance_type_1".to_string(),
        description: "".to_string(),
        labels: vec![],
    });

    // Create a host machine to associate with the instance type
    let (tmp_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    // Associate the machine with the instance type
    let _ = env
        .api
        .associate_machines_with_instance_type(tonic::Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: id.to_string(),
                machine_ids: vec![tmp_machine_id.to_string()],
            },
        ))
        .await
        .unwrap();

    // Associate a DPU  with the instance type.  This should fail.
    let _ = env
        .api
        .associate_machines_with_instance_type(tonic::Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: id.to_string(),
                machine_ids: vec![dpu_machine_id.to_string()],
            },
        ))
        .await
        .unwrap_err();

    // Try to update the instance type.  This should fail
    // because there's a machine associated with the instance type.
    let _ = env
        .api
        .update_instance_type(tonic::Request::new(rpc::forge::UpdateInstanceTypeRequest {
            id: id.to_string(),
            metadata: metadata.clone(),
            instance_type_attributes: update_instance_type_attributes.clone(),
            if_version_match: None,
        }))
        .await
        .unwrap_err();

    // Remove the association with the machine
    let _ = env
        .api
        .remove_machine_instance_type_association(tonic::Request::new(
            rpc::forge::RemoveMachineInstanceTypeAssociationRequest {
                machine_id: tmp_machine_id.to_string(),
            },
        ))
        .await
        .unwrap();

    // Now update the instance type again.  This time it should
    // pass because there are no associated machines.
    let forge_instance_type = env
        .api
        .update_instance_type(tonic::Request::new(rpc::forge::UpdateInstanceTypeRequest {
            id: id.to_string(),
            metadata: metadata.clone(),
            instance_type_attributes: update_instance_type_attributes.clone(),
            if_version_match: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .instance_type
        .unwrap();

    // Check that we're on the second version.
    let next_version: ConfigVersion = forge_instance_type.version.parse()?;

    // Make we didn't somehow end up with a new id.
    assert_eq!(forge_instance_type.id, id.to_string());

    assert_eq!(next_version.version_nr(), 2);

    // Verify that the attributes we sent in are the attributes we got back out.
    assert_eq!(
        forge_instance_type.attributes,
        update_instance_type_attributes
    );

    //Verify the metadata
    assert_eq!(forge_instance_type.metadata, metadata);

    // Now update the instance type again but only if it's still on the first version.
    // This should fail.
    let _ = env
        .api
        .update_instance_type(tonic::Request::new(rpc::forge::UpdateInstanceTypeRequest {
            id: id.to_string(),
            metadata: metadata.clone(),
            instance_type_attributes: update_instance_type_attributes.clone(),
            if_version_match: Some(version.to_string()),
        }))
        .await
        .unwrap_err();

    // Now update the instance type AGAIN but only if its on the second version.
    // This should pass.
    let forge_instance_type = env
        .api
        .update_instance_type(tonic::Request::new(rpc::forge::UpdateInstanceTypeRequest {
            id: id.to_string(),
            metadata: metadata.clone(),
            instance_type_attributes: update_instance_type_attributes.clone(),
            if_version_match: Some(next_version.to_string()),
        }))
        .await
        .unwrap()
        .into_inner()
        .instance_type
        .unwrap();

    // Check that we're on the third version.
    let next_version: ConfigVersion = forge_instance_type.version.parse()?;

    // Make we didn't somehow end up with a new id.
    assert_eq!(forge_instance_type.id, id.to_string());

    assert_eq!(next_version.version_nr(), 3);
    // Verify that the attributes we sent in are the attributes we got back out.
    assert_eq!(
        forge_instance_type.attributes,
        update_instance_type_attributes
    );

    //Verify the metadata
    assert_eq!(forge_instance_type.metadata, metadata);

    // Next, we'll retrieve updated instance type
    // and make sure everything still matches and that we
    // didn't screw-up the DB update and lie to ourselves.
    let forge_instance_types = env
        .api
        .find_instance_types_by_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypesByIdsRequest {
                instance_type_ids: vec![forge_instance_type.id.to_string()],
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_types;

    // We should have exactly one.
    assert_eq!(forge_instance_types.len(), 1);

    let instance_type = forge_instance_types[0].clone();

    // The ID should be the one we started with.
    assert_eq!(instance_type.id, id.to_string());

    // Verify that the attributes we sent in are the attributes we got back out.
    assert_eq!(instance_type.attributes, update_instance_type_attributes);

    //Verify the metadata
    assert_eq!(instance_type.metadata, metadata);

    // Now update instance type again, but use
    // use the name of an existing type.  This should fail.
    let _ = env
        .api
        .update_instance_type(tonic::Request::new(rpc::forge::UpdateInstanceTypeRequest {
            id: id.to_string(),
            metadata: Some(rpc::forge::Metadata {
                name: existing_instance_types[1].metadata.clone().unwrap().name,
                description: "".to_string(),
                labels: vec![],
            }),
            instance_type_attributes: update_instance_type_attributes.clone(),
            if_version_match: None,
        }))
        .await
        .unwrap_err();

    Ok(())
}

#[crate::sqlx_test]
async fn test_instance_type_delete(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // Find the existing instance types in the test env
    let existing_instance_type_ids = env
        .api
        .find_instance_type_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypeIdsRequest {},
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_type_ids;

    let existing_instance_types = env
        .api
        .find_instance_types_by_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypesByIdsRequest {
                instance_type_ids: existing_instance_type_ids,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_types;

    // Our known fixture instance type
    let id = existing_instance_types[0].id.clone();

    // Create a host machine to associate with the instance type
    let (tmp_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    // Associate the machine with the instance type
    let _ = env
        .api
        .associate_machines_with_instance_type(tonic::Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: id.to_string(),
                machine_ids: vec![tmp_machine_id.to_string()],
            },
        ))
        .await
        .unwrap();

    // Try to delete the instance type.  This should fail
    // because there's a machine associated with the instance type.
    let _ = env
        .api
        .delete_instance_type(tonic::Request::new(rpc::forge::DeleteInstanceTypeRequest {
            id: id.to_string(),
        }))
        .await
        .unwrap_err();

    // Remove the association with the machine
    let _ = env
        .api
        .remove_machine_instance_type_association(tonic::Request::new(
            rpc::forge::RemoveMachineInstanceTypeAssociationRequest {
                machine_id: tmp_machine_id.to_string(),
            },
        ))
        .await
        .unwrap();

    // Try to delete the instance type again.
    // This time it should pass because there are no
    // associated machines.
    let _ = env
        .api
        .delete_instance_type(tonic::Request::new(rpc::forge::DeleteInstanceTypeRequest {
            id: id.to_string(),
        }))
        .await
        .unwrap();

    // Next, we'll try to retrieve the deleted instance type
    let forge_instance_types = env
        .api
        .find_instance_types_by_ids(tonic::Request::new(
            rpc::forge::FindInstanceTypesByIdsRequest {
                instance_type_ids: vec![id.to_string()],
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .instance_types;

    // We shouldn't find it.
    assert_eq!(forge_instance_types.len(), 0);

    // Now try to delete it AGAIN
    // This should be a no-op that returns without error.
    let _ = env
        .api
        .delete_instance_type(tonic::Request::new(rpc::forge::DeleteInstanceTypeRequest {
            id: id.to_string(),
        }))
        .await
        .unwrap();

    // Now try to associate a machine with the instance type we just deleted.
    // This should fail.
    let _ = env
        .api
        .associate_machines_with_instance_type(tonic::Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: id.to_string(),
                machine_ids: vec![tmp_machine_id.to_string()],
            },
        ))
        .await
        .unwrap_err();

    // Now try to delete an instance type with a blank ID.
    let _ = env
        .api
        .delete_instance_type(tonic::Request::new(rpc::forge::DeleteInstanceTypeRequest {
            id: "".to_string(),
        }))
        .await
        .unwrap_err();

    Ok(())
}
