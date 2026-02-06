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

use carbide_uuid::vpc::VpcId;
use common::api_fixtures::{create_test_env, populate_network_security_groups};
use config_version::ConfigVersion;
use db::vpc::{self};
use db::{self, ObjectColumnFilter};
use forge_network::virtualization::VpcVirtualizationType;
use model::metadata::Metadata;
use model::vpc::{UpdateVpc, UpdateVpcVirtualization};
use rpc::forge::forge_server::Forge;

use crate::tests::common;
use crate::tests::common::rpc_builder::{VpcCreationRequest, VpcUpdateRequest};
use crate::{DatabaseError, db_init};

#[crate::sqlx_test]
async fn create_vpc(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // No network_virtualization_type, should default
    let forge_vpc = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("", "")
                .metadata(rpc::forge::Metadata {
                    name: "Forge".to_string(),
                    description: "".to_string(),
                    labels: Vec::new(),
                })
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    let version: ConfigVersion = forge_vpc.version.parse()?;
    assert_eq!(version.version_nr(), 1);
    // A VNI is allocated
    assert!(forge_vpc.vni.is_some());
    // We default to type Ethernet Virtualizer
    assert_eq!(forge_vpc.network_virtualization_type, Some(0));

    let no_org_vpc = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("", "")
                .network_virtualization_type(rpc::forge::VpcVirtualizationType::from(
                    VpcVirtualizationType::EthernetVirtualizer,
                ))
                .metadata(Metadata {
                    name: "Forge no Org".to_string(),
                    ..Metadata::default()
                })
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();
    let no_org_vpc_version: ConfigVersion = no_org_vpc.version.parse()?;
    assert_eq!(no_org_vpc_version.version_nr(), 1);

    assert!(no_org_vpc.deleted.is_none());
    let initial_no_org_vpc_version = no_org_vpc_version;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let no_org_vpc_id: VpcId = no_org_vpc.id.expect("should have id");

    // Try to update to invalid metadata
    for (invalid_metadata, expected_err) in common::metadata::invalid_metadata_testcases(true) {
        let invalid_updated_vpc = env
            .api
            .update_vpc(tonic::Request::new(rpc::forge::VpcUpdateRequest {
                name: "".to_string(),
                id: Some(no_org_vpc_id),
                if_version_match: None,
                metadata: Some(invalid_metadata.clone()),
                network_security_group_id: None,
                default_nvlink_logical_partition_id: None,
            }))
            .await;

        let err = invalid_updated_vpc.expect_err(&format!(
            "Invalid metadata of type should not be accepted: {invalid_metadata:?}"
        ));
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().contains(&expected_err),
            "Testcase: {:?}\nMessage is \"{}\".\nMessage should contain: \"{}\"",
            invalid_metadata,
            err.message(),
            expected_err
        );
    }

    let updated_metadata = Metadata {
        name: "new name".to_string(),
        description: "".to_string(),
        labels: HashMap::from([("label_new_key".to_string(), "label_new_value".to_string())]),
    };

    let updated_vpc = db::vpc::update(
        &UpdateVpc {
            id: no_org_vpc_id,
            if_version_match: None,
            metadata: updated_metadata.clone(),
            network_security_group_id: None,
        },
        &mut txn,
    )
    .await?;

    assert_eq!(updated_vpc.metadata, updated_metadata);
    assert_eq!(updated_vpc.version.version_nr(), 2);

    // This only works because `EthernetVirtualizer` is the default
    // virtualization type right now. Once we change the default type,
    // this will fail, and we'll need to update the test. BUT, I wanted
    // to be explicit here.
    assert_eq!(
        updated_vpc.network_virtualization_type,
        VpcVirtualizationType::EthernetVirtualizer
    );

    // Update virtualization type.
    let orig_virtualization_type = updated_vpc.network_virtualization_type;
    let _updated_vpc_virtualization = db::vpc::update_virtualization(
        &UpdateVpcVirtualization {
            id: no_org_vpc_id,
            if_version_match: None,
            network_virtualization_type: VpcVirtualizationType::Fnn,
        },
        &mut txn,
    )
    .await?;

    let mut vpcs = db::vpc::find_by(
        &mut txn,
        ObjectColumnFilter::One(vpc::IdColumn, &no_org_vpc_id),
    )
    .await?;
    let first = vpcs.swap_remove(0);
    assert_eq!(
        first.network_virtualization_type,
        VpcVirtualizationType::Fnn
    );

    // And then put the virtualization type back and mark
    // this as the latest `updated_vpc` for subsequent checks.
    let updated_vpc = db::vpc::update_virtualization(
        &UpdateVpcVirtualization {
            id: no_org_vpc_id,
            if_version_match: None,
            network_virtualization_type: orig_virtualization_type,
        },
        &mut txn,
    )
    .await?;

    let mut vpcs = db::vpc::find_by(
        &mut txn,
        ObjectColumnFilter::One(vpc::IdColumn, &no_org_vpc_id),
    )
    .await?;
    let first = vpcs.swap_remove(0);
    assert_eq!(
        first.network_virtualization_type,
        VpcVirtualizationType::EthernetVirtualizer
    );

    // Update on outdated version
    let update_result = db::vpc::update(
        &UpdateVpc {
            id: no_org_vpc_id,
            if_version_match: Some(initial_no_org_vpc_version),
            network_security_group_id: None,
            metadata: Metadata {
                name: "never this name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
        },
        &mut txn,
    )
    .await;
    assert!(matches!(
        update_result,
        Err(DatabaseError::ConcurrentModificationError(_, _))
    ));

    // Check that the data was indeed not touched
    let mut vpcs = db::vpc::find_by(
        &mut txn,
        ObjectColumnFilter::One(vpc::IdColumn, &no_org_vpc_id),
    )
    .await?;
    let first = vpcs.swap_remove(0);
    assert_eq!(&first.metadata.name, "new name");
    assert_eq!(first.version.version_nr(), 4); // includes 2 changes to VPC virtualization type

    // Update on correct version
    let updated_vpc = db::vpc::update(
        &UpdateVpc {
            id: no_org_vpc_id,
            network_security_group_id: None,
            if_version_match: Some(updated_vpc.version),
            metadata: Metadata {
                name: "yet another new name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
        },
        &mut txn,
    )
    .await?;
    assert_eq!(&updated_vpc.metadata.name, "yet another new name");
    assert_eq!(updated_vpc.version.version_nr(), 5);

    let mut vpcs = db::vpc::find_by(
        &mut txn,
        ObjectColumnFilter::One(vpc::IdColumn, &no_org_vpc_id),
    )
    .await?;
    let first = vpcs.swap_remove(0);
    assert_eq!(&first.metadata.name, "yet another new name");
    assert_eq!(first.version.version_nr(), 5);

    let vpc = db::vpc::try_delete(&mut txn, no_org_vpc_id).await?.unwrap();

    assert!(vpc.deleted.is_some());

    let vpcs = db::vpc::find_by(&mut txn, ObjectColumnFilter::One(vpc::IdColumn, &vpc.id)).await?;

    txn.commit().await?;

    assert!(vpcs.is_empty());

    let mut txn = env.pool.begin().await?;
    let vpcs = db::vpc::find_by(&mut txn, ObjectColumnFilter::<vpc::IdColumn>::All).await?;
    assert_eq!(vpcs.len(), 1);
    let forge_vpc_id: VpcId = forge_vpc.id.expect("should have id");
    assert_eq!(vpcs[0].id, forge_vpc_id);

    let vpc = db::vpc::try_delete(&mut txn, forge_vpc_id).await?.unwrap();
    assert!(vpc.deleted.is_some());
    txn.commit().await?;

    let mut txn = env.pool.begin().await?;
    let vpcs = db::vpc::find_by(&mut txn, ObjectColumnFilter::<vpc::IdColumn>::All).await?;
    assert!(vpcs.is_empty());
    txn.commit().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn create_vpc_with_labels(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let forge_vpc = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("", "Forge_unit_tests")
                .metadata(Metadata {
                    name: "test_VPC_with_labels".to_string(),
                    description: "this VPC must have labels.".to_string(),
                    labels: vec![("key1", "value1"), ("key2", "")]
                        .into_iter()
                        .map(|(k, v)| (k.into(), v.into()))
                        .collect(),
                })
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    let vpc_id: VpcId = forge_vpc.id.expect("should have id");

    assert_eq!(
        &forge_vpc.metadata.clone().unwrap().name,
        "test_VPC_with_labels"
    );
    assert_eq!(
        forge_vpc.metadata.clone().unwrap().description,
        "this VPC must have labels."
    );
    assert!(forge_vpc.metadata.clone().unwrap().labels.len() == 2);

    assert_eq!(
        forge_vpc
            .metadata
            .clone()
            .unwrap()
            .labels
            .iter()
            .find(|label| label.key == "key1")
            .and_then(|label| label.value.as_deref()),
        Some("value1")
    );

    assert_eq!(
        forge_vpc
            .metadata
            .clone()
            .unwrap()
            .labels
            .iter()
            .find(|label| label.key == "key2")
            .and_then(|label| label.value.as_deref()),
        None
    );

    let request_vpcs = tonic::Request::new(rpc::forge::VpcsByIdsRequest {
        vpc_ids: vec![vpc_id],
    });

    let vpc_list = env
        .api
        .find_vpcs_by_ids(request_vpcs)
        .await
        .map(|response| response.into_inner())
        .unwrap();

    assert_eq!(vpc_list.vpcs.len(), 1);
    let fetched_vpc = vpc_list.vpcs[0].clone();

    assert_eq!(
        &fetched_vpc.metadata.clone().unwrap().name,
        "test_VPC_with_labels"
    );
    assert_eq!(&fetched_vpc.tenant_organization_id, "Forge_unit_tests");
    assert_eq!(
        fetched_vpc.metadata.clone().unwrap().description,
        "this VPC must have labels."
    );
    assert!(fetched_vpc.metadata.clone().unwrap().labels.len() == 2);

    assert_eq!(
        fetched_vpc
            .metadata
            .clone()
            .unwrap()
            .labels
            .iter()
            .find(|label| label.key == "key1")
            .and_then(|label| label.value.as_deref()),
        Some("value1")
    );

    assert_eq!(
        fetched_vpc
            .metadata
            .unwrap()
            .labels
            .iter()
            .find(|label| label.key == "key2")
            .and_then(|label| label.value.as_deref()),
        None
    );

    Ok(())
}

#[crate::sqlx_test]
async fn create_vpc_with_invalid_metadata(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    for (invalid_metadata, expected_err) in common::metadata::invalid_metadata_testcases(true) {
        let result = env
            .api
            .create_vpc(
                VpcCreationRequest::builder("", "Forge_unit_tests")
                    .metadata(invalid_metadata.clone())
                    .tonic_request(),
            )
            .await;

        let err = result.expect_err(&format!(
            "Invalid metadata of type should not be accepted: {invalid_metadata:?}"
        ));
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().contains(&expected_err),
            "Testcase: {:?}\nMessage is \"{}\".\nMessage should contain: \"{}\"",
            invalid_metadata,
            err.message(),
            expected_err
        )
    }

    Ok(())
}

#[crate::sqlx_test]
async fn prevent_vpc_with_two_names(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let forge_vpc1 = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("vpc_name", "Forge_unit_tests")
                .metadata(Metadata {
                    name: "vpc_another_name".to_string(),
                    description: "No description.".to_string(),
                    ..Default::default()
                })
                .tonic_request(),
        )
        .await;

    match forge_vpc1 {
        Ok(..) => panic!("Expected VPC creation failure when two names are passed."),
        Err(e) => {
            assert_eq!(
                e.message(),
                "VPC name must be specified under metadata only."
            );
        }
    };

    let forge_vpc2 = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("vpc_name", "Forge_unit_tests")
                .metadata(Metadata {
                    description: "No description.".to_string(),
                    ..Default::default()
                })
                .tonic_request(),
        )
        .await;

    match forge_vpc2 {
        Ok(..) => {
            panic!("Expected VPC creation failure when metadata exists but vpc.name is not empty.")
        }
        Err(e) => {
            assert_eq!(
                e.message(),
                "VPC name must be specified under metadata only."
            );
        }
    };

    Ok(())
}

#[crate::sqlx_test]
async fn prevent_duplicate_vni(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // Create two VPCs

    let forge_vpc_1 = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("", "")
                .metadata(Metadata {
                    name: "prevent_duplicate_vni".to_string(),
                    ..Default::default()
                })
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();
    assert!(forge_vpc_1.vni.is_some());
    let forge_vpc_2 = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("", "")
                .metadata(Metadata {
                    name: "prevent_duplicate_vni".to_string(),
                    ..Default::default()
                })
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();
    assert!(forge_vpc_2.vni.is_some());
    assert_ne!(forge_vpc_1.vni, forge_vpc_2.vni);

    let vpc_2_id = forge_vpc_2.id.unwrap();

    // We can only update the VNI on a VPC that doesn't already have one, so clear it first
    let mut txn = env.pool.begin().await?;
    sqlx::query("UPDATE vpcs SET vni = NULL WHERE id = $1")
        .bind(vpc_2_id)
        .execute(&mut *txn)
        .await?;
    txn.commit().await?;

    // Try to set the second one's VNI to the first ones. It should fail
    let mut txn = env.pool.begin().await?;
    if let Ok(()) = db::vpc::set_vni(&mut txn, vpc_2_id, forge_vpc_1.vni.unwrap() as i32).await {
        panic!("VPCs should be prevented from having duplicate VNIs");
    }
    txn.commit().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn find_vpc_by_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let vpc_id = VpcId::new();

    sqlx::query(r#"
        INSERT INTO vpcs (id, name, organization_id, version) VALUES ($1, 'test vpc 1', '2829bbe3-c169-4cd9-8b2a-19a8b1618a93', 'V1-T1666644937952267');
    "#).bind(vpc_id).execute(txn.deref_mut()).await?;

    let some_vpc =
        db::vpc::find_by(&mut txn, ObjectColumnFilter::One(vpc::IdColumn, &vpc_id)).await?;
    assert_eq!(1, some_vpc.len());

    let first = some_vpc.first();
    assert!(matches!(first, Some(x) if x.id == vpc_id));

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_with_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let id = VpcId::new();

    // No network_virtualization_type, should default
    let forge_vpc = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("", "")
                .id(id)
                .metadata(Metadata {
                    name: "Forge".to_string(),
                    ..Default::default()
                })
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    assert_eq!(forge_vpc.id.unwrap(), id);
    Ok(())
}

#[crate::sqlx_test]
async fn vpc_deletion_is_idempotent(pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(pool).await;

    let vpc_req = VpcCreationRequest::builder("", "test")
        .metadata(Metadata {
            name: "test_vpc".to_string(),
            ..Default::default()
        })
        .tonic_request();
    let resp = env.api.create_vpc(vpc_req).await.unwrap().into_inner();

    let vpc_id = resp.id.unwrap();
    assert_eq!(resp.name, "test_vpc");

    let vpc_list = env
        .api
        .find_vpcs_by_ids(tonic::Request::new(rpc::forge::VpcsByIdsRequest {
            vpc_ids: vec![vpc_id],
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(vpc_list.vpcs.len(), 1);
    assert_eq!(vpc_list.vpcs[0].id, Some(vpc_id));
    assert_eq!(vpc_list.vpcs[0].name, "test_vpc");

    // Delete the first time. Queries should now yield no results
    env.api
        .delete_vpc(tonic::Request::new(rpc::forge::VpcDeletionRequest {
            id: Some(vpc_id),
        }))
        .await
        .unwrap()
        .into_inner();

    let vpc_list = env
        .api
        .find_vpcs_by_ids(tonic::Request::new(rpc::forge::VpcsByIdsRequest {
            vpc_ids: vec![vpc_id],
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(vpc_list.vpcs.is_empty());
    let vpc_list = env
        .api
        .find_vpc_ids(tonic::Request::new(rpc::forge::VpcSearchFilter {
            name: Some("test_vpc".to_string()),
            tenant_org_id: None,
            label: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(vpc_list.vpc_ids.is_empty());

    // With a duplicated delete query, we want to return NotFound
    let delete_result = env
        .api
        .delete_vpc(tonic::Request::new(rpc::forge::VpcDeletionRequest {
            id: Some(vpc_id),
        }))
        .await;
    let err = delete_result.expect_err("Deletion should fail");
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(err.message(), format!("vpc not found: {vpc_id}"));

    Ok(())
}

#[crate::sqlx_test]
async fn create_admin_vpc(pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(pool).await;
    let vni = 10000;
    db_init::create_admin_vpc(&env.pool, Some(vni)).await?;

    let mut txn = env.pool.begin().await?;
    let mut admin_vpc = db::vpc::find_by_vni(&mut txn, vni as i32).await?;

    let admin_vpc = admin_vpc.remove(0);

    assert_eq!(
        admin_vpc.network_virtualization_type,
        VpcVirtualizationType::Fnn
    );

    let admin_segment = db::network_segment::admin(&mut txn).await?;

    assert_eq!(admin_vpc.id, admin_segment.vpc_id.unwrap());

    Ok(())
}

#[crate::sqlx_test]
async fn create_update_network_security_group_for_vpc(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    populate_network_security_groups(env.api.clone()).await;

    let good_network_security_group_id = "fd3ab096-d811-11ef-8fe9-7be4b2483448";
    let bad_network_security_group_id = "ddfcabc4-92dc-41e2-874e-2c7eeb9fa156";

    let default_tenant_org = "Tenant1";

    // Attempt to create a VPC with an NSG of a
    // different tenant.  This should fail.
    let _ = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("", default_tenant_org)
                .network_security_group_id(bad_network_security_group_id)
                .metadata(Metadata::new_with_default_name())
                .tonic_request(),
        )
        .await
        .unwrap_err();

    // Try again with a good NSG ID.
    let vpc = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("", default_tenant_org)
                .network_security_group_id(good_network_security_group_id)
                .metadata(Metadata::new_with_default_name())
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    // Make sure the VPC has the security group we expect

    assert_eq!(
        vpc.network_security_group_id.as_deref(),
        Some(good_network_security_group_id)
    );

    let vpc_id = vpc.id;

    // Attempt to update the VPC with an NSG of a
    // different tenant.  This should fail.
    let _ = env
        .api
        .update_vpc(
            VpcUpdateRequest::builder("")
                .set_id(vpc_id)
                .network_security_group_id(bad_network_security_group_id)
                .metadata(Metadata::new_with_default_name())
                .tonic_request(),
        )
        .await
        .unwrap_err();

    // Try again with a good NSG ID.
    let vpc = env
        .api
        .update_vpc(
            VpcUpdateRequest::builder("")
                .set_id(vpc_id)
                .network_security_group_id(good_network_security_group_id)
                .metadata(Metadata::new_with_default_name())
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner()
        .vpc
        .unwrap();

    // Make sure the VPC has the security group we expect
    assert_eq!(
        vpc.network_security_group_id.as_deref(),
        Some(good_network_security_group_id)
    );

    // Update again to clear the the NSG attachment.
    let vpc = env
        .api
        .update_vpc(
            VpcUpdateRequest::builder("")
                .set_id(vpc_id)
                .metadata(Metadata::new_with_default_name())
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner()
        .vpc
        .unwrap();

    // Make sure the VPC has no NSG ID
    assert!(vpc.network_security_group_id.is_none());

    Ok(())
}
