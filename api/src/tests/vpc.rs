use crate::db::network_segment::NetworkSegment;
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
use crate::db::vpc::{self, UpdateVpc, UpdateVpcVirtualization, Vpc};
use crate::db::ObjectColumnFilter;
use crate::model::metadata::Metadata;
use crate::{db_init, CarbideError};
use common::api_fixtures::create_test_env;
use config_version::ConfigVersion;
use forge_network::virtualization::VpcVirtualizationType;
use forge_uuid::vpc::VpcId;
use rpc::forge::forge_server::Forge;
use std::collections::HashMap;
use std::ops::DerefMut;

use crate::tests::common;

#[crate::sqlx_test]
#[allow(deprecated)]
async fn create_vpc(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // No network_virtualization_type, should default
    let forge_vpc = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "".to_string(),
            tenant_organization_id: String::new(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: "Forge".to_string(),
                description: "".to_string(),
                labels: Vec::new(),
            }),
        }))
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
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "".to_string(),
            tenant_organization_id: String::new(),
            tenant_keyset_id: None,
            network_virtualization_type: Some(VpcVirtualizationType::EthernetVirtualizer as i32),
            metadata: Some(rpc::forge::Metadata {
                name: "Forge no Org".to_string(),
                description: "".to_string(),
                labels: Vec::new(),
            }),
        }))
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

    let no_org_vpc_id: VpcId = no_org_vpc.id.expect("should have id").try_into()?;

    let invalid_updated_vpc = env
        .api
        .update_vpc(tonic::Request::new(rpc::forge::VpcUpdateRequest {
            name: "".to_string(),
            id: Some(no_org_vpc_id.into()),
            if_version_match: None,
            metadata: Some(rpc::forge::Metadata {
                name: "new name with non-asci: €".to_string(),
                description: "".to_string(),
                labels: Vec::new(),
            }),
        }))
        .await;

    let error = invalid_updated_vpc
        .expect_err("expected VPC update to fail")
        .to_string();
    assert!(
        error.contains("must contain ASCII characters only"),
        "Error message should contain 'must contain ASCII characters only', but is {}",
        error
    );

    let updated_metadata = Metadata {
        name: "new name".to_string(),
        description: "".to_string(),
        labels: HashMap::from([("label_new_key".to_string(), "label_new_value".to_string())]),
    };

    let updated_vpc = UpdateVpc {
        id: no_org_vpc_id,
        if_version_match: None,
        metadata: updated_metadata.clone(),
    }
    .update(&mut txn)
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
    let _updated_vpc_virtualization = UpdateVpcVirtualization {
        id: no_org_vpc_id,
        if_version_match: None,
        network_virtualization_type: VpcVirtualizationType::Fnn,
    }
    .update(&mut txn)
    .await?;

    let mut vpcs = Vpc::find_by(
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
    let updated_vpc = UpdateVpcVirtualization {
        id: no_org_vpc_id,
        if_version_match: None,
        network_virtualization_type: orig_virtualization_type,
    }
    .update(&mut txn)
    .await?;

    let mut vpcs = Vpc::find_by(
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
    let update_result = UpdateVpc {
        id: no_org_vpc_id,
        if_version_match: Some(initial_no_org_vpc_version),
        metadata: Metadata {
            name: "never this name".to_string(),
            description: "".to_string(),
            labels: HashMap::new(),
        },
    }
    .update(&mut txn)
    .await;
    assert!(matches!(
        update_result,
        Err(CarbideError::ConcurrentModificationError(_, _))
    ));

    // Check that the data was indeed not touched
    let mut vpcs = Vpc::find_by(
        &mut txn,
        ObjectColumnFilter::One(vpc::IdColumn, &no_org_vpc_id),
    )
    .await?;
    let first = vpcs.swap_remove(0);
    assert_eq!(&first.metadata.name, "new name");
    assert_eq!(first.version.version_nr(), 4); // includes 2 changes to VPC virtualization type

    // Update on correct version
    let updated_vpc = UpdateVpc {
        id: no_org_vpc_id,
        if_version_match: Some(updated_vpc.version),
        metadata: Metadata {
            name: "yet another new name".to_string(),
            description: "".to_string(),
            labels: HashMap::new(),
        },
    }
    .update(&mut txn)
    .await?;
    assert_eq!(&updated_vpc.metadata.name, "yet another new name");
    assert_eq!(updated_vpc.version.version_nr(), 5);

    let mut vpcs = Vpc::find_by(
        &mut txn,
        ObjectColumnFilter::One(vpc::IdColumn, &no_org_vpc_id),
    )
    .await?;
    let first = vpcs.swap_remove(0);
    assert_eq!(&first.metadata.name, "yet another new name");
    assert_eq!(first.version.version_nr(), 5);

    let vpc = Vpc::try_delete(&mut txn, no_org_vpc_id).await?.unwrap();

    assert!(vpc.deleted.is_some());

    let vpcs = Vpc::find_by(&mut txn, ObjectColumnFilter::One(vpc::IdColumn, &vpc.id)).await?;

    txn.commit().await?;

    assert!(vpcs.is_empty());

    let mut txn = env.pool.begin().await?;
    let vpcs = Vpc::find_by(&mut txn, ObjectColumnFilter::<vpc::IdColumn>::All).await?;
    assert_eq!(vpcs.len(), 1);
    let forge_vpc_id: VpcId = forge_vpc.id.expect("should have id").try_into()?;
    assert_eq!(vpcs[0].id, forge_vpc_id);

    let vpc = Vpc::try_delete(&mut txn, forge_vpc_id).await?.unwrap();
    assert!(vpc.deleted.is_some());
    txn.commit().await?;

    let mut txn = env.pool.begin().await?;
    let vpcs = Vpc::find_by(&mut txn, ObjectColumnFilter::<vpc::IdColumn>::All).await?;
    assert!(vpcs.is_empty());
    txn.commit().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn create_vpc_with_labels(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let forge_vpc = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "".to_string(),
            tenant_organization_id: "Forge_unit_tests".to_string(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: "test_VPC_with_labels".to_string(),
                description: "this VPC must have labels.".to_string(),
                labels: vec![
                    rpc::forge::Label {
                        key: "key1".to_string(),
                        value: Some("value1".to_string()),
                    },
                    rpc::forge::Label {
                        key: "key2".to_string(),
                        value: None,
                    },
                ],
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    let vpc_id: VpcId = forge_vpc.id.expect("should have id").try_into()?;

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
        vpc_ids: vec![vpc_id.into()],
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
            .clone()
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
async fn create_vpc_with_invalid_labels(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let forge_vpc1 = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "".to_string(),
            tenant_organization_id: "Forge_unit_tests".to_string(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: "test_VPC_with_labels".to_string(),
                description: "this VPC must have labels.".to_string(),
                labels: vec![
                    rpc::forge::Label {
                        key: "key1".to_string(),
                        value: Some("value1".to_string()),
                    },
                    rpc::forge::Label {
                        key: "key2".to_string(),
                        value: None,
                    },
                    rpc::forge::Label {
                        key: "key3".to_string(),
                        value: Some("value1".to_string()),
                    },
                    rpc::forge::Label {
                        key: "key4".to_string(),
                        value: None,
                    },
                    rpc::forge::Label {
                        key: "key5".to_string(),
                        value: Some("value1".to_string()),
                    },
                    rpc::forge::Label {
                        key: "key6".to_string(),
                        value: None,
                    },
                    rpc::forge::Label {
                        key: "key7".to_string(),
                        value: Some("value1".to_string()),
                    },
                    rpc::forge::Label {
                        key: "key8".to_string(),
                        value: None,
                    },
                    rpc::forge::Label {
                        key: "key9".to_string(),
                        value: Some("value1".to_string()),
                    },
                    rpc::forge::Label {
                        key: "key10".to_string(),
                        value: None,
                    },
                    rpc::forge::Label {
                        key: "key11".to_string(),
                        value: Some("value1".to_string()),
                    },
                ],
            }),
        }))
        .await;

    let error = forge_vpc1
        .expect_err("expected allocation to fail")
        .to_string();
    assert!(
        error.contains("Cannot have more than 10 labels"),
        "Error message should contain 'Cannot have more than 10 labels', but is {}",
        error
    );

    let forge_vpc2 = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "".to_string(),
            tenant_organization_id: "Forge_unit_tests".to_string(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: "test_VPC_with_labels".to_string(),
                description: "this VPC must have labels.".to_string(),
                labels: vec![
                    rpc::forge::Label {
                        key: "Random257LongStringAZ7rfo6lZITregicb76ykFExk7b9rBjx5Y9T3h2CZnwPuMd8mdCCRXGKcScaiMHKdb81RUlKScU67J3bvVsRUzNRqBFT8akZqxWliFteFlpkAnxbUbRirNJjakt5lSOGv2Qs0BLRGpbqdIxCJiqTZJMJIZOWv3a2W5I9F4RGEn910rO54mrp5JODz3oS1Jp0M2ikc2WBJB70BcK0tETc8nBx6mp2hS3VUl4KemO57y6vqL".to_string(),
                        value: None,
                    },
                ],
            }),
        }))
        .await;

    let error = forge_vpc2
        .expect_err("expected allocation to fail")
        .to_string();
    assert!(
        error.contains("is too long"),
        "Error message should contain 'is too long', but is {}",
        error
    );

    let forge_vpc3 = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "".to_string(),
            tenant_organization_id: "Forge_unit_tests".to_string(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: "test_VPC_with_labels".to_string(),
                description: "this VPC must have labels.".to_string(),
                labels: vec![
                    rpc::forge::Label {
                        key: "key1".to_string(),
                        value: Some("Random257LongStringAZ7rfo6lZITregicb76ykFExk7b9rBjx5Y9T3h2CZnwPuMd8mdCCRXGKcScaiMHKdb81RUlKScU67J3bvVsRUzNRqBFT8akZqxWliFteFlpkAnxbUbRirNJjakt5lSOGv2Qs0BLRGpbqdIxCJiqTZJMJIZOWv3a2W5I9F4RGEn910rO54mrp5JODz3oS1Jp0M2ikc2WBJB70BcK0tETc8nBx6mp2hS3VUl4KemO57y6vqL".to_string()),
                    },
                ],
            }),
        }))
        .await;

    let error = forge_vpc3
        .expect_err("expected allocation to fail")
        .to_string();
    assert!(
        error.contains("is too long"),
        "Error message should contain 'is too long', but is {}",
        error
    );

    Ok(())
}

#[crate::sqlx_test]
async fn prevent_vpc_with_two_names(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let forge_vpc1 = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "vpc_name".to_string(),
            tenant_organization_id: "Forge_unit_tests".to_string(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: "vpc_another_name".to_string(),
                description: "No description.".to_string(),
                labels: vec![],
            }),
        }))
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
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "vpc_name".to_string(),
            tenant_organization_id: "Forge_unit_tests".to_string(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: "".to_string(),
                description: "No description.".to_string(),
                labels: vec![],
            }),
        }))
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
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "".to_string(),
            tenant_organization_id: String::new(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: "prevent_duplicate_vni".to_string(),
                description: "".to_string(),
                labels: Vec::new(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(forge_vpc_1.vni.is_some());
    let forge_vpc_2 = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "".to_string(),
            tenant_organization_id: String::new(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: "prevent_duplicate_vni".to_string(),
                description: "".to_string(),
                labels: Vec::new(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(forge_vpc_2.vni.is_some());
    assert_ne!(forge_vpc_1.vni, forge_vpc_2.vni);

    let vpc_2_id = forge_vpc_2.id.unwrap().try_into()?;

    // We can only update the VNI on a VPC that doesn't already have one, so clear it first
    let mut txn = env.pool.begin().await?;
    sqlx::query("UPDATE vpcs SET vni = NULL WHERE id = $1")
        .bind(vpc_2_id)
        .execute(&mut *txn)
        .await?;
    txn.commit().await?;

    // Try to set the second one's VNI to the first ones. It should fail
    let mut txn = env.pool.begin().await?;
    if let Ok(()) = Vpc::set_vni(&mut txn, vpc_2_id, forge_vpc_1.vni.unwrap() as i32).await {
        panic!("VPCs should be prevented from having duplicate VNIs");
    }
    txn.commit().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn find_vpc_by_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let vpc_id = VpcId::from(uuid::Uuid::new_v4());

    sqlx::query(r#"
        INSERT INTO vpcs (id, name, organization_id, version) VALUES ($1, 'test vpc 1', '2829bbe3-c169-4cd9-8b2a-19a8b1618a93', 'V1-T1666644937952267');
    "#).bind(vpc_id).execute(txn.deref_mut()).await?;

    let some_vpc = Vpc::find_by(&mut txn, ObjectColumnFilter::One(vpc::IdColumn, &vpc_id)).await?;
    assert_eq!(1, some_vpc.len());

    let first = some_vpc.first();
    assert!(matches!(first, Some(x) if x.id == vpc_id));

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_with_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let id = uuid::Uuid::new_v4();

    // No network_virtualization_type, should default
    let forge_vpc = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: Some(::rpc::Uuid {
                value: id.to_string(),
            }),
            name: "".to_string(),
            tenant_organization_id: String::new(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: "Forge".to_string(),
                description: "".to_string(),
                labels: Vec::new(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(forge_vpc.id.unwrap().value, id.to_string());
    Ok(())
}

#[crate::sqlx_test]
async fn vpc_deletion_is_idempotent(pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(pool).await;

    let vpc_req = rpc::forge::VpcCreationRequest {
        id: None,
        name: "".to_string(),
        tenant_organization_id: "test".to_string(),
        tenant_keyset_id: None,
        network_virtualization_type: None,
        metadata: Some(rpc::forge::Metadata {
            name: "test_vpc".to_string(),
            description: "".to_string(),
            labels: Vec::new(),
        }),
    };
    let resp = env
        .api
        .create_vpc(tonic::Request::new(vpc_req))
        .await
        .unwrap()
        .into_inner();

    let vpc_id = resp.id.clone().unwrap();
    assert_eq!(resp.name, "test_vpc");

    let vpc_list = env
        .api
        .find_vpcs(tonic::Request::new(rpc::forge::VpcSearchQuery {
            id: Some(vpc_id.clone()),
            name: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(vpc_list.vpcs.len(), 1);
    assert_eq!(vpc_list.vpcs[0].id, Some(vpc_id.clone()));
    assert_eq!(vpc_list.vpcs[0].name, "test_vpc");

    let vpc_list = env
        .api
        .find_vpcs(tonic::Request::new(rpc::forge::VpcSearchQuery {
            id: None,
            name: Some("test_vpc".to_string()),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(vpc_list.vpcs.len(), 1);
    assert_eq!(vpc_list.vpcs[0].id, Some(vpc_id.clone()));
    assert_eq!(vpc_list.vpcs[0].name, "test_vpc");

    // Delete the first time. Queries should now yield no results
    env.api
        .delete_vpc(tonic::Request::new(rpc::forge::VpcDeletionRequest {
            id: Some(vpc_id.clone()),
        }))
        .await
        .unwrap()
        .into_inner();

    let vpc_list = env
        .api
        .find_vpcs(tonic::Request::new(rpc::forge::VpcSearchQuery {
            id: Some(vpc_id.clone()),
            name: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(vpc_list.vpcs.is_empty());
    let vpc_list = env
        .api
        .find_vpcs(tonic::Request::new(rpc::forge::VpcSearchQuery {
            id: None,
            name: Some("test_vpc".to_string()),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(vpc_list.vpcs.is_empty());

    // With a duplicated delete query, we want to return NotFound
    let delete_result = env
        .api
        .delete_vpc(tonic::Request::new(rpc::forge::VpcDeletionRequest {
            id: Some(vpc_id.clone()),
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
    let mut admin_vpc = Vpc::find_by_vni(&mut txn, vni as i32).await?;

    let admin_vpc = admin_vpc.remove(0);

    assert_eq!(
        admin_vpc.network_virtualization_type,
        VpcVirtualizationType::Fnn
    );

    let admin_segment = NetworkSegment::admin(&mut txn).await?;

    assert_eq!(admin_vpc.id, admin_segment.vpc_id.unwrap());

    Ok(())
}
