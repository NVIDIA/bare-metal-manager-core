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

use carbide::db::vpc::{DeleteVpc, UpdateVpc, Vpc, VpcVirtualizationType};
use carbide::db::UuidKeyedObjectFilter;
use carbide::model::config_version::ConfigVersion;
use carbide::CarbideError;
use common::api_fixtures::create_test_env;
use rpc::forge::forge_server::Forge;

pub mod common;

const FIXTURE_CREATED_VPC_ID: uuid::Uuid = uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f");

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test]
async fn create_vpc(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // No network_virtualization_type, should default
    let forge_vpc = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "Forge".to_string(),
            tenant_organization_id: String::new(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
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
            name: "Forge no Org".to_string(),
            tenant_organization_id: String::new(),
            tenant_keyset_id: None,
            network_virtualization_type: Some(VpcVirtualizationType::EthernetVirtualizer as i32),
        }))
        .await
        .unwrap()
        .into_inner();
    let no_org_vpc_version: ConfigVersion = no_org_vpc.version.parse()?;
    assert_eq!(no_org_vpc_version.version_nr(), 1);

    assert!(no_org_vpc.deleted.is_none());
    let initial_no_org_vpc_version = no_org_vpc_version;

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let no_org_vpc_id: uuid::Uuid = no_org_vpc.id.expect("should have id").try_into()?;
    let updated_vpc = UpdateVpc {
        id: no_org_vpc_id,
        name: "new name".to_string(),
        tenant_organization_id: "new org".to_string(),
        if_version_match: None,
    }
    .update(&mut txn)
    .await?;

    assert_eq!(&updated_vpc.name, "new name");
    assert_eq!(&updated_vpc.tenant_organization_id, "new org");
    assert_eq!(updated_vpc.version.version_nr(), 2);

    // Update on outdated version
    let update_result = UpdateVpc {
        id: no_org_vpc_id,
        name: "never this name".to_string(),
        tenant_organization_id: "never this org".to_string(),
        if_version_match: Some(initial_no_org_vpc_version),
    }
    .update(&mut txn)
    .await;
    assert!(matches!(
        update_result,
        Err(CarbideError::ConcurrentModificationError(_, _))
    ));

    // Check that the data was indeed not touched
    let mut vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::One(no_org_vpc_id)).await?;
    let first = vpcs.swap_remove(0);
    assert_eq!(&first.name, "new name");
    assert_eq!(&first.tenant_organization_id, "new org");
    assert_eq!(first.version.version_nr(), 2);

    // Update on correct version
    let updated_vpc = UpdateVpc {
        id: no_org_vpc_id,
        name: "yet another new name".to_string(),
        tenant_organization_id: "yet another new org".to_string(),
        if_version_match: Some(updated_vpc.version),
    }
    .update(&mut txn)
    .await?;
    assert_eq!(&updated_vpc.name, "yet another new name");
    assert_eq!(&updated_vpc.tenant_organization_id, "yet another new org");
    assert_eq!(updated_vpc.version.version_nr(), 3);

    let mut vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::One(no_org_vpc_id)).await?;
    let first = vpcs.swap_remove(0);
    assert_eq!(&first.name, "yet another new name");
    assert_eq!(&first.tenant_organization_id, "yet another new org");
    assert_eq!(first.version.version_nr(), 3);

    let vpc = DeleteVpc { id: no_org_vpc_id }.delete(&mut txn).await?;

    assert!(vpc.deleted.is_some());

    let vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::One(vpc.id)).await?;

    txn.commit().await?;

    assert!(vpcs.is_empty());

    let mut txn = pool.begin().await?;
    let vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::All).await?;
    assert_eq!(vpcs.len(), 1);
    let forge_vpc_id: uuid::Uuid = forge_vpc.id.expect("should have id").try_into()?;
    assert_eq!(vpcs[0].id, forge_vpc_id);

    let vpc = DeleteVpc { id: forge_vpc_id }.delete(&mut txn).await?;
    assert!(vpc.deleted.is_some());
    txn.commit().await?;

    let mut txn = pool.begin().await?;
    let vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::All).await?;
    assert!(vpcs.is_empty());
    txn.commit().await?;

    Ok(())
}

#[sqlx::test]
async fn prevent_duplicate_vni(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create two VPCs

    let forge_vpc_1 = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "prevent_duplicate_vni".to_string(),
            tenant_organization_id: String::new(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(forge_vpc_1.vni.is_some());
    let forge_vpc_2 = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: None,
            name: "prevent_duplicate_vni".to_string(),
            tenant_organization_id: String::new(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(forge_vpc_2.vni.is_some());
    assert_ne!(forge_vpc_1.vni, forge_vpc_2.vni);

    let vpc_2_id = forge_vpc_2.id.unwrap().try_into()?;

    // We can only update the VNI on a VPC that doesn't already have one, so clear it first
    let mut txn = pool.begin().await?;
    sqlx::query("UPDATE vpcs SET vni = NULL WHERE id = $1")
        .bind(vpc_2_id)
        .execute(&mut *txn)
        .await?;
    txn.commit().await?;

    // Try to set the second one's VNI to the first ones. It should fail
    let mut txn = pool.begin().await?;
    if let Ok(()) = Vpc::set_vni(&mut txn, vpc_2_id, forge_vpc_1.vni.unwrap() as i32).await {
        panic!("VPCs should be prevented from having duplicate VNIs");
    }
    txn.commit().await?;

    Ok(())
}

#[sqlx::test(fixtures("create_vpc"))]
async fn find_vpc_by_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let some_vpc = Vpc::find(&mut txn, UuidKeyedObjectFilter::One(FIXTURE_CREATED_VPC_ID)).await?;
    assert_eq!(1, some_vpc.len());

    let first = some_vpc.first();
    assert!(matches!(first, Some(x) if x.id == FIXTURE_CREATED_VPC_ID));

    Ok(())
}

#[sqlx::test(fixtures("create_vpc"))]
async fn find_vpc_by_name(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let some_vpc = Vpc::find_by_name(&mut txn, "test vpc 1".to_string()).await?;

    assert_eq!(1, some_vpc.len());

    let first = some_vpc.first();

    assert!(matches!(first, Some(x) if x.id == FIXTURE_CREATED_VPC_ID));

    Ok(())
}

#[sqlx::test]
async fn test_vpc_with_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let id = uuid::Uuid::new_v4();

    // No network_virtualization_type, should default
    let forge_vpc = env
        .api
        .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
            id: Some(::rpc::Uuid {
                value: id.to_string(),
            }),
            name: "Forge".to_string(),
            tenant_organization_id: String::new(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(forge_vpc.id.unwrap().value, id.to_string());
    Ok(())
}
