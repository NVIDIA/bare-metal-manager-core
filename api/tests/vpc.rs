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

use carbide::db::vpc::{DeleteVpc, NewVpc, UpdateVpc, Vpc};
use carbide::db::UuidKeyedObjectFilter;
use carbide::CarbideError;

pub mod common;

const FIXTURE_CREATED_VPC_ID: uuid::Uuid = uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f");

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test]
async fn create_vpc(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let forge_vpc = NewVpc {
        name: "Forge".to_string(),
        tenant_organization_id: String::new(),
    }
    .persist(&mut txn)
    .await?;
    assert_eq!(forge_vpc.version.version_nr(), 1);

    let no_org_vpc = NewVpc {
        name: "Forge no Org".to_string(),
        tenant_organization_id: String::new(),
    }
    .persist(&mut txn)
    .await?;
    assert_eq!(no_org_vpc.version.version_nr(), 1);

    assert!(matches!(no_org_vpc.deleted, None));
    let initial_no_org_vpc_version = no_org_vpc.version;

    txn.commit().await?;

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let updated_vpc = UpdateVpc {
        id: no_org_vpc.id,
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
        id: no_org_vpc.id,
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
    let mut vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::One(no_org_vpc.id)).await?;
    let first = vpcs.swap_remove(0);
    assert_eq!(&first.name, "new name");
    assert_eq!(&first.tenant_organization_id, "new org");
    assert_eq!(first.version.version_nr(), 2);

    // Update on correct version
    let updated_vpc = UpdateVpc {
        id: no_org_vpc.id,
        name: "yet another new name".to_string(),
        tenant_organization_id: "yet another new org".to_string(),
        if_version_match: Some(updated_vpc.version),
    }
    .update(&mut txn)
    .await?;
    assert_eq!(&updated_vpc.name, "yet another new name");
    assert_eq!(&updated_vpc.tenant_organization_id, "yet another new org");
    assert_eq!(updated_vpc.version.version_nr(), 3);

    let mut vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::One(no_org_vpc.id)).await?;
    let first = vpcs.swap_remove(0);
    assert_eq!(&first.name, "yet another new name");
    assert_eq!(&first.tenant_organization_id, "yet another new org");
    assert_eq!(first.version.version_nr(), 3);

    let vpc = DeleteVpc { id: no_org_vpc.id }.delete(&mut txn).await?;

    assert!(matches!(vpc.deleted, Some(_)));

    let vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::One(vpc.id)).await?;

    txn.commit().await?;

    assert!(vpcs.is_empty());

    let mut txn = pool.begin().await?;
    let vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::All).await?;
    assert_eq!(vpcs.len(), 1);
    assert_eq!(vpcs[0].id, forge_vpc.id);

    let vpc = DeleteVpc { id: forge_vpc.id }.delete(&mut txn).await?;
    assert!(matches!(vpc.deleted, Some(_)));
    txn.commit().await?;

    let mut txn = pool.begin().await?;
    let vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::All).await?;
    assert!(vpcs.is_empty());
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
