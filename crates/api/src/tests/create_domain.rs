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
use db::ObjectColumnFilter;
use model::dns::NewDomain;

use crate::DatabaseError;

#[crate::sqlx_test]
async fn create_delete_valid_domain(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let test_name = "nv.metal.net".to_string();

    let domain = db::dns::domain::persist(NewDomain::new(test_name), &mut txn).await;

    assert!(domain.is_ok());

    let delete_result = db::dns::domain::delete(domain.unwrap(), &mut txn).await;

    assert!(delete_result.is_ok());

    let domains = db::dns::domain::find_by(
        &mut txn,
        ObjectColumnFilter::<db::dns::domain::IdColumn>::All,
    )
    .await
    .unwrap();

    assert_eq!(domains.len(), 0);

    txn.commit().await.unwrap();
}

#[crate::sqlx_test]
async fn create_invalid_domain_case(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let test_name = "DwRt".to_string();

    let domain = db::dns::domain::persist(NewDomain::new(test_name), &mut txn).await;

    txn.commit().await.unwrap();

    assert!(matches!(domain, Err(DatabaseError::InvalidArgument(_))));
}

#[crate::sqlx_test]
async fn create_invalid_domain_regex(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let domain =
        db::dns::domain::persist(NewDomain::new("ihaveaspace.com ".to_string()), &mut txn).await;

    txn.commit().await.unwrap();

    assert!(matches!(domain, Err(DatabaseError::InvalidArgument(_))));
}

#[crate::sqlx_test]
async fn find_domain(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let test_name = "nvfind.metal.net".to_string();

    let domain = db::dns::domain::persist(NewDomain::new(test_name), &mut txn).await;

    txn.commit().await.unwrap();

    assert!(domain.is_ok());

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let domains = db::dns::domain::find_by(
        &mut txn,
        ObjectColumnFilter::<db::dns::domain::IdColumn>::All,
    )
    .await
    .unwrap();

    assert_eq!(domains.len(), 1);
}

#[crate::sqlx_test]
async fn update_domain(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let test_name = "nv.metal.net".to_string();

    let domain = db::dns::domain::persist(NewDomain::new(test_name), &mut txn).await;

    txn.commit().await.unwrap();

    assert!(domain.is_ok());

    let updated_name = "updated.metal.net".to_string();

    let mut updated_domain = domain.unwrap();

    updated_domain.name = updated_name;
    updated_domain.increment_serial();

    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let update_result = db::dns::domain::update(&mut updated_domain, &mut txn).await;

    txn.commit().await.unwrap();

    assert!(update_result.is_ok());
}
