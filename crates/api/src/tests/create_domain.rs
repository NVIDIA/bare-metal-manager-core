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
        txn.as_mut(),
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
        txn.as_mut(),
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
