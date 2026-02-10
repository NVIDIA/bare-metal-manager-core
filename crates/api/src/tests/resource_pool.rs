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

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use common::api_fixtures::create_test_env;
use model::resource_pool::common::VPC_VNI;
use model::resource_pool::{
    OwnerType, ResourcePool, ResourcePoolError, ResourcePoolStats as St, ValueType,
};
use rpc::forge::forge_server::Forge;
use sqlx::migrate::MigrateDatabase;

use crate::tests;
use crate::tests::common;
use crate::tests::common::rpc_builder::VpcCreationRequest;

// Define an IPv4 pool from a range via the admin grpc
#[crate::sqlx_test]
async fn test_define_range(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;
    let toml = r#"
[test_define_range]
type = "ipv4"
ranges = [{ start = "172.0.1.0", end = "172.0.1.255" }]
"#;
    let rp_req = rpc::forge::GrowResourcePoolRequest {
        text: toml.to_string(),
    };
    env.api
        .admin_grow_resource_pool(tonic::Request::new(rp_req))
        .await
        .unwrap();

    let pool: ResourcePool<Ipv4Addr> =
        ResourcePool::new("test_define_range".to_string(), ValueType::Ipv4);

    let mut txn = db_pool.begin().await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool.name()).await?,
        St {
            used: 0,
            free: 255,
            auto_assign_free: 255,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );

    Ok(())
}

// Define an IPv4 pool from a prefix via the admin grpc
#[crate::sqlx_test]
async fn test_define_prefix(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;
    let toml = r#"
[test_define_range]
type = "ipv4"
prefix = "172.0.1.0/24"
"#;
    let rp_req = rpc::forge::GrowResourcePoolRequest {
        text: toml.to_string(),
    };
    env.api
        .admin_grow_resource_pool(tonic::Request::new(rp_req))
        .await
        .unwrap();

    let pool: ResourcePool<Ipv4Addr> =
        ResourcePool::new("test_define_range".to_string(), ValueType::Ipv4);

    let mut txn = db_pool.begin().await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool.name()).await?,
        St {
            used: 0,
            free: 255,
            auto_assign_free: 255,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_simple(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let mut txn = db_pool.begin().await?;
    let pool = ResourcePool::new("test_simple".to_string(), ValueType::Integer);

    // one auto-assignable value in the pool
    db::resource_pool::populate(&pool, &mut txn, vec!["1".to_string()], true).await?;

    // one non-auto-assignable value in the pool
    db::resource_pool::populate(&pool, &mut txn, vec!["2".to_string()], false).await?;

    // Get an auto-allocated value
    let auto_allocated =
        db::resource_pool::allocate(&pool, &mut txn, OwnerType::Machine, "123", None).await?;
    assert_eq!(auto_allocated, "1");
    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool.name()).await?,
        St {
            used: 1,
            free: 1,
            auto_assign_free: 0,
            auto_assign_used: 1,
            non_auto_assign_free: 1,
            non_auto_assign_used: 0
        }
    );

    // no more auto values
    match db::resource_pool::allocate(&pool, &mut txn, OwnerType::Machine, "id456", None).await {
        Err(db::resource_pool::ResourcePoolDatabaseError::ResourcePool(
            ResourcePoolError::Empty,
        )) => {} // expected
        Err(err) => panic!("Unexpected err: {err}"),
        Ok(_) => panic!("Pool should be empty"),
    }

    // Get an non-auto-allocated value
    let non_auto_allocated = db::resource_pool::allocate(
        &pool,
        &mut txn,
        OwnerType::Machine,
        "123",
        Some("2".to_string()),
    )
    .await?;
    assert_eq!(non_auto_allocated, "2");
    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool.name()).await?,
        St {
            used: 2,
            free: 0,
            auto_assign_free: 0,
            auto_assign_used: 1,
            non_auto_assign_free: 0,
            non_auto_assign_used: 1
        }
    );

    // return the values
    db::resource_pool::release(&pool, &mut txn, auto_allocated).await?;
    db::resource_pool::release(&pool, &mut txn, non_auto_allocated).await?;

    // and then there was one
    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool.name()).await?,
        St {
            used: 0,
            free: 2,
            auto_assign_free: 1,
            auto_assign_used: 0,
            non_auto_assign_free: 1,
            non_auto_assign_used: 0
        }
    );

    txn.rollback().await?;
    Ok(())
}

#[crate::sqlx_test]
async fn test_multiple(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let mut txn = db_pool.begin().await?;
    let pool1 = ResourcePool::new("test_multiple_1".to_string(), ValueType::Integer);
    let pool2 = ResourcePool::new("test_multiple_2".to_string(), ValueType::Integer);
    let pool3 = ResourcePool::new("test_multiple_3".to_string(), ValueType::Integer);

    db::resource_pool::populate(&pool1, &mut txn, (1..=10).collect::<Vec<_>>(), true).await?;
    db::resource_pool::populate(&pool2, &mut txn, (1..=100).collect::<Vec<_>>(), true).await?;
    db::resource_pool::populate(&pool3, &mut txn, (1..=500).collect::<Vec<_>>(), true).await?;

    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool1.name()).await?,
        St {
            used: 0,
            free: 10,
            auto_assign_free: 10,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool2.name()).await?,
        St {
            used: 0,
            free: 100,
            auto_assign_free: 100,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool3.name()).await?,
        St {
            used: 0,
            free: 500,
            auto_assign_free: 500,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );

    let mut got = Vec::with_capacity(10);
    for _ in 1..=10 {
        got.push(
            db::resource_pool::allocate(&pool2, &mut txn, OwnerType::Machine, "my_id", None)
                .await
                .unwrap(),
        );
    }

    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool1.name()).await?,
        St {
            used: 0,
            free: 10,
            auto_assign_free: 10,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool2.name()).await?,
        St {
            used: 10,
            free: 90,
            auto_assign_free: 90,
            auto_assign_used: 10,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool3.name()).await?,
        St {
            used: 0,
            free: 500,
            auto_assign_free: 500,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );

    for val in got {
        db::resource_pool::release(&pool2, &mut txn, val).await?;
    }

    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool1.name()).await?,
        St {
            used: 0,
            free: 10,
            auto_assign_free: 10,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool2.name()).await?,
        St {
            used: 0,
            free: 100,
            auto_assign_free: 100,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool3.name()).await?,
        St {
            used: 0,
            free: 500,
            auto_assign_free: 500,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );

    txn.rollback().await?;
    Ok(())
}

#[crate::sqlx_test]
async fn test_rollback(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let pool = ResourcePool::new("test_rollback".to_string(), ValueType::Integer);

    // Pool has a single value
    let mut txn = db_pool.begin().await?;
    db::resource_pool::populate(&pool, &mut txn, vec![1], true).await?;
    txn.commit().await?;

    // Which we allocate then rollback
    let mut txn = db_pool.begin().await?;
    db::resource_pool::allocate(&pool, &mut txn, OwnerType::Machine, "my_id", None).await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, pool.name()).await?,
        St {
            used: 1,
            free: 0,
            auto_assign_free: 0,
            auto_assign_used: 1,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    txn.rollback().await?;

    // The single value should be available
    assert_eq!(
        db::resource_pool::stats(&db_pool, pool.name()).await?,
        St {
            used: 0,
            free: 1,
            auto_assign_free: 1,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    let mut txn = db_pool.begin().await?;
    db::resource_pool::allocate(&pool, &mut txn, OwnerType::Machine, "my_id", None).await?;
    txn.commit().await?;

    // And now it's really allocated
    assert_eq!(
        db::resource_pool::stats(&db_pool, pool.name()).await?,
        St {
            used: 1,
            free: 0,
            auto_assign_free: 0,
            auto_assign_used: 1,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_assign_after_delete(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;

    // create_test_env makes a vpc-vni pool, so clean that up first
    let mut txn = db_pool.begin().await?;
    sqlx::query("DELETE FROM resource_pool WHERE name = $1")
        .bind(VPC_VNI)
        .execute(&mut *txn)
        .await?;
    txn.commit().await?;

    // Only one vpc-vni available
    let mut txn = db_pool.begin().await?;
    let vpc_vni_pool = ResourcePool::new(VPC_VNI.to_string(), ValueType::Integer);
    db::resource_pool::populate(&vpc_vni_pool, &mut txn, vec!["1".to_string()], true).await?;
    txn.commit().await?;

    // CreateVpc rpc call
    let vpc_req = VpcCreationRequest::builder("test_vpc_assign_after_delete_1", "test")
        .network_virtualization_type(rpc::forge::VpcVirtualizationType::EthernetVirtualizer)
        .tonic_request();
    let vpc1 = env.api.create_vpc(vpc_req).await.unwrap().into_inner();

    // Value is allocated
    let mut txn = db_pool.begin().await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, vpc_vni_pool.name()).await?,
        St {
            used: 1,
            free: 0,
            auto_assign_free: 0,
            auto_assign_used: 1,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    txn.commit().await?;

    // DeleteVpc rpc call
    let del_req = rpc::forge::VpcDeletionRequest { id: vpc1.id };
    env.api
        .delete_vpc(tonic::Request::new(del_req))
        .await
        .unwrap();

    // Value is free
    let mut txn = db_pool.begin().await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, vpc_vni_pool.name()).await?,
        St {
            used: 0,
            free: 1,
            auto_assign_free: 1,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    txn.commit().await?;

    // CreateVpc
    let vpc_req = VpcCreationRequest::builder("test_vpc_assign_after_delete_2", "test")
        .network_virtualization_type(rpc::forge::VpcVirtualizationType::EthernetVirtualizer)
        .tonic_request();
    let vpc2 = env.api.create_vpc(vpc_req).await.unwrap().into_inner();

    // Value allocated again
    let mut txn = db_pool.begin().await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, vpc_vni_pool.name()).await?,
        St {
            used: 1,
            free: 0,
            auto_assign_free: 0,
            auto_assign_used: 1,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    txn.commit().await?;

    let del_req = rpc::forge::VpcDeletionRequest { id: vpc2.id };
    env.api
        .delete_vpc(tonic::Request::new(del_req.clone()))
        .await
        .unwrap();

    // Value is free
    let mut txn = db_pool.begin().await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, vpc_vni_pool.name()).await?,
        St {
            used: 0,
            free: 1,
            auto_assign_free: 1,
            auto_assign_used: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );

    // Allocate the value for something else. Deleting the already deleted VPC again
    // shouldn't free the VNI another time
    let _vni =
        db::resource_pool::allocate(&vpc_vni_pool, &mut txn, OwnerType::Vpc, "testalloc", None)
            .await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, vpc_vni_pool.name()).await?,
        St {
            used: 1,
            free: 0,
            auto_assign_free: 0,
            auto_assign_used: 1,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    txn.commit().await?;

    // Delete the VPC again
    assert_eq!(
        env.api
            .delete_vpc(tonic::Request::new(del_req))
            .await
            .expect_err("should fail")
            .code(),
        tonic::Code::NotFound
    );

    // The VNI isn't freed
    let mut txn = db_pool.begin().await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, vpc_vni_pool.name()).await?,
        St {
            used: 1,
            free: 0,
            auto_assign_free: 0,
            auto_assign_used: 1,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    txn.commit().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_list(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let mut txn = db_pool.begin().await?;
    let names = &["a", "b", "c"];
    let max = &[10, 100, 500];

    // Setup
    let pool1 = ResourcePool::new(names[0].to_string(), ValueType::Integer);
    let pool2 = ResourcePool::new(names[1].to_string(), ValueType::Integer);
    let pool3 = ResourcePool::new(names[2].to_string(), ValueType::Integer);
    db::resource_pool::populate(&pool1, &mut txn, (1..=max[0]).collect::<Vec<_>>(), true).await?;
    db::resource_pool::populate(&pool2, &mut txn, (1..=max[1]).collect::<Vec<_>>(), true).await?;
    db::resource_pool::populate(&pool3, &mut txn, (1..=max[2]).collect::<Vec<_>>(), true).await?;
    for _ in 1..=5 {
        let _ = db::resource_pool::allocate(&pool1, &mut txn, OwnerType::Machine, "my_id", None)
            .await
            .unwrap();
    }

    // What we're testing
    let all = db::resource_pool::all(&mut txn).await?;

    // Verify
    assert_eq!(all.len(), 3);
    for (i, snapshot) in all.iter().enumerate() {
        assert_eq!(names[i], snapshot.name);
        assert_eq!(1, snapshot.min.parse::<i32>()?);
        assert_eq!(max[i], snapshot.max.parse::<i32>()?);
        if i == 0 {
            assert_eq!(5, snapshot.stats.used);
            assert_eq!(5, snapshot.stats.free);
        } else {
            assert_eq!(0, snapshot.stats.used);
        }
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 50)]
async fn test_parallel() -> Result<(), eyre::Report> {
    // We have to do [crate::sqlx_test] 's work manually here so that we can use a multi-threaded executor
    let db_url = std::env::var("DATABASE_URL")? + "/test_parallel";
    if sqlx::Postgres::database_exists(&db_url).await? {
        sqlx::Postgres::drop_database(&db_url).await?;
    }
    sqlx::Postgres::create_database(&db_url).await?;
    let db_pool = sqlx::Pool::<sqlx::postgres::Postgres>::connect(&db_url).await?;
    tests::MIGRATOR.run(&db_pool).await?;

    let mut txn = db_pool.begin().await?;
    let pool = Arc::new(ResourcePool::new(
        "test_parallel".to_string(),
        ValueType::Integer,
    ));
    db::resource_pool::populate(
        &pool,
        &mut txn,
        (1..=5_000).map(|i| i.to_string()).collect(),
        true,
    )
    .await?;
    txn.commit().await?;

    let mut handles = Vec::with_capacity(50);
    let all_values = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    for i in 0..50 {
        let all_values = all_values.clone();
        let p = pool.clone();
        let db_pool_c = db_pool.clone();
        let handle = tokio::task::spawn(async move {
            let mut got = Vec::with_capacity(100);
            for _ in 0..100 {
                let mut txn = db_pool_c.begin().await.unwrap();
                got.push(
                    db::resource_pool::allocate(
                        &p,
                        &mut txn,
                        OwnerType::Machine,
                        &i.to_string(),
                        None,
                    )
                    .await
                    .unwrap(),
                );
                txn.commit().await.unwrap();
            }
            all_values.lock().await.extend(got.clone());
        });
        handles.push(handle);
    }
    futures::future::join_all(handles).await;
    drop(pool);
    db_pool.close().await;

    // Every value we got was unique, so the HashSet had no duplicates
    assert_eq!(all_values.lock().await.len(), 5_000);

    sqlx::Postgres::drop_database(&db_url).await?;
    Ok(())
}

#[crate::sqlx_test]
async fn test_allocate(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let pool = ResourcePool::new("test_rollback".to_string(), ValueType::Integer);

    let mut txn = db_pool.begin().await?;
    db::resource_pool::populate(&pool, &mut txn, vec![1, 2], true).await?; // Auto-assign
    txn.commit().await?;

    // allocate in one transaction
    let mut txn1 = db_pool.begin().await?;
    let v1 =
        db::resource_pool::allocate(&pool, &mut txn1, OwnerType::Machine, "my_id", None).await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn1, pool.name()).await?,
        St {
            used: 1,
            free: 1,
            auto_assign_free: 1,
            auto_assign_used: 1,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );

    // allocate in second transaction
    let mut txn2 = db_pool.begin().await?;
    let v2 =
        db::resource_pool::allocate(&pool, &mut txn2, OwnerType::Machine, "my_id", None).await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn2, pool.name()).await?,
        St {
            used: 1,
            free: 1,
            auto_assign_free: 1,
            auto_assign_used: 1,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    // commit second transaction
    txn2.commit().await.expect("txn2 commit failed");
    txn1.commit().await.expect("txn1 commit failed");

    assert_eq!(
        db::resource_pool::stats(&db_pool, pool.name()).await?,
        St {
            used: 2,
            free: 0,
            auto_assign_free: 0,
            auto_assign_used: 2,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    assert_ne!(v1, v2);
    Ok(())
}
