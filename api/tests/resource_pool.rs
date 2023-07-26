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

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use carbide::resource_pool::common::VPC_VNI;
use carbide::resource_pool::ResourcePoolStats as St;
use carbide::resource_pool::{all, DbResourcePool, OwnerType, ResourcePoolError, ValueType};
use common::api_fixtures::create_test_env;
use rpc::forge::forge_server::Forge;
use sqlx::migrate::MigrateDatabase;

mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

// Define an IPv4 pool from a range via the admin grpc
#[sqlx::test]
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

    let pool: DbResourcePool<Ipv4Addr> =
        DbResourcePool::new("test_define_range".to_string(), ValueType::Ipv4);

    let mut txn = db_pool.begin().await?;
    assert_eq!(pool.stats(&mut txn).await?, St { used: 0, free: 255 });

    Ok(())
}

// Define an IPv4 pool from a prefix via the admin grpc
#[sqlx::test]
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

    let pool: DbResourcePool<Ipv4Addr> =
        DbResourcePool::new("test_define_range".to_string(), ValueType::Ipv4);

    let mut txn = db_pool.begin().await?;
    assert_eq!(pool.stats(&mut txn).await?, St { used: 0, free: 255 });

    Ok(())
}

#[sqlx::test]
async fn test_simple(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let mut txn = db_pool.begin().await?;
    let pool = DbResourcePool::new("test_simple".to_string(), ValueType::Integer);

    // one value in the pool
    pool.populate(&mut txn, vec!["1".to_string()]).await?;

    // which we get
    let allocated = pool.allocate(&mut txn, OwnerType::Machine, "123").await?;
    assert_eq!(allocated, "1");
    assert_eq!(pool.stats(&mut txn).await?, St { used: 1, free: 0 });

    // no more values
    match pool.allocate(&mut txn, OwnerType::Machine, "id456").await {
        Err(ResourcePoolError::Empty) => {} // expected
        Err(err) => panic!("Unexpected err: {err}"),
        Ok(_) => panic!("Pool should be empty"),
    }

    // return the value
    pool.release(&mut txn, allocated).await?;

    // and then there was one
    assert_eq!(pool.stats(&mut txn).await?, St { used: 0, free: 1 });

    txn.rollback().await?;
    Ok(())
}

#[sqlx::test]
async fn test_multiple(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let mut txn = db_pool.begin().await?;
    let pool1 = DbResourcePool::new("test_multiple_1".to_string(), ValueType::Integer);
    let pool2 = DbResourcePool::new("test_multiple_2".to_string(), ValueType::Integer);
    let pool3 = DbResourcePool::new("test_multiple_3".to_string(), ValueType::Integer);

    pool1
        .populate(&mut txn, (1..=10).collect::<Vec<_>>())
        .await?;
    pool2
        .populate(&mut txn, (1..=100).collect::<Vec<_>>())
        .await?;
    pool3
        .populate(&mut txn, (1..=500).collect::<Vec<_>>())
        .await?;

    assert_eq!(pool1.stats(&mut txn).await?, St { used: 0, free: 10 });
    assert_eq!(pool2.stats(&mut txn).await?, St { used: 0, free: 100 });
    assert_eq!(pool3.stats(&mut txn).await?, St { used: 0, free: 500 });

    let mut got = Vec::with_capacity(10);
    for _ in 1..=10 {
        got.push(
            pool2
                .allocate(&mut txn, OwnerType::Machine, "my_id")
                .await
                .unwrap(),
        );
    }

    assert_eq!(pool1.stats(&mut txn).await?, St { used: 0, free: 10 });
    assert_eq!(pool2.stats(&mut txn).await?, St { used: 10, free: 90 });
    assert_eq!(pool3.stats(&mut txn).await?, St { used: 0, free: 500 });

    for val in got {
        pool2.release(&mut txn, val).await?;
    }

    assert_eq!(pool1.stats(&mut txn).await?, St { used: 0, free: 10 });
    assert_eq!(pool2.stats(&mut txn).await?, St { used: 0, free: 100 });
    assert_eq!(pool3.stats(&mut txn).await?, St { used: 0, free: 500 });

    txn.rollback().await?;
    Ok(())
}

#[sqlx::test]
async fn test_rollback(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let pool = DbResourcePool::new("test_rollback".to_string(), ValueType::Integer);

    // Pool has a single value
    let mut txn = db_pool.begin().await?;
    pool.populate(&mut txn, vec![1]).await?;
    txn.commit().await?;

    // Which we allocate then rollback
    let mut txn = db_pool.begin().await?;
    pool.allocate(&mut txn, OwnerType::Machine, "my_id").await?;
    assert_eq!(pool.stats(&mut txn).await?, St { used: 1, free: 0 });
    txn.rollback().await?;

    // The single value should be available
    assert_eq!(pool.stats(&db_pool).await?, St { used: 0, free: 1 });
    let mut txn = db_pool.begin().await?;
    pool.allocate(&mut txn, OwnerType::Machine, "my_id").await?;
    txn.commit().await?;

    // And now it's really allocated
    assert_eq!(pool.stats(&db_pool).await?, St { used: 1, free: 0 });

    Ok(())
}

#[sqlx::test]
async fn test_vpc_assign_after_delete(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;

    // create_test_env makes a vpc-vni pool, so clean that up first
    let mut txn = db_pool.begin().await?;
    sqlx::query("DELETE FROM resource_pool WHERE name = $1")
        .bind(VPC_VNI)
        .execute(&mut txn)
        .await?;
    txn.commit().await?;

    // Only one vpc-vni available
    let mut txn = db_pool.begin().await?;
    let vpc_vni_pool = DbResourcePool::new(VPC_VNI.to_string(), ValueType::Integer);
    vpc_vni_pool
        .populate(&mut txn, vec!["1".to_string()])
        .await?;
    txn.commit().await?;

    // CreateVpc rpc call
    let vpc_req = rpc::forge::VpcCreationRequest {
        name: "test_vpc_assign_after_delete_1".to_string(),
        tenant_organization_id: "test".to_string(),
        tenant_keyset_id: None,
        network_virtualization_type: Some(
            rpc::forge::VpcVirtualizationType::EthernetVirtualizer as i32,
        ),
    };
    let resp = env
        .api
        .create_vpc(tonic::Request::new(vpc_req))
        .await
        .unwrap();

    // Value is allocated
    let mut txn = db_pool.begin().await?;
    assert_eq!(vpc_vni_pool.stats(&mut txn).await?, St { used: 1, free: 0 });
    txn.commit().await?;

    // DeleteVpc rpc call
    let del_req = rpc::forge::VpcDeletionRequest {
        id: resp.into_inner().id,
    };
    env.api
        .delete_vpc(tonic::Request::new(del_req))
        .await
        .unwrap();

    // Value is free
    let mut txn = db_pool.begin().await?;
    assert_eq!(vpc_vni_pool.stats(&mut txn).await?, St { used: 0, free: 1 });
    txn.commit().await?;

    // CreateVpc
    let vpc_req = rpc::forge::VpcCreationRequest {
        name: "test_vpc_assign_after_delete_2".to_string(),
        tenant_organization_id: "test".to_string(),
        tenant_keyset_id: None,
        network_virtualization_type: Some(
            rpc::forge::VpcVirtualizationType::EthernetVirtualizer as i32,
        ),
    };
    let _ = env
        .api
        .create_vpc(tonic::Request::new(vpc_req))
        .await
        .unwrap();

    // Value allocated again
    let mut txn = db_pool.begin().await?;
    assert_eq!(vpc_vni_pool.stats(&mut txn).await?, St { used: 1, free: 0 });
    txn.commit().await?;

    Ok(())
}

#[sqlx::test]
async fn test_list(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let mut txn = db_pool.begin().await?;
    let names = &["a", "b", "c"];
    let max = &[10, 100, 500];

    // Setup
    let pool1 = DbResourcePool::new(names[0].to_string(), ValueType::Integer);
    let pool2 = DbResourcePool::new(names[1].to_string(), ValueType::Integer);
    let pool3 = DbResourcePool::new(names[2].to_string(), ValueType::Integer);
    pool1
        .populate(&mut txn, (1..=max[0]).collect::<Vec<_>>())
        .await?;
    pool2
        .populate(&mut txn, (1..=max[1]).collect::<Vec<_>>())
        .await?;
    pool3
        .populate(&mut txn, (1..=max[2]).collect::<Vec<_>>())
        .await?;
    for _ in 1..=5 {
        let _ = pool1
            .allocate(&mut txn, OwnerType::Machine, "my_id")
            .await
            .unwrap();
    }

    // What we're testing
    let all = all(&mut txn).await?;

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
    // We have to do [sqlx::test] 's work manually here so that we can use a multi-threaded executor
    let db_url = std::env::var("DATABASE_URL")? + "/test_parallel";
    if sqlx::Postgres::database_exists(&db_url).await? {
        sqlx::Postgres::drop_database(&db_url).await?;
    }
    sqlx::Postgres::create_database(&db_url).await?;
    let db_pool = sqlx::Pool::<sqlx::postgres::Postgres>::connect(&db_url).await?;
    let m = sqlx::migrate!();
    m.run(&db_pool).await?;

    let mut txn = db_pool.begin().await?;
    let pool = Arc::new(DbResourcePool::new(
        "test_parallel".to_string(),
        ValueType::Integer,
    ));
    pool.populate(&mut txn, (1..=5_000).map(|i| i.to_string()).collect())
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
                    p.allocate(&mut txn, OwnerType::Machine, &i.to_string())
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
