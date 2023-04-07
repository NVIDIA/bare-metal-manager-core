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
use std::sync::Arc;

use carbide::resource_pool::ResourcePoolStats as St;
use carbide::resource_pool::{DbResourcePool, OwnerType, ResourcePool, ResourcePoolError};
use log::LevelFilter;
use sqlx::migrate::MigrateDatabase;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test]
async fn test_simple(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let pool = DbResourcePool::new("test_simple".to_string(), db_pool);

    // one value in the pool
    pool.populate(vec!["1".to_string()]).await?;

    // which we get
    let allocated = pool.allocate(OwnerType::Machine, "123").await?;
    assert_eq!(allocated, "1");
    assert_eq!(pool.stats().await?, St { used: 1, free: 0 });

    // no more values
    match pool.allocate(OwnerType::Machine, "id456").await {
        Err(ResourcePoolError::Empty) => {} // expected
        Err(err) => panic!("Unexpected err: {err}"),
        Ok(_) => panic!("Pool should be empty"),
    }

    // return the value
    pool.release(allocated).await?;

    // and then there was one
    assert_eq!(pool.stats().await?, St { used: 0, free: 1 });

    Ok(())
}

#[sqlx::test]
async fn test_multiple(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let pool1 = DbResourcePool::new("test_multiple_1".to_string(), db_pool.clone());
    let pool2 = DbResourcePool::new("test_multiple_2".to_string(), db_pool.clone());
    let pool3 = DbResourcePool::new("test_multiple_3".to_string(), db_pool);

    pool1.populate((1..=10).collect::<Vec<_>>()).await?;
    pool2.populate((1..=100).collect::<Vec<_>>()).await?;
    pool3.populate((1..=500).collect::<Vec<_>>()).await?;

    assert_eq!(pool1.stats().await?, St { used: 0, free: 10 });
    assert_eq!(pool2.stats().await?, St { used: 0, free: 100 });
    assert_eq!(pool3.stats().await?, St { used: 0, free: 500 });

    let mut got = Vec::with_capacity(10);
    for _ in 1..=10 {
        got.push(pool2.allocate(OwnerType::Machine, "my_id").await.unwrap());
    }

    assert_eq!(pool1.stats().await?, St { used: 0, free: 10 });
    assert_eq!(pool2.stats().await?, St { used: 10, free: 90 });
    assert_eq!(pool3.stats().await?, St { used: 0, free: 500 });

    for val in got {
        pool2.release(val).await?;
    }

    assert_eq!(pool1.stats().await?, St { used: 0, free: 10 });
    assert_eq!(pool2.stats().await?, St { used: 0, free: 100 });
    assert_eq!(pool3.stats().await?, St { used: 0, free: 500 });

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

    let pool = Arc::new(DbResourcePool::new(
        "test_parallel".to_string(),
        db_pool.clone(),
    ));
    pool.populate((1..=5_000).map(|i| i.to_string()).collect())
        .await?;

    let mut handles = Vec::with_capacity(50);
    let all_values = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    for i in 0..50 {
        let all_values = all_values.clone();
        let p = pool.clone();
        let handle = tokio::task::spawn(async move {
            let mut got = Vec::with_capacity(100);
            for _ in 0..100 {
                got.push(
                    p.allocate(OwnerType::Machine, &i.to_string())
                        .await
                        .unwrap(),
                );
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
