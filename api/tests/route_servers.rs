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

pub mod common;
use std::net::IpAddr;
use std::str::FromStr;

use carbide::db::route_servers::RouteServer;
use common::api_fixtures::create_test_env;
use rpc::{forge::RouteServers, protos::forge::forge_server::Forge};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test()]
async fn test_add_route_servers(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let expected_servers = [
        IpAddr::from_str("1.2.3.4")?,
        IpAddr::from_str("2.3.4.5")?,
        IpAddr::from_str("3.4.5.6")?,
    ];

    let request = tonic::Request::new(RouteServers {
        route_servers: expected_servers.iter().map(|a| a.to_string()).collect(),
    });

    env.api.add_route_servers(request).await?;

    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await?;
    let query = r#"SELECT * from route_servers;"#;
    let actual_servers: Vec<IpAddr> = sqlx::query_as::<_, RouteServer>(query)
        .fetch_all(&mut *txn)
        .await?
        .into_iter()
        .map(|rs| rs.address)
        .collect();

    assert_eq!(actual_servers, expected_servers);
    Ok(())
}

#[sqlx::test()]
async fn test_remove_route_servers(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let mut expected_servers = vec![
        IpAddr::from_str("1.2.3.4")?,
        IpAddr::from_str("2.3.4.5")?,
        IpAddr::from_str("3.4.5.6")?,
    ];

    let request: tonic::Request<RouteServers> = tonic::Request::new(RouteServers {
        route_servers: expected_servers.iter().map(|a| a.to_string()).collect(),
    });

    env.api.add_route_servers(request).await?;

    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await?;
    let query = r#"SELECT * from route_servers;"#;
    let actual_servers: Vec<IpAddr> = sqlx::query_as::<_, RouteServer>(query)
        .fetch_all(&mut *txn)
        .await?
        .into_iter()
        .map(|rs| rs.address)
        .collect();

    assert_eq!(actual_servers, expected_servers);

    let removed_servers = [expected_servers.pop().unwrap()];
    let request: tonic::Request<RouteServers> = tonic::Request::new(RouteServers {
        route_servers: removed_servers.iter().map(|a| a.to_string()).collect(),
    });

    env.api.remove_route_servers(request).await?;
    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await?;
    let query = r#"SELECT * from route_servers;"#;
    let actual_servers: Vec<IpAddr> = sqlx::query_as::<_, RouteServer>(query)
        .fetch_all(&mut *txn)
        .await?
        .into_iter()
        .map(|rs| rs.address)
        .collect();

    assert_eq!(actual_servers, expected_servers);

    let request: tonic::Request<RouteServers> = tonic::Request::new(RouteServers {
        route_servers: expected_servers.iter().map(|a| a.to_string()).collect(),
    });

    env.api.remove_route_servers(request).await?;
    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await?;
    let query = r#"SELECT * from route_servers;"#;
    let actual_servers: Vec<IpAddr> = sqlx::query_as::<_, RouteServer>(query)
        .fetch_all(&mut *txn)
        .await?
        .into_iter()
        .map(|rs| rs.address)
        .collect();

    assert!(actual_servers.is_empty());

    Ok(())
}

#[sqlx::test()]
async fn test_initial_set(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let expected_servers = [
        IpAddr::from_str("1.2.3.4")?,
        IpAddr::from_str("2.3.4.5")?,
        IpAddr::from_str("3.4.5.6")?,
    ];

    let set_request = tonic::Request::new(RouteServers {
        route_servers: expected_servers.iter().map(|a| a.to_string()).collect(),
    });

    env.api.replace_route_servers(set_request).await?;

    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await?;
    let query = r#"SELECT * from route_servers;"#;
    let actual_servers: Vec<IpAddr> = sqlx::query_as::<_, RouteServer>(query)
        .fetch_all(&mut *txn)
        .await?
        .into_iter()
        .map(|rs| rs.address)
        .collect();

    assert_eq!(actual_servers, expected_servers);
    Ok(())
}

#[sqlx::test()]
async fn test_subsequent_replace(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let expected_servers = [
        IpAddr::from_str("1.2.3.4")?,
        IpAddr::from_str("2.3.4.5")?,
        IpAddr::from_str("3.4.5.6")?,
    ];

    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await?;
    let query = r#"INSERT INTO route_servers values ($1);"#;
    for s in expected_servers.iter() {
        sqlx::query_as::<_, RouteServer>(query)
            .bind(s)
            .fetch_all(&mut *txn)
            .await?;
    }
    txn.commit().await?;

    let set_request = tonic::Request::new(RouteServers {
        route_servers: expected_servers.iter().map(|a| a.to_string()).collect(),
    });

    env.api.replace_route_servers(set_request).await?;

    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await?;
    let query = r#"SELECT * from route_servers;"#;
    let actual_servers: Vec<IpAddr> = sqlx::query_as::<_, RouteServer>(query)
        .fetch_all(&mut *txn)
        .await?
        .into_iter()
        .map(|rs| rs.address)
        .collect();

    assert_eq!(actual_servers, expected_servers);
    Ok(())
}

#[sqlx::test()]
async fn test_get(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let expected_servers = [
        IpAddr::from_str("1.2.3.4")?,
        IpAddr::from_str("2.3.4.5")?,
        IpAddr::from_str("3.4.5.6")?,
    ];

    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await?;
    let query = r#"INSERT INTO route_servers values ($1);"#;
    for s in expected_servers.iter() {
        sqlx::query_as::<_, RouteServer>(query)
            .bind(s)
            .fetch_all(&mut *txn)
            .await?;
    }
    txn.commit().await?;

    let get_request = tonic::Request::new(());
    let response = env.api.get_route_servers(get_request).await?;

    let actual_server = response.into_inner().route_servers;

    assert_eq!(
        actual_server,
        expected_servers
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<String>>()
    );

    Ok(())
}
