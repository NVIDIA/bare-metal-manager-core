/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::net::IpAddr;
use std::str::FromStr;

use ::rpc::forge as rpc;
use mac_address::MacAddress;
use model::site_explorer::{EndpointExplorationReport, ExploredDpu, ExploredManagedHost};
use rpc::forge_server::Forge;

use crate::tests::common::api_fixtures::create_test_env;

#[crate::sqlx_test()]
async fn test_find_explored_managed_host_ids(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    let mut txn = env.pool.begin().await?;
    let mut managed_hosts: Vec<ExploredManagedHost> = Vec::new();
    for i in 1..6 {
        let host_bmc_ip = IpAddr::from_str(format!("141.219.24.{i}").as_str())?;
        let bmc_ip = IpAddr::from_str(format!("10.231.11.{i}").as_str())?;
        let mac_address = MacAddress::from_str(format!("94:6D:AE:5F:09:C{i}").as_str())?;
        managed_hosts.push(ExploredManagedHost {
            host_bmc_ip,
            dpus: vec![ExploredDpu {
                bmc_ip,
                host_pf_mac_address: Some(mac_address),
                report: EndpointExplorationReport::default().into(),
            }],
        });
    }
    db::explored_managed_host::update(&mut txn, &managed_hosts.iter().collect::<Vec<_>>()).await?;
    txn.commit().await?;

    let id_list = env
        .api
        .find_explored_managed_host_ids(tonic::Request::new(
            ::rpc::site_explorer::ExploredManagedHostSearchFilter {},
        ))
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(id_list.host_ids.len(), 5);

    Ok(())
}

#[crate::sqlx_test()]
async fn test_find_explored_managed_hosts_by_ids(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    let mut txn = env.pool.begin().await?;
    let mut managed_hosts: Vec<ExploredManagedHost> = Vec::new();
    for i in 1..6 {
        let host_bmc_ip = IpAddr::from_str(format!("141.219.24.{i}").as_str())?;
        let bmc_ip = IpAddr::from_str(format!("10.231.11.{i}").as_str())?;
        let mac_address = MacAddress::from_str(format!("94:6D:AE:5F:09:C{i}").as_str())?;
        managed_hosts.push(ExploredManagedHost {
            host_bmc_ip,
            dpus: vec![ExploredDpu {
                bmc_ip,
                host_pf_mac_address: Some(mac_address),
                report: EndpointExplorationReport::default().into(),
            }],
        });
    }
    db::explored_managed_host::update(&mut txn, &managed_hosts.iter().collect::<Vec<_>>()).await?;
    txn.commit().await?;

    let id_list = env
        .api
        .find_explored_managed_host_ids(tonic::Request::new(
            ::rpc::site_explorer::ExploredManagedHostSearchFilter {},
        ))
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(id_list.host_ids.len(), 5);

    let request = tonic::Request::new(::rpc::site_explorer::ExploredManagedHostsByIdsRequest {
        host_ids: id_list.host_ids.clone(),
    });

    let host_list = env
        .api
        .find_explored_managed_hosts_by_ids(request)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(host_list.managed_hosts.len(), 5);

    // validate we got endpoints with specified ids
    let mut hosts_copy = host_list.managed_hosts;
    for _ in 0..5 {
        let host = hosts_copy.remove(0);
        let host_id = host.host_bmc_ip;
        assert!(id_list.host_ids.contains(&host_id));
    }

    Ok(())
}

#[crate::sqlx_test()]
async fn test_find_explored_managed_hosts_by_ids_over_max(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // create vector of IDs with more than max allowed
    // it does not matter if these are real or not, since we are testing an error back for passing more than max
    let end_index: u32 = env.config.max_find_by_ids + 1;
    let host_ids: Vec<String> = (1..=end_index).map(|i| format!("141.219.24.{i}")).collect();

    let request =
        tonic::Request::new(::rpc::site_explorer::ExploredManagedHostsByIdsRequest { host_ids });

    let response = env.api.find_explored_managed_hosts_by_ids(request).await;
    // validate
    assert!(
        response.is_err(),
        "expected an error when passing too many IDs"
    );
    assert_eq!(
        response.err().unwrap().message(),
        format!(
            "no more than {} IDs can be accepted",
            env.config.max_find_by_ids
        )
    );
}

#[crate::sqlx_test()]
async fn test_find_explored_managed_hosts_by_ids_none(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    let request =
        tonic::Request::new(::rpc::site_explorer::ExploredManagedHostsByIdsRequest::default());

    let response = env.api.find_explored_managed_hosts_by_ids(request).await;
    // validate
    assert!(response.is_err(), "expected an error when passing no IDs");
    assert_eq!(
        response.err().unwrap().message(),
        "at least one ID must be provided",
    );
}
