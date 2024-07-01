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
use tonic::Status;

use crate::api::{log_request_data, Api};
use crate::db::route_servers::RouteServer;
use crate::db::DatabaseError;
use crate::CarbideError;

pub(crate) async fn get(
    api: &Api,
    request: tonic::Request<()>,
) -> Result<tonic::Response<rpc::RouteServers>, Status> {
    log_request_data(&request);

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_route_servers",
                e,
            ))
        })
        .map_err(CarbideError::from)?;

    let route_servers = RouteServer::get(&mut txn).await?;

    Ok(tonic::Response::new(rpc::RouteServers {
        route_servers: route_servers
            .into_iter()
            .map(|rs| rs.address.to_string())
            .collect(),
    }))
}

pub(crate) async fn add(
    api: &Api,
    request: tonic::Request<rpc::RouteServers>,
) -> Result<tonic::Response<()>, Status> {
    log_request_data(&request);

    if !api.eth_data.route_servers_enabled {
        return Err(CarbideError::InvalidArgument("Route servers are disabled".to_string()).into());
    }
    let route_servers: Vec<IpAddr> = request
        .into_inner()
        .route_servers
        .iter()
        .map(|rs| IpAddr::from_str(rs))
        .collect::<Result<Vec<IpAddr>, _>>()
        .map_err(CarbideError::AddressParseError)?;

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_route_servers",
                e,
            ))
        })
        .map_err(CarbideError::from)?;

    RouteServer::add(&mut txn, &route_servers).await?;

    txn.commit()
        .await
        .map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit get_route_servers",
                e,
            ))
        })
        .map_err(CarbideError::from)?;

    Ok(tonic::Response::new(()))
}

pub(crate) async fn remove(
    api: &Api,
    request: tonic::Request<rpc::RouteServers>,
) -> Result<tonic::Response<()>, Status> {
    log_request_data(&request);

    let route_servers: Vec<IpAddr> = request
        .into_inner()
        .route_servers
        .iter()
        .map(|rs| IpAddr::from_str(rs))
        .collect::<Result<Vec<IpAddr>, _>>()
        .map_err(CarbideError::AddressParseError)?;

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_route_servers",
                e,
            ))
        })
        .map_err(CarbideError::from)?;

    RouteServer::remove(&mut txn, &route_servers).await?;

    txn.commit()
        .await
        .map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit get_route_servers",
                e,
            ))
        })
        .map_err(CarbideError::from)?;

    Ok(tonic::Response::new(()))
}

pub(crate) async fn replace(
    api: &Api,
    request: tonic::Request<rpc::RouteServers>,
) -> Result<tonic::Response<()>, Status> {
    log_request_data(&request);

    let route_servers: Vec<IpAddr> = request
        .into_inner()
        .route_servers
        .iter()
        .map(|rs| IpAddr::from_str(rs))
        .collect::<Result<Vec<IpAddr>, _>>()
        .map_err(CarbideError::AddressParseError)?;

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin get_route_servers",
                e,
            ))
        })
        .map_err(CarbideError::from)?;

    RouteServer::replace(&mut txn, &route_servers).await?;

    txn.commit()
        .await
        .map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "commit get_route_servers",
                e,
            ))
        })
        .map_err(CarbideError::from)?;

    Ok(tonic::Response::new(()))
}
