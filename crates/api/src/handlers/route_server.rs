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
use db::WithTransaction;
use futures_util::FutureExt;
use tonic::Status;

use crate::api::{Api, log_request_data};
use crate::{CarbideError, CarbideResult};

// get returns all RouteServer entries, including the
// address and source_type.
pub(crate) async fn get(
    api: &Api,
    request: tonic::Request<()>,
) -> Result<tonic::Response<rpc::RouteServerEntries>, Status> {
    log_request_data(&request);

    let route_servers = api
        .with_txn(|txn| db::route_servers::get(txn).boxed())
        .await??;

    Ok(tonic::Response::new(rpc::RouteServerEntries {
        route_servers: route_servers.into_iter().map(Into::into).collect(),
    }))
}

// add will add a new RouteServer entries. Since this comes in
// via the API, all new entries here will be tagged with the
// admin_api source type.
pub(crate) async fn add(
    api: &Api,
    request: tonic::Request<rpc::RouteServers>,
) -> Result<tonic::Response<()>, Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let route_servers = get_route_server_ip_addrs(&request.route_servers)?;
    let source_type: rpc::RouteServerSourceType = request
        .source_type
        .try_into()
        .map_err(|_| Status::invalid_argument("source_type"))?;

    let mut txn = api.txn_begin().await?;
    db::route_servers::add(&mut txn, &route_servers, source_type.into()).await?;
    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

// remove will remove RouteServer entries. Since this comes in
// via the API, this will be restricted to entries which have
// the admin_api source type.
pub(crate) async fn remove(
    api: &Api,
    request: tonic::Request<rpc::RouteServers>,
) -> Result<tonic::Response<()>, Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let route_servers = get_route_server_ip_addrs(&request.route_servers)?;
    let source_type: rpc::RouteServerSourceType = request
        .source_type
        .try_into()
        .map_err(|_| Status::invalid_argument("source_type"))?;

    let mut txn = api.txn_begin().await?;
    db::route_servers::remove(&mut txn, &route_servers, source_type.into()).await?;
    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

// replace will replace the existing route server addresses
// for the given source_type with provided list of route server
// addresses. Since this comes in via the API, all new entries
// here will be tagged with the admin_api source type.
pub(crate) async fn replace(
    api: &Api,
    request: tonic::Request<rpc::RouteServers>,
) -> Result<tonic::Response<()>, Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let route_servers = get_route_server_ip_addrs(&request.route_servers)?;
    let source_type: rpc::RouteServerSourceType = request
        .source_type
        .try_into()
        .map_err(|_| Status::invalid_argument("source_type"))?;

    let mut txn = api.txn_begin().await?;
    db::route_servers::replace(&mut txn, &route_servers, source_type.into()).await?;
    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

// get_route_server_ip_addrs is a little helper to
// pluck out the route server addresses from an
// incoming request and convert them into IpAddrs.
fn get_route_server_ip_addrs(route_servers: &[String]) -> CarbideResult<Vec<IpAddr>> {
    route_servers
        .iter()
        .map(|rs| IpAddr::from_str(rs))
        .collect::<Result<Vec<IpAddr>, _>>()
        .map_err(CarbideError::AddressParseError)
}
