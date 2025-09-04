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

use ::rpc::forge as rpc;
use sqlx::{Pool, Postgres, Transaction};
use std::net::IpAddr;
use std::str::FromStr;
use tonic::Status;

use crate::api::{Api, log_request_data};
use crate::db::DatabaseError;
use crate::db::route_servers::RouteServer;
use crate::{CarbideError, CarbideResult};

// get returns all RouteServer entries, including the
// address and source_type.
pub(crate) async fn get(
    api: &Api,
    request: tonic::Request<()>,
) -> Result<tonic::Response<rpc::RouteServerEntries>, Status> {
    log_request_data(&request);

    let mut txn = begin_txn(&api.database_connection, "route_servers.get").await?;
    let route_servers = RouteServer::get(&mut txn).await?;

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

    let mut txn = begin_txn(&api.database_connection, "route_servers.add").await?;
    RouteServer::add(&mut txn, &route_servers, source_type.into()).await?;
    commit_txn(txn, "route_servers.add").await?;

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

    let mut txn = begin_txn(&api.database_connection, "route_servers.remove").await?;
    RouteServer::remove(&mut txn, &route_servers, source_type.into()).await?;
    commit_txn(txn, "route_servers.remove").await?;

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

    let mut txn = begin_txn(&api.database_connection, "route_servers.replace").await?;
    RouteServer::replace(&mut txn, &route_servers, source_type.into()).await?;
    commit_txn(txn, "route_servers.replace").await?;

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

// begin_txn exists to attempt to get a database transaction open, returning
// a tonic::Status in the event it fails (making it easier for callers to
// pass through an error).
pub async fn begin_txn(
    db_conn: &Pool<Postgres>,
    phase: impl std::fmt::Display,
) -> Result<Transaction<'_, Postgres>, Status> {
    db_conn
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(format!("txn {phase}").as_str(), e))
        .map_err(Status::from)
}

// commit_txn exists to attempt to commit a transaction, returning
// a tonic::Status in the event it fails (making it easier for callers to
// pass through an error).
pub async fn commit_txn(
    txn: Transaction<'_, Postgres>,
    phase: impl std::fmt::Display,
) -> Result<(), Status> {
    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(format!("txn {phase}").as_str(), e))
        .map_err(Status::from)
}
