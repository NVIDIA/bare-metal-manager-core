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

use ::rpc::forge::{self as rpc, IsBmcInManagedHostResponse};
use config_version::ConfigVersion;
use std::{net::IpAddr, str::FromStr};
use tokio::net::lookup_host;
use tonic::{Request, Response, Status};

use crate::db::explored_managed_host::DbExploredManagedHost;
use crate::{
    api::{log_request_data, Api},
    db::{self, explored_endpoints::DbExploredEndpoint, DatabaseError},
    CarbideError,
};

pub(crate) async fn find_explored_endpoint_ids(
    api: &Api,
    request: Request<::rpc::site_explorer::ExploredEndpointSearchFilter>,
) -> Result<Response<::rpc::site_explorer::ExploredEndpointIdList>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin site_exporter::find_ids",
            e,
        ))
    })?;

    let filter: ::rpc::site_explorer::ExploredEndpointSearchFilter = request.into_inner();

    let endpoint_ips = DbExploredEndpoint::find_ips(&mut txn, filter)
        .await
        .map_err(CarbideError::from)?;

    Ok(Response::new(
        ::rpc::site_explorer::ExploredEndpointIdList {
            endpoint_ids: endpoint_ips.iter().map(|ip| ip.to_string()).collect(),
        },
    ))
}

pub(crate) async fn find_explored_endpoints_by_ids(
    api: &Api,
    request: Request<::rpc::site_explorer::ExploredEndpointsByIdsRequest>,
) -> Result<Response<::rpc::site_explorer::ExploredEndpointList>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin site_exporter::find_ids",
            e,
        ))
    })?;

    let ips: Vec<IpAddr> = request
        .into_inner()
        .endpoint_ids
        .iter()
        .map(|rs| IpAddr::from_str(rs))
        .collect::<Result<Vec<IpAddr>, _>>()
        .map_err(CarbideError::AddressParseError)?;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if ips.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if ips.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let result = DbExploredEndpoint::find_by_ips(&mut txn, ips)
        .await
        .map(|ep| ::rpc::site_explorer::ExploredEndpointList {
            endpoints: ep
                .into_iter()
                .map(::rpc::site_explorer::ExploredEndpoint::from)
                .collect(),
        })
        .map(Response::new)
        .map_err(CarbideError::from)?;
    Ok(result)
}

pub(crate) async fn find_explored_managed_host_ids(
    api: &Api,
    request: Request<::rpc::site_explorer::ExploredManagedHostSearchFilter>,
) -> Result<Response<::rpc::site_explorer::ExploredManagedHostIdList>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin site_exporter::find_ids",
            e,
        ))
    })?;

    let filter: ::rpc::site_explorer::ExploredManagedHostSearchFilter = request.into_inner();

    let host_ips = DbExploredManagedHost::find_ips(&mut txn, filter)
        .await
        .map_err(CarbideError::from)?;

    Ok(Response::new(
        ::rpc::site_explorer::ExploredManagedHostIdList {
            host_ids: host_ips.iter().map(|ip| ip.to_string()).collect(),
        },
    ))
}

pub(crate) async fn find_explored_managed_hosts_by_ids(
    api: &Api,
    request: Request<::rpc::site_explorer::ExploredManagedHostsByIdsRequest>,
) -> Result<Response<::rpc::site_explorer::ExploredManagedHostList>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin site_exporter::find_ids",
            e,
        ))
    })?;

    let ips: Vec<IpAddr> = request
        .into_inner()
        .host_ids
        .iter()
        .map(|rs| IpAddr::from_str(rs))
        .collect::<Result<Vec<IpAddr>, _>>()
        .map_err(CarbideError::AddressParseError)?;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if ips.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if ips.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let result = DbExploredManagedHost::find_by_ips(&mut txn, ips)
        .await
        .map(|ep| ::rpc::site_explorer::ExploredManagedHostList {
            managed_hosts: ep
                .into_iter()
                .map(::rpc::site_explorer::ExploredManagedHost::from)
                .collect(),
        })
        .map(Response::new)
        .map_err(CarbideError::from)?;

    Ok(result)
}

pub(crate) async fn get_site_exploration_report(
    api: &Api,
    request: tonic::Request<::rpc::forge::GetSiteExplorationRequest>,
) -> Result<Response<::rpc::site_explorer::SiteExplorationReport>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_site_exploration_report",
            e,
        ))
    })?;

    let report = db::site_exploration_report::fetch(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.rollback().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "end get_site_exploration_report",
            e,
        ))
    })?;

    Ok(tonic::Response::new(report.into()))
}

pub(crate) async fn clear_site_exploration_error(
    api: &Api,
    request: Request<rpc::ClearSiteExplorationErrorRequest>,
) -> Result<Response<()>, tonic::Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let bmc_ip = IpAddr::from_str(&req.ip_address).map_err(CarbideError::from)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin clear_last_known_error",
            e,
        ))
    })?;

    DbExploredEndpoint::clear_last_known_error(bmc_ip, &mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit clear_last_known_error",
            e,
        ))
    })?;

    Ok(Response::new(()))
}

pub(crate) async fn re_explore_endpoint(
    api: &Api,
    request: Request<rpc::ReExploreEndpointRequest>,
) -> Result<Response<()>, tonic::Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let bmc_ip = IpAddr::from_str(&req.ip_address).map_err(CarbideError::from)?;
    let if_version_match = req
        .if_version_match
        .map(|v| v.parse::<ConfigVersion>())
        .transpose()
        .map_err(CarbideError::from)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin re_explore_endpoint",
            e,
        ))
    })?;

    let eps = DbExploredEndpoint::find_all_by_ip(bmc_ip, &mut txn)
        .await
        .map_err(CarbideError::from)?;
    if eps.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "explored_endpoint",
            id: bmc_ip.to_string(),
        }
        .into());
    }

    for ep in eps.iter() {
        let expected_version = match if_version_match {
            Some(v) => v,
            None => ep.report_version,
        };
        match DbExploredEndpoint::re_explore_if_version_matches(bmc_ip, expected_version, &mut txn)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(CarbideError::ConcurrentModificationError(
                    "explored_endpoint",
                    expected_version.to_string(),
                )
                .into());
            }
            Err(e) => return Err(CarbideError::from(e).into()),
        }
    }

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit re_explore_endpoint",
            e,
        ))
    })?;

    Ok(Response::new(()))
}

pub(crate) async fn is_bmc_in_managed_host(
    api: &Api,
    request: tonic::Request<::rpc::forge::BmcEndpointRequest>,
) -> Result<Response<IsBmcInManagedHostResponse>, tonic::Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let address = if req.ip_address.contains(':') {
        req.ip_address.clone()
    } else {
        format!("{}:443", req.ip_address)
    };

    let mut addrs = lookup_host(address).await?;
    let Some(bmc_addr) = addrs.next() else {
        return Err(tonic::Status::invalid_argument(format!(
            "Could not resolve {}. Must be hostname[:port] or IPv4[:port]",
            req.ip_address
        )));
    };

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin site_exporter::is_endpoint_in_managed_host",
            e,
        ))
    })?;

    let in_managed_host =
        crate::site_explorer::is_endpoint_in_managed_host(bmc_addr.ip(), &mut txn)
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit site_exporter::is_endpoint_in_managed_host",
            e,
        ))
    })?;

    Ok(Response::new(IsBmcInManagedHostResponse {
        in_managed_host,
    }))
}
