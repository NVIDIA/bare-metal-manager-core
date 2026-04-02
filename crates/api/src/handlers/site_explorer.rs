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

use std::net::IpAddr;
use std::str::FromStr;

use config_version::ConfigVersion;
use nico_rpc::forge;
use nico_rpc::forge::IsBmcInManagedHostResponse;
use tokio::net::lookup_host;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

pub(crate) async fn find_explored_endpoint_ids(
    api: &Api,
    request: Request<nico_rpc::site_explorer::ExploredEndpointSearchFilter>,
) -> Result<Response<nico_rpc::site_explorer::ExploredEndpointIdList>, Status> {
    log_request_data(&request);

    let filter: nico_api_model::site_explorer::ExploredEndpointSearchFilter =
        request.into_inner().into();

    let endpoint_ips =
        nico_api_db::explored_endpoints::find_ips(&api.database_connection, filter).await?;

    Ok(Response::new(
        nico_rpc::site_explorer::ExploredEndpointIdList {
            endpoint_ids: endpoint_ips.iter().map(|ip| ip.to_string()).collect(),
        },
    ))
}

pub(crate) async fn find_explored_endpoints_by_ids(
    api: &Api,
    request: Request<nico_rpc::site_explorer::ExploredEndpointsByIdsRequest>,
) -> Result<Response<nico_rpc::site_explorer::ExploredEndpointList>, Status> {
    log_request_data(&request);

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

    let result = nico_api_db::explored_endpoints::find_by_ips(&api.database_connection, ips)
        .await
        .map(|ep| nico_rpc::site_explorer::ExploredEndpointList {
            endpoints: ep
                .into_iter()
                .map(nico_rpc::site_explorer::ExploredEndpoint::from)
                .collect(),
        })
        .map(Response::new)?;
    Ok(result)
}

pub(crate) async fn find_explored_managed_host_ids(
    api: &Api,
    request: Request<nico_rpc::site_explorer::ExploredManagedHostSearchFilter>,
) -> Result<Response<nico_rpc::site_explorer::ExploredManagedHostIdList>, Status> {
    log_request_data(&request);

    let filter: nico_api_model::site_explorer::ExploredManagedHostSearchFilter =
        request.into_inner().into();

    let host_ips =
        nico_api_db::explored_managed_host::find_ips(&api.database_connection, filter).await?;

    Ok(Response::new(
        nico_rpc::site_explorer::ExploredManagedHostIdList {
            host_ids: host_ips.iter().map(|ip| ip.to_string()).collect(),
        },
    ))
}

pub(crate) async fn find_explored_managed_hosts_by_ids(
    api: &Api,
    request: Request<nico_rpc::site_explorer::ExploredManagedHostsByIdsRequest>,
) -> Result<Response<nico_rpc::site_explorer::ExploredManagedHostList>, Status> {
    log_request_data(&request);

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

    let result = nico_api_db::explored_managed_host::find_by_ips(&api.database_connection, ips)
        .await
        .map(|ep| nico_rpc::site_explorer::ExploredManagedHostList {
            managed_hosts: ep
                .into_iter()
                .map(nico_rpc::site_explorer::ExploredManagedHost::from)
                .collect(),
        })
        .map(Response::new)?;

    Ok(result)
}

pub(crate) async fn get_site_exploration_report(
    api: &Api,
    request: tonic::Request<forge::GetSiteExplorationRequest>,
) -> Result<Response<nico_rpc::site_explorer::SiteExplorationReport>, Status> {
    log_request_data(&request);

    let report = nico_api_db::site_exploration_report::fetch(&mut api.db_reader()).await?;

    Ok(tonic::Response::new(report.into()))
}

pub(crate) async fn clear_site_exploration_error(
    api: &Api,
    request: Request<forge::ClearSiteExplorationErrorRequest>,
) -> Result<Response<()>, tonic::Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let bmc_ip = IpAddr::from_str(&req.ip_address).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    nico_api_db::explored_endpoints::clear_last_known_error(bmc_ip, &mut txn).await?;

    txn.commit().await?;

    Ok(Response::new(()))
}

pub(crate) async fn re_explore_endpoint(
    api: &Api,
    request: Request<forge::ReExploreEndpointRequest>,
) -> Result<Response<()>, tonic::Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let bmc_ip = IpAddr::from_str(&req.ip_address).map_err(CarbideError::from)?;
    let if_version_match = req
        .if_version_match
        .map(|v| v.parse::<ConfigVersion>())
        .transpose()
        .map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    let eps = nico_api_db::explored_endpoints::find_all_by_ip(bmc_ip, &mut txn).await?;
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
        match nico_api_db::explored_endpoints::re_explore_if_version_matches(
            bmc_ip,
            expected_version,
            &mut txn,
        )
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

    txn.commit().await?;

    Ok(Response::new(()))
}

pub(crate) async fn pause_explored_endpoint_remediation(
    api: &Api,
    request: Request<forge::PauseExploredEndpointRemediationRequest>,
) -> Result<Response<()>, tonic::Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let bmc_ip = IpAddr::from_str(&req.ip_address).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    let eps = nico_api_db::explored_endpoints::find_all_by_ip(bmc_ip, &mut txn).await?;
    if eps.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "explored_endpoint",
            id: bmc_ip.to_string(),
        }
        .into());
    }

    // Check if a machine exists for this endpoint
    let in_managed_host =
        crate::site_explorer::is_endpoint_in_managed_host(bmc_ip, txn.as_pgconn())
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?;

    if in_managed_host {
        return Err(CarbideError::InvalidArgument(format!(
            "Cannot pause/resume remediation for endpoint {bmc_ip} because a machine exists for it"
        ))
        .into());
    }

    nico_api_db::explored_endpoints::set_pause_remediation(bmc_ip, req.pause, &mut txn).await?;

    txn.commit().await?;

    Ok(Response::new(()))
}

pub(crate) async fn is_bmc_in_managed_host(
    api: &Api,
    request: tonic::Request<forge::BmcEndpointRequest>,
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
        return Err(CarbideError::InvalidArgument(format!(
            "Could not resolve {}. Must be hostname[:port] or IPv4[:port]",
            req.ip_address
        ))
        .into());
    };

    let in_managed_host =
        crate::site_explorer::is_endpoint_in_managed_host(bmc_addr.ip(), &api.database_connection)
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(IsBmcInManagedHostResponse {
        in_managed_host,
    }))
}

pub(crate) async fn delete_explored_endpoint(
    api: &Api,
    request: Request<forge::DeleteExploredEndpointRequest>,
) -> Result<Response<forge::DeleteExploredEndpointResponse>, tonic::Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let bmc_ip = IpAddr::from_str(&req.ip_address).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    // Check if the endpoint exists
    let endpoints = nico_api_db::explored_endpoints::find_all_by_ip(bmc_ip, &mut txn).await?;

    if endpoints.is_empty() {
        return Ok(Response::new(forge::DeleteExploredEndpointResponse {
            deleted: false,
            message: Some(format!("No explored endpoint found with IP {bmc_ip}")),
        }));
    }

    // Check if a machine exists for this endpoint
    let in_managed_host =
        crate::site_explorer::is_endpoint_in_managed_host(bmc_ip, txn.as_pgconn())
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?;

    if in_managed_host {
        return Err(CarbideError::InvalidArgument(format!(
            "Cannot delete endpoint {bmc_ip} because a machine exists for it. Did you mean to force-delete the machine?"
        ))
        .into());
    }

    // Delete the endpoint
    nico_api_db::explored_endpoints::delete(&mut txn, bmc_ip).await?;

    txn.commit().await?;

    Ok(Response::new(forge::DeleteExploredEndpointResponse {
        deleted: true,
        message: Some(format!(
            "Successfully deleted explored endpoint with IP {bmc_ip}"
        )),
    }))
}
