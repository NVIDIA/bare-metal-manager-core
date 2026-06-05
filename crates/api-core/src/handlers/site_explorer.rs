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

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use ::rpc::forge::{self as rpc, IsBmcInManagedHostResponse};
use carbide_site_explorer::{endpoint_exploration_work_key, enrich_endpoint_exploration_report};
use config_version::ConfigVersion;
use db::work_lock_manager::AcquireLockError;
use model::expected_entity::ExpectedEntity;
use tokio::net::lookup_host;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

pub(crate) async fn find_explored_endpoint_ids(
    api: &Api,
    request: Request<::rpc::site_explorer::ExploredEndpointSearchFilter>,
) -> Result<Response<::rpc::site_explorer::ExploredEndpointIdList>, Status> {
    log_request_data(&request);

    let filter: model::site_explorer::ExploredEndpointSearchFilter = request.into_inner().into();

    let endpoint_ips = db::explored_endpoints::find_ips(&api.database_connection, filter).await?;

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

    let result = db::explored_endpoints::find_by_ips(&api.database_connection, ips)
        .await
        .map(|ep| ::rpc::site_explorer::ExploredEndpointList {
            endpoints: ep
                .into_iter()
                .map(::rpc::site_explorer::ExploredEndpoint::from)
                .collect(),
        })
        .map(Response::new)?;
    Ok(result)
}

pub(crate) async fn find_explored_managed_host_ids(
    api: &Api,
    request: Request<::rpc::site_explorer::ExploredManagedHostSearchFilter>,
) -> Result<Response<::rpc::site_explorer::ExploredManagedHostIdList>, Status> {
    log_request_data(&request);

    let filter: model::site_explorer::ExploredManagedHostSearchFilter = request.into_inner().into();

    let host_ips = db::explored_managed_host::find_ips(&api.database_connection, filter).await?;

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

    let result = db::explored_managed_host::find_by_ips(&api.database_connection, ips)
        .await
        .map(|ep| ::rpc::site_explorer::ExploredManagedHostList {
            managed_hosts: ep
                .into_iter()
                .map(::rpc::site_explorer::ExploredManagedHost::from)
                .collect(),
        })
        .map(Response::new)?;

    Ok(result)
}

pub(crate) async fn get_site_exploration_report(
    api: &Api,
    request: tonic::Request<::rpc::forge::GetSiteExplorationRequest>,
) -> Result<Response<::rpc::site_explorer::SiteExplorationReport>, Status> {
    log_request_data(&request);

    let report = db::site_exploration_report::fetch(&mut api.db_reader()).await?;

    Ok(tonic::Response::new(report.into()))
}

pub(crate) async fn clear_site_exploration_error(
    api: &Api,
    request: Request<rpc::ClearSiteExplorationErrorRequest>,
) -> Result<Response<()>, tonic::Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let bmc_ip = IpAddr::from_str(&req.ip_address).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    db::explored_endpoints::clear_last_known_error(bmc_ip, &mut txn).await?;

    txn.commit().await?;

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

    let mut txn = api.txn_begin().await?;

    let eps = db::explored_endpoints::find_all_by_ip(bmc_ip, &mut txn).await?;
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
        match db::explored_endpoints::re_explore_if_version_matches(
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

pub(crate) async fn refresh_endpoint_report(
    api: &Api,
    request: Request<rpc::RefreshEndpointReportRequest>,
) -> Result<Response<::rpc::site_explorer::ExploredEndpoint>, tonic::Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let bmc_ip = IpAddr::from_str(&req.ip_address).map_err(CarbideError::from)?;
    let bmc_addr = SocketAddr::new(bmc_ip, 443);

    let mut txn = api.txn_begin().await?;

    let existing = db::explored_endpoints::find_all_by_ip(bmc_ip, &mut txn).await?;
    let existing_ep = existing
        .into_iter()
        .next()
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "explored_endpoint",
            id: bmc_ip.to_string(),
        })?;

    let boot_interface_mac = existing_ep.boot_interface_mac;
    let existing_report = existing_ep.report.clone();

    let bmc_interface = db::machine_interface::find_by_ip(&mut txn, bmc_ip)
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "machine_interface",
            id: bmc_ip.to_string(),
        })?;

    txn.commit().await?;

    let expected = if let Some(expected_machine) =
        crate::handlers::expected_machine::query(api, bmc_interface.mac_address).await?
    {
        Some(ExpectedEntity::Machine(expected_machine))
    } else if let Some(expected_switch) =
        crate::handlers::expected_switch::query(api, bmc_interface.mac_address).await?
    {
        Some(ExpectedEntity::Switch(expected_switch))
    } else {
        crate::handlers::expected_power_shelf::query(api, bmc_interface.mac_address)
            .await?
            .map(ExpectedEntity::PowerShelf)
    };

    // Acquire the per-endpoint work lock before probing. If the periodic site-explorer
    // loop (or another concurrent refresh) is already probing this endpoint, return an
    // error immediately rather than running a redundant Redfish call.
    let work_lock = match api
        .work_lock_manager_handle
        .try_acquire_lock(endpoint_exploration_work_key(bmc_ip))
        .await
    {
        Ok(lock) => lock,
        Err(AcquireLockError::WorkAlreadyLocked(_)) => {
            return Err(CarbideError::AlreadyInProgress(format!(
                "Endpoint refresh already in progress for {bmc_ip}"
            ))
            .into());
        }
        Err(e) => {
            return Err(CarbideError::internal(format!(
                "Failed to acquire endpoint work lock for {bmc_ip}: {e}"
            ))
            .into());
        }
    };

    // Run the probe + persist on a detached tokio task that owns the work lock.
    // Awaiting the JoinHandle preserves the synchronous UX. Even if the caller navigates
    // away mid-fetch, the probe will still run to completion.
    let endpoint_explorer = api.endpoint_explorer.clone();
    let database_connection = api.database_connection.clone();
    let runtime_config = api.runtime_config.clone();

    let join_handle = tokio::spawn(async move {
        let _work_lock = work_lock;

        let start = std::time::Instant::now();
        let result = endpoint_explorer
            .explore_endpoint(
                bmc_addr,
                &bmc_interface,
                expected.as_ref(),
                existing_report.last_exploration_error.as_ref(),
                boot_interface_mac,
            )
            .await;

        let report = match result {
            Ok(mut report) => {
                report.last_exploration_latency = Some(start.elapsed());
                let fw_config_snapshot = runtime_config.get_firmware_config().create_snapshot();
                enrich_endpoint_exploration_report(&mut report, &fw_config_snapshot);
                report
            }
            Err(e) => {
                let mut report = existing_report.clone();
                report.last_exploration_error = Some(e);
                report.last_exploration_latency = Some(start.elapsed());
                report
            }
        };

        let mut txn = db::Transaction::begin(&database_connection).await?;

        let current = db::explored_endpoints::find_all_by_ip(bmc_ip, &mut txn).await?;
        let current_version = current
            .first()
            .ok_or_else(|| {
                tonic::Status::from(CarbideError::NotFoundError {
                    kind: "explored_endpoint",
                    id: bmc_ip.to_string(),
                })
            })?
            .report_version;

        let updated =
            db::explored_endpoints::try_update(bmc_ip, current_version, &report, false, &mut txn)
                .await?;

        if !updated {
            return Err(tonic::Status::from(
                CarbideError::ConcurrentModificationError(
                    "explored_endpoint",
                    current_version.to_string(),
                ),
            ));
        }

        let endpoints = db::explored_endpoints::find_all_by_ip(bmc_ip, &mut txn).await?;

        txn.commit().await?;

        let ep = endpoints.into_iter().next().ok_or_else(|| {
            tonic::Status::from(CarbideError::internal(format!(
                "Endpoint {bmc_ip} not found after update"
            )))
        })?;

        Ok::<_, tonic::Status>(ep)
    });

    match join_handle.await {
        Ok(Ok(ep)) => Ok(Response::new(ep.into())),
        Ok(Err(status)) => Err(status),
        Err(join_err) => Err(CarbideError::internal(format!(
            "refresh_endpoint_report background task failed for {bmc_ip}: {join_err}"
        ))
        .into()),
    }
}

pub(crate) async fn pause_explored_endpoint_remediation(
    api: &Api,
    request: Request<rpc::PauseExploredEndpointRemediationRequest>,
) -> Result<Response<()>, tonic::Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let bmc_ip = IpAddr::from_str(&req.ip_address).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    let eps = db::explored_endpoints::find_all_by_ip(bmc_ip, &mut txn).await?;
    if eps.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "explored_endpoint",
            id: bmc_ip.to_string(),
        }
        .into());
    }

    // Check if a machine exists for this endpoint
    let in_managed_host =
        carbide_site_explorer::is_endpoint_in_managed_host(bmc_ip, txn.as_pgconn())
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?;

    if in_managed_host {
        return Err(CarbideError::InvalidArgument(format!(
            "Cannot pause/resume remediation for endpoint {bmc_ip} because a machine exists for it"
        ))
        .into());
    }

    db::explored_endpoints::set_pause_remediation(bmc_ip, req.pause, &mut txn).await?;

    txn.commit().await?;

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
        return Err(CarbideError::InvalidArgument(format!(
            "Could not resolve {}. Must be hostname[:port] or IPv4[:port]",
            req.ip_address
        ))
        .into());
    };

    let in_managed_host =
        carbide_site_explorer::is_endpoint_in_managed_host(bmc_addr.ip(), &api.database_connection)
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(IsBmcInManagedHostResponse {
        in_managed_host,
    }))
}

pub(crate) async fn delete_explored_endpoint(
    api: &Api,
    request: Request<rpc::DeleteExploredEndpointRequest>,
) -> Result<Response<rpc::DeleteExploredEndpointResponse>, tonic::Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let bmc_ip = IpAddr::from_str(&req.ip_address).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    // Check if the endpoint exists
    let endpoints = db::explored_endpoints::find_all_by_ip(bmc_ip, &mut txn).await?;

    if endpoints.is_empty() {
        return Ok(Response::new(rpc::DeleteExploredEndpointResponse {
            deleted: false,
            message: Some(format!("No explored endpoint found with IP {bmc_ip}")),
        }));
    }

    // Check if a machine exists for this endpoint
    let in_managed_host =
        carbide_site_explorer::is_endpoint_in_managed_host(bmc_ip, txn.as_pgconn())
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?;

    if in_managed_host {
        return Err(CarbideError::InvalidArgument(format!(
            "Cannot delete endpoint {bmc_ip} because a machine exists for it. Did you mean to force-delete the machine?"
        ))
        .into());
    }

    // Delete the endpoint
    db::explored_endpoints::delete(&mut txn, bmc_ip).await?;

    txn.commit().await?;

    Ok(Response::new(rpc::DeleteExploredEndpointResponse {
        deleted: true,
        message: Some(format!(
            "Successfully deleted explored endpoint with IP {bmc_ip}"
        )),
    }))
}
