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
use mac_address::MacAddress;
use std::{net::IpAddr, str::FromStr};
use tokio::net::lookup_host;
use tonic::{Request, Response, Status};

use crate::{
    api::{log_request_data, Api},
    db::{
        self, explored_endpoints::DbExploredEndpoint, machine_interface::MachineInterface,
        DatabaseError,
    },
    site_explorer::EndpointExplorer,
    CarbideError,
};

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

// Ad-hoc BMC exploration
pub(crate) async fn explore(
    api: &Api,
    request: tonic::Request<::rpc::forge::ExploreRequest>,
) -> Result<Response<::rpc::site_explorer::EndpointExplorationReport>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let address = if req.address.contains(':') {
        req.address.clone()
    } else {
        format!("{}:443", req.address)
    };

    let mut addrs = lookup_host(address).await?;
    let Some(bmc_addr) = addrs.next() else {
        return Err(tonic::Status::invalid_argument(format!(
            "Could not resolve {}. Must be hostname[:port] or IPv4[:port]",
            req.address
        )));
    };

    let bmc_mac_address: MacAddress;
    if let Some(mac_str) = req.mac_address {
        bmc_mac_address = mac_str.parse::<MacAddress>().map_err(CarbideError::from)?;
    } else {
        return Err(tonic::Status::invalid_argument(format!(
            "request did not specify mac address: {req:#?}"
        )));
    };

    let explorer = crate::site_explorer::RedfishEndpointExplorer::new(
        api.redfish_pool.clone(),
        api.credential_provider.clone(),
    );
    let expected_machine = crate::handlers::expected_machine::query(api, bmc_mac_address).await?;
    let machine_interface = MachineInterface::mock_with_mac(bmc_mac_address);

    let report = explorer
        .explore_endpoint(bmc_addr, &machine_interface, expected_machine, None)
        .await
        .map_err(|e| CarbideError::GenericError(e.to_string()))?;

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
