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

use mac_address::MacAddress;
use tokio::net::lookup_host;
use tonic::{Response, Status};

use crate::model::machine::MachineInterfaceSnapshot;
use crate::{
    api::{log_request_data, Api},
    CarbideError,
};

// Ad-hoc BMC exploration
pub(crate) async fn explore(
    api: &Api,
    request: tonic::Request<::rpc::forge::BmcEndpointRequest>,
) -> Result<Response<::rpc::site_explorer::EndpointExplorationReport>, Status> {
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

    let bmc_mac_address: MacAddress;
    if let Some(mac_str) = req.mac_address {
        bmc_mac_address = mac_str.parse::<MacAddress>().map_err(CarbideError::from)?;
    } else {
        return Err(tonic::Status::invalid_argument(format!(
            "request did not specify mac address: {req:#?}"
        )));
    };

    let expected_machine = crate::handlers::expected_machine::query(api, bmc_mac_address).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    let report = api
        .endpoint_explorer
        .explore_endpoint(bmc_addr, &machine_interface, expected_machine, None)
        .await
        .map_err(|e| CarbideError::GenericError(e.to_string()))?;

    Ok(tonic::Response::new(report.into()))
}

pub(crate) async fn redfish_reset_bmc(
    api: &Api,
    request: ::rpc::forge::BmcEndpointRequest,
) -> Result<Response<()>, tonic::Status> {
    let address = if request.ip_address.contains(':') {
        request.ip_address.clone()
    } else {
        format!("{}:443", request.ip_address)
    };

    let mut addrs = lookup_host(address).await?;
    let Some(bmc_addr) = addrs.next() else {
        return Err(tonic::Status::invalid_argument(format!(
            "Could not resolve {}. Must be hostname[:port] or IPv4[:port]",
            request.ip_address
        )));
    };

    let bmc_mac_address: MacAddress;
    if let Some(mac_str) = request.mac_address {
        bmc_mac_address = mac_str.parse::<MacAddress>().map_err(CarbideError::from)?;
    } else {
        return Err(tonic::Status::invalid_argument(format!(
            "request did not specify mac address: {request:#?}"
        )));
    };

    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);
    api.endpoint_explorer
        .redfish_reset_bmc(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::GenericError(e.to_string()))?;

    Ok(Response::new(()))
}

pub(crate) async fn ipmitool_reset_bmc(
    api: &Api,
    request: ::rpc::forge::BmcEndpointRequest,
) -> Result<Response<()>, tonic::Status> {
    let address = if request.ip_address.contains(':') {
        request.ip_address.clone()
    } else {
        format!("{}:443", request.ip_address)
    };

    let mut addrs = lookup_host(address).await?;
    let Some(bmc_addr) = addrs.next() else {
        return Err(tonic::Status::invalid_argument(format!(
            "Could not resolve {}. Must be hostname[:port] or IPv4[:port]",
            request.ip_address
        )));
    };

    let bmc_mac_address: MacAddress;
    if let Some(mac_str) = request.mac_address {
        bmc_mac_address = mac_str.parse::<MacAddress>().map_err(CarbideError::from)?;
    } else {
        return Err(tonic::Status::invalid_argument(format!(
            "request did not specify mac address: {request:#?}"
        )));
    };

    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);
    api.endpoint_explorer
        .ipmitool_reset_bmc(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::GenericError(e.to_string()))?;

    Ok(Response::new(()))
}

pub(crate) async fn redfish_power_control(
    api: &Api,
    request: ::rpc::forge::BmcEndpointRequest,
    action: libredfish::SystemPowerControl,
) -> Result<Response<()>, tonic::Status> {
    let address = if request.ip_address.contains(':') {
        request.ip_address.clone()
    } else {
        format!("{}:443", request.ip_address)
    };

    let mut addrs = lookup_host(address).await?;
    let Some(bmc_addr) = addrs.next() else {
        return Err(tonic::Status::invalid_argument(format!(
            "Could not resolve {}. Must be hostname[:port] or IPv4[:port]",
            request.ip_address
        )));
    };

    let bmc_mac_address: MacAddress;
    if let Some(mac_str) = request.mac_address {
        bmc_mac_address = mac_str.parse::<MacAddress>().map_err(CarbideError::from)?;
    } else {
        return Err(tonic::Status::invalid_argument(format!(
            "request did not specify mac address: {request:#?}"
        )));
    };

    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);
    api.endpoint_explorer
        .redfish_power_control(bmc_addr, &machine_interface, action)
        .await
        .map_err(|e| CarbideError::GenericError(e.to_string()))?;

    Ok(Response::new(()))
}
