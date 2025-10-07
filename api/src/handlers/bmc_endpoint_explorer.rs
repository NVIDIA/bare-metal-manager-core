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

use std::net::SocketAddr;
use std::time::Duration;

use forge_ssh::ssh::{
    DEFAULT_SSH_SESSION_TIMEOUT, DEFAULT_TCP_CONNECTION_TIMEOUT, DEFAULT_TCP_READ_TIMEOUT,
    DEFAULT_TCP_WRITE_TIMEOUT, SshConfig,
};
use libredfish::RoleId;
use mac_address::MacAddress;
use rpc::forge::BmcCredentialStatusResponse;
use tokio::net::lookup_host;
use tonic::{Response, Status};

use crate::db::DatabaseError;
use crate::db::machine_interface::find_by_ip;
use crate::model::machine::MachineInterfaceSnapshot;
use crate::{
    CarbideError,
    api::{Api, log_request_data},
};

// Ad-hoc BMC exploration
pub(crate) async fn explore(
    api: &Api,
    request: tonic::Request<::rpc::forge::BmcEndpointRequest>,
) -> Result<Response<::rpc::site_explorer::EndpointExplorationReport>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &req).await?;

    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);
    let expected_machine = crate::handlers::expected_machine::query(api, bmc_mac_address).await?;

    let report = api
        .endpoint_explorer
        .explore_endpoint(
            bmc_addr,
            &machine_interface,
            expected_machine.as_ref(),
            None,
        )
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(tonic::Response::new(report.into()))
}

pub(crate) async fn redfish_reset_bmc(
    api: &Api,
    request: ::rpc::forge::BmcEndpointRequest,
) -> Result<Response<()>, tonic::Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .redfish_reset_bmc(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

pub(crate) async fn ipmitool_reset_bmc(
    api: &Api,
    request: ::rpc::forge::BmcEndpointRequest,
) -> Result<Response<()>, tonic::Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .ipmitool_reset_bmc(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

pub(crate) async fn redfish_power_control(
    api: &Api,
    request: ::rpc::forge::BmcEndpointRequest,
    action: libredfish::SystemPowerControl,
) -> Result<Response<()>, tonic::Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .redfish_power_control(bmc_addr, &machine_interface, action)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

pub(crate) async fn bmc_credential_status(
    api: &Api,
    request: tonic::Request<::rpc::forge::BmcEndpointRequest>,
) -> Result<Response<BmcCredentialStatusResponse>, tonic::Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let (_bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &req).await?;

    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);
    let have_credentials = api
        .endpoint_explorer
        .have_credentials(&machine_interface)
        .await;

    Ok(Response::new(BmcCredentialStatusResponse {
        have_credentials,
    }))
}

pub(crate) async fn disable_secure_boot(
    api: &Api,
    request: ::rpc::forge::BmcEndpointRequest,
) -> Result<Response<()>, tonic::Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .disable_secure_boot(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

pub(crate) async fn lockdown(
    api: &Api,
    request: ::rpc::forge::BmcEndpointRequest,
    action: libredfish::EnabledDisabled,
) -> Result<Response<()>, tonic::Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .lockdown(bmc_addr, &machine_interface, action)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

pub(crate) async fn lockdown_status(
    api: &Api,
    request: ::rpc::forge::BmcEndpointRequest,
) -> Result<Response<::rpc::site_explorer::LockdownStatus>, tonic::Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    let response = api
        .endpoint_explorer
        .lockdown_status(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(response.into()))
}

pub(crate) async fn enable_infinite_boot(
    api: &Api,
    request: ::rpc::forge::BmcEndpointRequest,
) -> Result<Response<()>, tonic::Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .enable_infinite_boot(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

pub(crate) async fn is_infinite_boot_enabled(
    api: &Api,
    request: ::rpc::forge::BmcEndpointRequest,
) -> Result<Response<Option<bool>>, tonic::Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    let is_enabled = api
        .endpoint_explorer
        .is_infinite_boot_enabled(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(is_enabled))
}

pub(crate) async fn forge_setup(
    api: &Api,
    request: ::rpc::forge::ForgeSetupRequest,
) -> Result<Response<()>, tonic::Status> {
    let bmc_endpoint_request = request
        .bmc_endpoint_request
        .ok_or_else(|| tonic::Status::invalid_argument("bmc_endpoint_request is required"))?;
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .forge_setup(
            bmc_addr,
            &machine_interface,
            request.boot_interface_mac.as_deref(),
        )
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

pub(crate) async fn set_dpu_first_boot_order(
    api: &Api,
    request: ::rpc::forge::SetDpuFirstBootOrderRequest,
) -> Result<Response<()>, tonic::Status> {
    let bmc_endpoint_request = request
        .bmc_endpoint_request
        .ok_or_else(|| tonic::Status::invalid_argument("bmc_endpoint_request is required"))?;

    let boot_interface_mac = request
        .boot_interface_mac
        .as_ref()
        .filter(|mac| !mac.trim().is_empty())
        .ok_or_else(|| tonic::Status::invalid_argument("boot_interface_mac is required"))?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .set_boot_order_dpu_first(bmc_addr, &machine_interface, boot_interface_mac)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

async fn resolve_bmc_interface(
    api: &Api,
    request: &::rpc::forge::BmcEndpointRequest,
) -> Result<(SocketAddr, MacAddress), tonic::Status> {
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
    if let Some(mac_str) = &request.mac_address {
        bmc_mac_address = mac_str.parse::<MacAddress>().map_err(CarbideError::from)?;
    } else {
        let mut txn = api
            .database_connection
            .begin()
            .await
            .map_err(|e| DatabaseError::txn_begin("resolve_bmc_interface", e))?;

        if let Some(bmc_machine_interface) = find_by_ip(&mut txn, bmc_addr.ip()).await? {
            bmc_mac_address = bmc_machine_interface.mac_address;
        } else {
            return Err(tonic::Status::invalid_argument(format!(
                "could not find a mac address for the specified IP: {request:#?}"
            )));
        }
    };

    Ok((bmc_addr, bmc_mac_address))
}

pub(crate) async fn copy_bfb_to_dpu_rshim(
    api: &Api,
    request: &::rpc::forge::BmcEndpointRequest,
    ssh_config: Option<::rpc::forge::SshTimeoutConfig>,
) -> Result<Response<()>, tonic::Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    let ssh_timeout_config: Option<SshConfig> = ssh_config.map(|config| SshConfig {
        tcp_connection_timeout: Duration::from_secs(
            config
                .tcp_connection_timeout
                .unwrap_or(DEFAULT_TCP_CONNECTION_TIMEOUT.as_secs()),
        ),
        tcp_read_timeout: Duration::from_secs(
            config
                .tcp_read_timeout
                .unwrap_or(DEFAULT_TCP_READ_TIMEOUT.as_secs()),
        ),
        tcp_write_timeout: Duration::from_secs(
            config
                .tcp_write_timeout
                .unwrap_or(DEFAULT_TCP_WRITE_TIMEOUT.as_secs()),
        ),
        ssh_session_timeout: Duration::from_secs(
            config
                .ssh_session_timeout
                .unwrap_or(DEFAULT_SSH_SESSION_TIMEOUT.as_secs()),
        ),
    });

    api.endpoint_explorer
        .copy_bfb_to_dpu_rshim(bmc_addr, &machine_interface, ssh_timeout_config)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

pub(crate) async fn create_bmc_user(
    api: &Api,
    request: &::rpc::forge::BmcEndpointRequest,
    create_username: &str,
    create_password: &str,
    create_role_id: RoleId,
) -> Result<Response<()>, tonic::Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .create_bmc_user(
            bmc_addr,
            &machine_interface,
            create_username,
            create_password,
            create_role_id,
        )
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

pub(crate) async fn delete_bmc_user(
    api: &Api,
    request: &::rpc::forge::BmcEndpointRequest,
    delete_user: &str,
) -> Result<Response<()>, tonic::Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .delete_bmc_user(bmc_addr, &machine_interface, delete_user)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}
