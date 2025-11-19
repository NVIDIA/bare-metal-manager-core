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

use ::rpc::forge as rpc;
use db::machine_interface::find_by_ip;
use forge_ssh::ssh::{
    DEFAULT_SSH_SESSION_TIMEOUT, DEFAULT_TCP_CONNECTION_TIMEOUT, DEFAULT_TCP_READ_TIMEOUT,
    DEFAULT_TCP_WRITE_TIMEOUT, SshConfig,
};
use forge_uuid::machine::MachineId;
use libredfish::RoleId;
use mac_address::MacAddress;
use model::machine::machine_id::try_parse_machine_id;
use model::machine::{LoadSnapshotOptions, MachineInterfaceSnapshot};
use sqlx::PgConnection;
use tokio::net::lookup_host;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};

pub(crate) async fn admin_bmc_reset(
    api: &Api,
    request: Request<rpc::AdminBmcResetRequest>,
) -> Result<Response<rpc::AdminBmcResetResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: AdminBmcResetRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin("admin_bmc_reset").await?;

    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    txn.commit().await?;

    let endpoint_address = bmc_endpoint_request.ip_address.clone();

    tracing::info!(
        "Resetting BMC (ipmi tool: {}): {}",
        req.use_ipmitool,
        endpoint_address
    );

    if req.use_ipmitool {
        ipmitool_reset_bmc(api, bmc_endpoint_request).await?;
    } else {
        redfish_reset_bmc(api, bmc_endpoint_request).await?;
    }

    tracing::info!(
        "BMC Reset (ipmi tool: {}) request succeeded to {}",
        req.use_ipmitool,
        endpoint_address
    );

    Ok(Response::new(rpc::AdminBmcResetResponse {}))
}

pub(crate) async fn disable_secure_boot(
    api: &Api,
    request: Request<rpc::BmcEndpointRequest>,
) -> Result<Response<rpc::DisableSecureBootResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let mut txn = api.txn_begin("disable_secure_boot").await?;

    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, Some(req), None).await?;

    txn.commit().await?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .disable_secure_boot(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    let endpoint_address = bmc_endpoint_request.ip_address.clone();
    tracing::info!(
        "disable_secure_boot request succeeded to {}",
        endpoint_address
    );

    Ok(Response::new(rpc::DisableSecureBootResponse {}))
}

pub(crate) async fn lockdown(
    api: &Api,
    request: Request<rpc::LockdownRequest>,
) -> Result<Response<rpc::LockdownResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let action = req.action();
    let action = match action {
        rpc::LockdownAction::Enable => libredfish::EnabledDisabled::Enabled,
        rpc::LockdownAction::Disable => libredfish::EnabledDisabled::Disabled,
    };

    let mut txn = api.txn_begin("lockdown").await?;

    let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
        &mut txn,
        req.bmc_endpoint_request,
        req.machine_id,
    )
    .await?;

    txn.commit().await?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .lockdown(bmc_addr, &machine_interface, action)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    let endpoint_address = bmc_endpoint_request.ip_address.clone();
    tracing::info!(
        "lockdown {} request succeeded to {}",
        action.to_string().to_lowercase(),
        endpoint_address
    );

    Ok(Response::new(rpc::LockdownResponse {}))
}

pub(crate) async fn lockdown_status(
    api: &Api,
    request: Request<rpc::LockdownStatusRequest>,
) -> Result<Response<::rpc::site_explorer::LockdownStatus>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let mut txn = api.txn_begin("lockdown_status").await?;

    let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
        &mut txn,
        req.bmc_endpoint_request,
        req.machine_id,
    )
    .await?;

    txn.commit().await?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
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
    request: Request<rpc::EnableInfiniteBootRequest>,
) -> Result<Response<rpc::EnableInfiniteBootResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: EnableInfiniteBootRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin("enable_infinite_boot").await?;

    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    txn.commit().await?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .enable_infinite_boot(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    let endpoint_address = bmc_endpoint_request.ip_address.clone();
    tracing::info!(
        "enable_infinite_boot request succeeded to {}",
        endpoint_address
    );

    Ok(Response::new(rpc::EnableInfiniteBootResponse {}))
}

pub(crate) async fn is_infinite_boot_enabled(
    api: &Api,
    request: Request<rpc::IsInfiniteBootEnabledRequest>,
) -> Result<Response<rpc::IsInfiniteBootEnabledResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: IsInfiniteBootEnabledRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin("is_infinite_boot_enabled").await?;

    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    txn.commit().await?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    let is_enabled = api
        .endpoint_explorer
        .is_infinite_boot_enabled(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    tracing::info!(
        "is_infinite_boot_enabled request succeeded to {}, result: {:?}",
        bmc_endpoint_request.ip_address,
        is_enabled
    );

    Ok(Response::new(rpc::IsInfiniteBootEnabledResponse {
        is_enabled,
    }))
}

pub(crate) async fn forge_setup(
    api: &Api,
    request: Request<rpc::ForgeSetupRequest>,
) -> Result<Response<rpc::ForgeSetupResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: ForgeSetupRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin("forge_setup").await?;

    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    txn.commit().await?;

    let endpoint_address = &bmc_endpoint_request.ip_address;

    tracing::info!("Starting Forge Setup for BMC: {}", endpoint_address);

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .forge_setup(
            bmc_addr,
            &machine_interface,
            req.boot_interface_mac.as_deref(),
        )
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    tracing::info!("Forge Setup request succeeded to {}", endpoint_address);

    Ok(Response::new(rpc::ForgeSetupResponse {}))
}

pub(crate) async fn set_dpu_first_boot_order(
    api: &Api,
    request: Request<rpc::SetDpuFirstBootOrderRequest>,
) -> Result<Response<rpc::SetDpuFirstBootOrderResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: SetDpuFirstBootOrderRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin("set_dpu_first_boot_order").await?;

    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    txn.commit().await?;

    let endpoint_address = &bmc_endpoint_request.ip_address;

    tracing::info!(
        "Setting DPU first in boot order for BMC: {}",
        endpoint_address
    );

    let boot_interface_mac = req
        .boot_interface_mac
        .as_ref()
        .filter(|mac| !mac.trim().is_empty())
        .ok_or_else(|| Status::invalid_argument("boot_interface_mac is required"))?;

    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &bmc_endpoint_request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .set_boot_order_dpu_first(bmc_addr, &machine_interface, boot_interface_mac)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    tracing::info!(
        "Set DPU first in boot order request succeeded to {}",
        endpoint_address
    );

    Ok(Response::new(rpc::SetDpuFirstBootOrderResponse {}))
}

pub(crate) async fn admin_power_control(
    api: &Api,
    request: Request<rpc::AdminPowerControlRequest>,
) -> Result<Response<rpc::AdminPowerControlResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: AdminPowerControlRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let action = req.action();

    let mut txn = api.txn_begin("admin_power_control").await?;

    let (bmc_endpoint_request, machine_id) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    let action = match action {
        rpc::admin_power_control_request::SystemPowerControl::On => {
            libredfish::SystemPowerControl::On
        }
        rpc::admin_power_control_request::SystemPowerControl::GracefulShutdown => {
            libredfish::SystemPowerControl::GracefulShutdown
        }
        rpc::admin_power_control_request::SystemPowerControl::ForceOff => {
            libredfish::SystemPowerControl::ForceOff
        }
        rpc::admin_power_control_request::SystemPowerControl::GracefulRestart => {
            libredfish::SystemPowerControl::GracefulRestart
        }
        rpc::admin_power_control_request::SystemPowerControl::ForceRestart => {
            libredfish::SystemPowerControl::ForceRestart
        }
        rpc::admin_power_control_request::SystemPowerControl::AcPowercycle => {
            libredfish::SystemPowerControl::ACPowercycle
        }
    };

    let mut msg: Option<String> = None;
    if let Some(machine_id) = machine_id {
        let power_manager_enabled = api.runtime_config.power_manager_options.enabled;
        if power_manager_enabled {
            let snapshot = db::managed_host::load_snapshot(
                &mut txn,
                &machine_id,
                LoadSnapshotOptions {
                    include_history: true,
                    include_instance_data: false,
                    host_health_config: api.runtime_config.host_health,
                },
            )
            .await?
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "machine",
                id: machine_id.to_string(),
            })?;

            if let Some(power_state) = snapshot
                .host_snapshot
                .power_options
                .map(|x| x.desired_power_state)
                && power_state == model::power_manager::PowerState::On
                && action == libredfish::SystemPowerControl::ForceOff
            {
                msg = Some(
                        "!!WARNING!! Desired power state for the host is set as On while the requested action is Off. Carbide will attempt to bring the host online after some time.".to_string(),
                    )
            }
        }
    }

    txn.commit().await?;

    redfish_power_control(api, bmc_endpoint_request, action).await?;

    Ok(Response::new(rpc::AdminPowerControlResponse { msg }))
}

// Ad-hoc BMC exploration
pub(crate) async fn explore(
    api: &Api,
    request: tonic::Request<rpc::BmcEndpointRequest>,
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

async fn redfish_reset_bmc(
    api: &Api,
    request: rpc::BmcEndpointRequest,
) -> Result<Response<()>, Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .redfish_reset_bmc(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

async fn ipmitool_reset_bmc(
    api: &Api,
    request: rpc::BmcEndpointRequest,
) -> Result<Response<()>, Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .ipmitool_reset_bmc(bmc_addr, &machine_interface)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

async fn redfish_power_control(
    api: &Api,
    request: rpc::BmcEndpointRequest,
    action: libredfish::SystemPowerControl,
) -> Result<Response<()>, Status> {
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
    request: tonic::Request<rpc::BmcEndpointRequest>,
) -> Result<Response<rpc::BmcCredentialStatusResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let (_bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, &req).await?;

    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);
    let have_credentials = api
        .endpoint_explorer
        .have_credentials(&machine_interface)
        .await;

    Ok(Response::new(rpc::BmcCredentialStatusResponse {
        have_credentials,
    }))
}

pub(crate) async fn copy_bfb_to_dpu_rshim(
    api: &Api,
    request: Request<rpc::CopyBfbToDpuRshimRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let (bmc_endpoint_request, ssh_config) = match req.ssh_request {
        Some(ssh_req) => match ssh_req.endpoint_request {
            Some(bmc_request) => {
                // Port 22 is the default SSH port--carbide-api assumes port :4443
                let ip_address: String = if bmc_request.ip_address.contains(':') {
                    bmc_request.ip_address
                } else {
                    format!("{}:22", bmc_request.ip_address)
                };

                (
                    rpc::BmcEndpointRequest {
                        ip_address,
                        mac_address: bmc_request.mac_address,
                    },
                    ssh_req.timeout_config,
                )
            }
            None => {
                return Err(CarbideError::MissingArgument("bmc_endpoint_request").into());
            }
        },
        None => {
            return Err(CarbideError::MissingArgument("ssh_request").into());
        }
    };

    do_copy_bfb_to_dpu_rshim(api, &bmc_endpoint_request, ssh_config).await?;

    Ok(Response::new(()))
}

async fn resolve_bmc_interface(
    api: &Api,
    request: &rpc::BmcEndpointRequest,
) -> Result<(SocketAddr, MacAddress), Status> {
    let address = if request.ip_address.contains(':') {
        request.ip_address.clone()
    } else {
        format!("{}:443", request.ip_address)
    };

    let mut addrs = lookup_host(address).await?;
    let Some(bmc_addr) = addrs.next() else {
        return Err(Status::invalid_argument(format!(
            "Could not resolve {}. Must be hostname[:port] or IPv4[:port]",
            request.ip_address
        )));
    };

    let bmc_mac_address: MacAddress;
    if let Some(mac_str) = &request.mac_address {
        bmc_mac_address = mac_str.parse::<MacAddress>().map_err(CarbideError::from)?;
    } else {
        let mut txn = api.txn_begin("resolve_bmc_interface").await?;

        if let Some(bmc_machine_interface) = find_by_ip(&mut txn, bmc_addr.ip()).await? {
            bmc_mac_address = bmc_machine_interface.mac_address;
        } else {
            return Err(Status::invalid_argument(format!(
                "could not find a mac address for the specified IP: {request:#?}"
            )));
        }
    };

    Ok((bmc_addr, bmc_mac_address))
}

async fn do_copy_bfb_to_dpu_rshim(
    api: &Api,
    request: &rpc::BmcEndpointRequest,
    ssh_config: Option<rpc::SshTimeoutConfig>,
) -> Result<Response<()>, Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    // Create a separate address for Redfish probing (port 443) since bmc_addr uses SSH port 22
    let redfish_addr = SocketAddr::new(bmc_addr.ip(), 443);

    // Periodically probe the redfish endpoint until the DPU BMC is reachable (if host was powercycled)
    const MAX_PROBE_ATTEMPTS: u32 = 20; // 20 attempts
    const PROBE_INTERVAL: Duration = Duration::from_secs(30); // 30 seconds between attempts

    for attempt in 0..MAX_PROBE_ATTEMPTS {
        match api
            .endpoint_explorer
            .probe_redfish_endpoint(redfish_addr)
            .await
        {
            Ok(_) => {
                tracing::info!("DPU BMC is online, continuing...");
                break;
            }
            Err(_) if attempt == MAX_PROBE_ATTEMPTS - 1 => {
                return Err(Status::deadline_exceeded(
                    "DPU BMC did not come back online after host powercycle",
                ));
            }
            Err(_) => {
                tracing::info!(
                    "DPU BMC not yet reachable (attempt {}/{}), retrying in {} seconds...",
                    attempt + 1,
                    MAX_PROBE_ATTEMPTS,
                    PROBE_INTERVAL.as_secs()
                );
                tokio::time::sleep(PROBE_INTERVAL).await;
            }
        }
    }

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
    request: Request<rpc::CreateBmcUserRequest>,
) -> Result<Response<rpc::CreateBmcUserResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: CreateBmcUserRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin("create_bmc_user").await?;

    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    txn.commit().await?;

    let endpoint_address = &bmc_endpoint_request.ip_address;

    let role: RoleId = match req
        .create_role_id
        .unwrap_or("Administrator".to_string())
        .to_lowercase()
        .as_str()
    {
        "administrator" => RoleId::Administrator,
        "operator" => RoleId::Operator,
        "readonly" => RoleId::ReadOnly,
        "noaccess" => RoleId::NoAccess,
        _ => RoleId::Administrator,
    };

    tracing::info!(
        "Creating BMC User {} ({role}) on {endpoint_address}",
        req.create_username,
    );

    do_create_bmc_user(
        api,
        &bmc_endpoint_request,
        &req.create_username,
        &req.create_password,
        role,
    )
    .await?;

    tracing::info!(
        "Successfully created BMC User {} ({role}) on {endpoint_address}",
        req.create_username
    );

    Ok(Response::new(rpc::CreateBmcUserResponse {}))
}

pub(crate) async fn delete_bmc_user(
    api: &Api,
    request: Request<rpc::DeleteBmcUserRequest>,
) -> Result<Response<rpc::DeleteBmcUserResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    // Note: DeleteBmcUserRequest uses a string for machine_id instead of a real MachineId, which is wrong.
    let machine_id = req
        .machine_id
        .as_ref()
        .map(|id| try_parse_machine_id(id))
        .transpose()?;

    let mut txn = api.txn_begin("delete_bmc_user").await?;
    let (bmc_endpoint_request, _) =
        validate_and_complete_bmc_endpoint_request(&mut txn, req.bmc_endpoint_request, machine_id)
            .await?;

    txn.commit().await?;

    let endpoint_address = &bmc_endpoint_request.ip_address;

    tracing::info!(
        "Deleting BMC User {} on {endpoint_address}",
        req.delete_username,
    );

    do_delete_bmc_user(api, &bmc_endpoint_request, &req.delete_username).await?;

    tracing::info!(
        "Successfully deleted BMC User {} on {endpoint_address}",
        req.delete_username
    );

    Ok(Response::new(rpc::DeleteBmcUserResponse {}))
}

async fn do_create_bmc_user(
    api: &Api,
    request: &rpc::BmcEndpointRequest,
    create_username: &str,
    create_password: &str,
    create_role_id: RoleId,
) -> Result<Response<()>, Status> {
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

async fn do_delete_bmc_user(
    api: &Api,
    request: &rpc::BmcEndpointRequest,
    delete_user: &str,
) -> Result<Response<()>, Status> {
    let (bmc_addr, bmc_mac_address) = resolve_bmc_interface(api, request).await?;
    let machine_interface = MachineInterfaceSnapshot::mock_with_mac(bmc_mac_address);

    api.endpoint_explorer
        .delete_bmc_user(bmc_addr, &machine_interface, delete_user)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(Response::new(()))
}

/// Accepts an optional partial or complete BmcEndpointRequest and optional machine ID and returns a complete and valid BmcEndpointRequest.
///
/// * `txn`                  - Active database transaction
/// * `bmc_endpoint_request` - Optional BmcEndpointRequest.  Can supply _only_ ip_address or all fields.
/// * `machine_id`           - Optional machine ID that can be used to build a new BmcEndpointRequest.
pub(crate) async fn validate_and_complete_bmc_endpoint_request(
    txn: &mut PgConnection,
    bmc_endpoint_request: Option<rpc::BmcEndpointRequest>,
    machine_id: Option<MachineId>,
) -> Result<(rpc::BmcEndpointRequest, Option<MachineId>), Status> {
    match (bmc_endpoint_request, machine_id) {
        (Some(bmc_endpoint_request), _) => {
            let interface = db::machine_interface::find_by_ip(
                txn,
                bmc_endpoint_request.ip_address.parse().unwrap(),
            )
            .await?
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "machine_interface",
                id: bmc_endpoint_request.ip_address.clone(),
            })?;

            let bmc_mac = match bmc_endpoint_request.mac_address {
                // No MAC in the request, use the interface MAC
                None => interface.mac_address.to_string(),

                // MAC passed in the request, check if it matches the interface MAC
                Some(request_mac) => {
                    let parsed_mac = request_mac
                        .parse::<MacAddress>()
                        .map_err(|e| CarbideError::InvalidArgument(e.to_string()))?;

                    if parsed_mac != interface.mac_address {
                        return Err(CarbideError::BmcMacIpMismatch {
                            requested_ip: bmc_endpoint_request.ip_address.clone(),
                            requested_mac: request_mac,
                            found_mac: interface.mac_address.to_string(),
                        }
                        .into());
                    }

                    request_mac
                }
            };

            Ok((
                rpc::BmcEndpointRequest {
                    ip_address: bmc_endpoint_request.ip_address,
                    mac_address: Some(bmc_mac),
                },
                interface.machine_id,
            ))
        }
        // User provided machine_id
        (_, Some(machine_id)) => {
            log_machine_id(&machine_id);

            let mut topologies =
                db::machine_topology::find_latest_by_machine_ids(txn, &[machine_id]).await?;

            let topology =
                topologies
                    .remove(&machine_id)
                    .ok_or_else(|| CarbideError::NotFoundError {
                        kind: "machine",
                        id: machine_id.to_string(),
                    })?;

            let bmc_ip = topology.topology().bmc_info.ip.as_ref().ok_or_else(|| {
                CarbideError::internal(format!(
                    "Machine found for {machine_id} but BMC IP is missing"
                ))
            })?;

            let bmc_mac_address = topology.topology().bmc_info.mac.ok_or_else(|| {
                CarbideError::internal(format!("BMC endpoint for {bmc_ip} ({machine_id}) found but does not have associated MAC"))
            })?;

            Ok((
                rpc::BmcEndpointRequest {
                    ip_address: bmc_ip.to_owned(),
                    mac_address: Some(bmc_mac_address.to_string()),
                },
                Some(machine_id),
            ))
        }

        _ => Err(Status::invalid_argument(
            "Provide either machine_id or BmcEndpointRequest with at least ip_address",
        )),
    }
}
