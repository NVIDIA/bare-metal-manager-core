/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ::rpc::forge as rpc;
use tonic::{Request, Response, Status};
use utils::HostPortPair;

use crate::api::{Api, log_request_data};

pub(crate) fn version(
    api: &Api,
    request: Request<rpc::VersionRequest>,
) -> Result<Response<rpc::BuildInfo>, Status> {
    log_request_data(&request);
    let version_request = request.into_inner();

    let v = rpc::BuildInfo {
        build_version: carbide_version::v!(build_version).to_string(),
        build_date: carbide_version::v!(build_date).to_string(),
        git_sha: carbide_version::v!(git_sha).to_string(),
        rust_version: carbide_version::v!(rust_version).to_string(),
        build_user: carbide_version::v!(build_user).to_string(),
        build_hostname: carbide_version::v!(build_hostname).to_string(),

        runtime_config: if version_request.display_config {
            Some(api.runtime_config.redacted().into())
        } else {
            None
        },
    };
    Ok(Response::new(v))
}

pub(crate) fn echo(
    _api: &Api,
    request: Request<rpc::EchoRequest>,
) -> Result<Response<rpc::EchoResponse>, Status> {
    log_request_data(&request);

    let reply = rpc::EchoResponse {
        message: request.into_inner().message,
    };

    Ok(Response::new(reply))
}

// Override RUST_LOG or site-explorer create_machines
pub(crate) fn set_dynamic_config(
    api: &Api,
    request: Request<rpc::SetDynamicConfigRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    let exp_str = req.expiry.as_deref().unwrap_or("1h");
    let expiry = duration_str::parse(exp_str).map_err(|err| {
        Status::invalid_argument(format!("Invalid expiry string '{exp_str}'. {err}"))
    })?;
    const MAX_SET_INTERNAL_EXPIRY: Duration = Duration::from_secs(60 * 60 * 60); // 60 hours
    if MAX_SET_INTERNAL_EXPIRY < expiry {
        return Err(Status::invalid_argument(
            "Expiry exceeds max allowed of 60 hours",
        ));
    }
    let expire_at = chrono::Utc::now() + expiry;

    let Ok(requested_setting) = rpc::ConfigSetting::try_from(req.setting) else {
        return Err(Status::invalid_argument(format!(
            "Not a supported dynamic config setting: {}",
            req.setting
        )));
    };

    if req.value.is_empty() && !matches!(requested_setting, rpc::ConfigSetting::BmcProxy) {
        return Err(Status::invalid_argument("'value' cannot be empty"));
    }

    match requested_setting {
        rpc::ConfigSetting::LogFilter => {
            let level = &api.dynamic_settings.log_filter;
            level.update(&req.value, Some(expire_at)).map_err(|err| {
                Status::invalid_argument(format!(
                    "Invalid log filter string '{}'. {err}",
                    req.value
                ))
            })?;
            tracing::info!(
                "Log filter updated to '{}'; global log level: {}",
                req.value,
                tracing_subscriber::filter::LevelFilter::current()
            );
        }
        rpc::ConfigSetting::CreateMachines => {
            let is_enabled = req.value.parse::<bool>().map_err(|err| {
                Status::invalid_argument(format!(
                    "Invalid create_machines string '{}'. {err}",
                    req.value
                ))
            })?;
            api.dynamic_settings
                .create_machines
                .store(is_enabled, Ordering::Relaxed);
            tracing::info!("site-explorer create_machines updated to '{}'", req.value);
        }
        rpc::ConfigSetting::BmcProxy => {
            let Some(true) = api.runtime_config.site_explorer.allow_changing_bmc_proxy else {
                return Err(Status::permission_denied(
                    "site-explorer.bmc_proxy is not allowed to be changed on this server",
                ));
            };

            if req.value.is_empty() {
                api.dynamic_settings.bmc_proxy.store(Arc::new(None))
            } else {
                let host_port_pair = req.value.parse::<HostPortPair>().map_err(|err| {
                    Status::invalid_argument(format!(
                        "Invalid bmc_proxy string '{}': {err}",
                        req.value
                    ))
                })?;

                api.dynamic_settings
                    .bmc_proxy
                    .store(Arc::new(Some(host_port_pair)));
            }
            tracing::info!("site-explorer create_machines updated to '{}'", req.value);
        }
        rpc::ConfigSetting::TracingEnabled => {
            let enable = req.value.parse().map_err(|_| {
                Status::invalid_argument(format!(
                    "Expected bool for TracingEnabled, got {}",
                    &req.value
                ))
            })?;
            api.dynamic_settings
                .tracing_enabled
                .store(enable, Ordering::Relaxed);
        }
    }
    Ok(Response::new(()))
}
