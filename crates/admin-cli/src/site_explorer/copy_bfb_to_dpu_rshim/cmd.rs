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

use ::rpc::admin_cli::CarbideCliResult;
use ::rpc::forge::{BmcEndpointRequest, CopyBfbToDpuRshimRequest, SshRequest};

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn copy_bfb_to_dpu_rshim(api_client: &ApiClient, args: Args) -> CarbideCliResult<()> {
    // Power cycle host if requested
    if let Some(host_ip) = args.host_bmc_ip {
        tracing::info!(
            "Power cycling host at {} to ensure the DPU has rshim control",
            host_ip
        );

        // Power off
        tracing::info!("Powering off host...");
        api_client
            .admin_power_control(
                Some(::rpc::forge::BmcEndpointRequest {
                    ip_address: host_ip.clone(),
                    mac_address: None,
                }),
                None,
                ::rpc::forge::admin_power_control_request::SystemPowerControl::ForceOff,
            )
            .await?;

        // Wait for power off
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // Power on
        tracing::info!("Powering on host");
        api_client
            .admin_power_control(
                Some(::rpc::forge::BmcEndpointRequest {
                    ip_address: host_ip,
                    mac_address: None,
                }),
                None,
                ::rpc::forge::admin_power_control_request::SystemPowerControl::On,
            )
            .await?;
    }

    tracing::info!("Follow SCP progress in the carbide-api logs...");

    api_client
        .0
        .copy_bfb_to_dpu_rshim(CopyBfbToDpuRshimRequest {
            ssh_request: Some(SshRequest {
                endpoint_request: Some(BmcEndpointRequest {
                    ip_address: args.address.to_string(),
                    mac_address: args.mac.map(|m| m.to_string()),
                }),
            }),
        })
        .await?;
    Ok(())
}
