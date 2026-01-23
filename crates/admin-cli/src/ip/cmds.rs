/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::admin_cli::CarbideCliResult;
use ::rpc::forge as forgerpc;

use super::args::IpFind;
use crate::rpc::ApiClient;

pub async fn find(args: IpFind, api_client: &ApiClient) -> CarbideCliResult<()> {
    let req = forgerpc::FindIpAddressRequest {
        ip: args.ip.to_string(),
    };
    let resp = api_client.0.find_ip_address(req).await?;
    for r in resp.matches {
        tracing::info!("{}", r.message);
    }
    if !resp.errors.is_empty() {
        tracing::warn!("These matchers failed:");
        for err in resp.errors {
            tracing::warn!("\t{err}");
        }
    }
    Ok(())
}
