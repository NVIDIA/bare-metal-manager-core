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
use ::rpc::forge as forgerpc;

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn find(args: Args, api_client: &ApiClient) -> CarbideCliResult<()> {
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
