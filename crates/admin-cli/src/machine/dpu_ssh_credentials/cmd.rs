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

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};

use super::super::common::MachineQuery;
use crate::rpc::ApiClient;

pub async fn dpu_ssh_credentials(
    api_client: &ApiClient,
    query: MachineQuery,
    format: OutputFormat,
) -> CarbideCliResult<()> {
    let cred = api_client
        .0
        .get_dpu_ssh_credential(query.query.to_string())
        .await?;
    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&cred)?);
    } else {
        println!("{}:{}", cred.username, cred.password);
    }
    Ok(())
}
