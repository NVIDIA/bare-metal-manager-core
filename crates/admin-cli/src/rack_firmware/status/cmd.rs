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

use ::rpc::admin_cli::{CarbideCliError, OutputFormat};

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn get_job_status(
    opts: Args,
    format: OutputFormat,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    let request = rpc::forge::RackFirmwareJobStatusRequest {
        job_id: opts.job_id,
    };

    let response = api_client
        .0
        .get_rack_firmware_job_status(request)
        .await
        .map_err(CarbideCliError::from)?;

    if format == OutputFormat::Json {
        let result = serde_json::json!({
            "job_id": response.job_id,
            "state": response.state,
            "state_description": response.state_description,
            "rack_id": response.rack_id,
            "node_id": response.node_id,
            "error_message": response.error_message,
            "result_json": response.result_json,
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Firmware Job Status");
        println!("  Job ID:      {}", response.job_id);
        println!("  State:       {}", response.state);
        println!("  Description: {}", response.state_description);
        println!("  Rack:        {}", response.rack_id);
        println!("  Node:        {}", response.node_id);

        if !response.error_message.is_empty() {
            println!("  Error:       {}", response.error_message);
        }

        if !response.result_json.is_empty() {
            println!("  Result:      {}", response.result_json);
        }
    }

    Ok(())
}
