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

use std::fs;

use ::rpc::admin_cli::{CarbideCliError, OutputFormat};

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn create(
    opts: Args,
    format: OutputFormat,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    // Read JSON file
    let config_json = fs::read_to_string(&opts.json_file).map_err(|e| {
        CarbideCliError::GenericError(format!(
            "Failed to read file {}: {}",
            opts.json_file.display(),
            e
        ))
    })?;

    // Check that the JSON is valid
    serde_json::from_str::<serde_json::Value>(&config_json)
        .map_err(|e| CarbideCliError::GenericError(format!("Invalid JSON in file: {}", e)))?;

    let request = rpc::forge::RackFirmwareCreateRequest {
        config_json,
        artifactory_token: opts.artifactory_token,
    };

    let result = api_client.0.create_rack_firmware(request).await?;

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Created Rack firmware configuration:");
        println!("  ID: {}", result.id);
        println!("  Available: {}", result.available);
        println!("  Created: {}", result.created);
    }

    Ok(())
}
