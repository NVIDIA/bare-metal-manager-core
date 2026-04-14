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

use std::path::PathBuf;

use ::rpc::admin_cli::CarbideCliError;
use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(help = "Rack hardware type for this firmware configuration.")]
    pub rack_hardware_type: String,
    #[clap(help = "Path to JSON configuration file.")]
    pub json_file: PathBuf,
    #[clap(help = "Artifactory token for downloading firmware files.")]
    pub artifactory_token: String,
}

impl TryFrom<Args> for rpc::forge::RackFirmwareCreateRequest {
    type Error = CarbideCliError;

    fn try_from(args: Args) -> Result<Self, Self::Error> {
        let config_json = std::fs::read_to_string(&args.json_file).map_err(|e| {
            CarbideCliError::GenericError(format!(
                "Failed to read file {}: {}",
                args.json_file.display(),
                e
            ))
        })?;

        // Check that the JSON is valid.
        serde_json::from_str::<serde_json::Value>(&config_json)
            .map_err(|e| CarbideCliError::GenericError(format!("Invalid JSON in file: {}", e)))?;

        Ok(Self {
            rack_hardware_type: Some(rpc::common::RackHardwareType {
                value: args.rack_hardware_type,
            }),
            config_json,
            artifactory_token: args.artifactory_token,
        })
    }
}
