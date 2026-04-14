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
use prettytable::{Table, row};

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn create(
    opts: Args,
    format: OutputFormat,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    let request: rpc::forge::RackFirmwareCreateRequest = opts.try_into()?;
    let result = api_client.0.create_rack_firmware(request).await?;

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let mut table = Table::new();
        table.add_row(row!["ID", result.id]);
        let hw_type = result
            .rack_hardware_type
            .as_ref()
            .map(|t| t.value.as_str())
            .unwrap_or("N/A");
        table.add_row(row!["Hardware Type", hw_type]);
        table.add_row(row!["Default", result.is_default]);
        table.add_row(row!["Available", result.available]);
        table.add_row(row!["Created", result.created]);
        table.printstd();
    }

    Ok(())
}
