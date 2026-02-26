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
use prettytable::{Cell, Row, Table};

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn list(
    opts: Args,
    format: OutputFormat,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    let request = rpc::forge::RackFirmwareListRequest {
        only_available: opts.only_available,
    };

    let result = api_client.0.list_rack_firmware(request).await?;

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&result.configs)?);
    } else if result.configs.is_empty() {
        println!("No Rack firmware configurations found.");
    } else {
        let mut table = Table::new();
        table.set_titles(Row::new(vec![
            Cell::new("ID"),
            Cell::new("Available"),
            Cell::new("Created"),
            Cell::new("Updated"),
        ]));

        for config in result.configs {
            table.add_row(Row::new(vec![
                Cell::new(&config.id),
                Cell::new(&config.available.to_string()),
                Cell::new(&config.created),
                Cell::new(&config.updated),
            ]));
        }

        table.printstd();
    }

    Ok(())
}
