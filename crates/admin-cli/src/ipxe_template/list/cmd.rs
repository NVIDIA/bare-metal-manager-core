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
    _opts: Args,
    format: OutputFormat,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    let result = api_client
        .0
        .list_ipxe_templates()
        .await?;

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&result.templates)?);
    } else if result.templates.is_empty() {
        println!("No iPXE templates found.");
    } else {
        let mut table = Table::new();
        table.set_titles(Row::new(vec![
            Cell::new("Name"),
            Cell::new("Description"),
            Cell::new("Required Params"),
            Cell::new("Required Artifacts"),
        ]));

        for tmpl in &result.templates {
            table.add_row(Row::new(vec![
                Cell::new(&tmpl.name),
                Cell::new(&tmpl.description),
                Cell::new(&tmpl.required_params.join(", ")),
                Cell::new(&tmpl.required_artifacts.join(", ")),
            ]));
        }

        table.printstd();
    }

    Ok(())
}
