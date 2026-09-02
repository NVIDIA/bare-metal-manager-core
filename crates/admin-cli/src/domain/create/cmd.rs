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

use ::rpc::admin_cli::output::OutputFormat;
use ::rpc::protos::dns::DomainList;

use super::args::Args;
use crate::errors::{CarbideCliError, CarbideCliResult};
use crate::rpc::ApiClient;

pub(super) async fn create(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let domain = api_client.0.create_domain(args).await?;

    match output_format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&domain)?),
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&domain)?),
        OutputFormat::Csv => {
            crate::domain::show::cmd::convert_domain_to_nice_table(DomainList {
                domains: vec![domain],
            })
            .to_csv(std::io::stdout())
            .map_err(CarbideCliError::CsvError)?
            .flush()?;
        }
        OutputFormat::AsciiTable => println!(
            "{}",
            crate::domain::show::cmd::convert_domain_to_nice_format(&domain)?
        ),
    }

    Ok(())
}
