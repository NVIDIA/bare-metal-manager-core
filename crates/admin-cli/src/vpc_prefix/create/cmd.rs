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

use ::rpc::admin_cli::output::{FormattedOutput, OutputFormat};
use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use rpc::forge::VpcPrefixCreationRequest;

use super::args::Args;
use crate::rpc::ApiClient;
use crate::vpc_prefix::show::cmd::ShowOutput;

fn parse_label(s: &str) -> rpc::forge::Label {
    match s.split_once(':') {
        Some((k, v)) => rpc::forge::Label {
            key: k.trim().to_string(),
            value: Some(v.trim().to_string()),
        },
        None => rpc::forge::Label {
            key: s.trim().to_string(),
            value: None,
        },
    }
}

pub async fn create(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let output = do_create(api_client, args).await?;

    output
        .write_output(output_format, ::rpc::admin_cli::Destination::Stdout())
        .map_err(CarbideCliError::from)
}

async fn do_create(
    api_client: &ApiClient,
    create_args: Args,
) -> Result<ShowOutput, CarbideCliError> {
    let labels = create_args
        .labels
        .unwrap_or_default()
        .iter()
        .map(|s| parse_label(s))
        .collect();

    let new_prefix = VpcPrefixCreationRequest {
        id: create_args.vpc_prefix_id,
        prefix: String::new(), // Deprecated field
        name: String::new(),   // Deprecated field
        vpc_id: Some(create_args.vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: create_args.prefix.to_string(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: create_args.name,
            labels,
            description: create_args.description.unwrap_or_default(),
        }),
    };

    api_client
        .0
        .create_vpc_prefix(new_prefix)
        .await
        .map(ShowOutput::One)
        .map_err(Into::into)
}
