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
use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::forge::dpu_extension_service_credential::Type;

use super::super::show::cmd::convert_extension_services_to_table;
use super::args::Args;
use crate::rpc::ApiClient;

pub async fn handle_update(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let credential =
        if args.username.is_some() || args.password.is_some() || args.registry_url.is_some() {
            if args.username.is_none() || args.password.is_none() || args.registry_url.is_none() {
                return Err(CarbideCliError::GenericError(
                    "All of username, password and registry URL are required to create credential"
                        .to_string(),
                ));
            }

            Some(::rpc::forge::DpuExtensionServiceCredential {
                registry_url: args.registry_url.unwrap(),
                r#type: Some(Type::UsernamePassword(rpc::forge::UsernamePassword {
                    username: args.username.unwrap(),
                    password: args.password.unwrap(),
                })),
            })
        } else {
            None
        };

    let observability = if let Some(r) = args.observability {
        serde_json::from_str(&r)?
    } else {
        vec![]
    };

    let extension_service = api_client
        .update_extension_service(
            args.service_id,
            args.service_name,
            args.description,
            args.data,
            credential,
            observability,
            args.if_version_ctr_match,
        )
        .await?;

    if is_json {
        println!("{}", serde_json::to_string_pretty(&extension_service)?);
    } else {
        convert_extension_services_to_table(&[extension_service]).printstd();
    }

    Ok(())
}
