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

pub async fn get(
    opts: Args,
    format: OutputFormat,
    api_client: &ApiClient,
) -> Result<(), CarbideCliError> {
    let result = match api_client
        .0
        .get_ipxe_template(rpc::forge::GetIpxeTemplateRequest {
            name: opts.name.clone(),
        })
        .await
    {
        Ok(tmpl) => tmpl,
        Err(status) if status.code() == tonic::Code::NotFound => {
            return Err(CarbideCliError::GenericError(format!(
                "iPXE template not found: {}",
                opts.name
            )));
        }
        Err(err) => return Err(CarbideCliError::from(err)),
    };

    if format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Name:        {}", result.name);
        println!("Description: {}", result.description);

        if !result.required_params.is_empty() {
            println!("Required params:    {}", result.required_params.join(", "));
        }
        if !result.reserved_params.is_empty() {
            println!("Reserved params:    {}", result.reserved_params.join(", "));
        }
        if !result.required_artifacts.is_empty() {
            println!(
                "Required artifacts: {}",
                result.required_artifacts.join(", ")
            );
        }

        println!("\nTemplate:\n---\n{}\n---", result.template);
    }

    Ok(())
}
