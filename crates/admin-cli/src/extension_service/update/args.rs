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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::forge::dpu_extension_service_credential::Type;
use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(short = 'i', long = "id", help = "The extension service ID to update")]
    pub service_id: String,

    #[clap(
        short = 'n',
        long = "name",
        help = "New extension service name (optional)"
    )]
    pub service_name: Option<String>,

    #[clap(long, help = "New extension service description (optional)")]
    pub description: Option<String>,

    #[clap(short = 'd', long, help = "New extension service data")]
    pub data: String,

    #[clap(long, help = "New registry URL for the service credential (optional)")]
    pub registry_url: Option<String>,

    #[clap(
        short = 'u',
        long,
        help = "New username for the service credential (optional)"
    )]
    pub username: Option<String>,

    #[clap(
        short = 'p',
        long,
        help = "New password for the service credential (optional)"
    )]
    pub password: Option<String>,

    #[clap(
        long,
        help = "Update only if current number of versions matches this number (optional)"
    )]
    pub if_version_ctr_match: Option<i32>,

    #[clap(
        long,
        help = "JSON array containing a defined set of extension observability configs (optional)"
    )]
    pub observability: Option<String>,
}

impl TryFrom<Args> for ::rpc::forge::UpdateDpuExtensionServiceRequest {
    type Error = CarbideCliError;

    fn try_from(args: Args) -> CarbideCliResult<Self> {
        let credential =
            if args.username.is_some() || args.password.is_some() || args.registry_url.is_some() {
                if args.username.is_none() || args.password.is_none() || args.registry_url.is_none()
                {
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

        let observability: Vec<::rpc::forge::DpuExtensionServiceObservabilityConfig> =
            if let Some(r) = args.observability {
                serde_json::from_str(&r)?
            } else {
                vec![]
            };

        Ok(Self {
            service_id: args.service_id,
            service_name: args.service_name,
            description: args.description,
            data: args.data,
            credential,
            if_version_ctr_match: args.if_version_ctr_match,
            observability: Some(::rpc::forge::DpuExtensionServiceObservability {
                configs: observability,
            }),
        })
    }
}
