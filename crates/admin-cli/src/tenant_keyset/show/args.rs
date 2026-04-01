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

use ::rpc::admin_cli::CarbideCliError;
use ::rpc::forge as forgerpc;
use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(
        default_value(""),
        help = "The Tenant KeySet ID in the format of <tenant_org_id>/<keyset_id> to query, leave empty for all (default)"
    )]
    pub id: String,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,
}

impl TryFrom<&Args> for Option<forgerpc::TenantKeysetIdentifier> {
    type Error = CarbideCliError;

    fn try_from(args: &Args) -> Result<Self, Self::Error> {
        if args.id.is_empty() {
            return Ok(None);
        }

        let split_id = args.id.split('/').collect::<Vec<&str>>();
        if split_id.len() != 2 {
            return Err(CarbideCliError::GenericError(
                "Invalid format for Tenant KeySet ID".to_string(),
            ));
        }

        Ok(Some(forgerpc::TenantKeysetIdentifier {
            organization_id: split_id[0].to_string(),
            keyset_id: split_id[1].to_string(),
        }))
    }
}
