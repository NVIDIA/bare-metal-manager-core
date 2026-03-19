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

use clap::Parser;
use mac_address::MacAddress;
use rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use rpc::{CredentialType, forge as forgerpc};

use crate::credential::common::{BmcCredentialType, password_validator};

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[clap(
        long,
        require_equals(true),
        required(true),
        help = "The BMC Credential kind"
    )]
    pub kind: BmcCredentialType,
    #[clap(long, required(true), help = "The password of BMC")]
    pub password: String,
    #[clap(long, help = "The username of BMC")]
    pub username: Option<String>,
    #[clap(long, help = "The MAC address of the BMC")]
    pub mac_address: Option<MacAddress>,
}

impl TryFrom<Args> for forgerpc::CredentialCreationRequest {
    type Error = CarbideCliError;
    fn try_from(args: Args) -> CarbideCliResult<Self> {
        let password = password_validator(args.password)?;
        Ok(Self {
            credential_type: CredentialType::from(args.kind).into(),
            username: args.username,
            password,
            mac_address: args.mac_address.map(|mac| mac.to_string()),
            vendor: None,
        })
    }
}
