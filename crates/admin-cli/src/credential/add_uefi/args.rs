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
use rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use rpc::{CredentialType, forge as forgerpc};

use crate::credential::common::{UefiCredentialType, password_validator};

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[clap(long, require_equals(true), required(true), help = "The UEFI kind")]
    pub kind: UefiCredentialType,

    #[clap(long, require_equals(true), help = "The UEFI password")]
    pub password: String,
}

impl TryFrom<Args> for forgerpc::CredentialCreationRequest {
    type Error = CarbideCliError;
    fn try_from(args: Args) -> CarbideCliResult<Self> {
        let mut password = password_validator(args.password)?;
        if password.is_empty() {
            password = forge_secrets::credentials::Credentials::generate_password_no_special_char();
        }
        Ok(Self {
            credential_type: CredentialType::from(args.kind).into(),
            username: None,
            password,
            mac_address: None,
            vendor: None,
        })
    }
}
