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
use nico_rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use nico_rpc::{CredentialType, forge};

use crate::credential::common::url_validator;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[clap(long, required(true), help = "The UFM url")]
    pub url: String,
}

impl TryFrom<Args> for forge::CredentialDeletionRequest {
    type Error = CarbideCliError;
    fn try_from(args: Args) -> CarbideCliResult<Self> {
        let username = url_validator(args.url)?;
        Ok(Self {
            credential_type: CredentialType::Ufm.into(),
            username: Some(username),
            mac_address: None,
        })
    }
}
