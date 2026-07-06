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
use rpc::forge as forgerpc;

use crate::credential::common::{RotationCredentialKind, password_validator};
use crate::errors::{CarbideCliError, CarbideCliResult};

#[derive(Parser, Debug, Clone)]
#[command(after_long_help = "\
EXAMPLES:

Rotate the site-wide BMC root password, letting the server auto-generate a strong one:
    $ nico-admin-cli credential rotate --type=bmc

Rotate the host UEFI password to an explicit value:
    $ nico-admin-cli credential rotate --type=host-uefi --password=Str0ng-Explicit-Pw!

Rotate the SuperNIC lockdown IKM with an audit note:
    $ nico-admin-cli credential rotate --type=lockdown-ikm --reason=\"quarterly rotation\"

")]
pub struct Args {
    #[clap(
        long = "type",
        require_equals(true),
        required(true),
        help = "Credential family to rotate"
    )]
    pub credential_type: RotationCredentialKind,

    #[clap(
        long,
        require_equals(true),
        help = "Explicit rotate-to password. Omit to have the server auto-generate a strong one."
    )]
    pub password: Option<String>,

    #[clap(
        long,
        help = "Free-form note recorded with the rotation (must not contain secrets)"
    )]
    pub reason: Option<String>,
}

impl TryFrom<Args> for forgerpc::RotateCredentialRequest {
    type Error = CarbideCliError;
    fn try_from(args: Args) -> CarbideCliResult<Self> {
        let password = match args.password {
            Some(password) => Some(password_validator(password)?),
            None => None,
        };
        Ok(Self {
            credential_type: forgerpc::RotationCredentialType::from(args.credential_type) as i32,
            password,
            reason: args.reason,
        })
    }
}
