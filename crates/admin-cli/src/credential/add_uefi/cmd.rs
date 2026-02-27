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

use ::rpc::admin_cli::CarbideCliResult;
use ::rpc::{CredentialType, forge as forgerpc};
use forge_secrets::credentials::Credentials;

use super::args::Args;
use crate::credential::common::password_validator;
use crate::rpc::ApiClient;

pub async fn add_uefi(c: Args, api_client: &ApiClient) -> CarbideCliResult<()> {
    let mut password = password_validator(c.password)?;
    if password.is_empty() {
        password = Credentials::generate_password_no_special_char();
    }

    let req = forgerpc::CredentialCreationRequest {
        credential_type: CredentialType::from(c.kind).into(),
        username: None,
        password,
        mac_address: None,
        vendor: None,
    };
    api_client.0.create_credential(req).await?;
    Ok(())
}
