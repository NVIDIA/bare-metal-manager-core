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

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn add_dpu_factory_default(c: Args, api_client: &ApiClient) -> CarbideCliResult<()> {
    let req = forgerpc::CredentialCreationRequest {
        credential_type: CredentialType::DpuBmcFactoryDefault.into(),
        username: Some(c.username),
        password: c.password,
        mac_address: None,
        vendor: None,
    };
    api_client.0.create_credential(req).await?;
    Ok(())
}
