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
use ::rpc::forge::ClearHostUefiPasswordRequest;

use crate::machine::MachineQuery;
use crate::rpc::ApiClient;

pub async fn clear_uefi_password(
    query: MachineQuery,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let request = ClearHostUefiPasswordRequest {
        host_id: None,
        machine_query: Some(query.query.clone()),
    };
    let response = api_client.0.clear_host_uefi_password(request).await?;
    println!(
        "successfully cleared UEFI password for host {query:#?}; (jid: {:#?})",
        response.job_id
    );
    Ok(())
}
