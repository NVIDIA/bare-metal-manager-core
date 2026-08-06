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

use rpc::forge::DeleteDecommissionedManagedHostRequest;

use super::args::Args;
use crate::errors::CarbideCliResult;
use crate::rpc::ApiClient;

pub async fn delete_decommissioned(api_client: &ApiClient, args: Args) -> CarbideCliResult<()> {
    let machine_id = args.machine_id;
    api_client
        .0
        .delete_decommissioned_managed_host(DeleteDecommissionedManagedHostRequest {
            machine_id: Some(machine_id),
        })
        .await?;
    println!("Deleted decommissioned managed host {machine_id}.");
    Ok(())
}
