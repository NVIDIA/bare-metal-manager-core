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
use ::rpc::forge::DeleteInstanceTypeRequest;

use super::args::Args;
use crate::rpc::ApiClient;

/// Delete an instance type.
pub async fn delete(args: Args, api_client: &ApiClient) -> CarbideCliResult<()> {
    api_client
        .0
        .delete_instance_type(DeleteInstanceTypeRequest {
            id: args.id.clone(),
        })
        .await?;
    println!("Deleted instance type {} successfully.", args.id);
    Ok(())
}
