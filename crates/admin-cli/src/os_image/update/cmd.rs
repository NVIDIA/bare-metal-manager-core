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

use super::args::Args;
use crate::os_image::common::str_to_rpc_uuid;
use crate::rpc::ApiClient;

pub async fn update(args: Args, api_client: &ApiClient) -> CarbideCliResult<()> {
    let id = str_to_rpc_uuid(&args.id)?;
    let image = api_client
        .update_os_image(
            id,
            args.auth_type,
            args.auth_token,
            args.name,
            args.description,
        )
        .await?;
    if let Some(x) = image.attributes {
        if let Some(y) = x.id {
            println!("OS image {y} updated successfully.");
        } else {
            eprintln!("Updating the OS image may have failed, image id missing.");
        }
    } else {
        eprintln!("Updating the OS image may have failed, image attributes missing.");
    }
    Ok(())
}
