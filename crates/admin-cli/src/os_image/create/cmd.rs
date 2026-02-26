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
use ::rpc::forge as forgerpc;

use super::args::Args;
use crate::os_image::common::str_to_rpc_uuid;
use crate::rpc::ApiClient;

pub async fn create(args: Args, api_client: &ApiClient) -> CarbideCliResult<()> {
    let id = str_to_rpc_uuid(&args.id)?;
    let image_attrs = forgerpc::OsImageAttributes {
        id: Some(id),
        source_url: args.url,
        digest: args.digest,
        tenant_organization_id: args.tenant_org_id,
        create_volume: args.create_volume.unwrap_or(false),
        name: args.name,
        description: args.description,
        auth_type: args.auth_type,
        auth_token: args.auth_token,
        rootfs_id: args.rootfs_id,
        rootfs_label: args.rootfs_label,
        boot_disk: args.boot_disk,
        capacity: args.capacity,
        bootfs_id: args.bootfs_id,
        efifs_id: args.efifs_id,
    };
    let image = api_client.0.create_os_image(image_attrs).await?;
    if let Some(x) = image.attributes {
        if let Some(y) = x.id {
            println!("OS image {y} created successfully.");
        } else {
            eprintln!("OS image creation may have failed, image id missing.");
        }
    } else {
        eprintln!("OS image creation may have failed, image attributes missing.");
    }
    Ok(())
}
