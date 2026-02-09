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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge::{self as forgerpc, DeleteOsImageRequest};

use super::args::{CreateOsImage, DeleteOsImage, ListOsImage, UpdateOsImage};
use crate::rpc::ApiClient;

fn str_to_rpc_uuid(id: &str) -> CarbideCliResult<::rpc::common::Uuid> {
    let id: ::rpc::common::Uuid = uuid::Uuid::parse_str(id)
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))?
        .into();
    Ok(id)
}

pub async fn show(
    args: ListOsImage,
    output_format: OutputFormat,
    api_client: &ApiClient,
    _page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    let mut images = Vec::new();
    if let Some(x) = args.id {
        let id = str_to_rpc_uuid(&x)?;
        let image = api_client.0.get_os_image(id).await?;
        images.push(image);
    } else {
        images = api_client.list_os_image(args.tenant_org_id).await?;
    }
    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&images).map_err(CarbideCliError::JsonError)?
        );
    } else {
        // todo: pretty print in table form
        println!("{images:?}");
    }
    Ok(())
}

pub async fn create(args: CreateOsImage, api_client: &ApiClient) -> CarbideCliResult<()> {
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

pub async fn delete(args: DeleteOsImage, api_client: &ApiClient) -> CarbideCliResult<()> {
    let id = str_to_rpc_uuid(&args.id)?;
    api_client
        .0
        .delete_os_image(DeleteOsImageRequest {
            id: Some(id.clone()),
            tenant_organization_id: args.tenant_org_id,
        })
        .await?;
    println!("OS image {id} deleted successfully.");
    Ok(())
}

pub async fn update(args: UpdateOsImage, api_client: &ApiClient) -> CarbideCliResult<()> {
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
