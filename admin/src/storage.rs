/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use super::CarbideCliError;

use crate::cfg::storage::{
    CreateOsImage, CreateStoragePool, CreateStorageVolume, DeleteOsImage, DeleteStorageCluster,
    DeleteStoragePool, DeleteStorageVolume, ImportStorageCluster, ListOsImage, ListStorageCluster,
    ListStoragePool, ListStorageVolume, UpdateOsImage, UpdateStorageCluster, UpdateStoragePool,
    UpdateStorageVolume,
};
use crate::rpc::ApiClient;
use ::rpc::admin_cli::CarbideCliResult;
use ::rpc::admin_cli::OutputFormat;
use ::rpc::forge as forgerpc;

fn str_to_rpc_uuid(id: &str) -> CarbideCliResult<::rpc::common::Uuid> {
    let id: ::rpc::common::Uuid = uuid::Uuid::parse_str(id)
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))?
        .into();
    Ok(id)
}

fn opt_str_to_rpc_uuid(id: Option<String>) -> CarbideCliResult<Option<::rpc::common::Uuid>> {
    match id {
        Some(x) => {
            let id = str_to_rpc_uuid(&x)?;
            Ok(Some(id))
        }
        None => Ok(None),
    }
}

pub async fn cluster_show(
    args: ListStorageCluster,
    output_format: OutputFormat,
    api_client: &ApiClient,
    _page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    let mut clusters = Vec::new();
    if let Some(x) = args.id {
        let id = str_to_rpc_uuid(&x)?;
        let cluster = api_client.0.get_storage_cluster(id).await?;
        clusters.push(cluster);
    } else {
        clusters = api_client.0.list_storage_cluster().await?.clusters;
    }
    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&clusters).map_err(CarbideCliError::JsonError)?
        );
    } else {
        // there's usually only one storage cluster on a site
        println!("{clusters:?}");
    }
    Ok(())
}

pub async fn cluster_import(
    args: ImportStorageCluster,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let host = args.hosts.split(',').map(|x| x.to_string()).collect();
    let cluster_attrs = forgerpc::StorageClusterAttributes {
        host,
        port: args.port.unwrap_or(4001),
        username: args.username,
        password: args.password,
        description: None,
    };
    let cluster = api_client.0.import_storage_cluster(cluster_attrs).await?;
    if let Some(x) = cluster.id {
        println!("Imported cluster {x} successfully.");
    } else {
        eprintln!("Imported cluster may have failed, cluster id unavailable.");
    }

    Ok(())
}

pub async fn cluster_delete(
    args: DeleteStorageCluster,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let id = str_to_rpc_uuid(&args.id)?;
    api_client.delete_storage_cluster(id, args.name).await?;
    println!("Deleted cluster {} successfully.", args.id);
    Ok(())
}

pub async fn cluster_update(
    args: UpdateStorageCluster,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let mut host = Vec::new();
    if let Some(x) = args.hosts {
        host = x.split(',').map(|x| x.to_string()).collect();
    }
    let id = str_to_rpc_uuid(&args.id)?;
    let cluster = api_client
        .update_storage_cluster(id, host, args.port, args.username, args.password)
        .await?;
    if let Some(x) = cluster.id {
        println!("Updated cluster {x} successfully.");
    } else {
        eprintln!("Updating cluster may have failed, cluster id unavailable.");
    }
    Ok(())
}

pub async fn pool_show(
    args: ListStoragePool,
    output_format: OutputFormat,
    api_client: &ApiClient,
    _page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    let mut pools = Vec::new();
    if let Some(x) = args.id {
        let id = str_to_rpc_uuid(&x)?;
        let pool = api_client.0.get_storage_pool(id).await?;
        pools.push(pool);
    } else {
        let mut cluster_id: Option<::rpc::common::Uuid> = None;
        if let Some(x) = args.cluster_id {
            let id = str_to_rpc_uuid(&x)?;
            cluster_id = Some(id);
        }
        pools = api_client
            .list_storage_pool(cluster_id, args.tenant_org_id)
            .await?;
    }
    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&pools).map_err(CarbideCliError::JsonError)?
        );
    } else {
        // todo: pretty print in table form
        println!("{pools:?}");
    }
    Ok(())
}

pub async fn pool_create(args: CreateStoragePool, api_client: &ApiClient) -> CarbideCliResult<()> {
    let id = str_to_rpc_uuid(&args.id)?;
    let cluster_id = str_to_rpc_uuid(&args.cluster_id)?;
    let raid_level = args.raid_level.0 as i32;
    let boot = args.boot.unwrap_or(false);
    let pool_attrs = forgerpc::StoragePoolAttributes {
        cluster_id: Some(cluster_id),
        raid_level,
        capacity: args.capacity,
        tenant_organization_id: args.tenant_org_id,
        use_for_boot_volumes: boot,
        id: Some(id),
        name: args.name,
        description: args.description,
    };
    let pool = api_client.0.create_storage_pool(pool_attrs).await?;
    if let Some(x) = pool.attributes {
        if let Some(y) = x.id {
            println!("Storage pool {y} created successfully.");
        } else {
            eprintln!("Storage pool creation is pending or may have failed, pool id missing?");
        }
    } else {
        eprintln!("Storage pool creation is pending or may have failed, pool attributes missing?");
    }
    Ok(())
}

pub async fn pool_delete(args: DeleteStoragePool, api_client: &ApiClient) -> CarbideCliResult<()> {
    let id = str_to_rpc_uuid(&args.id)?;
    let cluster_id = str_to_rpc_uuid(&args.cluster_id)?;
    api_client
        .delete_storage_pool(cluster_id, id.clone())
        .await?;
    println!("Deleted storage pool {id} successfully.");
    Ok(())
}

pub async fn pool_update(args: UpdateStoragePool, api_client: &ApiClient) -> CarbideCliResult<()> {
    let id = str_to_rpc_uuid(&args.id)?;
    let pool = api_client
        .update_storage_pool(id, args.capacity, args.name, args.description)
        .await?;
    if let Some(x) = pool.attributes {
        if let Some(y) = x.id {
            println!("Storage pool {y} updated successfully.");
        } else {
            eprintln!("Updating the storage pool is pending or may have failed, pool id missing?");
        }
    } else {
        eprintln!(
            "Updating the storage pool is pending or may have failed, pool attributes missing?"
        );
    }
    Ok(())
}

pub async fn volume_show(
    args: ListStorageVolume,
    output_format: OutputFormat,
    api_client: &ApiClient,
    _page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    let mut volumes = Vec::new();
    if let Some(x) = args.id {
        let id = str_to_rpc_uuid(&x)?;
        let volume = api_client.0.get_storage_volume(id).await?;
        volumes.push(volume);
    } else {
        let cluster_id = opt_str_to_rpc_uuid(args.cluster_id)?;
        let pool_id = opt_str_to_rpc_uuid(args.pool_id)?;
        let instance_id = opt_str_to_rpc_uuid(args.instance_id)?;
        let source_id = opt_str_to_rpc_uuid(args.source_volume)?;

        let filter = forgerpc::StorageVolumeFilter {
            cluster_id,
            pool_id,
            machine_id: None,
            instance_id,
            volume_id: None,
            source_id,
            boot_volumes: args.boot_volumes,
            os_images: args.os_images,
            exclude_snapshots: args.exclude_snapshots,
        };
        volumes = api_client.0.list_storage_volume(filter).await?.volumes;
    }
    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&volumes).map_err(CarbideCliError::JsonError)?
        );
    } else {
        // todo: pretty print in table form
        println!("{volumes:?}");
    }
    Ok(())
}

pub async fn volume_create(
    args: CreateStorageVolume,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let id = str_to_rpc_uuid(&args.id)?;
    let cluster_id = str_to_rpc_uuid(&args.cluster_id)?;
    let pool_id = str_to_rpc_uuid(&args.pool_id)?;
    let source_id = opt_str_to_rpc_uuid(args.source_volume)?;
    let volume_attrs = forgerpc::StorageVolumeAttributes {
        cluster_id: Some(cluster_id),
        pool_id: Some(pool_id),
        capacity: args.capacity,
        delete_with_instance: false,
        use_existing_volume: None,
        boot_volume: None,
        os_image_id: None,
        source_id,
        id: Some(id),
        name: args.name,
        description: args.description,
    };
    let volume = api_client.0.create_storage_volume(volume_attrs).await?;
    if let Some(x) = volume.attributes {
        if let Some(y) = x.id {
            println!("Storage volume {y} created successfully.")
        } else {
            eprintln!("Storage volume creation is pending or may have failed, volume id missing?");
        }
    } else {
        eprintln!(
            "Storage volume creation is pending or may have failed, volume attributes missing?"
        );
    }
    Ok(())
}

pub async fn volume_delete(
    args: DeleteStorageVolume,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let id = str_to_rpc_uuid(&args.id)?;
    let cluster_id = str_to_rpc_uuid(&args.cluster_id)?;
    let pool_id = str_to_rpc_uuid(&args.pool_id)?;
    api_client
        .delete_storage_volume(cluster_id, pool_id, id.clone())
        .await?;
    println!("Storage volume {id} deleted successfully.");
    Ok(())
}

pub async fn volume_update(
    args: UpdateStorageVolume,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let id = str_to_rpc_uuid(&args.id)?;
    let volume = api_client
        .update_storage_volume(id, args.capacity, args.name, args.description)
        .await?;
    if let Some(x) = volume.attributes {
        if let Some(y) = x.id {
            println!("Storage volume {y} updated successfully.")
        } else {
            eprintln!(
                "Updating the storage volume is pending or may have failed, volume id missing?"
            );
        }
    } else {
        eprintln!(
            "Updating the storage volume is pending or may have failed, volume attributes missing?"
        );
    }
    Ok(())
}

pub async fn os_image_show(
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

pub async fn os_image_create(args: CreateOsImage, api_client: &ApiClient) -> CarbideCliResult<()> {
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

pub async fn os_image_delete(args: DeleteOsImage, api_client: &ApiClient) -> CarbideCliResult<()> {
    let id = str_to_rpc_uuid(&args.id)?;
    api_client
        .delete_os_image(id.clone(), args.tenant_org_id)
        .await?;
    println!("OS image {id} deleted successfully.");
    Ok(())
}

pub async fn os_image_update(args: UpdateOsImage, api_client: &ApiClient) -> CarbideCliResult<()> {
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
