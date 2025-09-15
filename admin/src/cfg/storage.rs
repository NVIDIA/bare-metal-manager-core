/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use clap::Parser;
use forge_uuid::instance::InstanceId;
use rpc::errors::RpcDataConversionError;
use rpc::forge::StorageRaidLevels;
use std::fmt;
use std::str::FromStr;

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum StorageActions {
    #[clap(subcommand, about = "Storage cluster commands.", visible_alias = "c")]
    Cluster(StorageClusterActions),
    #[clap(subcommand, about = "Storage pool commands.", visible_alias = "p")]
    Pool(StoragePoolActions),
    #[clap(subcommand, about = "Storage volume commands.", visible_alias = "v")]
    Volume(StorageVolumeActions),
}

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum StorageClusterActions {
    #[clap(
        about = "Import into Forge a storage cluster that is already setup.",
        visible_alias = "i"
    )]
    Import(ImportStorageCluster),
    #[clap(
        about = "Show storage cluster(s) configured in Forge.",
        visible_alias = "s"
    )]
    Show(ListStorageCluster),
    #[clap(
        about = "Delete a storage cluster that is no longer in use.",
        visible_alias = "d"
    )]
    Delete(DeleteStorageCluster),
    #[clap(
        about = "Update the hostnames/ip addresses and login credentials of an existing cluster.",
        visible_alias = "u"
    )]
    Update(UpdateStorageCluster),
}

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum StoragePoolActions {
    #[clap(
        about = "Create a storage pool/allocation for a tenant's use.",
        visible_alias = "c"
    )]
    Create(CreateStoragePool),
    #[clap(
        about = "Show one or more storage pools for a cluster or tenant.",
        visible_alias = "s"
    )]
    Show(ListStoragePool),
    #[clap(
        about = "Delete a storage pool that is not used anymore.",
        visible_alias = "d"
    )]
    Delete(DeleteStoragePool),
    #[clap(
        about = "Update the capacity or name and description of a pool.",
        visible_alias = "u"
    )]
    Update(UpdateStoragePool),
}

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum StorageVolumeActions {
    #[clap(
        about = "Create a volume or snapshot of a volume in a storage pool.",
        visible_alias = "c"
    )]
    Create(CreateStorageVolume),
    #[clap(
        about = "Show one or more volumes filtering by various options.",
        visible_alias = "s"
    )]
    Show(ListStorageVolume),
    #[clap(
        about = "Delete a volume that is not attached to any host.",
        visible_alias = "d"
    )]
    Delete(DeleteStorageVolume),
    #[clap(
        about = "Update the capacity or name and description of a volume.",
        visible_alias = "u"
    )]
    Update(UpdateStorageVolume),
}

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum OsImageActions {
    #[clap(
        about = "Create an OS image entry in the OS catalog for a tenant.",
        visible_alias = "c"
    )]
    Create(CreateOsImage),
    #[clap(
        about = "Show one or more OS image entries in the catalog.",
        visible_alias = "s"
    )]
    Show(ListOsImage),
    #[clap(
        about = "Delete an OS image entry that is not used on any instances.",
        visible_alias = "d"
    )]
    Delete(DeleteOsImage),
    #[clap(
        about = "Update the authentication details or name and description for an OS image.",
        visible_alias = "u"
    )]
    Update(UpdateOsImage),
}

#[derive(Parser, Debug, Clone)]
pub struct ImportStorageCluster {
    #[clap(
        short = 'H',
        long,
        help = "Specify hosts or IP addresses of NVMesh Cluster management servers, comma separated."
    )]
    pub hosts: String,
    #[clap(
        default_value("4001"),
        short = 'P',
        long,
        help = "Specify the NVMesh management service port number."
    )]
    pub port: Option<u32>,
    #[clap(
        short = 'U',
        long,
        help = "Specify the administrator username for the NVMesh Cluster management service."
    )]
    pub username: Option<String>,
    #[clap(
        short = 'S',
        long,
        help = "Specify the administrator password for the NVMesh Cluster management service."
    )]
    pub password: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct ListStorageCluster {
    #[clap(
        short = 'i',
        long,
        help = "Optionally specify the cluster uuid to list."
    )]
    pub id: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct DeleteStorageCluster {
    #[clap(short = 'i', long, help = "Specify the cluster id to delete.")]
    pub id: String,
    #[clap(short = 'n', long, help = "Specify the cluster name to delete.")]
    pub name: String,
}

#[derive(Parser, Debug, Clone)]
pub struct UpdateStorageCluster {
    #[clap(short = 'i', long, help = "Cluster uuid to update.")]
    pub id: String,
    #[clap(
        short = 'H',
        long,
        help = "Specify hosts or IP addresses of NVMesh Cluster management servers, comma separated."
    )]
    pub hosts: Option<String>,
    #[clap(
        default_value("4001"),
        short = 'P',
        long,
        help = "Specify the NVMesh management service port number."
    )]
    pub port: Option<u32>,
    #[clap(
        short = 'U',
        long,
        help = "Specify the administrator username for the NVMesh Cluster management service."
    )]
    pub username: Option<String>,
    #[clap(
        short = 'S',
        long,
        help = "Specify the administrator password for the NVMesh Cluster management service."
    )]
    pub password: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct CreateStoragePool {
    #[clap(short = 'i', long, help = "uuid of the storage pool to create.")]
    pub id: String,
    #[clap(short = 'c', long, help = "Cluster uuid to create the pool in.")]
    pub cluster_id: String,
    #[clap(
        default_value("Raid10"),
        short = 'r',
        long,
        help = "Redundancy level: Raid0,Raid1,Raid10,Concatenated,ErasureCoding."
    )]
    pub raid_level: StorageRaidLevelsOption,
    #[clap(short = 's', long, help = "Size of the storage pool in bytes.")]
    pub capacity: u64,
    #[clap(short = 't', long, help = "Tenant organization identifier.")]
    pub tenant_org_id: String,
    #[clap(
        short = 'b',
        long,
        help = "Use this pool for storing OS image volumes and associated snapshots."
    )]
    pub boot: Option<bool>,
    #[clap(short = 'n', long, help = "Name for the storage pool.")]
    pub name: Option<String>,
    #[clap(short = 'd', long, help = "Description for the storage pool.")]
    pub description: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct ListStoragePool {
    #[clap(short = 'i', long, help = "uuid of the storage pool to show.")]
    pub id: Option<String>,
    #[clap(
        short = 'c',
        long,
        help = "Cluster uuid to filter storage pools listing."
    )]
    pub cluster_id: Option<String>,
    #[clap(
        short = 't',
        long,
        help = "Tenant organization identifier to filter storage pools listing."
    )]
    pub tenant_org_id: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct DeleteStoragePool {
    #[clap(short = 'i', long, help = "uuid of the storage pool to delete.")]
    pub id: String,
    #[clap(
        short = 'c',
        long,
        help = "Cluster uuid of the storage pool to delete."
    )]
    pub cluster_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct UpdateStoragePool {
    #[clap(short = 'i', long, help = "uuid of the storage pool to update.")]
    pub id: String,
    #[clap(
        short = 's',
        long,
        help = "Optional, new larger size of pool in bytes."
    )]
    pub capacity: Option<u64>,
    #[clap(short = 'n', long, help = "Optional, name for the storage pool.")]
    pub name: Option<String>,
    #[clap(
        short = 'd',
        long,
        help = "Optional, description for the storage pool."
    )]
    pub description: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct CreateStorageVolume {
    #[clap(short = 'i', long, help = "uuid of the volume to create.")]
    pub id: String,
    #[clap(short = 'c', long, help = "Cluster uuid to create the volume in.")]
    pub cluster_id: String,
    #[clap(short = 'p', long, help = "Pool uuid to create the volume in.")]
    pub pool_id: String,
    #[clap(short = 's', long, help = "Size of the volume in bytes.")]
    pub capacity: u64,
    #[clap(
        short = 'r',
        long,
        help = "Source volume uuid for creating a snapshot."
    )]
    pub source_volume: Option<String>,
    #[clap(short = 'n', long, help = "Name for the volume.")]
    pub name: Option<String>,
    #[clap(short = 'd', long, help = "Description for the volume.")]
    pub description: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct ListStorageVolume {
    #[clap(short = 'i', long, help = "Optional, uuid of the volume to show.")]
    pub id: Option<String>,
    #[clap(short = 'c', long, help = "Cluster uuid to filter volumes listing.")]
    pub cluster_id: Option<String>,
    #[clap(short = 'p', long, help = "Pool uuid to filter volumes listing.")]
    pub pool_id: Option<String>,
    #[clap(short = 'm', long, help = "Machine id to filter volumes listing.")]
    pub machine_id: Option<String>,
    #[clap(short = 'n', long, help = "Instance id to filter volumes listing.")]
    pub instance_id: Option<InstanceId>,
    #[clap(
        short = 'r',
        long,
        help = "Source volume uuid to filter snapshot volumes listing."
    )]
    pub source_volume: Option<String>,
    #[clap(
        short = 'b',
        long,
        help = "Only boot volumes (volumes marked as bootable)."
    )]
    pub boot_volumes: Option<bool>,
    #[clap(short = 'o', long, help = "Only OS image source volumes.")]
    pub os_images: Option<bool>,
    #[clap(short = 'x', long, help = "Exclude snapshots in listing.")]
    pub exclude_snapshots: Option<bool>,
}

#[derive(Parser, Debug, Clone)]
pub struct DeleteStorageVolume {
    #[clap(short = 'i', long, help = "uuid of the volume to delete.")]
    pub id: String,
    #[clap(short = 'c', long, help = "Cluster uuid of the volume to delete.")]
    pub cluster_id: String,
    #[clap(short = 'p', long, help = "Pool uuid of the volume to delete.")]
    pub pool_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct UpdateStorageVolume {
    #[clap(short = 'i', long, help = "uuid of the volume to update.")]
    pub id: String,
    #[clap(
        short = 's',
        long,
        help = "Optional, new larger size of the volume in bytes."
    )]
    pub capacity: Option<u64>,
    #[clap(short = 'n', long, help = "Optional, name of the volume.")]
    pub name: Option<String>,
    #[clap(short = 'd', long, help = "Optional, description of the volume.")]
    pub description: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct CreateOsImage {
    #[clap(short = 'i', long, help = "uuid of the OS image to create.")]
    pub id: String,
    #[clap(short = 'u', long, help = "url of the OS image qcow file.")]
    pub url: String,
    #[clap(
        short = 'm',
        long,
        help = "Digest of the OS image file, typically a SHA-256."
    )]
    pub digest: String,
    #[clap(
        short = 't',
        long,
        help = "Tenant organization identifier for the OS catalog to create this in."
    )]
    pub tenant_org_id: String,
    #[clap(
        short = 'v',
        long,
        help = "Create a source volume for block storage use."
    )]
    pub create_volume: Option<bool>,
    #[clap(
        short = 's',
        long,
        help = "Size of the OS image source volume to create."
    )]
    pub capacity: Option<u64>,
    #[clap(short = 'n', long, help = "Name of the OS image entry.")]
    pub name: Option<String>,
    #[clap(short = 'd', long, help = "Description of the OS image entry.")]
    pub description: Option<String>,
    #[clap(short = 'y', long, help = "Authentication type, usually Bearer.")]
    pub auth_type: Option<String>,
    #[clap(short = 'p', long, help = "Authentication token, usually in base64.")]
    pub auth_token: Option<String>,
    #[clap(
        short = 'f',
        long,
        help = "uuid of the root filesystem of the OS image."
    )]
    pub rootfs_id: Option<String>,
    #[clap(
        short = 'l',
        long,
        help = "Label of the root filesystem of the OS image."
    )]
    pub rootfs_label: Option<String>,
    #[clap(short = 'b', long, help = "Boot device path if using local disk.")]
    pub boot_disk: Option<String>,
    #[clap(long, help = "UUID of the image boot filesystem (/boot)")]
    pub bootfs_id: Option<String>,
    #[clap(long, help = "UUID of the image EFI filesystem (/boot/efi)")]
    pub efifs_id: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct ListOsImage {
    #[clap(short = 'i', long, help = "uuid of the OS image to show.")]
    pub id: Option<String>,
    #[clap(
        short = 't',
        long,
        help = "Tenant organization identifier to filter OS images listing."
    )]
    pub tenant_org_id: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct DeleteOsImage {
    #[clap(short = 'i', long, help = "uuid of the OS image to delete.")]
    pub id: String,
    #[clap(
        short = 't',
        long,
        help = "Tenant organization identifier of OS image to delete."
    )]
    pub tenant_org_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct UpdateOsImage {
    #[clap(short = 'i', long, help = "uuid of the OS image to update.")]
    pub id: String,
    #[clap(short = 'n', long, help = "Optional, name of the OS image entry.")]
    pub name: Option<String>,
    #[clap(
        short = 'd',
        long,
        help = "Optional, description of the OS image entry."
    )]
    pub description: Option<String>,
    #[clap(
        short = 'y',
        long,
        help = "Optional, Authentication type, usually Bearer."
    )]
    pub auth_type: Option<String>,
    #[clap(
        short = 'p',
        long,
        help = "Optional, Authentication token, usually in base64."
    )]
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRaidLevelsOption(pub StorageRaidLevels);

impl fmt::Display for StorageRaidLevelsOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<StorageRaidLevels> for StorageRaidLevelsOption {
    fn from(value: StorageRaidLevels) -> Self {
        Self(value)
    }
}

impl TryFrom<i32> for StorageRaidLevelsOption {
    type Error = RpcDataConversionError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        let val = rpc::forge::StorageRaidLevels::try_from(value).map_err(|_e| {
            RpcDataConversionError::InvalidValue("StorageRaidLevel".to_string(), value.to_string())
        })?;
        Ok(StorageRaidLevelsOption::from(val))
    }
}

impl FromStr for StorageRaidLevelsOption {
    type Err = RpcDataConversionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Concatenated" => Ok(StorageRaidLevels::Concatenated.into()),
            "Raid0" => Ok(StorageRaidLevels::Raid0.into()),
            "Raid1" => Ok(StorageRaidLevels::Raid1.into()),
            "Raid10" => Ok(StorageRaidLevels::Raid10.into()),
            "ErasureCoding" => Ok(StorageRaidLevels::ErasureCoding.into()),
            _ => Err(RpcDataConversionError::InvalidValue(
                "StorageRaidLevel".to_string(),
                s.to_string(),
            )),
        }
    }
}
