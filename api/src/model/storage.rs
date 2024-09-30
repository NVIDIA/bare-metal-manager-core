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

use ::rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Debug;
use std::str::FromStr;
use uuid::Uuid;

use crate::model::tenant::TenantOrganizationId;

use forge_uuid::machine::MachineId;

/// This file is just for the struct definitions and grpc proto object conversions
/// methods are implemented in api/src/db/storage.rs and callers in api/src/storage.rs
/// NVMesh storage model is
/// Cluster (collection of storage target servers setup by the Provider)
///  -> Storage Pool (provisioned per Tenant)
///     -> Volume (disk exposed to the host)
///        -> Snapshot (if it's a snapshot; a combination of volumes, source and copy-on-write space and metadata space, is the disk exposed to host)
/// ObjectAttributes are those specified when creating the Object
/// actual Object has current Status, Attributes provided at creation time, and other identifiers

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageClusterAttributes {
    pub host: Vec<String>,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCluster {
    pub name: String,
    pub id: Uuid,
    pub capacity: u64,
    pub allocated: u64,
    pub available: u64,
    pub healthy: bool,
    pub attributes: StorageClusterAttributes,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StorageRaidLevels {
    Concatenated,
    Raid0,
    Raid1,
    Raid10,
    ErasureCoding,
}

impl fmt::Display for StorageRaidLevels {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePoolAttributes {
    pub id: Uuid,
    pub cluster_id: Uuid,
    pub raid_level: StorageRaidLevels,
    pub capacity: u64,
    pub tenant_organization_id: TenantOrganizationId,
    pub use_for_boot_volumes: bool,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePool {
    pub nvmesh_uuid: Uuid,
    pub allocated: u64,
    pub available: u64,
    pub attributes: StoragePoolAttributes,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct StorageVolumeAttributes {
    pub id: Uuid,
    pub cluster_id: Uuid,
    // storage pool to create the volume in
    pub pool_id: Uuid,
    pub capacity: u64,
    pub delete_with_instance: bool,
    // this can only be set when creating an instance, to use a pre-existing volume
    pub use_existing_volume: Option<bool>,
    // set if instance is to be configured to boot from this volume (can set to only one volume per instance)
    pub boot_volume: Option<bool>,
    // optionally set the os image to use if setting boot_volume=true
    pub os_image_id: Option<Uuid>,
    // only for snapshots, source volume id
    pub source_id: Option<Uuid>,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StorageVolumeHealth {
    Initializing,
    Healthy,
    Degraded,
    Failed,
    Rebuilding,
}

impl fmt::Display for StorageVolumeHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageVolumeStatus {
    pub health: StorageVolumeHealth,
    /// attached and in use on an instance
    pub attached: bool,
    pub status_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageVolume {
    pub nvmesh_uuid: Uuid,
    pub attributes: StorageVolumeAttributes,
    pub status: StorageVolumeStatus,
    /// volume can be used on one or more instances
    pub instance_id: Vec<Uuid>,
    /// client for a volume on the nvmesh fabric is the dpu
    pub dpu_machine_id: Vec<MachineId>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageVolumeFilter {
    pub volume_id: Option<Uuid>,         // one volume
    pub instance_id: Option<Uuid>,       // upto 8 volumes
    pub machine_id: Option<MachineId>,   // upto 8 volumes
    pub pool_id: Option<Uuid>,           // large collection of volumes
    pub cluster_id: Option<Uuid>,        // very large collection of volumes
    pub source_id: Option<Uuid>,         // only snapshot volumes using this source volume
    pub boot_volumes: Option<bool>,      // only boot volumes
    pub os_images: Option<bool>,         // only os image volumes or snapshots
    pub exclude_snapshots: Option<bool>, // only source volumes, no snapshots
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsImageAttributes {
    pub id: Uuid,
    pub source_url: String,
    pub digest: String,
    pub tenant_organization_id: TenantOrganizationId,
    pub create_volume: bool,
    pub name: Option<String>,
    pub description: Option<String>,
    pub auth_type: Option<String>,
    pub auth_token: Option<String>,
    pub rootfs_id: Option<String>,
    pub rootfs_label: Option<String>,
    pub boot_disk: Option<String>,
    pub capacity: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OsImageStatus {
    Uninitialized, // initial state when db entry created
    InProgress,    // golden volume creation in progress if applicable
    Failed,        // golden volume creation error
    Ready,         // ready for use during allocate instance calls
    Disabled,      // disabled or deprecated, no new instance allocations can use it
}

impl fmt::Display for OsImageStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsImage {
    pub attributes: OsImageAttributes,
    pub status: OsImageStatus,
    pub status_message: Option<String>,
    pub volume_id: Option<Uuid>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
}

impl TryFrom<rpc::forge::StorageClusterAttributes> for StorageClusterAttributes {
    type Error = RpcDataConversionError;
    fn try_from(cluster_attrs: rpc::forge::StorageClusterAttributes) -> Result<Self, Self::Error> {
        Ok(Self {
            host: cluster_attrs.host,
            port: cluster_attrs.port as u16,
            username: cluster_attrs.username,
            password: cluster_attrs.password,
            description: cluster_attrs.description,
        })
    }
}

impl TryFrom<StorageClusterAttributes> for rpc::forge::StorageClusterAttributes {
    type Error = RpcDataConversionError;
    fn try_from(cluster_attrs: StorageClusterAttributes) -> Result<Self, Self::Error> {
        Ok(Self {
            host: cluster_attrs.host,
            port: cluster_attrs.port as u32,
            username: cluster_attrs.username,
            password: cluster_attrs.password,
            description: cluster_attrs.description,
        })
    }
}

impl TryFrom<StorageCluster> for rpc::forge::StorageCluster {
    type Error = RpcDataConversionError;

    fn try_from(cluster: StorageCluster) -> Result<Self, Self::Error> {
        let id: rpc::Uuid = rpc::Uuid::from(cluster.id);
        Ok(Self {
            name: cluster.name,
            id: Some(id),
            capacity: cluster.capacity,
            allocated: cluster.allocated,
            available: cluster.available,
            healthy: cluster.healthy,
            attributes: Some(rpc::forge::StorageClusterAttributes::try_from(
                cluster.attributes,
            )?),
            created_at: cluster.created_at,
            modified_at: cluster.modified_at,
        })
    }
}

impl TryFrom<rpc::forge::StorageRaidLevels> for StorageRaidLevels {
    type Error = RpcDataConversionError;
    fn try_from(value: rpc::forge::StorageRaidLevels) -> Result<Self, Self::Error> {
        match value {
            rpc::forge::StorageRaidLevels::Concatenated => Ok(StorageRaidLevels::Concatenated),
            rpc::forge::StorageRaidLevels::Raid0 => Ok(StorageRaidLevels::Raid0),
            rpc::forge::StorageRaidLevels::Raid1 => Ok(StorageRaidLevels::Raid1),
            rpc::forge::StorageRaidLevels::Raid10 => Ok(StorageRaidLevels::Raid10),
            rpc::forge::StorageRaidLevels::ErasureCoding => Ok(StorageRaidLevels::ErasureCoding),
        }
    }
}

impl TryFrom<i32> for StorageRaidLevels {
    type Error = RpcDataConversionError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        let val = rpc::forge::StorageRaidLevels::try_from(value).map_err(|_e| {
            RpcDataConversionError::InvalidValue("StorageRaidLevel".to_string(), value.to_string())
        })?;
        StorageRaidLevels::try_from(val)
    }
}

impl TryFrom<StorageRaidLevels> for rpc::forge::StorageRaidLevels {
    type Error = RpcDataConversionError;
    fn try_from(value: StorageRaidLevels) -> Result<Self, Self::Error> {
        match value {
            StorageRaidLevels::Concatenated => Ok(rpc::forge::StorageRaidLevels::Concatenated),
            StorageRaidLevels::Raid0 => Ok(rpc::forge::StorageRaidLevels::Raid0),
            StorageRaidLevels::Raid1 => Ok(rpc::forge::StorageRaidLevels::Raid1),
            StorageRaidLevels::Raid10 => Ok(rpc::forge::StorageRaidLevels::Raid10),
            StorageRaidLevels::ErasureCoding => Ok(rpc::forge::StorageRaidLevels::ErasureCoding),
        }
    }
}

impl TryFrom<StorageRaidLevels> for libnvmesh::nvmesh_model::RaidLevels {
    type Error = RpcDataConversionError;
    fn try_from(value: StorageRaidLevels) -> Result<Self, Self::Error> {
        match value {
            StorageRaidLevels::Concatenated => {
                Ok(libnvmesh::nvmesh_model::RaidLevels::Concatenated)
            }
            StorageRaidLevels::Raid0 => Ok(libnvmesh::nvmesh_model::RaidLevels::Raid0),
            StorageRaidLevels::Raid1 => Ok(libnvmesh::nvmesh_model::RaidLevels::Raid1),
            StorageRaidLevels::Raid10 => Ok(libnvmesh::nvmesh_model::RaidLevels::Raid10),
            StorageRaidLevels::ErasureCoding => {
                Ok(libnvmesh::nvmesh_model::RaidLevels::ErasureCoding)
            }
        }
    }
}

impl TryFrom<libnvmesh::nvmesh_model::RaidLevels> for StorageRaidLevels {
    type Error = RpcDataConversionError;
    fn try_from(value: libnvmesh::nvmesh_model::RaidLevels) -> Result<Self, Self::Error> {
        match value {
            libnvmesh::nvmesh_model::RaidLevels::Concatenated => {
                Ok(StorageRaidLevels::Concatenated)
            }
            libnvmesh::nvmesh_model::RaidLevels::Raid0 => Ok(StorageRaidLevels::Raid0),
            libnvmesh::nvmesh_model::RaidLevels::Raid1 => Ok(StorageRaidLevels::Raid1),
            libnvmesh::nvmesh_model::RaidLevels::Raid10 => Ok(StorageRaidLevels::Raid10),
            libnvmesh::nvmesh_model::RaidLevels::ErasureCoding => {
                Ok(StorageRaidLevels::ErasureCoding)
            }
        }
    }
}

impl FromStr for StorageRaidLevels {
    type Err = RpcDataConversionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Concatenated" => Ok(StorageRaidLevels::Concatenated),
            "Raid0" => Ok(StorageRaidLevels::Raid0),
            "Raid1" => Ok(StorageRaidLevels::Raid1),
            "Raid10" => Ok(StorageRaidLevels::Raid10),
            "ErasureCoding" => Ok(StorageRaidLevels::ErasureCoding),
            _ => Err(RpcDataConversionError::InvalidValue(
                "StorageRaidLevel".to_string(),
                s.to_string(),
            )),
        }
    }
}

impl TryFrom<rpc::forge::StoragePoolAttributes> for StoragePoolAttributes {
    type Error = RpcDataConversionError;
    fn try_from(pool_attrs: rpc::forge::StoragePoolAttributes) -> Result<Self, Self::Error> {
        if pool_attrs.cluster_id.is_none() {
            return Err(RpcDataConversionError::MissingArgument("cluster id"));
        }
        let cluster_id = Uuid::try_from(pool_attrs.cluster_id.clone().unwrap()).map_err(|_e| {
            RpcDataConversionError::InvalidUuid(
                "cluster id",
                pool_attrs.cluster_id.clone().unwrap().to_string(),
            )
        })?;
        if pool_attrs.id.is_none() {
            return Err(RpcDataConversionError::MissingArgument("pool id"));
        }
        let id = Uuid::try_from(pool_attrs.id.clone().unwrap()).map_err(|_e| {
            RpcDataConversionError::InvalidUuid(
                "pool id",
                pool_attrs.id.clone().unwrap().to_string(),
            )
        })?;

        Ok(Self {
            cluster_id,
            raid_level: StorageRaidLevels::try_from(pool_attrs.raid_level)?,
            capacity: pool_attrs.capacity,
            tenant_organization_id: TenantOrganizationId::try_from(
                pool_attrs.tenant_organization_id.clone(),
            )
            .map_err(|_e| {
                RpcDataConversionError::InvalidValue(
                    "tenant_organization_id".to_string(),
                    pool_attrs.tenant_organization_id.clone(),
                )
            })?,
            use_for_boot_volumes: pool_attrs.use_for_boot_volumes,
            id,
            name: pool_attrs.name,
            description: pool_attrs.description,
        })
    }
}

impl TryFrom<StoragePoolAttributes> for rpc::forge::StoragePoolAttributes {
    type Error = RpcDataConversionError;

    fn try_from(pool_attrs: StoragePoolAttributes) -> Result<Self, Self::Error> {
        let cluster_id = rpc::Uuid::from(pool_attrs.cluster_id);
        let id = rpc::Uuid::from(pool_attrs.id);
        Ok(Self {
            cluster_id: Some(cluster_id),
            raid_level: rpc::forge::StorageRaidLevels::try_from(pool_attrs.raid_level)? as i32,
            capacity: pool_attrs.capacity,
            tenant_organization_id: pool_attrs.tenant_organization_id.to_string(),
            use_for_boot_volumes: pool_attrs.use_for_boot_volumes,
            id: Some(id),
            name: pool_attrs.name,
            description: pool_attrs.description,
        })
    }
}

impl TryFrom<StoragePool> for rpc::forge::StoragePool {
    type Error = RpcDataConversionError;
    fn try_from(pool: StoragePool) -> Result<Self, Self::Error> {
        let nvmesh_uuid = rpc::Uuid::from(pool.nvmesh_uuid);
        Ok(Self {
            nvmesh_uuid: Some(nvmesh_uuid),
            allocated: pool.allocated,
            available: pool.available,
            attributes: Some(rpc::forge::StoragePoolAttributes::try_from(
                pool.attributes,
            )?),
            created_at: pool.created_at,
            modified_at: pool.modified_at,
        })
    }
}

impl TryFrom<StorageVolumeAttributes> for rpc::forge::StorageVolumeAttributes {
    type Error = RpcDataConversionError;
    fn try_from(vol_attrs: StorageVolumeAttributes) -> Result<Self, Self::Error> {
        let cluster_id = rpc::Uuid::from(vol_attrs.cluster_id);
        let pool_id = rpc::Uuid::from(vol_attrs.pool_id);
        let id = rpc::Uuid::from(vol_attrs.id);

        Ok(Self {
            cluster_id: Some(cluster_id),
            pool_id: Some(pool_id),
            capacity: vol_attrs.capacity,
            delete_with_instance: vol_attrs.delete_with_instance,
            id: Some(id),
            name: vol_attrs.name,
            description: vol_attrs.description,
            boot_volume: vol_attrs.boot_volume,
            source_id: vol_attrs.source_id.map(|x| x.into()),
            os_image_id: vol_attrs.os_image_id.map(|x| x.into()),
            use_existing_volume: vol_attrs.use_existing_volume,
        })
    }
}

impl TryFrom<rpc::forge::StorageVolumeAttributes> for StorageVolumeAttributes {
    type Error = RpcDataConversionError;
    fn try_from(vol_attrs: rpc::forge::StorageVolumeAttributes) -> Result<Self, Self::Error> {
        if vol_attrs.cluster_id.is_none() {
            return Err(RpcDataConversionError::MissingArgument("cluster id"));
        }
        if vol_attrs.pool_id.is_none() {
            return Err(RpcDataConversionError::MissingArgument("pool id"));
        }
        if vol_attrs.id.is_none() {
            return Err(RpcDataConversionError::MissingArgument("volume id"));
        }
        let cluster_id = Uuid::try_from(vol_attrs.cluster_id.clone().unwrap()).map_err(|_e| {
            RpcDataConversionError::InvalidUuid(
                "cluster id",
                vol_attrs.cluster_id.clone().unwrap().to_string(),
            )
        })?;
        let pool_id = Uuid::try_from(vol_attrs.pool_id.clone().unwrap()).map_err(|_e| {
            RpcDataConversionError::InvalidUuid(
                "pool id",
                vol_attrs.pool_id.clone().unwrap().to_string(),
            )
        })?;
        let id = Uuid::try_from(vol_attrs.id.clone().unwrap()).map_err(|_e| {
            RpcDataConversionError::InvalidUuid(
                "volume id",
                vol_attrs.id.clone().unwrap().to_string(),
            )
        })?;
        let source_id = match vol_attrs.source_id {
            Some(x) => Some(Uuid::try_from(x.clone()).map_err(|_e| {
                RpcDataConversionError::InvalidUuid("source id", x.clone().to_string())
            })?),
            None => None,
        };
        let os_image_id = match vol_attrs.os_image_id {
            Some(x) => Some(Uuid::try_from(x.clone()).map_err(|_e| {
                RpcDataConversionError::InvalidUuid("os image id", x.clone().to_string())
            })?),
            None => None,
        };
        Ok(Self {
            cluster_id,
            pool_id,
            capacity: vol_attrs.capacity,
            delete_with_instance: vol_attrs.delete_with_instance,
            id,
            name: vol_attrs.name,
            description: vol_attrs.description,
            boot_volume: vol_attrs.boot_volume,
            source_id,
            os_image_id,
            use_existing_volume: vol_attrs.use_existing_volume,
        })
    }
}

impl TryFrom<StorageVolumeHealth> for rpc::forge::StorageVolumeHealth {
    type Error = RpcDataConversionError;
    fn try_from(value: StorageVolumeHealth) -> Result<Self, Self::Error> {
        match value {
            StorageVolumeHealth::Initializing => {
                Ok(rpc::forge::StorageVolumeHealth::VolumeInitializing)
            }
            StorageVolumeHealth::Healthy => Ok(rpc::forge::StorageVolumeHealth::VolumeHealthy),
            StorageVolumeHealth::Degraded => Ok(rpc::forge::StorageVolumeHealth::VolumeDegraded),
            StorageVolumeHealth::Failed => Ok(rpc::forge::StorageVolumeHealth::VolumeFailed),
            StorageVolumeHealth::Rebuilding => {
                Ok(rpc::forge::StorageVolumeHealth::VolumeRebuilding)
            }
        }
    }
}

impl TryFrom<rpc::forge::StorageVolumeHealth> for StorageVolumeHealth {
    type Error = RpcDataConversionError;
    fn try_from(value: rpc::forge::StorageVolumeHealth) -> Result<Self, Self::Error> {
        match value {
            rpc::forge::StorageVolumeHealth::VolumeInitializing => {
                Ok(StorageVolumeHealth::Initializing)
            }
            rpc::forge::StorageVolumeHealth::VolumeHealthy => Ok(StorageVolumeHealth::Healthy),
            rpc::forge::StorageVolumeHealth::VolumeDegraded => Ok(StorageVolumeHealth::Degraded),
            rpc::forge::StorageVolumeHealth::VolumeFailed => Ok(StorageVolumeHealth::Failed),
            rpc::forge::StorageVolumeHealth::VolumeRebuilding => {
                Ok(StorageVolumeHealth::Rebuilding)
            }
        }
    }
}

impl TryFrom<i32> for StorageVolumeHealth {
    type Error = RpcDataConversionError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        let val = rpc::forge::StorageVolumeHealth::try_from(value).map_err(|_e| {
            RpcDataConversionError::InvalidValue(
                "StorageVolumeHealth".to_string(),
                value.to_string(),
            )
        })?;
        StorageVolumeHealth::try_from(val)
    }
}

impl FromStr for StorageVolumeHealth {
    type Err = RpcDataConversionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Initializing" => Ok(StorageVolumeHealth::Initializing),
            "Healthy" => Ok(StorageVolumeHealth::Healthy),
            "Degraded" => Ok(StorageVolumeHealth::Degraded),
            "Failed" => Ok(StorageVolumeHealth::Failed),
            "Rebuilding" => Ok(StorageVolumeHealth::Rebuilding),
            _ => Err(RpcDataConversionError::InvalidValue(
                "StorageVolumeHealth".to_string(),
                s.to_string(),
            )),
        }
    }
}

impl TryFrom<StorageVolumeStatus> for rpc::forge::StorageVolumeStatus {
    type Error = RpcDataConversionError;
    fn try_from(status: StorageVolumeStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            health: rpc::forge::StorageVolumeHealth::try_from(status.health)? as i32,
            attached: status.attached,
            status_message: status.status_message,
        })
    }
}

impl TryFrom<rpc::forge::StorageVolumeStatus> for StorageVolumeStatus {
    type Error = RpcDataConversionError;
    fn try_from(status: rpc::forge::StorageVolumeStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            health: StorageVolumeHealth::try_from(status.health)?,
            attached: status.attached,
            status_message: status.status_message,
        })
    }
}

impl TryFrom<StorageVolumeFilter> for rpc::forge::StorageVolumeFilter {
    type Error = RpcDataConversionError;
    fn try_from(filter: StorageVolumeFilter) -> Result<Self, Self::Error> {
        let cluster_id = filter.cluster_id.map(rpc::Uuid::from);
        let pool_id = filter.pool_id.map(rpc::Uuid::from);
        let volume_id = filter.volume_id.map(rpc::Uuid::from);
        let machine_id = filter
            .machine_id
            .map(|x| rpc::MachineId::from(x.to_string()));
        let instance_id = filter.instance_id.map(rpc::Uuid::from);
        let source_id = filter.source_id.map(rpc::Uuid::from);
        Ok(Self {
            cluster_id,
            pool_id,
            machine_id,
            instance_id,
            volume_id,
            source_id,
            boot_volumes: filter.boot_volumes,
            os_images: filter.os_images,
            exclude_snapshots: filter.exclude_snapshots,
        })
    }
}

impl TryFrom<rpc::forge::StorageVolumeFilter> for StorageVolumeFilter {
    type Error = RpcDataConversionError;
    fn try_from(filter: rpc::forge::StorageVolumeFilter) -> Result<Self, Self::Error> {
        let cluster_id = match filter.cluster_id {
            Some(x) => Some(Uuid::try_from(x.clone()).map_err(|_e| {
                RpcDataConversionError::InvalidUuid("cluster id", x.clone().to_string())
            })?),
            None => None,
        };
        let pool_id = match filter.pool_id {
            Some(x) => Some(Uuid::try_from(x.clone()).map_err(|_e| {
                RpcDataConversionError::InvalidUuid("pool id", x.clone().to_string())
            })?),
            None => None,
        };
        let volume_id = match filter.volume_id {
            Some(x) => Some(Uuid::try_from(x.clone()).map_err(|_e| {
                RpcDataConversionError::InvalidUuid("volume id", x.clone().to_string())
            })?),
            None => None,
        };
        let machine_id = match filter.machine_id {
            Some(x) => Some(MachineId::from_str(x.to_string().as_str()).map_err(|_e| {
                RpcDataConversionError::InvalidValue("machine id".to_string(), x.to_string())
            })?),
            None => None,
        };
        let instance_id =
            match filter.instance_id {
                Some(x) => Some(Uuid::try_from(x.clone()).map_err(|_e| {
                    RpcDataConversionError::InvalidInstanceId(x.clone().to_string())
                })?),
                None => None,
            };
        let source_id = match filter.source_id {
            Some(x) => Some(Uuid::try_from(x.clone()).map_err(|_e| {
                RpcDataConversionError::InvalidUuid("source id", x.clone().to_string())
            })?),
            None => None,
        };
        Ok(Self {
            volume_id,
            instance_id,
            machine_id,
            pool_id,
            cluster_id,
            source_id,
            boot_volumes: filter.boot_volumes,
            os_images: filter.os_images,
            exclude_snapshots: filter.exclude_snapshots,
        })
    }
}

impl TryFrom<StorageVolume> for rpc::forge::StorageVolume {
    type Error = RpcDataConversionError;
    fn try_from(vol: StorageVolume) -> Result<Self, Self::Error> {
        let nvmesh_uuid = rpc::Uuid::from(vol.nvmesh_uuid);
        let mut instance_id: Vec<rpc::Uuid> = Vec::new();
        for i in vol.instance_id.iter() {
            let id = rpc::Uuid::from(*i);
            instance_id.push(id);
        }
        let mut dpu_machine_id: Vec<rpc::MachineId> = Vec::new();
        for dpu in vol.dpu_machine_id.iter() {
            let dpu_id = rpc::MachineId::from(dpu.to_string());
            dpu_machine_id.push(dpu_id);
        }
        Ok(Self {
            nvmesh_uuid: Some(nvmesh_uuid),
            attributes: Some(rpc::forge::StorageVolumeAttributes::try_from(
                vol.attributes,
            )?),
            status: Some(rpc::forge::StorageVolumeStatus::try_from(vol.status)?),
            instance_id,
            dpu_machine_id,
            created_at: vol.created_at,
            modified_at: vol.modified_at,
        })
    }
}

impl TryFrom<rpc::forge::StorageVolume> for StorageVolume {
    type Error = RpcDataConversionError;
    fn try_from(vol: rpc::forge::StorageVolume) -> Result<Self, Self::Error> {
        if vol.attributes.is_none() {
            return Err(RpcDataConversionError::MissingArgument("volume attributes"));
        }
        if vol.status.is_none() {
            return Err(RpcDataConversionError::MissingArgument("volume status"));
        }
        let nvmesh_uuid = match vol.nvmesh_uuid {
            Some(x) => Uuid::try_from(x.clone()).map_err(|_e| {
                RpcDataConversionError::InvalidUuid("nvmesh uuid", x.clone().to_string())
            })?,
            None => {
                return Err(RpcDataConversionError::InvalidValue(
                    "nvmesh_uuid".to_string(),
                    "none".to_string(),
                ))
            }
        };
        let mut instance_id: Vec<Uuid> = Vec::new();
        for i in vol.instance_id.iter() {
            let id = Uuid::try_from(i.clone())
                .map_err(|_e| RpcDataConversionError::InvalidInstanceId(i.to_string()))?;
            instance_id.push(id);
        }
        let mut dpu_machine_id: Vec<MachineId> = Vec::new();
        for dpu in vol.dpu_machine_id.iter() {
            let dpu_id = MachineId::from_str(dpu.to_string().as_str())
                .map_err(|_e| RpcDataConversionError::InvalidMachineId(dpu.to_string()))?;
            dpu_machine_id.push(dpu_id);
        }
        Ok(Self {
            nvmesh_uuid,
            attributes: StorageVolumeAttributes::try_from(vol.attributes.unwrap())?,
            status: StorageVolumeStatus::try_from(vol.status.unwrap())?,
            instance_id,
            dpu_machine_id,
            created_at: vol.created_at,
            modified_at: vol.modified_at,
        })
    }
}

impl TryFrom<OsImageAttributes> for rpc::forge::OsImageAttributes {
    type Error = RpcDataConversionError;
    fn try_from(image_attrs: OsImageAttributes) -> Result<Self, Self::Error> {
        let id = rpc::Uuid::from(image_attrs.id);
        Ok(Self {
            id: Some(id),
            source_url: image_attrs.source_url,
            digest: image_attrs.digest,
            tenant_organization_id: image_attrs.tenant_organization_id.to_string(),
            create_volume: image_attrs.create_volume,
            name: image_attrs.name,
            description: image_attrs.description,
            auth_type: image_attrs.auth_type,
            auth_token: image_attrs.auth_token,
            rootfs_id: image_attrs.rootfs_id,
            rootfs_label: image_attrs.rootfs_label,
            boot_disk: image_attrs.boot_disk,
            capacity: image_attrs.capacity,
        })
    }
}

impl TryFrom<rpc::forge::OsImageAttributes> for OsImageAttributes {
    type Error = RpcDataConversionError;
    fn try_from(image_attrs: rpc::forge::OsImageAttributes) -> Result<Self, Self::Error> {
        if image_attrs.id.is_none() {
            return Err(RpcDataConversionError::MissingArgument("image id"));
        }
        let id = Uuid::try_from(image_attrs.id.clone().unwrap()).map_err(|_e| {
            RpcDataConversionError::InvalidUuid("os image id", image_attrs.id.unwrap().to_string())
        })?;
        Ok(Self {
            id,
            source_url: image_attrs.source_url,
            digest: image_attrs.digest,
            tenant_organization_id: TenantOrganizationId::try_from(
                image_attrs.tenant_organization_id,
            )
            .map_err(|e| {
                RpcDataConversionError::InvalidValue(
                    "tenant_organization_id".to_string(),
                    e.to_string(),
                )
            })?,
            create_volume: image_attrs.create_volume,
            name: image_attrs.name,
            description: image_attrs.description,
            auth_type: image_attrs.auth_type,
            auth_token: image_attrs.auth_token,
            rootfs_id: image_attrs.rootfs_id,
            rootfs_label: image_attrs.rootfs_label,
            boot_disk: image_attrs.boot_disk,
            capacity: image_attrs.capacity,
        })
    }
}

impl TryFrom<OsImageStatus> for rpc::forge::OsImageStatus {
    type Error = RpcDataConversionError;
    fn try_from(value: OsImageStatus) -> Result<Self, Self::Error> {
        match value {
            OsImageStatus::Uninitialized => Ok(rpc::forge::OsImageStatus::ImageUninitialized),
            OsImageStatus::InProgress => Ok(rpc::forge::OsImageStatus::ImageInProgress),
            OsImageStatus::Failed => Ok(rpc::forge::OsImageStatus::ImageFailed),
            OsImageStatus::Ready => Ok(rpc::forge::OsImageStatus::ImageReady),
            OsImageStatus::Disabled => Ok(rpc::forge::OsImageStatus::ImageDisabled),
        }
    }
}

impl FromStr for OsImageStatus {
    type Err = RpcDataConversionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Uninitialized" => Ok(OsImageStatus::Uninitialized),
            "InProgress" => Ok(OsImageStatus::InProgress),
            "Failed" => Ok(OsImageStatus::Failed),
            "Ready" => Ok(OsImageStatus::Ready),
            "Disabled" => Ok(OsImageStatus::Disabled),
            _ => Err(RpcDataConversionError::InvalidValue(
                "OsImageStatus".to_string(),
                s.to_string(),
            )),
        }
    }
}

impl TryFrom<OsImage> for rpc::forge::OsImage {
    type Error = RpcDataConversionError;
    fn try_from(image: OsImage) -> Result<Self, Self::Error> {
        let volume_id = image.volume_id.map(rpc::Uuid::from);
        Ok(Self {
            attributes: Some(rpc::forge::OsImageAttributes::try_from(image.attributes)?),
            status: rpc::forge::OsImageStatus::try_from(image.status)? as i32,
            status_message: image.status_message,
            volume_id,
            created_at: image.created_at,
            modified_at: image.modified_at,
        })
    }
}
