/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use carbide_uuid::instance::InstanceId;
use carbide_uuid::instance_type::InstanceTypeId;
use carbide_uuid::machine::MachineId;
use config_version::ConfigVersion;
use rpc::errors::RpcDataConversionError;

use crate::instance::config::InstanceConfig;
use crate::metadata::Metadata;

pub mod config;
pub mod snapshot;
pub mod status;

pub enum InstanceNetworkSyncStatus {
    InstanceNetworkObservationNotAvailable(Vec<MachineId>),
    ZeroDpuNoObservationNeeded,
    InstanceNetworkSynced,
    InstanceNetworkNotSynced(Vec<MachineId>),
}

pub struct NewInstance<'a> {
    pub instance_id: InstanceId,
    pub machine_id: MachineId,
    pub instance_type_id: Option<InstanceTypeId>,
    pub config: &'a InstanceConfig,
    pub metadata: Metadata,
    pub config_version: ConfigVersion,
    pub network_config_version: ConfigVersion,
    pub ib_config_version: ConfigVersion,
    pub extension_services_config_version: ConfigVersion,
    pub nvlink_config_version: ConfigVersion,
}

pub struct DeleteInstance {
    pub instance_id: InstanceId,
    pub issue: Option<rpc::forge::Issue>,
    pub is_repair_tenant: Option<bool>,
}

impl TryFrom<rpc::InstanceReleaseRequest> for DeleteInstance {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::InstanceReleaseRequest) -> Result<Self, Self::Error> {
        let instance_id = value
            .id
            .ok_or(RpcDataConversionError::MissingArgument("id"))?;
        Ok(DeleteInstance {
            instance_id,
            issue: value.issue,
            is_repair_tenant: value.is_repair_tenant,
        })
    }
}
