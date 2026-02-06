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
