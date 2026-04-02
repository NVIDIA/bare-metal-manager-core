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

use config_version::ConfigVersion;
use nico_rpc::forge;
use nico_uuid::instance::InstanceId;
use nico_uuid::machine::MachineId;

// Represents Instance returned via RPC call.
// Adds some widely used helpers.
#[derive(Debug, PartialEq)]
pub struct RpcInstance(forge::Instance);

impl RpcInstance {
    pub fn new(v: forge::Instance) -> Self {
        Self(v)
    }

    pub fn id(&self) -> InstanceId {
        self.0.id.unwrap()
    }

    pub fn machine_id(&self) -> MachineId {
        self.0.machine_id.unwrap()
    }

    pub fn rpc_id(&self) -> Option<InstanceId> {
        self.0.id
    }

    pub fn inner(&self) -> &forge::Instance {
        &self.0
    }

    pub fn into_inner(self) -> forge::Instance {
        self.0
    }

    pub fn status(&self) -> RpcInstanceStatus<'_> {
        RpcInstanceStatus::new(self.0.status.as_ref().unwrap())
    }

    pub fn config(&self) -> RpcInstanceConfig<'_> {
        RpcInstanceConfig::new(self.0.config.as_ref().unwrap())
    }

    pub fn config_version(&self) -> ConfigVersion {
        self.0.config_version.parse::<ConfigVersion>().unwrap()
    }

    pub fn ib_config_version(&self) -> ConfigVersion {
        self.0.ib_config_version.parse::<ConfigVersion>().unwrap()
    }

    pub fn network_config_version(&self) -> ConfigVersion {
        self.0
            .network_config_version
            .parse::<ConfigVersion>()
            .unwrap()
    }

    pub fn metadata(&self) -> &forge::Metadata {
        self.0.metadata.as_ref().unwrap()
    }
}

pub struct RpcInstanceStatus<'a>(&'a forge::InstanceStatus);

impl<'a> RpcInstanceStatus<'a> {
    pub fn new(v: &'a forge::InstanceStatus) -> Self {
        Self(v)
    }

    pub fn inner(&self) -> &forge::InstanceStatus {
        self.0
    }

    pub fn tenant(&self) -> forge::TenantState {
        self.0.tenant.as_ref().unwrap().state()
    }

    pub fn network(&self) -> &'a forge::InstanceNetworkStatus {
        self.0.network.as_ref().unwrap()
    }

    pub fn infiniband(&self) -> &'a forge::InstanceInfinibandStatus {
        self.0.infiniband.as_ref().unwrap()
    }

    pub fn configs_synced(&self) -> forge::SyncState {
        self.0.configs_synced()
    }
}

pub struct RpcInstanceConfig<'a>(&'a forge::InstanceConfig);

impl<'a> RpcInstanceConfig<'a> {
    pub fn new(v: &'a forge::InstanceConfig) -> Self {
        Self(v)
    }

    pub fn inner(&self) -> &'a forge::InstanceConfig {
        self.0
    }

    pub fn tenant(&self) -> &'a forge::TenantConfig {
        self.0.tenant.as_ref().unwrap()
    }

    pub fn os(&self) -> &'a forge::OperatingSystem {
        self.0.os.as_ref().unwrap()
    }

    pub fn network(&self) -> &'a forge::InstanceNetworkConfig {
        self.0.network.as_ref().unwrap()
    }

    pub fn infiniband(&self) -> &'a forge::InstanceInfinibandConfig {
        self.0.infiniband.as_ref().unwrap()
    }
}
