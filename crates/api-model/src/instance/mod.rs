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
use crate::metadata::{LabelFilter, Metadata};

pub mod config;
pub mod snapshot;
pub mod status;

#[derive(Clone, Debug, Default)]
pub struct InstanceSearchFilter {
    pub label: Option<LabelFilter>,
    pub tenant_org_id: Option<String>,
    pub vpc_id: Option<String>,
    pub instance_type_id: Option<String>,
}

impl From<rpc::forge::InstanceSearchFilter> for InstanceSearchFilter {
    fn from(filter: rpc::forge::InstanceSearchFilter) -> Self {
        InstanceSearchFilter {
            label: filter.label.map(LabelFilter::from),
            tenant_org_id: filter.tenant_org_id,
            vpc_id: filter.vpc_id,
            instance_type_id: filter.instance_type_id,
        }
    }
}

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

#[cfg(test)]
mod tests {
    use rpc::forge as rpc_forge;

    use super::*;

    #[test]
    fn instance_search_filter_from_rpc_all_fields() {
        let rpc_filter = rpc_forge::InstanceSearchFilter {
            label: Some(rpc_forge::Label {
                key: "env".to_string(),
                value: Some("staging".to_string()),
            }),
            tenant_org_id: Some("org-456".to_string()),
            vpc_id: Some("vpc-789".to_string()),
            instance_type_id: Some("type-abc".to_string()),
        };
        let filter = InstanceSearchFilter::from(rpc_filter);
        let label = filter.label.unwrap();
        assert_eq!(label.key, "env");
        assert_eq!(label.value, Some("staging".to_string()));
        assert_eq!(filter.tenant_org_id, Some("org-456".to_string()));
        assert_eq!(filter.vpc_id, Some("vpc-789".to_string()));
        assert_eq!(filter.instance_type_id, Some("type-abc".to_string()));
    }

    #[test]
    fn instance_search_filter_from_rpc_no_fields() {
        let rpc_filter = rpc_forge::InstanceSearchFilter {
            label: None,
            tenant_org_id: None,
            vpc_id: None,
            instance_type_id: None,
        };
        let filter = InstanceSearchFilter::from(rpc_filter);
        assert!(filter.label.is_none());
        assert!(filter.tenant_org_id.is_none());
        assert!(filter.vpc_id.is_none());
        assert!(filter.instance_type_id.is_none());
    }
}
