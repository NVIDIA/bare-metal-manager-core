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
pub mod capability;

use std::collections::HashMap;
use std::net::IpAddr;

pub use capability::{
    ALL_VPC_VIRTUALIZATION_TYPES, DataPlaneKind, FabricInterfaceType, VpcCapabilities,
    VpcCapabilityError, VpcVirtualizationTypeCapabilities,
};
use carbide_network::virtualization::VpcVirtualizationType;
use carbide_uuid::machine::MachineId;
use carbide_uuid::network_security_group::NetworkSecurityGroupId;
use carbide_uuid::nvlink::NvLinkLogicalPartitionId;
use carbide_uuid::vpc::VpcId;
use carbide_uuid::vpc_peering::VpcPeeringId;
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::metadata::{LabelFilter, Metadata};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VpcConfig {
    pub tenant_organization_id: String,
    pub tenant_keyset_id: Option<String>,
    pub network_virtualization_type: VpcVirtualizationType,
    pub network_security_group_id: Option<NetworkSecurityGroupId>,
    pub default_nvlink_logical_partition_id: Option<NvLinkLogicalPartitionId>,
    pub vni: Option<i32>,
    pub routing_profile_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct VpcStatus {
    /// Allocated VNI.
    pub vni: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vpc {
    pub id: VpcId,
    pub version: ConfigVersion,
    pub config: VpcConfig,
    pub status: VpcStatus,
    pub metadata: Metadata,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct VpcDefinition {
    pub organization_id: Option<String>,
    pub network_virtualization_type: VpcVirtualizationType,
    pub routing_profile_type: Option<String>,
    pub vni: Option<i32>,
}

#[derive(Clone, Debug, Default)]
pub struct VpcSearchFilter {
    pub name: Option<String>,
    pub tenant_org_id: Option<String>,
    pub label: Option<LabelFilter>,
}

#[derive(Clone, Debug)]
pub struct NewVpc {
    pub id: VpcId,
    pub tenant_organization_id: String,
    pub network_virtualization_type: VpcVirtualizationType,
    pub metadata: Metadata,
    pub network_security_group_id: Option<NetworkSecurityGroupId>,
    pub routing_profile_type: Option<String>,
    pub vni: Option<i32>,
}

#[derive(Clone, Debug)]
pub struct UpdateVpc {
    pub id: VpcId,
    pub network_security_group_id: Option<NetworkSecurityGroupId>,
    pub if_version_match: Option<ConfigVersion>,
    pub metadata: Metadata,
}

/// UpdateVpcVirtualization exists as a mechanism to translate
/// an incoming VpcUpdateVirtualizationRequest and turn it
/// into something we can `update()` to the database.
#[derive(Clone, Debug)]
pub struct UpdateVpcVirtualization {
    pub id: VpcId,
    pub if_version_match: Option<ConfigVersion>,
    pub network_virtualization_type: VpcVirtualizationType,
}

impl<'r> sqlx::FromRow<'r, PgRow> for Vpc {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let vpc_labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("labels")?;

        let metadata = Metadata {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            labels: vpc_labels.0,
        };

        let status: sqlx::types::Json<VpcStatus> = row.try_get("status")?;

        Ok(Vpc {
            id: row.try_get("id")?,
            version: row.try_get("version")?,
            config: VpcConfig {
                tenant_organization_id: row.try_get("organization_id")?,
                tenant_keyset_id: None, // TODO: fix this once DB gets updated
                network_security_group_id: row.try_get("network_security_group_id")?,
                network_virtualization_type: row.try_get("network_virtualization_type")?,
                routing_profile_type: row.try_get("routing_profile_type")?,
                vni: row.try_get("vni")?,
                default_nvlink_logical_partition_id: None,
            },
            status: status.0,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
            metadata,
        })
    }
}

#[derive(Clone, Debug, FromRow)]
pub struct VpcDpuLoopback {
    pub dpu_id: MachineId,
    pub vpc_id: VpcId,
    pub loopback_ip: IpAddr,
}

impl VpcDpuLoopback {
    pub fn new(dpu_id: MachineId, vpc_id: VpcId, loopback_ip: IpAddr) -> Self {
        Self {
            dpu_id,
            vpc_id,
            loopback_ip,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VpcPeering {
    pub id: VpcPeeringId,
    pub vpc_id: VpcId,
    pub peer_vpc_id: VpcId,
}

impl<'r> FromRow<'r, PgRow> for VpcPeering {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(VpcPeering {
            id: row.try_get("id")?,
            vpc_id: row.try_get("vpc1_id")?,
            peer_vpc_id: row.try_get("vpc2_id")?,
        })
    }
}
