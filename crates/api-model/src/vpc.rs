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
use std::collections::HashMap;
use std::net::IpAddr;

use carbide_uuid::machine::MachineId;
use carbide_uuid::network_security_group::{
    NetworkSecurityGroupId, NetworkSecurityGroupIdParseError,
};
use carbide_uuid::vpc::VpcId;
use carbide_uuid::vpc_peering::VpcPeeringId;
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use forge_network::virtualization::{DEFAULT_NETWORK_VIRTUALIZATION_TYPE, VpcVirtualizationType};
use rpc::errors::RpcDataConversionError;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::metadata::Metadata;
use crate::tenant::RoutingProfileType;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vpc {
    pub id: VpcId,
    pub tenant_organization_id: String,
    pub network_security_group_id: Option<NetworkSecurityGroupId>,
    pub version: ConfigVersion,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub tenant_keyset_id: Option<String>,
    pub network_virtualization_type: VpcVirtualizationType,
    pub routing_profile_type: Option<RoutingProfileType>,
    // Option because we can't allocate it until DB generates an id for us
    pub vni: Option<i32>,
    pub dpa_vni: Option<i32>,
    pub metadata: Metadata,
}

#[derive(Clone, Debug)]
pub struct NewVpc {
    pub id: VpcId,
    pub tenant_organization_id: String,
    pub network_virtualization_type: VpcVirtualizationType,
    pub metadata: Metadata,
    pub network_security_group_id: Option<NetworkSecurityGroupId>,
    pub routing_profile_type: Option<RoutingProfileType>,
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

        let routing_profile_type: Option<String> = row.try_get("routing_profile_type")?;

        // TODO(chet): Once `tenant_keyset_id` is taken care of,
        // this entire FromRow implementation can go away with a
        // rename of `tenant_organization_id` to match (or just
        // a rename of the `organization_id` column).
        Ok(Vpc {
            id: row.try_get("id")?,
            version: row.try_get("version")?,
            tenant_organization_id: row.try_get("organization_id")?,
            network_security_group_id: row.try_get("network_security_group_id")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
            tenant_keyset_id: None, //TODO: fix this once DB gets updated
            network_virtualization_type: row.try_get("network_virtualization_type")?,
            routing_profile_type: routing_profile_type
                .map(|p| p.parse::<RoutingProfileType>())
                .transpose()
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            vni: row.try_get("vni")?,
            dpa_vni: row.try_get("dpa_vni")?,
            metadata,
        })
    }
}

impl From<Vpc> for rpc::forge::Vpc {
    fn from(src: Vpc) -> Self {
        rpc::forge::Vpc {
            id: Some(src.id),
            version: src.version.version_string(),
            name: src.metadata.name.clone(),
            tenant_organization_id: src.tenant_organization_id,
            network_security_group_id: src
                .network_security_group_id
                .map(|nsg_id| nsg_id.to_string()),
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
            tenant_keyset_id: src.tenant_keyset_id,
            vni: src.vni.map(|x| x as u32),
            dpa_vni: src.dpa_vni.map(|x| x as u32),
            network_virtualization_type: Some(
                rpc::forge::VpcVirtualizationType::from(src.network_virtualization_type).into(),
            ),
            metadata: {
                Some(rpc::Metadata {
                    name: src.metadata.name,
                    description: src.metadata.description,
                    labels: src
                        .metadata
                        .labels
                        .iter()
                        .map(|(key, value)| rpc::forge::Label {
                            key: key.clone(),
                            value: if value.clone().is_empty() {
                                None
                            } else {
                                Some(value.clone())
                            },
                        })
                        .collect(),
                })
            },
            default_nvlink_logical_partition_id: None,
        }
    }
}

impl TryFrom<rpc::forge::VpcCreationRequest> for NewVpc {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::VpcCreationRequest) -> Result<Self, Self::Error> {
        let virt_type = match value.network_virtualization_type {
            None => DEFAULT_NETWORK_VIRTUALIZATION_TYPE,
            Some(v) => v.try_into()?,
        };
        let id = value.id.unwrap_or_else(|| uuid::Uuid::new_v4().into());

        // If Metadata isn't passed or empty, then use the old name field
        let use_legacy_name = if let Some(metadata) = &value.metadata {
            metadata.name.is_empty()
        } else {
            true
        };

        let mut metadata = match value.metadata {
            Some(metadata) => metadata.try_into()?,
            None => Metadata::new_with_default_name(),
        };
        if use_legacy_name {
            metadata.name = value.name;
        }

        metadata.validate(true).map_err(|e| {
            RpcDataConversionError::InvalidArgument(format!("VPC metadata is not valid: {e}"))
        })?;

        Ok(NewVpc {
            id,
            tenant_organization_id: value.tenant_organization_id,
            network_security_group_id: value
                .network_security_group_id
                .map(|nsg_id| nsg_id.parse())
                .transpose()
                .map_err(|e: NetworkSecurityGroupIdParseError| {
                    RpcDataConversionError::InvalidNetworkSecurityGroupId(e.value())
                })?,
            routing_profile_type: Some(RoutingProfileType::External),
            network_virtualization_type: virt_type,
            metadata,
        })
    }
}

impl TryFrom<rpc::forge::VpcUpdateRequest> for UpdateVpc {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::VpcUpdateRequest) -> Result<Self, Self::Error> {
        let if_version_match: Option<ConfigVersion> =
            match &value.if_version_match {
                Some(version) => Some(version.parse::<ConfigVersion>().map_err(|_| {
                    RpcDataConversionError::InvalidConfigVersion(version.to_string())
                })?),
                None => None,
            };

        // If Metadata isn't passed or empty, then use the old name field
        let use_legacy_name = if let Some(metadata) = &value.metadata {
            metadata.name.is_empty()
        } else {
            true
        };

        let mut metadata = match value.metadata {
            Some(metadata) => metadata.try_into()?,
            None => Metadata::new_with_default_name(),
        };
        if use_legacy_name {
            metadata.name = value.name;
        }

        metadata.validate(true).map_err(|e| {
            RpcDataConversionError::InvalidArgument(format!("VPC metadata is not valid: {e}"))
        })?;

        Ok(UpdateVpc {
            id: value
                .id
                .ok_or(RpcDataConversionError::MissingArgument("id"))?,
            network_security_group_id: value
                .network_security_group_id
                .map(|nsg_id| nsg_id.parse())
                .transpose()
                .map_err(|e: NetworkSecurityGroupIdParseError| {
                    RpcDataConversionError::InvalidNetworkSecurityGroupId(e.value())
                })?,
            if_version_match,
            metadata,
        })
    }
}

impl TryFrom<rpc::forge::VpcUpdateVirtualizationRequest> for UpdateVpcVirtualization {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::VpcUpdateVirtualizationRequest) -> Result<Self, Self::Error> {
        let if_version_match: Option<ConfigVersion> =
            match &value.if_version_match {
                Some(version) => Some(version.parse::<ConfigVersion>().map_err(|_| {
                    RpcDataConversionError::InvalidConfigVersion(version.to_string())
                })?),
                None => None,
            };

        let network_virtualization_type = match value.network_virtualization_type {
            Some(v) => v.try_into()?,
            None => {
                return Err(RpcDataConversionError::MissingArgument(
                    "network_virtualization_type",
                ));
            }
        };

        Ok(UpdateVpcVirtualization {
            id: value
                .id
                .ok_or(RpcDataConversionError::MissingArgument("id"))?,
            if_version_match,
            network_virtualization_type,
        })
    }
}

impl From<Vpc> for rpc::forge::VpcDeletionResult {
    fn from(_src: Vpc) -> Self {
        rpc::forge::VpcDeletionResult {}
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

impl From<VpcPeering> for rpc::forge::VpcPeering {
    fn from(db_vpc_peering: VpcPeering) -> Self {
        let VpcPeering {
            id,
            vpc_id,
            peer_vpc_id,
        } = db_vpc_peering;

        let id = Some(id);
        let vpc_id = Some(vpc_id);
        let peer_vpc_id = Some(peer_vpc_id);

        Self {
            id,
            vpc_id,
            peer_vpc_id,
        }
    }
}
