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

use carbide_network::virtualization::DEFAULT_NETWORK_VIRTUALIZATION_TYPE;
use carbide_utils::none_if_empty::NoneIfEmpty;
use carbide_uuid::network_security_group::NetworkSecurityGroupIdParseError;
use config_version::ConfigVersion;
use model::metadata::{LabelFilter, Metadata};
use model::vpc::{
    NewVpc, UpdateVpc, UpdateVpcVirtualization, Vpc, VpcPeering, VpcSearchFilter, VpcStatus,
};

use crate as rpc;
use crate::errors::RpcDataConversionError;

impl From<rpc::forge::VpcSearchFilter> for VpcSearchFilter {
    fn from(filter: rpc::forge::VpcSearchFilter) -> Self {
        VpcSearchFilter {
            name: filter.name,
            tenant_org_id: filter.tenant_org_id,
            label: filter.label.map(LabelFilter::from),
        }
    }
}

#[allow(deprecated)]
impl From<Vpc> for rpc::forge::Vpc {
    fn from(src: Vpc) -> Self {
        let allocated_vni = src.status.vni.map(|v| v as u32);
        let desired_vni = src.config.vni.map(|v| v as u32);
        let virt_type =
            rpc::forge::VpcVirtualizationType::from(src.config.network_virtualization_type) as i32;
        let nsg_id = src
            .config
            .network_security_group_id
            .map(|nsg_id| nsg_id.to_string());
        let metadata = Some(rpc::Metadata {
            name: src.metadata.name,
            description: src.metadata.description,
            labels: src
                .metadata
                .labels
                .iter()
                .map(|(key, value)| rpc::forge::Label {
                    key: key.clone(),
                    value: value.clone().none_if_empty(),
                })
                .collect(),
        });

        rpc::forge::Vpc {
            id: Some(src.id),
            version: src.version.version_string(),
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
            metadata,

            config: Some(rpc::forge::VpcConfig {
                tenant_organization_id: src.config.tenant_organization_id.clone(),
                tenant_keyset_id: src.config.tenant_keyset_id.clone(),
                network_virtualization_type: Some(virt_type),
                network_security_group_id: nsg_id.clone(),
                default_nvlink_logical_partition_id: src.config.default_nvlink_logical_partition_id,
                vni: desired_vni,
                routing_profile_type: src.config.routing_profile_type.clone(),
            }),
            status: Some(rpc::forge::VpcStatus::from(src.status)),

            // Deprecated flat fields - populated for external client compatibility.
            // Remove after rest component use VpcConfig/VpcStatus
            tenant_organization_id: src.config.tenant_organization_id,
            tenant_keyset_id: src.config.tenant_keyset_id,
            deprecated_vni: allocated_vni,
            vni: desired_vni,
            network_virtualization_type: Some(virt_type),
            network_security_group_id: nsg_id,
            default_nvlink_logical_partition_id: src.config.default_nvlink_logical_partition_id,
            routing_profile_type: src.config.routing_profile_type,
        }
    }
}

impl From<VpcStatus> for rpc::forge::VpcStatus {
    fn from(src: VpcStatus) -> Self {
        rpc::forge::VpcStatus {
            // This is the pattern we have elsewhere because a VNI should never be negative.
            vni: src.vni.map(|x| x as u32),
        }
    }
}

impl TryFrom<rpc::forge::VpcCreationRequest> for NewVpc {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::VpcCreationRequest) -> Result<Self, Self::Error> {
        let virt_type = match value.network_virtualization_type {
            None => DEFAULT_NETWORK_VIRTUALIZATION_TYPE,
            Some(v) => rpc::network::vpc_virtualization_type_try_from_rpc(v)?,
        };
        let id = value.id.unwrap_or_else(|| uuid::Uuid::new_v4().into());

        let metadata = match value.metadata {
            Some(metadata) => metadata.try_into()?,
            None => Metadata::new_with_default_name(),
        };

        metadata.validate(true).map_err(|e| {
            RpcDataConversionError::InvalidArgument(format!("VPC metadata is not valid: {e}"))
        })?;

        Ok(NewVpc {
            id,
            tenant_organization_id: value.tenant_organization_id,
            vni: value.vni.map(|v| v.try_into()).transpose().map_err(
                |e: std::num::TryFromIntError| {
                    RpcDataConversionError::InvalidValue(
                        format!(
                            "`{}` cannot be converted to VNI",
                            value.vni.unwrap_or_default()
                        ),
                        e.to_string(),
                    )
                },
            )?,
            network_security_group_id: value
                .network_security_group_id
                .map(|nsg_id| nsg_id.parse())
                .transpose()
                .map_err(|e: NetworkSecurityGroupIdParseError| {
                    RpcDataConversionError::InvalidNetworkSecurityGroupId(e.value())
                })?,
            routing_profile_type: None,
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

        let metadata = match value.metadata {
            Some(metadata) => metadata.try_into()?,
            None => Metadata::new_with_default_name(),
        };

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
            Some(v) => rpc::network::vpc_virtualization_type_try_from_rpc(v)?,
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

#[cfg(test)]
mod tests {
    use carbide_network::virtualization::VpcVirtualizationType;
    use carbide_test_support::value_scenarios;
    use carbide_uuid::vpc::VpcId;
    use model::vpc::VpcConfig;

    use super::*;

    fn sample_vpc() -> Vpc {
        Vpc {
            id: VpcId::from(uuid::Uuid::new_v4()),
            version: ConfigVersion::initial(),
            config: VpcConfig {
                tenant_organization_id: "tenant-1".to_string(),
                tenant_keyset_id: Some("keyset-1".to_string()),
                network_virtualization_type: VpcVirtualizationType::Fnn,
                network_security_group_id: None,
                default_nvlink_logical_partition_id: None,
                vni: Some(42),
                routing_profile_type: Some("EXTERNAL".to_string()),
            },
            status: VpcStatus { vni: Some(100) },
            metadata: Metadata::new_with_default_name(),
            created: chrono::Utc::now(),
            updated: chrono::Utc::now(),
            deleted: None,
        }
    }

    #[test]
    #[allow(deprecated)]
    fn vpc_to_rpc_populates_structured_and_deprecated_flat_fields() {
        let vpc = sample_vpc();
        let rpc_vpc = rpc::forge::Vpc::from(vpc);

        let config = rpc_vpc.config.as_ref().expect("config must be set");
        assert_eq!(config.tenant_organization_id, "tenant-1");
        assert_eq!(config.tenant_keyset_id.as_deref(), Some("keyset-1"));
        assert_eq!(config.vni, Some(42));
        assert_eq!(config.routing_profile_type.as_deref(), Some("EXTERNAL"));
        assert_eq!(
            config.network_virtualization_type,
            Some(rpc::forge::VpcVirtualizationType::Fnn as i32)
        );

        let status = rpc_vpc.status.as_ref().expect("status must be set");
        assert_eq!(status.vni, Some(100));

        assert_eq!(rpc_vpc.tenant_organization_id, "tenant-1");
        assert_eq!(rpc_vpc.tenant_keyset_id.as_deref(), Some("keyset-1"));
        assert_eq!(rpc_vpc.vni, Some(42));
        assert_eq!(rpc_vpc.deprecated_vni, Some(100));
        assert_eq!(rpc_vpc.routing_profile_type.as_deref(), Some("EXTERNAL"));
        assert_eq!(
            rpc_vpc.network_virtualization_type,
            Some(rpc::forge::VpcVirtualizationType::Fnn as i32)
        );
        assert_eq!(status.vni, rpc_vpc.deprecated_vni);
    }

    // `VpcSearchFilter::from` is a total conversion, so we project its output to
    // the fields the originals asserted: name, tenant_org_id, and the label as its
    // (key, value) pair (None when no label is present).
    #[test]
    fn vpc_search_filter_from_rpc() {
        type Projected = (
            Option<String>,
            Option<String>,
            Option<(String, Option<String>)>,
        );

        value_scenarios!(
            run = |rpc_filter| {
                let filter = VpcSearchFilter::from(rpc_filter);
                let projected: Projected = (
                    filter.name,
                    filter.tenant_org_id,
                    filter.label.map(|l| (l.key, l.value)),
                );
                projected
            };
            "all fields populated" {
                rpc::forge::VpcSearchFilter {
                    name: Some("my-vpc".to_string()),
                    tenant_org_id: Some("org-123".to_string()),
                    label: Some(rpc::forge::Label {
                        key: "env".to_string(),
                        value: Some("prod".to_string()),
                    }),
                } => (
                    Some("my-vpc".to_string()),
                    Some("org-123".to_string()),
                    Some(("env".to_string(), Some("prod".to_string()))),
                ),
            }

            "no fields" {
                rpc::forge::VpcSearchFilter {
                    name: None,
                    tenant_org_id: None,
                    label: None,
                } => (None, None, None),
            }

            "label key only" {
                rpc::forge::VpcSearchFilter {
                    name: None,
                    tenant_org_id: None,
                    label: Some(rpc::forge::Label {
                        key: "team".to_string(),
                        value: None,
                    }),
                } => (None, None, Some(("team".to_string(), None))),
            }
        );
    }
}
