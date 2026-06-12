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

impl From<Vpc> for rpc::forge::Vpc {
    fn from(src: Vpc) -> Self {
        rpc::forge::Vpc {
            id: Some(src.id),
            version: src.version.version_string(),
            tenant_organization_id: src.tenant_organization_id,
            network_security_group_id: src
                .network_security_group_id
                .map(|nsg_id| nsg_id.to_string()),
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
            tenant_keyset_id: src.tenant_keyset_id,
            deprecated_vni: src.status.as_ref().and_then(|x| x.vni.map(|v| v as u32)),
            vni: src.vni.map(|x| x as u32),
            network_virtualization_type: Some(
                rpc::forge::VpcVirtualizationType::from(src.network_virtualization_type).into(),
            ),
            status: src.status.map(rpc::forge::VpcStatus::from),
            routing_profile_type: src.routing_profile_type,
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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};
    use carbide_uuid::vpc::VpcId;
    use carbide_uuid::vpc_peering::VpcPeeringId;
    use chrono::{DateTime, Utc};

    use super::*;

    // A nil VpcId, handy for rows where the id's exact value is irrelevant.
    fn nil_vpc_id() -> VpcId {
        VpcId::from(uuid::Uuid::nil())
    }

    fn nil_peering_id() -> VpcPeeringId {
        VpcPeeringId::from(uuid::Uuid::nil())
    }

    fn epoch() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(0, 0).unwrap()
    }

    // A valid proto Metadata whose domain projection passes `validate(true)`:
    // its name is long enough and ASCII.
    fn valid_proto_metadata() -> rpc::Metadata {
        rpc::Metadata {
            name: "my-vpc".to_string(),
            description: String::new(),
            labels: vec![],
        }
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

        check_values(
            [
                Check {
                    scenario: "all fields populated",
                    input: rpc::forge::VpcSearchFilter {
                        name: Some("my-vpc".to_string()),
                        tenant_org_id: Some("org-123".to_string()),
                        label: Some(rpc::forge::Label {
                            key: "env".to_string(),
                            value: Some("prod".to_string()),
                        }),
                    },
                    expect: (
                        Some("my-vpc".to_string()),
                        Some("org-123".to_string()),
                        Some(("env".to_string(), Some("prod".to_string()))),
                    ),
                },
                Check {
                    scenario: "no fields",
                    input: rpc::forge::VpcSearchFilter {
                        name: None,
                        tenant_org_id: None,
                        label: None,
                    },
                    expect: (None, None, None),
                },
                Check {
                    scenario: "label key only",
                    input: rpc::forge::VpcSearchFilter {
                        name: None,
                        tenant_org_id: None,
                        label: Some(rpc::forge::Label {
                            key: "team".to_string(),
                            value: None,
                        }),
                    },
                    expect: (None, None, Some(("team".to_string(), None))),
                },
            ],
            |rpc_filter| {
                let filter = VpcSearchFilter::from(rpc_filter);
                let projected: Projected = (
                    filter.name,
                    filter.tenant_org_id,
                    filter.label.map(|l| (l.key, l.value)),
                );
                projected
            },
        );
    }

    // `VpcStatus::from` is total: the model's `Option<i32>` VNI becomes the proto's
    // `Option<u32>`, present-or-absent.
    #[test]
    fn vpc_status_into_rpc() {
        check_values(
            [
                Check {
                    scenario: "vni present",
                    input: VpcStatus { vni: Some(4242) },
                    expect: Some(4242u32),
                },
                Check {
                    scenario: "vni absent",
                    input: VpcStatus { vni: None },
                    expect: None,
                },
            ],
            |status| rpc::forge::VpcStatus::from(status).vni,
        );
    }

    // `From<Vpc> for rpc::forge::Vpc` is total. Project the fields the conversion
    // actually computes so each row can pin one variant of every optional/derived
    // field.
    #[derive(Debug, PartialEq)]
    struct ProjectedVpc {
        version: String,
        nsg: Option<String>,
        deleted_present: bool,
        deprecated_vni: Option<u32>,
        vni: Option<u32>,
        virt_type: Option<i32>,
        status_vni: Option<u32>,
        routing_profile_type: Option<String>,
        metadata_name: String,
        labels: Vec<(String, Option<String>)>,
    }

    // A fixed, deterministic version so a row's expected `version_string()` matches
    // the converted value byte-for-byte; the real `initial()` constructor stamps `now()`.
    fn fixed_version() -> ConfigVersion {
        use std::str::FromStr;
        ConfigVersion::from_str("V1-T1700000000000000").unwrap()
    }

    fn base_vpc() -> Vpc {
        Vpc {
            id: nil_vpc_id(),
            tenant_organization_id: "org".to_string(),
            network_security_group_id: None,
            version: fixed_version(),
            created: epoch(),
            updated: epoch(),
            deleted: None,
            tenant_keyset_id: None,
            network_virtualization_type:
                carbide_network::virtualization::VpcVirtualizationType::EthernetVirtualizer,
            routing_profile_type: None,
            vni: None,
            metadata: Metadata::new_with_default_name(),
            status: None,
        }
    }

    #[test]
    fn vpc_into_rpc() {
        let ethernet = rpc::forge::VpcVirtualizationType::EthernetVirtualizer as i32;
        let flat = rpc::forge::VpcVirtualizationType::Flat as i32;
        let fnn = rpc::forge::VpcVirtualizationType::Fnn as i32;

        check_values(
            [
                Check {
                    scenario: "minimal vpc, all optionals absent",
                    input: base_vpc(),
                    expect: ProjectedVpc {
                        version: fixed_version().version_string(),
                        nsg: None,
                        deleted_present: false,
                        deprecated_vni: None,
                        vni: None,
                        virt_type: Some(ethernet),
                        status_vni: None,
                        routing_profile_type: None,
                        metadata_name: "default_name".to_string(),
                        labels: vec![],
                    },
                },
                Check {
                    scenario: "nsg present, deleted present",
                    input: Vpc {
                        network_security_group_id: Some("nsg-1".parse().unwrap()),
                        deleted: Some(epoch()),
                        ..base_vpc()
                    },
                    expect: ProjectedVpc {
                        version: fixed_version().version_string(),
                        nsg: Some("nsg-1".to_string()),
                        deleted_present: true,
                        deprecated_vni: None,
                        vni: None,
                        virt_type: Some(ethernet),
                        status_vni: None,
                        routing_profile_type: None,
                        metadata_name: "default_name".to_string(),
                        labels: vec![],
                    },
                },
                Check {
                    scenario: "explicit vni and status vni populate both fields",
                    input: Vpc {
                        vni: Some(7),
                        status: Some(VpcStatus { vni: Some(7) }),
                        ..base_vpc()
                    },
                    expect: ProjectedVpc {
                        version: fixed_version().version_string(),
                        nsg: None,
                        deleted_present: false,
                        // deprecated_vni is sourced from status.vni.
                        deprecated_vni: Some(7),
                        vni: Some(7),
                        virt_type: Some(ethernet),
                        status_vni: Some(7),
                        routing_profile_type: None,
                        metadata_name: "default_name".to_string(),
                        labels: vec![],
                    },
                },
                Check {
                    scenario: "status present but vni unset leaves deprecated_vni None",
                    input: Vpc {
                        status: Some(VpcStatus { vni: None }),
                        ..base_vpc()
                    },
                    expect: ProjectedVpc {
                        version: fixed_version().version_string(),
                        nsg: None,
                        deleted_present: false,
                        deprecated_vni: None,
                        vni: None,
                        virt_type: Some(ethernet),
                        status_vni: None,
                        routing_profile_type: None,
                        metadata_name: "default_name".to_string(),
                        labels: vec![],
                    },
                },
                Check {
                    scenario: "flat virtualization type",
                    input: Vpc {
                        network_virtualization_type:
                            carbide_network::virtualization::VpcVirtualizationType::Flat,
                        ..base_vpc()
                    },
                    expect: ProjectedVpc {
                        version: fixed_version().version_string(),
                        nsg: None,
                        deleted_present: false,
                        deprecated_vni: None,
                        vni: None,
                        virt_type: Some(flat),
                        status_vni: None,
                        routing_profile_type: None,
                        metadata_name: "default_name".to_string(),
                        labels: vec![],
                    },
                },
                Check {
                    scenario: "fnn virtualization type",
                    input: Vpc {
                        network_virtualization_type:
                            carbide_network::virtualization::VpcVirtualizationType::Fnn,
                        ..base_vpc()
                    },
                    expect: ProjectedVpc {
                        version: fixed_version().version_string(),
                        nsg: None,
                        deleted_present: false,
                        deprecated_vni: None,
                        vni: None,
                        virt_type: Some(fnn),
                        status_vni: None,
                        routing_profile_type: None,
                        metadata_name: "default_name".to_string(),
                        labels: vec![],
                    },
                },
                Check {
                    scenario: "deprecated nvue virtualization type collapses to ethernet",
                    input: Vpc {
                        #[allow(deprecated)]
                        network_virtualization_type:
                            carbide_network::virtualization::VpcVirtualizationType::EthernetVirtualizerWithNvue,
                        ..base_vpc()
                    },
                    expect: ProjectedVpc {
                        version: fixed_version().version_string(),
                        nsg: None,
                        deleted_present: false,
                        deprecated_vni: None,
                        vni: None,
                        virt_type: Some(ethernet),
                        status_vni: None,
                        routing_profile_type: None,
                        metadata_name: "default_name".to_string(),
                        labels: vec![],
                    },
                },
                Check {
                    scenario: "routing profile type carried through",
                    input: Vpc {
                        routing_profile_type: Some("internal".to_string()),
                        ..base_vpc()
                    },
                    expect: ProjectedVpc {
                        version: fixed_version().version_string(),
                        nsg: None,
                        deleted_present: false,
                        deprecated_vni: None,
                        vni: None,
                        virt_type: Some(ethernet),
                        status_vni: None,
                        routing_profile_type: Some("internal".to_string()),
                        metadata_name: "default_name".to_string(),
                        labels: vec![],
                    },
                },
                Check {
                    scenario: "labels: empty value becomes None, non-empty stays Some",
                    input: Vpc {
                        metadata: Metadata {
                            name: "named".to_string(),
                            description: String::new(),
                            labels: std::collections::HashMap::from([
                                ("env".to_string(), "prod".to_string()),
                                ("blank".to_string(), String::new()),
                            ]),
                        },
                        ..base_vpc()
                    },
                    expect: ProjectedVpc {
                        version: fixed_version().version_string(),
                        nsg: None,
                        deleted_present: false,
                        deprecated_vni: None,
                        vni: None,
                        virt_type: Some(ethernet),
                        status_vni: None,
                        routing_profile_type: None,
                        metadata_name: "named".to_string(),
                        labels: vec![
                            ("blank".to_string(), None),
                            ("env".to_string(), Some("prod".to_string())),
                        ],
                    },
                },
            ],
            |vpc| {
                let proto = rpc::forge::Vpc::from(vpc);
                let metadata = proto.metadata.unwrap();
                let mut labels: Vec<(String, Option<String>)> = metadata
                    .labels
                    .into_iter()
                    .map(|l| (l.key, l.value))
                    .collect();
                labels.sort_by(|a, b| a.0.cmp(&b.0));
                ProjectedVpc {
                    version: proto.version,
                    nsg: proto.network_security_group_id,
                    deleted_present: proto.deleted.is_some(),
                    deprecated_vni: proto.deprecated_vni,
                    vni: proto.vni,
                    virt_type: proto.network_virtualization_type,
                    status_vni: proto.status.and_then(|s| s.vni),
                    routing_profile_type: proto.routing_profile_type,
                    metadata_name: metadata.name,
                    labels,
                }
            },
        );
    }

    // `From<Vpc> for rpc::forge::VpcDeletionResult` is total and discards its input,
    // always yielding the empty result. Project to `true` to assert it ran.
    #[test]
    fn vpc_into_deletion_result() {
        check_values(
            [Check {
                scenario: "any vpc yields the empty deletion result",
                input: base_vpc(),
                expect: true,
            }],
            |vpc| {
                let _: rpc::forge::VpcDeletionResult = vpc.into();
                true
            },
        );
    }

    // `From<VpcPeering> for rpc::forge::VpcPeering` is total: each id field is wrapped
    // in `Some`. Project to the presence of all three.
    #[test]
    fn vpc_peering_into_rpc() {
        check_values(
            [Check {
                scenario: "all three ids wrapped in Some",
                input: VpcPeering {
                    id: nil_peering_id(),
                    vpc_id: nil_vpc_id(),
                    peer_vpc_id: nil_vpc_id(),
                },
                expect: (true, true, true),
            }],
            |peering| {
                let proto = rpc::forge::VpcPeering::from(peering);
                (
                    proto.id.is_some(),
                    proto.vpc_id.is_some(),
                    proto.peer_vpc_id.is_some(),
                )
            },
        );
    }

    fn base_creation_request() -> rpc::forge::VpcCreationRequest {
        rpc::forge::VpcCreationRequest {
            tenant_organization_id: "org".to_string(),
            tenant_keyset_id: None,
            network_virtualization_type: None,
            id: None,
            metadata: Some(valid_proto_metadata()),
            network_security_group_id: None,
            default_nvlink_logical_partition_id: None,
            vni: None,
            routing_profile_type: None,
        }
    }

    // `TryFrom<VpcCreationRequest> for NewVpc` is fallible; its error type isn't
    // PartialEq, so error rows use `Fails` and the run closure drops the error.
    // Each Ok row projects the field it exercises.
    #[test]
    fn new_vpc_try_from_creation_request() {
        let ethernet =
            carbide_network::virtualization::VpcVirtualizationType::EthernetVirtualizer;
        let flat = carbide_network::virtualization::VpcVirtualizationType::Flat;

        check_cases(
            [
                Case {
                    scenario: "absent virt type defaults to ethernet",
                    input: base_creation_request(),
                    expect: Yields(ethernet),
                },
                Case {
                    scenario: "explicit flat virt type",
                    input: rpc::forge::VpcCreationRequest {
                        network_virtualization_type: Some(
                            rpc::forge::VpcVirtualizationType::Flat as i32,
                        ),
                        ..base_creation_request()
                    },
                    expect: Yields(flat),
                },
                Case {
                    scenario: "absent metadata defaults to a valid name",
                    input: rpc::forge::VpcCreationRequest {
                        metadata: None,
                        ..base_creation_request()
                    },
                    expect: Yields(ethernet),
                },
                Case {
                    scenario: "unknown virt enum value is rejected",
                    input: rpc::forge::VpcCreationRequest {
                        network_virtualization_type: Some(99999),
                        ..base_creation_request()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "empty nsg id is rejected",
                    input: rpc::forge::VpcCreationRequest {
                        network_security_group_id: Some(String::new()),
                        ..base_creation_request()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "metadata that fails validation is rejected",
                    input: rpc::forge::VpcCreationRequest {
                        metadata: Some(rpc::Metadata {
                            name: String::new(),
                            description: String::new(),
                            labels: vec![],
                        }),
                        ..base_creation_request()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "duplicate label keys in metadata are rejected",
                    input: rpc::forge::VpcCreationRequest {
                        metadata: Some(rpc::Metadata {
                            name: "named".to_string(),
                            description: String::new(),
                            labels: vec![
                                rpc::forge::Label {
                                    key: "dup".to_string(),
                                    value: Some("a".to_string()),
                                },
                                rpc::forge::Label {
                                    key: "dup".to_string(),
                                    value: Some("b".to_string()),
                                },
                            ],
                        }),
                        ..base_creation_request()
                    },
                    expect: Fails,
                },
            ],
            |req| {
                NewVpc::try_from(req)
                    .map(|new| new.network_virtualization_type)
                    .map_err(drop)
            },
        );
    }

    // Projects an Ok NewVpc to the fields the optional inputs drive: nsg presence and
    // the VNI. Separate from the virt-type table to keep one Ok projection per table.
    #[test]
    fn new_vpc_carries_optional_fields() {
        check_cases(
            [
                Case {
                    scenario: "nsg and vni present",
                    input: rpc::forge::VpcCreationRequest {
                        network_security_group_id: Some("nsg-7".to_string()),
                        vni: Some(42),
                        ..base_creation_request()
                    },
                    expect: Yields((true, Some(42i32))),
                },
                Case {
                    scenario: "nsg and vni absent",
                    input: base_creation_request(),
                    expect: Yields((false, None)),
                },
            ],
            |req| {
                NewVpc::try_from(req)
                    .map(|new| (new.network_security_group_id.is_some(), new.vni))
                    .map_err(drop)
            },
        );
    }

    fn base_update_request() -> rpc::forge::VpcUpdateRequest {
        rpc::forge::VpcUpdateRequest {
            id: Some(nil_vpc_id()),
            if_version_match: None,
            metadata: Some(valid_proto_metadata()),
            network_security_group_id: None,
            default_nvlink_logical_partition_id: None,
        }
    }

    // `TryFrom<VpcUpdateRequest> for UpdateVpc` is fallible; error type isn't
    // PartialEq, so errors use `Fails`. Project Ok rows to (nsg present, if-version
    // present).
    #[test]
    fn update_vpc_try_from_request() {
        check_cases(
            [
                Case {
                    scenario: "minimal valid request",
                    input: base_update_request(),
                    expect: Yields((false, false)),
                },
                Case {
                    scenario: "nsg and matching version present",
                    input: rpc::forge::VpcUpdateRequest {
                        network_security_group_id: Some("nsg-1".to_string()),
                        if_version_match: Some(fixed_version().version_string()),
                        ..base_update_request()
                    },
                    expect: Yields((true, true)),
                },
                Case {
                    scenario: "absent metadata defaults to a valid name",
                    input: rpc::forge::VpcUpdateRequest {
                        metadata: None,
                        ..base_update_request()
                    },
                    expect: Yields((false, false)),
                },
                Case {
                    scenario: "missing id is rejected",
                    input: rpc::forge::VpcUpdateRequest {
                        id: None,
                        ..base_update_request()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "unparseable if_version_match is rejected",
                    input: rpc::forge::VpcUpdateRequest {
                        if_version_match: Some("not-a-version".to_string()),
                        ..base_update_request()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "empty nsg id is rejected",
                    input: rpc::forge::VpcUpdateRequest {
                        network_security_group_id: Some(String::new()),
                        ..base_update_request()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "metadata that fails validation is rejected",
                    input: rpc::forge::VpcUpdateRequest {
                        metadata: Some(rpc::Metadata {
                            name: String::new(),
                            description: String::new(),
                            labels: vec![],
                        }),
                        ..base_update_request()
                    },
                    expect: Fails,
                },
            ],
            |req| {
                UpdateVpc::try_from(req)
                    .map(|u| (u.network_security_group_id.is_some(), u.if_version_match.is_some()))
                    .map_err(drop)
            },
        );
    }

    fn base_virt_request() -> rpc::forge::VpcUpdateVirtualizationRequest {
        rpc::forge::VpcUpdateVirtualizationRequest {
            id: Some(nil_vpc_id()),
            if_version_match: None,
            network_virtualization_type: Some(
                rpc::forge::VpcVirtualizationType::EthernetVirtualizer as i32,
            ),
        }
    }

    // `TryFrom<VpcUpdateVirtualizationRequest> for UpdateVpcVirtualization` is
    // fallible; error type isn't PartialEq, so errors use `Fails`. Ok rows project
    // the resolved virtualization type.
    #[test]
    fn update_vpc_virtualization_try_from_request() {
        let ethernet =
            carbide_network::virtualization::VpcVirtualizationType::EthernetVirtualizer;
        let flat = carbide_network::virtualization::VpcVirtualizationType::Flat;

        check_cases(
            [
                Case {
                    scenario: "ethernet virt type",
                    input: base_virt_request(),
                    expect: Yields(ethernet),
                },
                Case {
                    scenario: "flat virt type with matching version",
                    input: rpc::forge::VpcUpdateVirtualizationRequest {
                        if_version_match: Some(fixed_version().version_string()),
                        network_virtualization_type: Some(
                            rpc::forge::VpcVirtualizationType::Flat as i32,
                        ),
                        ..base_virt_request()
                    },
                    expect: Yields(flat),
                },
                Case {
                    scenario: "missing id is rejected",
                    input: rpc::forge::VpcUpdateVirtualizationRequest {
                        id: None,
                        ..base_virt_request()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "missing virt type is rejected",
                    input: rpc::forge::VpcUpdateVirtualizationRequest {
                        network_virtualization_type: None,
                        ..base_virt_request()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "unknown virt enum value is rejected",
                    input: rpc::forge::VpcUpdateVirtualizationRequest {
                        network_virtualization_type: Some(99999),
                        ..base_virt_request()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "unparseable if_version_match is rejected",
                    input: rpc::forge::VpcUpdateVirtualizationRequest {
                        if_version_match: Some("not-a-version".to_string()),
                        ..base_virt_request()
                    },
                    expect: Fails,
                },
            ],
            |req| {
                UpdateVpcVirtualization::try_from(req)
                    .map(|u| u.network_virtualization_type)
                    .map_err(drop)
            },
        );
    }
}
