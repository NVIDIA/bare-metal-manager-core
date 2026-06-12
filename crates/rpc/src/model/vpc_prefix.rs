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

use carbide_uuid::vpc::VpcPrefixId;
use ipnetwork::IpNetwork;
use model::metadata::Metadata;
use model::vpc_prefix::{
    DeleteVpcPrefix, NewVpcPrefix, UpdateVpcPrefix, VpcPrefix, VpcPrefixConfig,
    VpcPrefixControllerState, state_sla,
};

use crate as rpc;
use crate::TenantState;
use crate::errors::RpcDataConversionError;

impl TryFrom<rpc::forge::VpcPrefixCreationRequest> for NewVpcPrefix {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::VpcPrefixCreationRequest) -> Result<Self, Self::Error> {
        let rpc::forge::VpcPrefixCreationRequest {
            id,
            prefix,
            vpc_id,
            config,
            metadata,
        } = value;

        let id = id.unwrap_or_else(VpcPrefixId::new);
        let vpc_id = vpc_id.ok_or(RpcDataConversionError::MissingArgument("vpc_id"))?;

        let metadata = match metadata {
            Some(metadata) => metadata.try_into()?,
            None => Metadata::new_with_default_name(),
        };

        metadata.validate(true).map_err(|e| {
            RpcDataConversionError::InvalidArgument(format!(
                "VPCPrefix metadata is not valid: {}",
                e
            ))
        })?;

        let config = match config {
            Some(config) => VpcPrefixConfig::try_from(config)?,
            None => VpcPrefixConfig {
                prefix: IpNetwork::try_from(prefix.as_str())?,
            },
        };

        Ok(Self {
            id,
            config,
            metadata,
            vpc_id,
        })
    }
}

impl TryFrom<rpc::forge::VpcPrefixConfig> for VpcPrefixConfig {
    type Error = RpcDataConversionError;

    fn try_from(rpc_config: rpc::forge::VpcPrefixConfig) -> Result<Self, Self::Error> {
        let rpc::forge::VpcPrefixConfig { prefix } = rpc_config;

        Ok(Self {
            prefix: IpNetwork::try_from(prefix.as_str())?,
        })
    }
}

impl TryFrom<rpc::forge::VpcPrefixUpdateRequest> for UpdateVpcPrefix {
    type Error = RpcDataConversionError;

    fn try_from(
        rpc_update_prefix: rpc::forge::VpcPrefixUpdateRequest,
    ) -> Result<Self, Self::Error> {
        let rpc::forge::VpcPrefixUpdateRequest {
            id,
            prefix,
            config,
            metadata,
        } = rpc_update_prefix;

        if prefix.is_some()
            || config
                .as_ref()
                .map(|c| !c.prefix.is_empty())
                .unwrap_or(false)
        {
            return Err(RpcDataConversionError::InvalidArgument(
                "Resizing VPC prefixes is currently unsupported".to_owned(),
            ));
        }
        let id = id.ok_or(RpcDataConversionError::MissingArgument("id"))?;

        let metadata = match metadata {
            Some(metadata) => metadata.try_into()?,
            None => Metadata::new_with_default_name(),
        };

        metadata.validate(true).map_err(|e| {
            RpcDataConversionError::InvalidArgument(format!(
                "VPC prefix metadata is not valid: {}",
                e
            ))
        })?;

        Ok(Self { id, metadata })
    }
}

impl TryFrom<rpc::forge::VpcPrefixDeletionRequest> for DeleteVpcPrefix {
    type Error = RpcDataConversionError;

    fn try_from(
        rpc_delete_prefix: rpc::forge::VpcPrefixDeletionRequest,
    ) -> Result<Self, Self::Error> {
        let id = rpc_delete_prefix
            .id
            .ok_or(RpcDataConversionError::MissingArgument("id"))?;
        Ok(Self { id })
    }
}

impl From<VpcPrefix> for rpc::forge::VpcPrefix {
    fn from(db_vpc_prefix: VpcPrefix) -> Self {
        // Derive the coarse tenant-facing state from the internal controller state.
        let tenant_state = match &db_vpc_prefix.status.controller_state.value {
            VpcPrefixControllerState::Provisioning => TenantState::Provisioning,
            VpcPrefixControllerState::Ready => TenantState::Ready,
            VpcPrefixControllerState::Deleting { .. } => TenantState::Terminating,
        };
        // Surface soft-deleted prefixes as terminating before the controller catches up.
        let tenant_state = if db_vpc_prefix.is_marked_as_deleted() {
            TenantState::Terminating
        } else {
            tenant_state
        };

        let VpcPrefix {
            id,
            config,
            metadata,
            status,
            vpc_id,
            ..
        } = db_vpc_prefix;

        let id = Some(id);
        let prefix = config.prefix.to_string();
        let vpc_id = Some(vpc_id);

        // Lifecycle state remains the JSON serialization of the internal controller state.
        let lifecycle_state =
            serde_json::to_string(&status.controller_state.value).unwrap_or_default();
        let lifecycle_sla = state_sla(
            &status.controller_state.value,
            &status.controller_state.version,
        );

        Self {
            id,
            prefix: prefix.clone(), // Deprecated
            vpc_id,
            total_31_segments: status.total_31_segments, // Deprecated
            available_31_segments: status.available_31_segments, // Deprecated
            status: Some(rpc::forge::VpcPrefixStatus {
                total_31_segments: status.total_31_segments,
                available_31_segments: status.available_31_segments,
                total_linknet_segments: status.total_linknet_segments,
                available_linknet_segments: status.available_linknet_segments,
                lifecycle: Some(rpc::forge::LifecycleStatus {
                    state: lifecycle_state,
                    version: status.controller_state.version.version_string(),
                    state_reason: status.controller_state_outcome.map(Into::into),
                    sla: Some(lifecycle_sla.into()),
                }),
                tenant_state: tenant_state as i32,
            }),
            metadata: Some(metadata.into()),
            config: Some(rpc::forge::VpcPrefixConfig { prefix }),
        }
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};
    use carbide_uuid::vpc::VpcId;
    use chrono::{DateTime, Utc};
    use config_version::{ConfigVersion, Versioned};
    use model::vpc_prefix::{VpcPrefixDeletionState, VpcPrefixStatus};

    use super::*;

    /// A proto Metadata whose name is long enough to pass `validate(true)`.
    fn valid_metadata(name: &str) -> rpc::forge::Metadata {
        rpc::forge::Metadata {
            name: name.to_owned(),
            description: String::new(),
            labels: Vec::new(),
        }
    }

    /// A bare creation request: only the fields a row cares about are filled in
    /// by mutating the returned value.
    fn creation_request() -> rpc::forge::VpcPrefixCreationRequest {
        rpc::forge::VpcPrefixCreationRequest {
            id: None,
            prefix: "10.0.0.0/24".to_owned(),
            vpc_id: Some(VpcId::new()),
            config: None,
            metadata: None,
        }
    }

    /// Builds a minimal VPC prefix for status conversion tests.
    fn test_vpc_prefix(
        controller_state: VpcPrefixControllerState,
        deleted: Option<DateTime<Utc>>,
    ) -> VpcPrefix {
        VpcPrefix {
            id: VpcPrefixId::new(),
            vpc_id: VpcId::new(),
            config: VpcPrefixConfig {
                prefix: "10.0.0.0/24".parse().unwrap(),
            },
            metadata: Metadata::default(),
            status: VpcPrefixStatus {
                controller_state: Versioned::new(controller_state, ConfigVersion::initial()),
                controller_state_outcome: None,
                last_used_prefix: None,
                total_31_segments: 0,
                available_31_segments: 0,
                total_linknet_segments: 0,
                available_linknet_segments: 0,
            },
            deleted,
        }
    }

    #[test]
    fn vpc_prefix_status_derives_tenant_state_from_controller_state() {
        let cases = [
            (
                VpcPrefixControllerState::Provisioning,
                TenantState::Provisioning,
            ),
            (VpcPrefixControllerState::Ready, TenantState::Ready),
            (
                VpcPrefixControllerState::Deleting {
                    deletion_state: VpcPrefixDeletionState::DBDelete,
                },
                TenantState::Terminating,
            ),
        ];

        for (controller_state, expected_tenant_state) in cases {
            // Convert each controller state without any soft-delete marker.
            let status = rpc::forge::VpcPrefix::from(test_vpc_prefix(controller_state, None))
                .status
                .expect("VPC prefix status should be populated");

            // Report the coarse tenant-facing enum independently from lifecycle JSON.
            assert_eq!(status.tenant_state, expected_tenant_state as i32);
        }
    }

    #[test]
    fn vpc_prefix_status_reports_soft_deleted_ready_prefix_as_terminating() {
        // Convert a ready prefix with the durable soft-delete marker set.
        let status = rpc::forge::VpcPrefix::from(test_vpc_prefix(
            VpcPrefixControllerState::Ready,
            Some(Utc::now()),
        ))
        .status
        .expect("VPC prefix status should be populated");

        // Keep lifecycle state as controller JSON while overriding tenant_state.
        let lifecycle = status
            .lifecycle
            .expect("VPC prefix lifecycle should be populated");
        assert_eq!(lifecycle.state, r#"{"state":"ready"}"#);
        assert_eq!(status.tenant_state, TenantState::Terminating as i32);
    }

    #[test]
    fn new_vpc_prefix_from_creation_request() {
        check_cases(
            [
                Case {
                    scenario: "deprecated prefix string used when config absent",
                    input: creation_request(),
                    expect: Yields("10.0.0.0/24".to_owned()),
                },
                Case {
                    scenario: "config prefix wins over deprecated prefix string",
                    input: rpc::forge::VpcPrefixCreationRequest {
                        prefix: "10.0.0.0/24".to_owned(),
                        config: Some(rpc::forge::VpcPrefixConfig {
                            prefix: "192.168.0.0/16".to_owned(),
                        }),
                        ..creation_request()
                    },
                    expect: Yields("192.168.0.0/16".to_owned()),
                },
                Case {
                    scenario: "explicit valid metadata accepted",
                    input: rpc::forge::VpcPrefixCreationRequest {
                        metadata: Some(valid_metadata("my-prefix")),
                        ..creation_request()
                    },
                    expect: Yields("10.0.0.0/24".to_owned()),
                },
                Case {
                    scenario: "ipv6 prefix accepted",
                    input: rpc::forge::VpcPrefixCreationRequest {
                        prefix: "2001:db8::/32".to_owned(),
                        ..creation_request()
                    },
                    expect: Yields("2001:db8::/32".to_owned()),
                },
                Case {
                    scenario: "missing vpc_id rejected",
                    input: rpc::forge::VpcPrefixCreationRequest {
                        vpc_id: None,
                        ..creation_request()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "invalid deprecated prefix string rejected",
                    input: rpc::forge::VpcPrefixCreationRequest {
                        prefix: "not-a-cidr".to_owned(),
                        ..creation_request()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "invalid config prefix rejected",
                    input: rpc::forge::VpcPrefixCreationRequest {
                        config: Some(rpc::forge::VpcPrefixConfig {
                            prefix: "bogus".to_owned(),
                        }),
                        ..creation_request()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "empty-name metadata fails validation",
                    input: rpc::forge::VpcPrefixCreationRequest {
                        metadata: Some(valid_metadata("")),
                        ..creation_request()
                    },
                    expect: Fails,
                },
            ],
            |req| {
                NewVpcPrefix::try_from(req)
                    .map(|new| new.config.prefix.to_string())
                    .map_err(drop)
            },
        );
    }

    #[test]
    fn vpc_prefix_config_from_proto() {
        check_cases(
            [
                Case {
                    scenario: "valid ipv4 cidr",
                    input: "10.0.0.0/24",
                    expect: Yields("10.0.0.0/24".to_owned()),
                },
                Case {
                    scenario: "valid ipv6 cidr",
                    input: "2001:db8::/32",
                    expect: Yields("2001:db8::/32".to_owned()),
                },
                Case {
                    scenario: "empty prefix rejected",
                    input: "",
                    expect: Fails,
                },
                Case {
                    scenario: "non-cidr text rejected",
                    input: "nonsense",
                    expect: Fails,
                },
            ],
            |prefix| {
                VpcPrefixConfig::try_from(rpc::forge::VpcPrefixConfig {
                    prefix: prefix.to_owned(),
                })
                .map(|config| config.prefix.to_string())
                .map_err(drop)
            },
        );
    }

    #[test]
    fn update_vpc_prefix_from_request() {
        let id = VpcPrefixId::new();
        check_cases(
            [
                Case {
                    scenario: "id present, default metadata accepted",
                    input: rpc::forge::VpcPrefixUpdateRequest {
                        id: Some(id),
                        prefix: None,
                        config: None,
                        metadata: None,
                    },
                    expect: Yields(true),
                },
                Case {
                    scenario: "id present, explicit valid metadata accepted",
                    input: rpc::forge::VpcPrefixUpdateRequest {
                        id: Some(id),
                        prefix: None,
                        config: None,
                        metadata: Some(valid_metadata("renamed")),
                    },
                    expect: Yields(true),
                },
                Case {
                    scenario: "empty config prefix is not a resize",
                    input: rpc::forge::VpcPrefixUpdateRequest {
                        id: Some(id),
                        prefix: None,
                        config: Some(rpc::forge::VpcPrefixConfig {
                            prefix: String::new(),
                        }),
                        metadata: None,
                    },
                    expect: Yields(true),
                },
                Case {
                    scenario: "deprecated prefix resize rejected",
                    input: rpc::forge::VpcPrefixUpdateRequest {
                        id: Some(id),
                        prefix: Some("10.0.0.0/24".to_owned()),
                        config: None,
                        metadata: None,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "config prefix resize rejected",
                    input: rpc::forge::VpcPrefixUpdateRequest {
                        id: Some(id),
                        prefix: None,
                        config: Some(rpc::forge::VpcPrefixConfig {
                            prefix: "10.0.0.0/24".to_owned(),
                        }),
                        metadata: None,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "missing id rejected",
                    input: rpc::forge::VpcPrefixUpdateRequest {
                        id: None,
                        prefix: None,
                        config: None,
                        metadata: None,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "empty-name metadata fails validation",
                    input: rpc::forge::VpcPrefixUpdateRequest {
                        id: Some(id),
                        prefix: None,
                        config: None,
                        metadata: Some(valid_metadata("")),
                    },
                    expect: Fails,
                },
            ],
            |req| {
                UpdateVpcPrefix::try_from(req)
                    .map(|update| update.id == id)
                    .map_err(drop)
            },
        );
    }

    #[test]
    fn delete_vpc_prefix_from_request() {
        let id = VpcPrefixId::new();
        check_cases(
            [
                Case {
                    scenario: "id present accepted",
                    input: rpc::forge::VpcPrefixDeletionRequest { id: Some(id) },
                    expect: Yields(true),
                },
                Case {
                    scenario: "missing id rejected",
                    input: rpc::forge::VpcPrefixDeletionRequest { id: None },
                    expect: Fails,
                },
            ],
            |req| {
                DeleteVpcPrefix::try_from(req)
                    .map(|delete| delete.id == id)
                    .map_err(drop)
            },
        );
    }

    #[test]
    fn vpc_prefix_to_proto_lifecycle_state_json() {
        check_values(
            [
                Check {
                    scenario: "provisioning serializes to controller json",
                    input: VpcPrefixControllerState::Provisioning,
                    expect: r#"{"state":"provisioning"}"#.to_owned(),
                },
                Check {
                    scenario: "ready serializes to controller json",
                    input: VpcPrefixControllerState::Ready,
                    expect: r#"{"state":"ready"}"#.to_owned(),
                },
                Check {
                    scenario: "deleting serializes with deletion_state",
                    input: VpcPrefixControllerState::Deleting {
                        deletion_state: VpcPrefixDeletionState::DBDelete,
                    },
                    expect: r#"{"state":"deleting","deletion_state":{"state":"dbdelete"}}"#
                        .to_owned(),
                },
            ],
            |controller_state| {
                rpc::forge::VpcPrefix::from(test_vpc_prefix(controller_state, None))
                    .status
                    .and_then(|s| s.lifecycle)
                    .map(|l| l.state)
                    .unwrap_or_default()
            },
        );
    }

    #[test]
    fn vpc_prefix_to_proto_carries_fields() {
        check_values(
            [
                Check {
                    scenario: "deprecated prefix string populated",
                    input: "deprecated_prefix",
                    expect: true,
                },
                Check {
                    scenario: "config prefix matches deprecated prefix",
                    input: "config_matches",
                    expect: true,
                },
                Check {
                    scenario: "id is surfaced",
                    input: "id_present",
                    expect: true,
                },
                Check {
                    scenario: "vpc_id is surfaced",
                    input: "vpc_id_present",
                    expect: true,
                },
                Check {
                    scenario: "metadata is surfaced",
                    input: "metadata_present",
                    expect: true,
                },
            ],
            |which| {
                let proto = rpc::forge::VpcPrefix::from(test_vpc_prefix(
                    VpcPrefixControllerState::Ready,
                    None,
                ));
                match which {
                    "deprecated_prefix" => proto.prefix == "10.0.0.0/24",
                    "config_matches" => proto.config.map(|c| c.prefix) == Some(proto.prefix),
                    "id_present" => proto.id.is_some(),
                    "vpc_id_present" => proto.vpc_id.is_some(),
                    "metadata_present" => proto.metadata.is_some(),
                    _ => false,
                }
            },
        );
    }
}
