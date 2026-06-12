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

use model::network_prefix::NewNetworkPrefix;
use model::network_segment::{
    AllocationStrategy, NetworkSegment, NetworkSegmentControllerState, NetworkSegmentSearchConfig,
    NetworkSegmentSearchFilter, NetworkSegmentType, NewNetworkSegment, state_sla,
};

use crate as rpc;
use crate::TenantState;
use crate::errors::RpcDataConversionError;
use crate::model::{RpcTryFrom, RpcTryInto};

impl From<rpc::forge::NetworkSegmentSearchFilter> for NetworkSegmentSearchFilter {
    fn from(filter: rpc::forge::NetworkSegmentSearchFilter) -> Self {
        NetworkSegmentSearchFilter {
            name: filter.name,
            tenant_org_id: filter.tenant_org_id,
        }
    }
}

const DEFAULT_MTU_TENANT: i32 = 9000;
const DEFAULT_MTU_OTHER: i32 = 1500;

impl From<rpc::forge::NetworkSegmentSearchConfig> for NetworkSegmentSearchConfig {
    fn from(value: rpc::forge::NetworkSegmentSearchConfig) -> Self {
        NetworkSegmentSearchConfig {
            include_history: value.include_history,
            include_num_free_ips: value.include_num_free_ips,
        }
    }
}

impl RpcTryFrom<i32> for NetworkSegmentType {
    type Error = RpcDataConversionError;
    fn rpc_try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            x if x == rpc::forge::NetworkSegmentType::Tenant as i32 => NetworkSegmentType::Tenant,
            x if x == rpc::forge::NetworkSegmentType::Admin as i32 => NetworkSegmentType::Admin,
            x if x == rpc::forge::NetworkSegmentType::Underlay as i32 => {
                NetworkSegmentType::Underlay
            }
            x if x == rpc::forge::NetworkSegmentType::HostInband as i32 => {
                NetworkSegmentType::HostInband
            }
            _ => {
                return Err(RpcDataConversionError::InvalidNetworkSegmentType(value));
            }
        })
    }
}

/// Converts from Protobuf NetworkSegmentCreationRequest into NewNetworkSegment
///
/// subdomain_id - Converting from Protobuf UUID(String) to Rust UUID type can fail.
/// Use try_from in order to return a Result where Result is an error if the conversion
/// from String -> UUID fails
impl TryFrom<rpc::forge::NetworkSegmentCreationRequest> for NewNetworkSegment {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::NetworkSegmentCreationRequest) -> Result<Self, Self::Error> {
        if value.prefixes.is_empty() {
            return Err(RpcDataConversionError::InvalidArgument(
                "Prefixes are empty.".to_string(),
            ));
        }

        let prefixes = value
            .prefixes
            .into_iter()
            .map(NewNetworkPrefix::try_from)
            .collect::<Result<Vec<NewNetworkPrefix>, RpcDataConversionError>>()?;

        let id = value.id.unwrap_or_else(|| uuid::Uuid::new_v4().into());

        let segment_type: NetworkSegmentType = value.segment_type.rpc_try_into()?;
        if segment_type == NetworkSegmentType::Tenant
            && prefixes.iter().any(|ip| match ip.prefix {
                ipnetwork::IpNetwork::V4(v4) => v4.prefix() >= 31,
                ipnetwork::IpNetwork::V6(v6) => v6.prefix() >= 127,
            })
        {
            return Err(RpcDataConversionError::InvalidArgument(
                "IPv4 prefix /31 and /32 (or IPv6 /127 and /128) are not allowed for tenant segments.".to_string(),
            ));
        }

        // This TryFrom implementation is part of the API handler logic for
        // network segment creation, and is not used by FNN. Therefore, the only
        // type of tenant segment we could be creating is a stretchable one.
        let can_stretch = matches!(segment_type, NetworkSegmentType::Tenant).then_some(true);

        Ok(NewNetworkSegment {
            id,
            name: value.name,
            subdomain_id: value.subdomain_id,
            vpc_id: value.vpc_id,
            mtu: value.mtu.unwrap_or(match segment_type {
                NetworkSegmentType::Tenant => DEFAULT_MTU_TENANT,
                _ => DEFAULT_MTU_OTHER,
            }),
            prefixes,
            vlan_id: None,
            vni: None,
            segment_type,
            can_stretch,
            allocation_strategy: AllocationStrategy::Dynamic,
        })
    }
}

///
/// Marshal a Data Object (NetworkSegment) into an RPC NetworkSegment
///
/// subdomain_id - Rust UUID -> ProtoBuf UUID(String) cannot fail, so convert it or return None
#[allow(deprecated)]
impl TryFrom<NetworkSegment> for rpc::NetworkSegment {
    type Error = RpcDataConversionError;
    fn try_from(src: NetworkSegment) -> Result<Self, Self::Error> {
        // Deprecated TenantState mapping - kept to populate the backward-compat flat field.
        // Note that even though the segment might already be ready,
        // we only return `Ready` after the state machine also noticed that.
        // Otherwise we would need to allow address allocation before the
        // controller state is ready, which spreads out the state mismatch.
        let tenant_state = match &src.status.controller_state.value {
            NetworkSegmentControllerState::Provisioning => TenantState::Provisioning,
            NetworkSegmentControllerState::Ready => TenantState::Ready,
            NetworkSegmentControllerState::Deleting { .. } => TenantState::Terminating,
        };
        // If deletion is requested, immediately overwrite to terminating.
        // The state controller will eventually catch up.
        let tenant_state = if src.is_marked_as_deleted() {
            TenantState::Terminating
        } else {
            tenant_state
        };

        // lifecycle.state: full JSON serialization of the internal controller state.
        // Consistent with how Switch and PowerShelf populate LifecycleStatus.
        let lifecycle_state =
            serde_json::to_string(&src.status.controller_state.value).unwrap_or_default();

        let sla: rpc::forge::StateSla = state_sla(
            &src.status.controller_state.value,
            &src.status.controller_state.version,
        )
        .into();

        let state_reason: Option<rpc::forge::ControllerStateReason> =
            src.status.controller_state_outcome.map(Into::into);

        let history: Vec<rpc::forge::NetworkSegmentStateHistory> =
            src.status.history.into_iter().map(Into::into).collect();

        let flags: Vec<i32> = {
            use crate::forge::NetworkSegmentFlag::*;

            let mut flags = vec![];

            let can_stretch = src.status.can_stretch.unwrap_or_else(|| {
                // If the segment's can_stretch flag is NULL in the database,
                // we're going to have to go off of what an FNN-created
                // segment's prefixes would look like, and then assume any such
                // FNN segment is _not_ stretchable.
                src.prefixes.iter().all(|p| !p.smells_like_fnn())
            });

            if can_stretch {
                flags.push(CanStretch);
            }

            // Just so a gRPC client can tell the difference between a missing
            // `flags` field and an empty one.
            if flags.is_empty() {
                flags.push(NoOp);
            }

            flags.into_iter().map(|flag| flag as i32).collect()
        };

        let prefixes: Vec<rpc::forge::NetworkPrefix> =
            src.prefixes.into_iter().map(Into::into).collect();

        let version = src.version.version_string();

        Ok(rpc::NetworkSegment {
            id: Some(src.id),
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),

            // New structured fields - internal clients use these.
            // Note: prefixes are placed under config in the proto even though they are top-level
            // in the Rust model. The Rust model keeps them top-level because each NetworkPrefix
            // contains mixed config fields (CIDR, gateway) and status fields (free_ip_count,
            // svi_ip). The proto puts them under config as the closest semantic fit for now.
            config: Some(rpc::forge::NetworkSegmentConfig {
                vpc_id: src.config.vpc_id,
                subdomain_id: src.config.subdomain_id,
                mtu: Some(src.config.mtu),
                prefixes: prefixes.clone(),
                segment_type: src.config.segment_type as i32,
            }),
            status: Some(rpc::forge::NetworkSegmentStatus {
                flags: flags.clone(),
                lifecycle: Some(rpc::forge::LifecycleStatus {
                    state: lifecycle_state,
                    version: version.clone(),
                    state_reason: state_reason.clone(),
                    sla: Some(sla),
                }),
                tenant_state: tenant_state as i32,
            }),
            metadata: Some(rpc::forge::Metadata {
                name: src.config.name.clone(),
                description: String::new(),
                labels: vec![],
            }),

            // Deprecated flat fields - populated for external client compatibility.
            // Remove after nico-rest migrates to config/status/metadata (Phase 3).
            vpc_id: src.config.vpc_id,
            name: src.config.name,
            subdomain_id: src.config.subdomain_id,
            mtu: Some(src.config.mtu),
            prefixes,
            segment_type: src.config.segment_type as i32,
            flags,
            version,
            state: tenant_state as i32,
            history,
            state_reason,
            state_sla: Some(sla),
        })
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use super::*;

    fn make_test_creation_request(
        prefixes: Vec<rpc::forge::NetworkPrefix>,
        segment_type: NetworkSegmentType,
    ) -> rpc::forge::NetworkSegmentCreationRequest {
        rpc::forge::NetworkSegmentCreationRequest {
            id: None,
            mtu: Some(1500),
            name: "TEST_SEGMENT".to_string(),
            prefixes,
            subdomain_id: None,
            vpc_id: None,
            segment_type: match segment_type {
                NetworkSegmentType::Admin => rpc::forge::NetworkSegmentType::Admin as i32,
                NetworkSegmentType::Tenant => rpc::forge::NetworkSegmentType::Tenant as i32,
                NetworkSegmentType::Underlay => rpc::forge::NetworkSegmentType::Underlay as i32,
                NetworkSegmentType::HostInband => rpc::forge::NetworkSegmentType::HostInband as i32,
            },
        }
    }

    fn ipv4_prefix(prefix: &str, gateway: Option<&str>) -> rpc::forge::NetworkPrefix {
        rpc::forge::NetworkPrefix {
            id: None,
            prefix: prefix.to_string(),
            gateway: gateway.map(|g| g.to_string()),
            reserve_first: 1,
            free_ip_count: 0,
            svi_ip: None,
        }
    }

    fn ipv6_prefix(prefix: &str) -> rpc::forge::NetworkPrefix {
        rpc::forge::NetworkPrefix {
            id: None,
            prefix: prefix.to_string(),
            gateway: None,
            reserve_first: 0,
            free_ip_count: 0,
            svi_ip: None,
        }
    }

    // Every row drives the same conversion (NewNetworkSegment::try_from): IPv6 and
    // dual-stack prefixes are accepted (and the resulting prefix count / IPv6-ness
    // preserved), while tenant segments reject too-small IPv4 (/31, /32) and IPv6
    // (/127, /128) prefixes. Accepting rows project to (prefix count, first prefix
    // is IPv6); rejecting rows assert only that the conversion fails.
    #[test]
    fn try_from_creation_request_validates_prefixes() {
        check_cases(
            [
                Case {
                    scenario: "ipv6 prefix accepted (admin)",
                    input: make_test_creation_request(
                        vec![ipv6_prefix("2001:db8::/64")],
                        NetworkSegmentType::Admin,
                    ),
                    expect: Yields((1, true)),
                },
                Case {
                    scenario: "dual-stack prefixes accepted (admin)",
                    input: make_test_creation_request(
                        vec![
                            ipv4_prefix("192.0.2.0/24", Some("192.0.2.1")),
                            ipv6_prefix("2001:db8::/64"),
                        ],
                        NetworkSegmentType::Admin,
                    ),
                    expect: Yields((2, false)),
                },
                Case {
                    scenario: "tenant /64 IPv6 allowed",
                    input: make_test_creation_request(
                        vec![ipv6_prefix("2001:db8::/64")],
                        NetworkSegmentType::Tenant,
                    ),
                    expect: Yields((1, true)),
                },
                Case {
                    scenario: "tenant /127 IPv6 rejected",
                    input: make_test_creation_request(
                        vec![ipv6_prefix("2001:db8::1/127")],
                        NetworkSegmentType::Tenant,
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "tenant /128 IPv6 rejected",
                    input: make_test_creation_request(
                        vec![ipv6_prefix("2001:db8::1/128")],
                        NetworkSegmentType::Tenant,
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "tenant /24 IPv4 allowed",
                    input: make_test_creation_request(
                        vec![ipv4_prefix("192.0.2.0/24", Some("192.0.2.1"))],
                        NetworkSegmentType::Tenant,
                    ),
                    expect: Yields((1, false)),
                },
                Case {
                    scenario: "tenant /31 IPv4 rejected",
                    input: make_test_creation_request(
                        vec![ipv4_prefix("192.0.2.0/31", Some("192.0.2.1"))],
                        NetworkSegmentType::Tenant,
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "tenant /32 IPv4 rejected",
                    input: make_test_creation_request(
                        vec![ipv4_prefix("192.0.2.0/32", None)],
                        NetworkSegmentType::Tenant,
                    ),
                    expect: Fails,
                },
            ],
            // The error type (RpcDataConversionError) is not asserted by these rows,
            // so failing rows discard it; accepting rows project to the prefix count
            // and whether the first prefix is IPv6.
            |request| {
                NewNetworkSegment::try_from(request)
                    .map(|segment| (segment.prefixes.len(), segment.prefixes[0].prefix.is_ipv6()))
                    .map_err(drop)
            },
        );
    }

    // Empty prefixes are rejected outright, regardless of segment type.
    #[test]
    fn try_from_creation_request_rejects_empty_prefixes() {
        check_cases(
            [
                Case {
                    scenario: "admin with no prefixes",
                    input: make_test_creation_request(vec![], NetworkSegmentType::Admin),
                    expect: Fails,
                },
                Case {
                    scenario: "tenant with no prefixes",
                    input: make_test_creation_request(vec![], NetworkSegmentType::Tenant),
                    expect: Fails,
                },
            ],
            |request| NewNetworkSegment::try_from(request).map(drop).map_err(drop),
        );
    }

    // When `mtu` is absent the conversion supplies a type-dependent default:
    // 9000 for tenant segments, 1500 otherwise. An explicit `mtu` overrides both.
    // Each row projects to the resulting segment's mtu.
    #[test]
    fn try_from_creation_request_defaults_mtu_by_type() {
        fn request_with_mtu(
            mtu: Option<i32>,
            segment_type: NetworkSegmentType,
        ) -> rpc::forge::NetworkSegmentCreationRequest {
            let mut request = make_test_creation_request(
                vec![ipv4_prefix("192.0.2.0/24", Some("192.0.2.1"))],
                segment_type,
            );
            request.mtu = mtu;
            request
        }

        check_cases(
            [
                Case {
                    scenario: "tenant default mtu is 9000",
                    input: request_with_mtu(None, NetworkSegmentType::Tenant),
                    expect: Yields(DEFAULT_MTU_TENANT),
                },
                Case {
                    scenario: "admin default mtu is 1500",
                    input: request_with_mtu(None, NetworkSegmentType::Admin),
                    expect: Yields(DEFAULT_MTU_OTHER),
                },
                Case {
                    scenario: "underlay default mtu is 1500",
                    input: request_with_mtu(None, NetworkSegmentType::Underlay),
                    expect: Yields(DEFAULT_MTU_OTHER),
                },
                Case {
                    scenario: "host-inband default mtu is 1500",
                    input: request_with_mtu(None, NetworkSegmentType::HostInband),
                    expect: Yields(DEFAULT_MTU_OTHER),
                },
                Case {
                    scenario: "explicit mtu overrides tenant default",
                    input: request_with_mtu(Some(1400), NetworkSegmentType::Tenant),
                    expect: Yields(1400),
                },
                Case {
                    scenario: "explicit mtu overrides admin default",
                    input: request_with_mtu(Some(1400), NetworkSegmentType::Admin),
                    expect: Yields(1400),
                },
            ],
            |request| NewNetworkSegment::try_from(request).map(|s| s.mtu).map_err(drop),
        );
    }

    // `can_stretch` is set to Some(true) for tenant segments and left None for
    // every other type. Each row projects to the resulting `can_stretch`.
    #[test]
    fn try_from_creation_request_sets_can_stretch_for_tenant() {
        check_cases(
            [
                Case {
                    scenario: "tenant is stretchable",
                    input: make_test_creation_request(
                        vec![ipv4_prefix("192.0.2.0/24", Some("192.0.2.1"))],
                        NetworkSegmentType::Tenant,
                    ),
                    expect: Yields(Some(true)),
                },
                Case {
                    scenario: "admin is not stretchable",
                    input: make_test_creation_request(
                        vec![ipv4_prefix("192.0.2.0/24", Some("192.0.2.1"))],
                        NetworkSegmentType::Admin,
                    ),
                    expect: Yields(None),
                },
                Case {
                    scenario: "underlay is not stretchable",
                    input: make_test_creation_request(
                        vec![ipv4_prefix("192.0.2.0/24", Some("192.0.2.1"))],
                        NetworkSegmentType::Underlay,
                    ),
                    expect: Yields(None),
                },
                Case {
                    scenario: "host-inband is not stretchable",
                    input: make_test_creation_request(
                        vec![ipv4_prefix("192.0.2.0/24", Some("192.0.2.1"))],
                        NetworkSegmentType::HostInband,
                    ),
                    expect: Yields(None),
                },
            ],
            |request| {
                NewNetworkSegment::try_from(request)
                    .map(|s| s.can_stretch)
                    .map_err(drop)
            },
        );
    }

    // The conversion carries the segment type through and defaults the allocation
    // strategy to Dynamic. Each row projects to (segment_type, allocation_strategy).
    #[test]
    fn try_from_creation_request_carries_segment_type() {
        check_cases(
            [
                Case {
                    scenario: "tenant type preserved",
                    input: make_test_creation_request(
                        vec![ipv4_prefix("192.0.2.0/24", Some("192.0.2.1"))],
                        NetworkSegmentType::Tenant,
                    ),
                    expect: Yields((NetworkSegmentType::Tenant, AllocationStrategy::Dynamic)),
                },
                Case {
                    scenario: "admin type preserved",
                    input: make_test_creation_request(
                        vec![ipv4_prefix("192.0.2.0/24", Some("192.0.2.1"))],
                        NetworkSegmentType::Admin,
                    ),
                    expect: Yields((NetworkSegmentType::Admin, AllocationStrategy::Dynamic)),
                },
                Case {
                    scenario: "underlay type preserved",
                    input: make_test_creation_request(
                        vec![ipv4_prefix("192.0.2.0/24", Some("192.0.2.1"))],
                        NetworkSegmentType::Underlay,
                    ),
                    expect: Yields((NetworkSegmentType::Underlay, AllocationStrategy::Dynamic)),
                },
                Case {
                    scenario: "host-inband type preserved",
                    input: make_test_creation_request(
                        vec![ipv4_prefix("192.0.2.0/24", Some("192.0.2.1"))],
                        NetworkSegmentType::HostInband,
                    ),
                    expect: Yields((NetworkSegmentType::HostInband, AllocationStrategy::Dynamic)),
                },
            ],
            |request| {
                NewNetworkSegment::try_from(request)
                    .map(|s| (s.segment_type, s.allocation_strategy))
                    .map_err(drop)
            },
        );
    }

    // An unrecognized `segment_type` discriminant fails the whole conversion.
    #[test]
    fn try_from_creation_request_rejects_unknown_segment_type() {
        let mut request = make_test_creation_request(
            vec![ipv4_prefix("192.0.2.0/24", Some("192.0.2.1"))],
            NetworkSegmentType::Admin,
        );
        request.segment_type = 999;

        Case {
            scenario: "unknown segment type discriminant",
            input: request,
            expect: Fails,
        }
        .check(|request| NewNetworkSegment::try_from(request).map(drop).map_err(drop));
    }

    // i32 -> NetworkSegmentType: each valid discriminant maps to its arm, and any
    // out-of-range value fails. The error type is not asserted, so failing rows
    // discard it.
    #[test]
    fn network_segment_type_from_i32() {
        check_cases(
            [
                Case {
                    scenario: "0 -> Tenant",
                    input: rpc::forge::NetworkSegmentType::Tenant as i32,
                    expect: Yields(NetworkSegmentType::Tenant),
                },
                Case {
                    scenario: "1 -> Admin",
                    input: rpc::forge::NetworkSegmentType::Admin as i32,
                    expect: Yields(NetworkSegmentType::Admin),
                },
                Case {
                    scenario: "2 -> Underlay",
                    input: rpc::forge::NetworkSegmentType::Underlay as i32,
                    expect: Yields(NetworkSegmentType::Underlay),
                },
                Case {
                    scenario: "3 -> HostInband",
                    input: rpc::forge::NetworkSegmentType::HostInband as i32,
                    expect: Yields(NetworkSegmentType::HostInband),
                },
                Case {
                    scenario: "unknown discriminant rejected",
                    input: 999,
                    expect: Fails,
                },
                Case {
                    scenario: "negative discriminant rejected",
                    input: -1,
                    expect: Fails,
                },
            ],
            |value| NetworkSegmentType::rpc_try_from(value).map_err(drop),
        );
    }

    // NetworkSegmentSearchFilter::from is a direct field copy; each row projects
    // to (name, tenant_org_id) so present vs absent optionals are both exercised.
    #[test]
    fn search_filter_from_proto() {
        check_values(
            [
                Check {
                    scenario: "both fields present",
                    input: rpc::forge::NetworkSegmentSearchFilter {
                        name: Some("seg".to_string()),
                        tenant_org_id: Some("org".to_string()),
                    },
                    expect: (Some("seg".to_string()), Some("org".to_string())),
                },
                Check {
                    scenario: "name only",
                    input: rpc::forge::NetworkSegmentSearchFilter {
                        name: Some("seg".to_string()),
                        tenant_org_id: None,
                    },
                    expect: (Some("seg".to_string()), None),
                },
                Check {
                    scenario: "tenant_org_id only",
                    input: rpc::forge::NetworkSegmentSearchFilter {
                        name: None,
                        tenant_org_id: Some("org".to_string()),
                    },
                    expect: (None, Some("org".to_string())),
                },
                Check {
                    scenario: "both absent",
                    input: rpc::forge::NetworkSegmentSearchFilter {
                        name: None,
                        tenant_org_id: None,
                    },
                    expect: (None, None),
                },
            ],
            |proto| {
                let filter = NetworkSegmentSearchFilter::from(proto);
                (filter.name, filter.tenant_org_id)
            },
        );
    }

    // NetworkSegmentSearchConfig::from is a direct bool copy; each row projects to
    // (include_history, include_num_free_ips) across all four combinations.
    #[test]
    fn search_config_from_proto() {
        check_values(
            [
                Check {
                    scenario: "both false",
                    input: rpc::forge::NetworkSegmentSearchConfig {
                        include_history: false,
                        include_num_free_ips: false,
                    },
                    expect: (false, false),
                },
                Check {
                    scenario: "history only",
                    input: rpc::forge::NetworkSegmentSearchConfig {
                        include_history: true,
                        include_num_free_ips: false,
                    },
                    expect: (true, false),
                },
                Check {
                    scenario: "free ips only",
                    input: rpc::forge::NetworkSegmentSearchConfig {
                        include_history: false,
                        include_num_free_ips: true,
                    },
                    expect: (false, true),
                },
                Check {
                    scenario: "both true",
                    input: rpc::forge::NetworkSegmentSearchConfig {
                        include_history: true,
                        include_num_free_ips: true,
                    },
                    expect: (true, true),
                },
            ],
            |proto| {
                let config = NetworkSegmentSearchConfig::from(proto);
                (config.include_history, config.include_num_free_ips)
            },
        );
    }
}
