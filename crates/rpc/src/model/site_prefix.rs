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

use ipnetwork::IpNetwork;
use model::site_prefix::{
    PrefixMatch, SitePrefix, SitePrefixAuthority, SitePrefixLifecycleState, SitePrefixRoutingScope,
    SitePrefixSearchFilter,
};
use model::tenant::TenantOrganizationId;

use crate::errors::RpcDataConversionError;
use crate::forge as rpc;

impl From<SitePrefixAuthority> for rpc::SitePrefixAuthority {
    fn from(value: SitePrefixAuthority) -> Self {
        match value {
            SitePrefixAuthority::Configured => Self::Configured,
            SitePrefixAuthority::TenantManaged => Self::TenantManaged,
        }
    }
}

impl TryFrom<rpc::SitePrefixAuthority> for SitePrefixAuthority {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::SitePrefixAuthority) -> Result<Self, Self::Error> {
        match value {
            rpc::SitePrefixAuthority::Configured => Ok(Self::Configured),
            rpc::SitePrefixAuthority::TenantManaged => Ok(Self::TenantManaged),
            rpc::SitePrefixAuthority::Unspecified => Err(RpcDataConversionError::InvalidValue(
                "SitePrefixAuthority".to_string(),
                value.as_str_name().to_string(),
            )),
        }
    }
}

impl From<SitePrefixRoutingScope> for rpc::SitePrefixRoutingScope {
    fn from(value: SitePrefixRoutingScope) -> Self {
        match value {
            SitePrefixRoutingScope::DatacenterOnly => Self::DatacenterOnly,
        }
    }
}

impl TryFrom<rpc::SitePrefixRoutingScope> for SitePrefixRoutingScope {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::SitePrefixRoutingScope) -> Result<Self, Self::Error> {
        match value {
            rpc::SitePrefixRoutingScope::DatacenterOnly => Ok(Self::DatacenterOnly),
            rpc::SitePrefixRoutingScope::Unspecified => Err(RpcDataConversionError::InvalidValue(
                "SitePrefixRoutingScope".to_string(),
                value.as_str_name().to_string(),
            )),
        }
    }
}

impl From<SitePrefixLifecycleState> for rpc::SitePrefixLifecycleState {
    fn from(value: SitePrefixLifecycleState) -> Self {
        match value {
            SitePrefixLifecycleState::Provisioning => Self::Provisioning,
            SitePrefixLifecycleState::Ready => Self::Ready,
            SitePrefixLifecycleState::Deleting => Self::Deleting,
            SitePrefixLifecycleState::Error => Self::Error,
        }
    }
}

impl TryFrom<rpc::SitePrefixLifecycleState> for SitePrefixLifecycleState {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::SitePrefixLifecycleState) -> Result<Self, RpcDataConversionError> {
        match value {
            rpc::SitePrefixLifecycleState::Provisioning => Ok(Self::Provisioning),
            rpc::SitePrefixLifecycleState::Ready => Ok(Self::Ready),
            rpc::SitePrefixLifecycleState::Deleting => Ok(Self::Deleting),
            rpc::SitePrefixLifecycleState::Error => Ok(Self::Error),
            rpc::SitePrefixLifecycleState::Unspecified => {
                Err(RpcDataConversionError::InvalidValue(
                    "SitePrefixLifecycleState".to_string(),
                    value.as_str_name().to_string(),
                ))
            }
        }
    }
}

impl From<SitePrefix> for rpc::SitePrefix {
    fn from(value: SitePrefix) -> Self {
        let SitePrefix {
            id,
            config,
            metadata,
            status,
            version,
            created_at,
            updated_at,
        } = value;

        Self {
            id: Some(id),
            config: Some(rpc::SitePrefixConfig {
                prefix: config.prefix.to_string(),
                tenant_organization_id: config
                    .tenant_organization_id
                    .map(|tenant_organization_id| tenant_organization_id.to_string()),
                routing_scope: rpc::SitePrefixRoutingScope::from(config.routing_scope) as i32,
            }),
            status: Some(rpc::SitePrefixStatus {
                authority: rpc::SitePrefixAuthority::from(status.authority) as i32,
                lifecycle_state: rpc::SitePrefixLifecycleState::from(status.lifecycle_state) as i32,
            }),
            metadata: Some(metadata.into()),
            version: version.version_string(),
            created_at: Some(created_at.into()),
            updated_at: Some(updated_at.into()),
        }
    }
}

impl TryFrom<rpc::SitePrefixSearchFilter> for SitePrefixSearchFilter {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::SitePrefixSearchFilter) -> Result<Self, Self::Error> {
        let tenant_organization_id = value
            .tenant_organization_id
            .map(|tenant_organization_id| {
                TenantOrganizationId::try_from(tenant_organization_id.clone())
                    .map_err(|_| RpcDataConversionError::InvalidTenantOrg(tenant_organization_id))
            })
            .transpose()?;

        let authority = value
            .authority
            .map(parse_site_prefix_authority)
            .transpose()?;
        let routing_scope = value
            .routing_scope
            .map(parse_site_prefix_routing_scope)
            .transpose()?;
        let lifecycle_state = value
            .lifecycle_state
            .map(parse_site_prefix_lifecycle_state)
            .transpose()?;

        let prefix_match = match (value.prefix_match, value.prefix_match_type) {
            (None, None) => None,
            (Some(prefix), Some(prefix_match_type)) => {
                let prefix = IpNetwork::try_from(prefix.as_str())?;
                let prefix_match_type =
                    rpc::PrefixMatchType::try_from(prefix_match_type).map_err(|_| {
                        RpcDataConversionError::InvalidValue(
                            "PrefixMatchType".to_string(),
                            prefix_match_type.to_string(),
                        )
                    })?;
                Some(match prefix_match_type {
                    rpc::PrefixMatchType::PrefixExact => PrefixMatch::Exact(prefix),
                    rpc::PrefixMatchType::PrefixContains => PrefixMatch::Contains(prefix),
                    rpc::PrefixMatchType::PrefixContainedBy => PrefixMatch::ContainedBy(prefix),
                })
            }
            (Some(_), None) => {
                return Err(RpcDataConversionError::MissingArgument("prefix_match_type"));
            }
            (None, Some(_)) => {
                return Err(RpcDataConversionError::InvalidArgument(
                    "prefix_match_type requires prefix_match".to_string(),
                ));
            }
        };

        Ok(Self {
            tenant_organization_id,
            authority,
            routing_scope,
            lifecycle_state,
            prefix_match,
        })
    }
}

fn parse_site_prefix_authority(value: i32) -> Result<SitePrefixAuthority, RpcDataConversionError> {
    let value = rpc::SitePrefixAuthority::try_from(value).map_err(|_| {
        RpcDataConversionError::InvalidValue("SitePrefixAuthority".to_string(), value.to_string())
    })?;
    value.try_into()
}

fn parse_site_prefix_routing_scope(
    value: i32,
) -> Result<SitePrefixRoutingScope, RpcDataConversionError> {
    let value = rpc::SitePrefixRoutingScope::try_from(value).map_err(|_| {
        RpcDataConversionError::InvalidValue(
            "SitePrefixRoutingScope".to_string(),
            value.to_string(),
        )
    })?;
    value.try_into()
}

fn parse_site_prefix_lifecycle_state(
    value: i32,
) -> Result<SitePrefixLifecycleState, RpcDataConversionError> {
    let value = rpc::SitePrefixLifecycleState::try_from(value).map_err(|_| {
        RpcDataConversionError::InvalidValue(
            "SitePrefixLifecycleState".to_string(),
            value.to_string(),
        )
    })?;
    value.try_into()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use carbide_test_support::Outcome::{Fails, Yields};
    use carbide_test_support::{Case, check_cases};
    use carbide_uuid::site_prefix::SitePrefixId;
    use chrono::{DateTime, Utc};
    use config_version::ConfigVersion;
    use model::metadata::Metadata;
    use model::site_prefix::{SitePrefixConfig, SitePrefixStatus};

    use super::*;

    #[derive(Debug, Default, Eq, PartialEq)]
    struct SearchFilterView {
        tenant_organization_id: Option<String>,
        authority: Option<SitePrefixAuthority>,
        routing_scope: Option<SitePrefixRoutingScope>,
        lifecycle_state: Option<SitePrefixLifecycleState>,
        prefix_match: Option<(&'static str, String)>,
    }

    impl From<SitePrefixSearchFilter> for SearchFilterView {
        fn from(value: SitePrefixSearchFilter) -> Self {
            let prefix_match = value.prefix_match.map(|prefix_match| match prefix_match {
                PrefixMatch::Exact(prefix) => ("exact", prefix.to_string()),
                PrefixMatch::Contains(prefix) => ("contains", prefix.to_string()),
                PrefixMatch::ContainedBy(prefix) => ("contained_by", prefix.to_string()),
            });

            Self {
                tenant_organization_id: value
                    .tenant_organization_id
                    .map(|tenant_organization_id| tenant_organization_id.to_string()),
                authority: value.authority,
                routing_scope: value.routing_scope,
                lifecycle_state: value.lifecycle_state,
                prefix_match,
            }
        }
    }

    #[test]
    fn site_prefix_search_filter_conversion_is_strict() {
        check_cases(
            [
                Case {
                    scenario: "empty filter returns the complete inventory",
                    input: rpc::SitePrefixSearchFilter::default(),
                    expect: Yields(SearchFilterView::default()),
                },
                Case {
                    scenario: "all scalar filters and exact prefix match",
                    input: rpc::SitePrefixSearchFilter {
                        tenant_organization_id: Some("tenant-a".to_string()),
                        authority: Some(rpc::SitePrefixAuthority::TenantManaged as i32),
                        routing_scope: Some(rpc::SitePrefixRoutingScope::DatacenterOnly as i32),
                        lifecycle_state: Some(rpc::SitePrefixLifecycleState::Provisioning as i32),
                        prefix_match: Some("10.0.0.0/8".to_string()),
                        prefix_match_type: Some(rpc::PrefixMatchType::PrefixExact as i32),
                    },
                    expect: Yields(SearchFilterView {
                        tenant_organization_id: Some("tenant-a".to_string()),
                        authority: Some(SitePrefixAuthority::TenantManaged),
                        routing_scope: Some(SitePrefixRoutingScope::DatacenterOnly),
                        lifecycle_state: Some(SitePrefixLifecycleState::Provisioning),
                        prefix_match: Some(("exact", "10.0.0.0/8".to_string())),
                    }),
                },
                Case {
                    scenario: "contains prefix match",
                    input: rpc::SitePrefixSearchFilter {
                        prefix_match: Some("10.0.0.0/24".to_string()),
                        prefix_match_type: Some(rpc::PrefixMatchType::PrefixContains as i32),
                        ..Default::default()
                    },
                    expect: Yields(SearchFilterView {
                        prefix_match: Some(("contains", "10.0.0.0/24".to_string())),
                        ..Default::default()
                    }),
                },
                Case {
                    scenario: "contained-by prefix match",
                    input: rpc::SitePrefixSearchFilter {
                        prefix_match: Some("10.0.0.0/8".to_string()),
                        prefix_match_type: Some(rpc::PrefixMatchType::PrefixContainedBy as i32),
                        ..Default::default()
                    },
                    expect: Yields(SearchFilterView {
                        prefix_match: Some(("contained_by", "10.0.0.0/8".to_string())),
                        ..Default::default()
                    }),
                },
                Case {
                    scenario: "invalid tenant organization ID",
                    input: rpc::SitePrefixSearchFilter {
                        tenant_organization_id: Some("tenant a".to_string()),
                        ..Default::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "unspecified authority",
                    input: rpc::SitePrefixSearchFilter {
                        authority: Some(rpc::SitePrefixAuthority::Unspecified as i32),
                        ..Default::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "unknown authority",
                    input: rpc::SitePrefixSearchFilter {
                        authority: Some(999),
                        ..Default::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "unspecified routing scope",
                    input: rpc::SitePrefixSearchFilter {
                        routing_scope: Some(rpc::SitePrefixRoutingScope::Unspecified as i32),
                        ..Default::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "unspecified lifecycle state",
                    input: rpc::SitePrefixSearchFilter {
                        lifecycle_state: Some(rpc::SitePrefixLifecycleState::Unspecified as i32),
                        ..Default::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "prefix without match type",
                    input: rpc::SitePrefixSearchFilter {
                        prefix_match: Some("10.0.0.0/8".to_string()),
                        ..Default::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "match type without prefix",
                    input: rpc::SitePrefixSearchFilter {
                        prefix_match_type: Some(rpc::PrefixMatchType::PrefixExact as i32),
                        ..Default::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "invalid prefix",
                    input: rpc::SitePrefixSearchFilter {
                        prefix_match: Some("not-a-prefix".to_string()),
                        prefix_match_type: Some(rpc::PrefixMatchType::PrefixExact as i32),
                        ..Default::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "unknown prefix match type",
                    input: rpc::SitePrefixSearchFilter {
                        prefix_match: Some("10.0.0.0/8".to_string()),
                        prefix_match_type: Some(999),
                        ..Default::default()
                    },
                    expect: Fails,
                },
            ],
            |filter| {
                SitePrefixSearchFilter::try_from(filter)
                    .map(SearchFilterView::from)
                    .map_err(drop)
            },
        );
    }

    #[test]
    fn site_prefix_model_to_rpc_conversion_covers_inventory_variants() {
        struct ConversionCase {
            scenario: &'static str,
            authority: SitePrefixAuthority,
            tenant_organization_id: Option<&'static str>,
            lifecycle_state: SitePrefixLifecycleState,
        }

        let cases = [
            ConversionCase {
                scenario: "configured ready",
                authority: SitePrefixAuthority::Configured,
                tenant_organization_id: None,
                lifecycle_state: SitePrefixLifecycleState::Ready,
            },
            ConversionCase {
                scenario: "configured deleting",
                authority: SitePrefixAuthority::Configured,
                tenant_organization_id: None,
                lifecycle_state: SitePrefixLifecycleState::Deleting,
            },
            ConversionCase {
                scenario: "tenant provisioning",
                authority: SitePrefixAuthority::TenantManaged,
                tenant_organization_id: Some("tenant-a"),
                lifecycle_state: SitePrefixLifecycleState::Provisioning,
            },
            ConversionCase {
                scenario: "tenant ready",
                authority: SitePrefixAuthority::TenantManaged,
                tenant_organization_id: Some("tenant-a"),
                lifecycle_state: SitePrefixLifecycleState::Ready,
            },
            ConversionCase {
                scenario: "tenant deleting",
                authority: SitePrefixAuthority::TenantManaged,
                tenant_organization_id: Some("tenant-a"),
                lifecycle_state: SitePrefixLifecycleState::Deleting,
            },
            ConversionCase {
                scenario: "tenant error",
                authority: SitePrefixAuthority::TenantManaged,
                tenant_organization_id: Some("tenant-a"),
                lifecycle_state: SitePrefixLifecycleState::Error,
            },
        ];

        for case in cases {
            let id = SitePrefixId::new();
            let created_at: DateTime<Utc> = "2026-07-23T12:00:00Z".parse().unwrap();
            let updated_at: DateTime<Utc> = "2026-07-23T12:01:00Z".parse().unwrap();
            let version = ConfigVersion::initial();
            let model = SitePrefix {
                id,
                config: SitePrefixConfig {
                    prefix: "10.0.0.0/8".parse().unwrap(),
                    tenant_organization_id: case
                        .tenant_organization_id
                        .map(|tenant_organization_id| tenant_organization_id.parse().unwrap()),
                    routing_scope: SitePrefixRoutingScope::DatacenterOnly,
                },
                metadata: Metadata {
                    name: "site-prefix".to_string(),
                    description: "conversion test".to_string(),
                    labels: HashMap::from([("env".to_string(), "test".to_string())]),
                },
                status: SitePrefixStatus {
                    authority: case.authority,
                    lifecycle_state: case.lifecycle_state,
                },
                version,
                created_at,
                updated_at,
            };

            let converted = rpc::SitePrefix::from(model);
            assert_eq!(converted.id, Some(id), "{}", case.scenario);
            assert_eq!(
                converted.version,
                version.version_string(),
                "{}",
                case.scenario
            );
            assert_eq!(
                DateTime::<Utc>::try_from(converted.created_at.unwrap()).unwrap(),
                created_at,
                "{}",
                case.scenario
            );
            assert_eq!(
                DateTime::<Utc>::try_from(converted.updated_at.unwrap()).unwrap(),
                updated_at,
                "{}",
                case.scenario
            );

            let config = converted.config.expect("config should be populated");
            assert_eq!(config.prefix, "10.0.0.0/8", "{}", case.scenario);
            assert_eq!(
                config.tenant_organization_id.as_deref(),
                case.tenant_organization_id,
                "{}",
                case.scenario
            );
            assert_eq!(
                rpc::SitePrefixRoutingScope::try_from(config.routing_scope).unwrap(),
                rpc::SitePrefixRoutingScope::DatacenterOnly,
                "{}",
                case.scenario
            );

            let status = converted.status.expect("status should be populated");
            assert_eq!(
                SitePrefixAuthority::try_from(
                    rpc::SitePrefixAuthority::try_from(status.authority).unwrap()
                )
                .unwrap(),
                case.authority,
                "{}",
                case.scenario
            );
            assert_eq!(
                SitePrefixLifecycleState::try_from(
                    rpc::SitePrefixLifecycleState::try_from(status.lifecycle_state).unwrap()
                )
                .unwrap(),
                case.lifecycle_state,
                "{}",
                case.scenario
            );

            let metadata = converted.metadata.expect("metadata should be populated");
            assert_eq!(metadata.name, "site-prefix", "{}", case.scenario);
            assert_eq!(metadata.description, "conversion test", "{}", case.scenario);
            assert_eq!(metadata.labels.len(), 1, "{}", case.scenario);
        }
    }
}
