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

use carbide_uuid::site_prefix::SitePrefixId;
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::ConfigValidationError;
use crate::metadata::Metadata;
use crate::tenant::TenantOrganizationId;

/// Identifies which lifecycle authority owns a site prefix.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, sqlx::Type)]
#[sqlx(type_name = "site_prefix_authority")]
#[sqlx(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SitePrefixAuthority {
    Configured,
    TenantManaged,
}

/// Describes where a site prefix may be routed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, sqlx::Type)]
#[sqlx(type_name = "site_prefix_routing_scope")]
#[sqlx(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SitePrefixRoutingScope {
    DatacenterOnly,
}

/// Tenant-facing lifecycle state for a site prefix.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, sqlx::Type)]
#[sqlx(type_name = "site_prefix_lifecycle_state")]
#[sqlx(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SitePrefixLifecycleState {
    Provisioning,
    Ready,
    Deleting,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SitePrefix {
    pub id: SitePrefixId,
    pub config: SitePrefixConfig,
    pub metadata: Metadata,
    pub status: SitePrefixStatus,
    pub version: ConfigVersion,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SitePrefixConfig {
    pub prefix: IpNetwork,
    pub tenant_organization_id: Option<TenantOrganizationId>,
    pub routing_scope: SitePrefixRoutingScope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SitePrefixStatus {
    pub authority: SitePrefixAuthority,
    pub lifecycle_state: SitePrefixLifecycleState,
}

/// A site prefix before it is persisted.
#[derive(Clone, Debug)]
pub struct NewSitePrefix {
    pub id: SitePrefixId,
    pub config: SitePrefixConfig,
    pub metadata: Metadata,
    pub status: SitePrefixStatus,
}

impl NewSitePrefix {
    /// Builds the database representation of a configured site fabric prefix.
    pub fn configured(prefix: IpNetwork) -> Self {
        let prefix = IpNetwork::new(prefix.network(), prefix.prefix())
            .expect("an existing IP network has a valid prefix length");
        Self {
            id: SitePrefixId::new(),
            config: SitePrefixConfig {
                prefix,
                tenant_organization_id: None,
                routing_scope: SitePrefixRoutingScope::DatacenterOnly,
            },
            metadata: Metadata {
                name: prefix.to_string(),
                ..Metadata::default()
            },
            status: SitePrefixStatus {
                authority: SitePrefixAuthority::Configured,
                lifecycle_state: SitePrefixLifecycleState::Ready,
            },
        }
    }

    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        let prefix = self.config.prefix;
        if prefix.ip() != prefix.network() {
            return Err(ConfigValidationError::invalid_value(format!(
                "site prefix {prefix} is not in canonical CIDR form"
            )));
        }

        match (
            self.status.authority,
            self.config.tenant_organization_id.is_some(),
        ) {
            (SitePrefixAuthority::Configured, false)
            | (SitePrefixAuthority::TenantManaged, true) => {}
            (SitePrefixAuthority::Configured, true) => {
                return Err(ConfigValidationError::invalid_value(
                    "a configured site prefix cannot have a tenant owner",
                ));
            }
            (SitePrefixAuthority::TenantManaged, false) => {
                return Err(ConfigValidationError::invalid_value(
                    "a tenant-managed site prefix requires a tenant owner",
                ));
            }
        }

        if self.status.authority == SitePrefixAuthority::Configured
            && !matches!(
                self.status.lifecycle_state,
                SitePrefixLifecycleState::Ready | SitePrefixLifecycleState::Deleting
            )
        {
            return Err(ConfigValidationError::invalid_value(
                "a configured site prefix must be ready or deleting",
            ));
        }

        self.metadata.validate(false)
    }
}

#[derive(Clone, Debug)]
pub enum PrefixMatch {
    Exact(IpNetwork),
    Contains(IpNetwork),
    ContainedBy(IpNetwork),
}

#[derive(Clone, Debug, Default)]
pub struct SitePrefixSearchFilter {
    pub tenant_organization_id: Option<TenantOrganizationId>,
    pub authority: Option<SitePrefixAuthority>,
    pub routing_scope: Option<SitePrefixRoutingScope>,
    pub lifecycle_state: Option<SitePrefixLifecycleState>,
    pub prefix_match: Option<PrefixMatch>,
}

impl<'r> FromRow<'r, PgRow> for SitePrefix {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("labels")?;

        Ok(Self {
            id: row.try_get("id")?,
            config: SitePrefixConfig {
                prefix: row.try_get("prefix")?,
                tenant_organization_id: row.try_get("tenant_organization_id")?,
                routing_scope: row.try_get("routing_scope")?,
            },
            metadata: Metadata {
                name: row.try_get("name")?,
                description: row.try_get("description")?,
                labels: labels.0,
            },
            status: SitePrefixStatus {
                authority: row.try_get("authority")?,
                lifecycle_state: row.try_get("lifecycle_state")?,
            },
            version: row.try_get("version")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::{Fails, Yields};
    use carbide_test_support::{Case, check_cases};

    use super::*;

    fn site_prefix(
        prefix: &str,
        authority: SitePrefixAuthority,
        tenant_organization_id: Option<&str>,
        lifecycle_state: SitePrefixLifecycleState,
    ) -> NewSitePrefix {
        NewSitePrefix {
            id: SitePrefixId::new(),
            config: SitePrefixConfig {
                prefix: prefix.parse().unwrap(),
                tenant_organization_id: tenant_organization_id.map(|id| id.parse().unwrap()),
                routing_scope: SitePrefixRoutingScope::DatacenterOnly,
            },
            metadata: Metadata::default(),
            status: SitePrefixStatus {
                authority,
                lifecycle_state,
            },
        }
    }

    #[test]
    fn validate_site_prefix_invariants() {
        check_cases(
            [
                Case {
                    scenario: "configured prefix",
                    input: site_prefix(
                        "10.0.0.0/8",
                        SitePrefixAuthority::Configured,
                        None,
                        SitePrefixLifecycleState::Ready,
                    ),
                    expect: Yields(()),
                },
                Case {
                    scenario: "configured prefix being deleted",
                    input: site_prefix(
                        "10.0.0.0/8",
                        SitePrefixAuthority::Configured,
                        None,
                        SitePrefixLifecycleState::Deleting,
                    ),
                    expect: Yields(()),
                },
                Case {
                    scenario: "tenant-managed prefix",
                    input: site_prefix(
                        "10.0.0.0/8",
                        SitePrefixAuthority::TenantManaged,
                        Some("tenant-a"),
                        SitePrefixLifecycleState::Provisioning,
                    ),
                    expect: Yields(()),
                },
                Case {
                    scenario: "noncanonical prefix",
                    input: site_prefix(
                        "10.0.0.1/24",
                        SitePrefixAuthority::Configured,
                        None,
                        SitePrefixLifecycleState::Ready,
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "configured prefix with tenant owner",
                    input: site_prefix(
                        "10.0.0.0/8",
                        SitePrefixAuthority::Configured,
                        Some("tenant-a"),
                        SitePrefixLifecycleState::Ready,
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "tenant-managed prefix without owner",
                    input: site_prefix(
                        "10.0.0.0/8",
                        SitePrefixAuthority::TenantManaged,
                        None,
                        SitePrefixLifecycleState::Provisioning,
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "configured prefix in provisioning",
                    input: site_prefix(
                        "10.0.0.0/8",
                        SitePrefixAuthority::Configured,
                        None,
                        SitePrefixLifecycleState::Provisioning,
                    ),
                    expect: Fails,
                },
            ],
            |site_prefix| site_prefix.validate().map_err(drop),
        );
    }
}
