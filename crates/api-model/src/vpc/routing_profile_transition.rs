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

use carbide_uuid::vpc::VpcId;
use carbide_uuid::vpc_routing_profile_transition::VpcRoutingProfileTransitionId;
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use super::VpcRoutingProfileOverrides;

/// Durable stage of an operator-managed routing-profile and VNI transition.
///
/// Both pending states retain the source and target VNI leases. The state says
/// which endpoint is active in the VPC record while an operator verifies
/// dataplane convergence before explicitly finalizing the inactive lease.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum VpcRoutingProfileTransitionState {
    /// The target profile and VNI are active; the source lease is retained.
    CutoverPendingFinalize,
    /// The source profile and VNI are active after rollback; the target lease is retained.
    RollbackPendingFinalize,
    /// The cutover was accepted and the source lease was released.
    Finalized,
    /// The rollback was accepted and the target lease was released.
    RolledBack,
}

impl VpcRoutingProfileTransitionState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::RolledBack)
    }

    /// Whether this persisted state may advance directly to `next`.
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::CutoverPendingFinalize,
                Self::RollbackPendingFinalize | Self::Finalized
            ) | (
                Self::RollbackPendingFinalize,
                Self::CutoverPendingFinalize | Self::RolledBack
            )
        )
    }
}

/// Persisted history and recovery point for one VPC routing-profile transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VpcRoutingProfileTransition {
    pub id: VpcRoutingProfileTransitionId,
    pub vpc_id: VpcId,
    pub version: ConfigVersion,
    pub state: VpcRoutingProfileTransitionState,
    pub source_routing_profile_type: String,
    pub target_routing_profile_type: String,
    pub source_pool_name: String,
    pub target_pool_name: String,
    pub source_vni: i32,
    pub target_vni: i32,
    pub source_requested_vni: Option<i32>,
    pub target_requested_vni: Option<i32>,
    pub source_routing_profile_overrides: Option<VpcRoutingProfileOverrides>,
    pub target_routing_profile_overrides: Option<VpcRoutingProfileOverrides>,
    pub source_vpc_version: ConfigVersion,
    pub cutover_vpc_version: ConfigVersion,
    pub rollback_vpc_version: Option<ConfigVersion>,
    pub reason: String,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub completed: Option<DateTime<Utc>>,
}

/// Immutable provenance captured when a cutover first reserves its target VNI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewVpcRoutingProfileTransition {
    pub id: VpcRoutingProfileTransitionId,
    pub vpc_id: VpcId,
    pub source_routing_profile_type: String,
    pub target_routing_profile_type: String,
    pub source_pool_name: String,
    pub target_pool_name: String,
    pub source_vni: i32,
    pub target_vni: i32,
    pub source_requested_vni: Option<i32>,
    pub target_requested_vni: Option<i32>,
    pub source_routing_profile_overrides: Option<VpcRoutingProfileOverrides>,
    pub target_routing_profile_overrides: Option<VpcRoutingProfileOverrides>,
    pub source_vpc_version: ConfigVersion,
    pub cutover_vpc_version: ConfigVersion,
    pub reason: String,
}

/// Optimistic state update after the associated VPC change has been persisted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateVpcRoutingProfileTransitionState {
    pub id: VpcRoutingProfileTransitionId,
    pub if_version_match: ConfigVersion,
    /// Persisted predecessor required for this exact state-machine edge.
    pub expected_state: VpcRoutingProfileTransitionState,
    pub state: VpcRoutingProfileTransitionState,
    /// Set when entering or re-entering the cutover-pending stage.
    pub cutover_vpc_version: Option<ConfigVersion>,
    /// Set when entering the rollback-pending stage.
    pub rollback_vpc_version: Option<ConfigVersion>,
}

impl<'r> FromRow<'r, PgRow> for VpcRoutingProfileTransition {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let source_routing_profile_overrides = row
            .try_get::<Option<sqlx::types::Json<VpcRoutingProfileOverrides>>, _>(
                "source_routing_profile_overrides",
            )?
            .map(|overrides| overrides.0);
        let target_routing_profile_overrides = row
            .try_get::<Option<sqlx::types::Json<VpcRoutingProfileOverrides>>, _>(
                "target_routing_profile_overrides",
            )?
            .map(|overrides| overrides.0);

        Ok(Self {
            id: row.try_get("id")?,
            vpc_id: row.try_get("vpc_id")?,
            version: row.try_get("version")?,
            state: row.try_get("state")?,
            source_routing_profile_type: row.try_get("source_routing_profile_type")?,
            target_routing_profile_type: row.try_get("target_routing_profile_type")?,
            source_pool_name: row.try_get("source_pool_name")?,
            target_pool_name: row.try_get("target_pool_name")?,
            source_vni: row.try_get("source_vni")?,
            target_vni: row.try_get("target_vni")?,
            source_requested_vni: row.try_get("source_requested_vni")?,
            target_requested_vni: row.try_get("target_requested_vni")?,
            source_routing_profile_overrides,
            target_routing_profile_overrides,
            source_vpc_version: row.try_get("source_vpc_version")?,
            cutover_vpc_version: row.try_get("cutover_vpc_version")?,
            rollback_vpc_version: row.try_get("rollback_vpc_version")?,
            reason: row.try_get("reason")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            completed: row.try_get("completed")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;

    use super::VpcRoutingProfileTransitionState::*;

    #[test]
    fn terminal_state_classification_is_exhaustive() {
        value_scenarios!(run = |state| state.is_terminal();
            "leases are retained" {
                CutoverPendingFinalize => false,
                RollbackPendingFinalize => false,
            }
            "inactive lease was released" {
                Finalized => true,
                RolledBack => true,
            }
        );
    }
}
