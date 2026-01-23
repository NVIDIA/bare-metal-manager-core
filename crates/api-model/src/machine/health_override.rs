/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::BTreeMap;

use health_report::{HealthReport, OverrideMode};
use serde::{Deserialize, Serialize};

/// All health report overrides stored as JSON in postgres.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HealthReportOverrides {
    /// Stores the "replace" override
    /// The "replace" mode was called "override" in the past
    pub replace: Option<HealthReport>,
    /// A map from the health report source to the health report
    pub merges: BTreeMap<String, HealthReport>,
}

pub struct MaintenanceOverride {
    pub maintenance_reference: String,
    pub maintenance_start_time: Option<rpc::Timestamp>,
}

impl HealthReportOverrides {
    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> impl Iterator<Item = (HealthReport, OverrideMode)> {
        self.merges
            .into_values()
            .map(|r| (r, OverrideMode::Merge))
            .chain(self.replace.map(|r| (r, OverrideMode::Replace)))
    }

    /// Derive legacy Maintenance mode fields
    /// They are determine by the value of a well-known health override, that is also set
    /// via SetMaintenance API
    pub fn maintenance_override(&self) -> Option<MaintenanceOverride> {
        let ovr = self.merges.get("maintenance")?;
        let maintenance_alert_id = "Maintenance".parse().unwrap();
        let alert = ovr
            .alerts
            .iter()
            .find(|alert| alert.id == maintenance_alert_id)?;
        Some(MaintenanceOverride {
            maintenance_reference: alert.message.clone(),
            maintenance_start_time: alert.in_alert_since.map(rpc::Timestamp::from),
        })
    }
}
