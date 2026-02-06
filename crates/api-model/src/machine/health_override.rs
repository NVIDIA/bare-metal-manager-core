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
