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

use chrono::{DateTime, Utc};
use health_report::{HealthReport, HealthReportApplyMode};
use serde::{Deserialize, Serialize};

/// History of health for a single Object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthHistoryRecord {
    /// The observed health of the Object
    pub health: health_report::HealthReport,

    /// The time when the health was observed
    pub time: DateTime<Utc>,
}

/// A collection of externally-managed health report sources.
///
/// External systems and operators can submit health reports via the API. These are
/// stored as a set of sources, each identified by the `HealthReport::source` field.
/// A single `replace` source can be set to completely override all other health data,
/// while multiple `merges` sources augment the existing health data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HealthReportSources {
    /// A health report that replaces all other health data when set.
    pub replace: Option<HealthReport>,
    /// A map from the health report source identifier to the health report.
    pub merges: BTreeMap<String, HealthReport>,
}

impl HealthReportSources {
    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> impl Iterator<Item = (HealthReport, HealthReportApplyMode)> {
        self.merges
            .into_values()
            .map(|r| (r, HealthReportApplyMode::Merge))
            .chain(self.replace.map(|r| (r, HealthReportApplyMode::Replace)))
    }
}

impl From<HealthHistoryRecord> for rpc::forge::HealthHistoryRecord {
    fn from(record: HealthHistoryRecord) -> rpc::forge::HealthHistoryRecord {
        rpc::forge::HealthHistoryRecord {
            health: Some(record.health.into()),
            time: Some(record.time.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_reports_default_is_empty() {
        let sources = HealthReportSources::default();
        assert!(sources.replace.is_none());
        assert!(sources.merges.is_empty());
        assert_eq!(sources.into_iter().count(), 0);
    }

    #[test]
    fn health_reports_into_iter_merges_only() {
        let mut sources = HealthReportSources::default();
        sources.merges.insert(
            "source-a".to_string(),
            HealthReport::empty("source-a".to_string()),
        );
        sources.merges.insert(
            "source-b".to_string(),
            HealthReport::empty("source-b".to_string()),
        );

        let items: Vec<_> = sources.into_iter().collect();
        assert_eq!(items.len(), 2);
        assert!(
            items
                .iter()
                .all(|(_, mode)| *mode == HealthReportApplyMode::Merge)
        );
    }

    #[test]
    fn health_reports_into_iter_replace_only() {
        let sources = HealthReportSources {
            replace: Some(HealthReport::empty("admin-replace".to_string())),
            merges: BTreeMap::new(),
        };

        let items: Vec<_> = sources.into_iter().collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0.source, "admin-replace");
        assert_eq!(items[0].1, HealthReportApplyMode::Replace);
    }

    #[test]
    fn health_reports_into_iter_mixed() {
        let mut merges = BTreeMap::new();
        merges.insert(
            "external-monitor".to_string(),
            HealthReport::empty("external-monitor".to_string()),
        );

        let sources = HealthReportSources {
            replace: Some(HealthReport::empty("sre-override".to_string())),
            merges,
        };

        let items: Vec<_> = sources.into_iter().collect();
        assert_eq!(items.len(), 2);

        let merge_items: Vec<_> = items
            .iter()
            .filter(|(_, mode)| *mode == HealthReportApplyMode::Merge)
            .collect();
        let replace_items: Vec<_> = items
            .iter()
            .filter(|(_, mode)| *mode == HealthReportApplyMode::Replace)
            .collect();
        assert_eq!(merge_items.len(), 1);
        assert_eq!(replace_items.len(), 1);
        assert_eq!(merge_items[0].0.source, "external-monitor");
        assert_eq!(replace_items[0].0.source, "sre-override");
    }

    #[test]
    fn health_reports_json_round_trip() {
        let mut merges = BTreeMap::new();
        merges.insert(
            "external-monitor".to_string(),
            HealthReport::empty("external-monitor".to_string()),
        );

        let sources = HealthReportSources {
            replace: Some(HealthReport::empty("admin-replace".to_string())),
            merges,
        };

        let json = serde_json::to_string(&sources).unwrap();
        let deserialized: HealthReportSources = serde_json::from_str(&json).unwrap();
        assert_eq!(sources, deserialized);
    }

    #[test]
    fn health_reports_deserialize_null_as_default() {
        // The DB column can be NULL, which gets deserialized as default
        let json = r#"{"merges":{}}"#;
        let sources: HealthReportSources = serde_json::from_str(json).unwrap();
        assert!(sources.replace.is_none());
        assert!(sources.merges.is_empty());
    }
}
