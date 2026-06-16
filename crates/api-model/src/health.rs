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
    /// True when a repair-related health merge override is active (`repair-request` or
    /// `request-online-repair`).
    pub fn repair_merge_active(&self) -> bool {
        self.merges
            .contains_key(health_report::REPAIR_REQUEST_MERGE_SOURCE)
            || self
                .merges
                .contains_key(health_report::REQUEST_ONLINE_REPAIR_MERGE_SOURCE)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn iter(&self) -> impl Iterator<Item = (&HealthReport, HealthReportApplyMode)> {
        self.merges
            .values()
            .map(|r| (r, HealthReportApplyMode::Merge))
            .chain(
                self.replace
                    .as_ref()
                    .map(|r| (r, HealthReportApplyMode::Replace)),
            )
    }

    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> impl Iterator<Item = (HealthReport, HealthReportApplyMode)> {
        self.merges
            .into_values()
            .map(|r| (r, HealthReportApplyMode::Merge))
            .chain(self.replace.map(|r| (r, HealthReportApplyMode::Replace)))
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases, scenarios};

    use super::*;

    /// Build a `HealthReportSources` from a replace source name and a list of merge
    /// source names, using empty reports keyed by their own source identifier.
    fn sources(replace: Option<&str>, merges: &[&str]) -> HealthReportSources {
        HealthReportSources {
            replace: replace.map(|s| HealthReport::empty(s.to_string())),
            merges: merges
                .iter()
                .map(|s| (s.to_string(), HealthReport::empty(s.to_string())))
                .collect(),
        }
    }

    #[test]
    fn health_reports_default_is_empty() {
        let sources = HealthReportSources::default();
        assert!(sources.replace.is_none());
        assert!(sources.merges.is_empty());
        assert_eq!(sources.into_iter().count(), 0);
    }

    #[test]
    fn health_reports_into_iter() {
        // `into_iter` yields every merge source as `Merge` followed by the replace
        // source (if any) as `Replace`. Each row projects the iterator to a list of
        // (source name, apply mode) pairs so the ordering and modes are asserted
        // directly. This is infallible, so every row `Yields`.
        check_cases(
            [
                Case {
                    scenario: "empty yields nothing",
                    input: sources(None, &[]),
                    expect: Yields(vec![]),
                },
                Case {
                    scenario: "single merge",
                    input: sources(None, &["only"]),
                    expect: Yields(vec![("only".to_string(), HealthReportApplyMode::Merge)]),
                },
                Case {
                    scenario: "merges only",
                    input: sources(None, &["source-a", "source-b"]),
                    expect: Yields(vec![
                        ("source-a".to_string(), HealthReportApplyMode::Merge),
                        ("source-b".to_string(), HealthReportApplyMode::Merge),
                    ]),
                },
                Case {
                    // The map is keyed by source name, so iteration follows the
                    // BTreeMap's sorted key order regardless of insertion order.
                    scenario: "merges sorted by source key, not insertion order",
                    input: sources(None, &["zebra", "alpha", "mike"]),
                    expect: Yields(vec![
                        ("alpha".to_string(), HealthReportApplyMode::Merge),
                        ("mike".to_string(), HealthReportApplyMode::Merge),
                        ("zebra".to_string(), HealthReportApplyMode::Merge),
                    ]),
                },
                Case {
                    scenario: "replace only",
                    input: sources(Some("admin-replace"), &[]),
                    expect: Yields(vec![(
                        "admin-replace".to_string(),
                        HealthReportApplyMode::Replace,
                    )]),
                },
                Case {
                    scenario: "mixed merge and replace",
                    input: sources(Some("sre-override"), &["external-monitor"]),
                    expect: Yields(vec![
                        ("external-monitor".to_string(), HealthReportApplyMode::Merge),
                        ("sre-override".to_string(), HealthReportApplyMode::Replace),
                    ]),
                },
                Case {
                    // The replace source always trails the merges, even when its name
                    // would sort before them.
                    scenario: "replace trails merges regardless of its name",
                    input: sources(Some("aaa-replace"), &["mmm", "zzz"]),
                    expect: Yields(vec![
                        ("mmm".to_string(), HealthReportApplyMode::Merge),
                        ("zzz".to_string(), HealthReportApplyMode::Merge),
                        ("aaa-replace".to_string(), HealthReportApplyMode::Replace),
                    ]),
                },
            ],
            |sources: HealthReportSources| {
                Ok::<_, ()>(
                    sources
                        .into_iter()
                        .map(|(report, mode)| (report.source, mode))
                        .collect::<Vec<_>>(),
                )
            },
        );
    }

    #[test]
    fn health_reports_iter() {
        // `iter` borrows rather than consuming, but yields the same (source, mode)
        // sequence as `into_iter`: merges first in sorted key order, then the
        // replace source. Infallible, so every row `Yields`.
        scenarios!(
            run = |sources: HealthReportSources| {
                Ok::<_, ()>(
                    sources
                        .iter()
                        .map(|(report, mode)| (report.source.clone(), mode))
                        .collect::<Vec<_>>(),
                )
            };
            "empty borrows nothing" {
                sources(None, &[]) => Yields(vec![]),
            }

            "merges only" {
                sources(None, &["source-b", "source-a"]) => Yields(vec![
                    ("source-a".to_string(), HealthReportApplyMode::Merge),
                    ("source-b".to_string(), HealthReportApplyMode::Merge),
                ]),
            }

            "replace only" {
                sources(Some("admin-replace"), &[]) => Yields(vec![(
                    "admin-replace".to_string(),
                    HealthReportApplyMode::Replace,
                )]),
            }

            "mixed merge and replace" {
                sources(Some("sre-override"), &["external-monitor"]) => Yields(vec![
                    ("external-monitor".to_string(), HealthReportApplyMode::Merge),
                    ("sre-override".to_string(), HealthReportApplyMode::Replace),
                ]),
            }
        );
    }

    #[test]
    fn health_reports_repair_merge_active() {
        // `repair_merge_active` is true exactly when a merge source named
        // `repair-request` or `request-online-repair` is present. The replace slot
        // is irrelevant, as are unrelated merge sources. Infallible predicate, so
        // every row `Yields` a bool.
        check_cases(
            [
                Case {
                    scenario: "no sources at all",
                    input: sources(None, &[]),
                    expect: Yields(false),
                },
                Case {
                    scenario: "only unrelated merges",
                    input: sources(None, &["external-monitor", "sre"]),
                    expect: Yields(false),
                },
                Case {
                    scenario: "repair-request merge present",
                    input: sources(None, &[health_report::REPAIR_REQUEST_MERGE_SOURCE]),
                    expect: Yields(true),
                },
                Case {
                    scenario: "request-online-repair merge present",
                    input: sources(None, &[health_report::REQUEST_ONLINE_REPAIR_MERGE_SOURCE]),
                    expect: Yields(true),
                },
                Case {
                    scenario: "both repair merges present",
                    input: sources(
                        None,
                        &[
                            health_report::REPAIR_REQUEST_MERGE_SOURCE,
                            health_report::REQUEST_ONLINE_REPAIR_MERGE_SOURCE,
                        ],
                    ),
                    expect: Yields(true),
                },
                Case {
                    scenario: "repair merge alongside unrelated merges",
                    input: sources(
                        None,
                        &[
                            "external-monitor",
                            health_report::REPAIR_REQUEST_MERGE_SOURCE,
                        ],
                    ),
                    expect: Yields(true),
                },
                Case {
                    // The repair signal lives in the merges map; a replace source by
                    // the same name does not count.
                    scenario: "repair name in replace slot does not count",
                    input: sources(Some(health_report::REPAIR_REQUEST_MERGE_SOURCE), &[]),
                    expect: Yields(false),
                },
                Case {
                    scenario: "repair merge present with an unrelated replace",
                    input: sources(
                        Some("admin-replace"),
                        &[health_report::REQUEST_ONLINE_REPAIR_MERGE_SOURCE],
                    ),
                    expect: Yields(true),
                },
            ],
            |sources: HealthReportSources| Ok::<_, ()>(sources.repair_merge_active()),
        );
    }

    #[test]
    fn health_reports_deserialize() {
        // `HealthReportSources` deserializes from JSON. A full round-trip (serialize
        // then deserialize) must reproduce the original, and a partial document
        // (the DB column can be NULL / absent `replace`) deserializes to default.
        // Deserialization is fallible; `serde_json::Error` is not PartialEq, so
        // failing rows would use `Fails`, but every case here is valid input.
        let round_trip = sources(Some("admin-replace"), &["external-monitor"]);
        let round_trip_json = serde_json::to_string(&round_trip).unwrap();

        scenarios!(
            run = |json: &str| serde_json::from_str::<HealthReportSources>(json).map_err(|_| ());
            "round trips serialized form" {
                round_trip_json.as_str() => Yields(round_trip),
            }

            "null replace deserializes to default" {
                r#"{"merges":{}}"# => Yields(HealthReportSources::default()),
            }
        );
    }
}
