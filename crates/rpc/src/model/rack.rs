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

use model::rack::{Rack, RackSearchFilter, derive_rack_aggregate_health};

use crate as rpc;
use crate::Timestamp;
use crate::forge::LifecycleStatus;

impl From<Rack> for rpc::forge::Rack {
    fn from(value: Rack) -> Self {
        let health = derive_rack_aggregate_health(&value.health_reports);
        let health_sources = value
            .health_reports
            .iter()
            .map(|(hr, m)| rpc::forge::HealthSourceOrigin {
                mode: m as i32,
                source: hr.source.clone(),
            })
            .collect();

        let lifecycle = LifecycleStatus {
            state: serde_json::to_string(&value.controller_state.value).unwrap_or_default(),
            version: value.controller_state.version.version_string(),
            state_reason: value.controller_state_outcome.map(Into::into),
            sla: Some(rpc::forge::StateSla {
                sla: None, // TODO: Calculate SLA properly
                time_in_state_above_sla: false,
            }),
        };

        rpc::forge::Rack {
            id: Some(value.id),
            rack_state: value.controller_state.value.to_string(),
            created: Some(Timestamp::from(value.created)),
            updated: Some(Timestamp::from(value.updated)),
            deleted: value.deleted.map(Timestamp::from),
            metadata: Some(value.metadata.into()),
            version: value.version.version_string(),
            config: Some(rpc::forge::RackConfig {}),
            status: Some(rpc::forge::RackStatus {
                health: Some(health.into()),
                health_sources,
                lifecycle: Some(lifecycle),
            }),
        }
    }
}

impl From<rpc::forge::RackSearchFilter> for RackSearchFilter {
    fn from(filter: rpc::forge::RackSearchFilter) -> Self {
        RackSearchFilter {
            label: filter.label.map(model::metadata::LabelFilter::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::{Check, check_values};
    use carbide_uuid::rack::RackId;
    use chrono::{DateTime, TimeZone, Utc};
    use config_version::{ConfigVersion, Versioned};
    use model::metadata::{LabelFilter, Metadata};
    use model::rack::{
        LABEL_CHASSIS_MANUFACTURER, LABEL_LOCATION_DATACENTER, RackConfig, RackMaintenanceState,
        RackState, RackValidationState,
    };

    use super::*;

    // Build a model `Rack` whose only interesting fields are the controller
    // state (which drives `rack_state` and `lifecycle.state`) and `deleted`.
    // Everything else is held at a fixed, conversion-neutral value so each row
    // isolates the one projection it exercises.
    fn rack_with(state: RackState, deleted: Option<DateTime<Utc>>) -> Rack {
        Rack {
            id: RackId::default(),
            rack_profile_id: None,
            config: RackConfig::default(),
            controller_state: Versioned::new(state, ConfigVersion::new(7)),
            controller_state_outcome: None,
            firmware_upgrade_job: None,
            nvos_update_job: None,
            health_reports: Default::default(),
            created: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            updated: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            deleted,
            metadata: Metadata::default(),
            version: ConfigVersion::new(7),
        }
    }

    // `RackSearchFilter::from` maps the optional proto label onto the model's
    // optional `LabelFilter`; project to that `label` field for each input.
    #[test]
    fn rack_search_filter_from_rpc() {
        check_values(
            [
                Check {
                    scenario: "label with key and value",
                    input: rpc::forge::RackSearchFilter {
                        label: Some(rpc::forge::Label {
                            key: LABEL_LOCATION_DATACENTER.to_string(),
                            value: Some("az01".to_string()),
                        }),
                    },
                    expect: Some(LabelFilter {
                        key: LABEL_LOCATION_DATACENTER.to_string(),
                        value: Some("az01".to_string()),
                    }),
                },
                Check {
                    scenario: "label with key only",
                    input: rpc::forge::RackSearchFilter {
                        label: Some(rpc::forge::Label {
                            key: LABEL_CHASSIS_MANUFACTURER.to_string(),
                            value: None,
                        }),
                    },
                    expect: Some(LabelFilter {
                        key: LABEL_CHASSIS_MANUFACTURER.to_string(),
                        value: None,
                    }),
                },
                Check {
                    scenario: "no label",
                    input: rpc::forge::RackSearchFilter { label: None },
                    expect: None,
                },
            ],
            |rpc_filter| RackSearchFilter::from(rpc_filter).label,
        );
    }

    // `From<Rack>` copies the controller state through `RackState`'s `Display`
    // into the (deprecated) flat `rack_state` field. One row per enum arm,
    // including the nested `Validating`/`Maintenance`/`Error` payloads.
    #[test]
    fn rack_state_field_from_display() {
        check_values(
            [
                Check {
                    scenario: "created",
                    input: RackState::Created,
                    expect: "Created".to_string(),
                },
                Check {
                    scenario: "discovering",
                    input: RackState::Discovering,
                    expect: "Discovering".to_string(),
                },
                Check {
                    scenario: "ready",
                    input: RackState::Ready,
                    expect: "Ready".to_string(),
                },
                Check {
                    scenario: "deleting",
                    input: RackState::Deleting,
                    expect: "Deleting".to_string(),
                },
                Check {
                    scenario: "validating pending",
                    input: RackState::Validating {
                        validating_state: RackValidationState::Pending,
                    },
                    expect: "Validating(Pending)".to_string(),
                },
                Check {
                    scenario: "validating in progress",
                    input: RackState::Validating {
                        validating_state: RackValidationState::InProgress {
                            run_id: "r1".to_string(),
                        },
                    },
                    expect: "Validating(InProgress)".to_string(),
                },
                Check {
                    scenario: "maintenance completed",
                    input: RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::Completed,
                    },
                    expect: "Maintenance(Completed)".to_string(),
                },
                Check {
                    scenario: "error carries cause",
                    input: RackState::Error {
                        cause: "boom".to_string(),
                    },
                    expect: "Error(boom)".to_string(),
                },
            ],
            |state| rpc::forge::Rack::from(rack_with(state, None)).rack_state,
        );
    }

    // The `lifecycle.state` field carries the same controller state, but as the
    // serde-JSON of `RackState` (internally tagged on `state`, snake_case). Each
    // row pins the exact JSON for one arm so the serde contract is covered
    // alongside the `Display` projection above.
    #[test]
    fn lifecycle_state_field_from_serde_json() {
        check_values(
            [
                Check {
                    scenario: "created",
                    input: RackState::Created,
                    expect: r#"{"state":"created"}"#.to_string(),
                },
                Check {
                    scenario: "discovering",
                    input: RackState::Discovering,
                    expect: r#"{"state":"discovering"}"#.to_string(),
                },
                Check {
                    scenario: "ready",
                    input: RackState::Ready,
                    expect: r#"{"state":"ready"}"#.to_string(),
                },
                Check {
                    scenario: "deleting",
                    input: RackState::Deleting,
                    expect: r#"{"state":"deleting"}"#.to_string(),
                },
                Check {
                    scenario: "error carries cause",
                    input: RackState::Error {
                        cause: "boom".to_string(),
                    },
                    expect: r#"{"state":"error","cause":"boom"}"#.to_string(),
                },
            ],
            |state| {
                rpc::forge::Rack::from(rack_with(state, None))
                    .status
                    .and_then(|s| s.lifecycle)
                    .map(|l| l.state)
                    .unwrap_or_default()
            },
        );
    }

    // The optional `deleted` timestamp maps through only when present: `Some`
    // becomes a populated proto `Timestamp`, `None` stays `None`.
    #[test]
    fn deleted_timestamp_present_or_absent() {
        check_values(
            [
                Check {
                    scenario: "not deleted",
                    input: None,
                    expect: false,
                },
                Check {
                    scenario: "deleted",
                    input: Some(Utc.timestamp_opt(1_700_000_500, 0).unwrap()),
                    expect: true,
                },
            ],
            |deleted| {
                rpc::forge::Rack::from(rack_with(RackState::Ready, deleted))
                    .deleted
                    .is_some()
            },
        );
    }

    // `version` is serialized through `ConfigVersion::version_string`, and `id`
    // is wrapped verbatim into the optional proto field. Both are direct,
    // lossless mappings; fold each into a `bool` so one table can assert both.
    #[test]
    fn version_and_id_map_through() {
        check_values(
            [
                Check {
                    scenario: "version string matches ConfigVersion",
                    input: RackState::Ready,
                    expect: true,
                },
            ],
            |state| {
                let rack = rack_with(state, None);
                let want_version = rack.version.version_string();
                let want_id = rack.id.clone();
                let proto = rpc::forge::Rack::from(rack);
                proto.version == want_version && proto.id == Some(want_id)
            },
        );
    }
}
