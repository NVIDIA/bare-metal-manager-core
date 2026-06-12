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
    use model::metadata::LabelFilter;
    use model::rack::{LABEL_CHASSIS_MANUFACTURER, LABEL_LOCATION_DATACENTER};

    use super::*;

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
}
