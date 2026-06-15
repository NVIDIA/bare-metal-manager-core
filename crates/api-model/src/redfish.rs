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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::types::Json;
use sqlx::{FromRow, Row};

pub struct ActionRequest {
    pub request_id: i64,
    pub requester: String,
    pub approvers: Vec<String>,
    pub approver_dates: Vec<DateTime<Utc>>,
    pub machine_ips: Vec<String>,
    pub board_serials: Vec<String>,
    pub target: String,
    pub action: String,
    pub parameters: String,
    pub applied_at: Option<DateTime<Utc>>,
    pub applier: Option<String>,
    pub results: Vec<Option<BMCResponse>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BMCResponse {
    pub headers: HashMap<String, String>,
    pub status: String,
    pub body: String,
    pub completed_at: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for ActionRequest {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let request_id = row.try_get("request_id")?;
        let requester = row.try_get("requester")?;
        let approvers: Vec<_> = row.try_get("approvers")?;
        let approver_dates: Vec<_> = row.try_get("approver_dates")?;
        let machine_ips: Vec<String> = row.try_get("machine_ips")?;
        let board_serials: Vec<String> = row.try_get("board_serials")?;
        let target = row.try_get("target")?;
        let action = row.try_get("action")?;
        let parameters = row.try_get("parameters")?;
        let applied_at = row.try_get("applied_at")?;
        let applier = row.try_get("applier")?;
        let results: Option<Vec<Option<Json<BMCResponse>>>> = row.try_get("results")?;
        Ok(Self {
            request_id,
            requester,
            approvers,
            approver_dates,
            machine_ips,
            board_serials,
            target,
            action,
            parameters,
            applied_at,
            applier,
            results: results
                .unwrap_or_default()
                .into_iter()
                .map(|option| option.map(|json| json.0))
                .collect(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RedfishActionId {
    pub request_id: i64,
}

impl From<i64> for RedfishActionId {
    fn from(request_id: i64) -> Self {
        RedfishActionId { request_id }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RedfishListActionsFilter {
    pub machine_ip: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RedfishCreateAction {
    pub target: String,
    pub action: String,
    pub parameters: String,
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{scenarios, value_scenarios};

    use super::*;

    /// `From<i64>` is a plain field move; enumerate the integer boundaries it must
    /// carry through unchanged.
    #[test]
    fn redfish_action_id_from_i64_carries_the_value() {
        value_scenarios!(
            run = |n| RedfishActionId::from(n).request_id;
            "positive" {
                99i64 => 99i64,
            }

            "zero" {
                0 => 0,
            }

            "one" {
                1 => 1,
            }

            "negative" {
                -1 => -1,
            }

            "i64::MAX" {
                i64::MAX => i64::MAX,
            }

            "i64::MIN" {
                i64::MIN => i64::MIN,
            }
        );
    }

    #[test]
    fn redfish_action_id_is_copy() {
        let id = RedfishActionId { request_id: 1 };
        let id2 = id;
        assert_eq!(id.request_id, id2.request_id);
    }

    #[test]
    fn redfish_list_actions_filter_default_is_empty() {
        value_scenarios!(
            run = |filter| filter.machine_ip;
            "default leaves machine_ip unset" {
                RedfishListActionsFilter::default() => None,
            }
        );
    }

    fn bmc_response(status: &str, body: &str) -> BMCResponse {
        BMCResponse {
            headers: HashMap::new(),
            status: status.to_string(),
            body: body.to_string(),
            completed_at: DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
        }
    }

    /// `BMCResponse` is round-tripped through JSON when persisted; assert the
    /// serialized form survives a deserialize back to the same fields. The error
    /// type (`serde_json::Error`) isn't `PartialEq`, so map it away.
    #[test]
    fn bmc_response_round_trips_through_json() {
        scenarios!(
            run = |response| {
                let json = serde_json::to_string(&response).map_err(drop)?;
                let back: BMCResponse = serde_json::from_str(&json).map_err(drop)?;
                Ok::<_, ()>((back.status, back.body))
            };
            "ok with empty body" {
                bmc_response("200 OK", "") => Yields(("200 OK".to_string(), String::new())),
            }

            "ok with json body" {
                bmc_response("200 OK", r#"{"k":"v"}"#) => Yields(("200 OK".to_string(), r#"{"k":"v"}"#.to_string())),
            }

            "error status" {
                bmc_response("500 Internal Server Error", "boom") => Yields(("500 Internal Server Error".to_string(), "boom".to_string())),
            }

            "unicode body" {
                bmc_response("202 Accepted", "café ☕") => Yields(("202 Accepted".to_string(), "café ☕".to_string())),
            }
        );
    }

    /// Headers are an arbitrary map; assert the serialized form preserves a chosen
    /// key after the JSON round-trip.
    #[test]
    fn bmc_response_round_trip_preserves_headers() {
        scenarios!(
            run = |(key, value): (&str, &str)| {
                let mut headers = HashMap::new();
                headers.insert(key.to_string(), value.to_string());
                let response = BMCResponse {
                    headers,
                    status: "200 OK".to_string(),
                    body: String::new(),
                    completed_at: DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
                };
                let json = serde_json::to_string(&response).map_err(drop)?;
                let back: BMCResponse = serde_json::from_str(&json).map_err(drop)?;
                Ok::<_, ()>(back.headers.get(key).cloned())
            };
            "single header" {
                ("Content-Type", "application/json") => Yields(Some("application/json".to_string())),
            }

            "header value with spaces" {
                ("ETag", "W/\"abc 123\"") => Yields(Some("W/\"abc 123\"".to_string())),
            }

            "empty header value" {
                ("X-Empty", "") => Yields(Some(String::new())),
            }
        );
    }
}
