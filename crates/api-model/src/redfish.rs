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

impl From<rpc::forge::RedfishActionId> for RedfishActionId {
    fn from(id: rpc::forge::RedfishActionId) -> Self {
        RedfishActionId {
            request_id: id.request_id,
        }
    }
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

impl From<rpc::forge::RedfishListActionsRequest> for RedfishListActionsFilter {
    fn from(req: rpc::forge::RedfishListActionsRequest) -> Self {
        RedfishListActionsFilter {
            machine_ip: req.machine_ip,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RedfishCreateAction {
    pub target: String,
    pub action: String,
    pub parameters: String,
}

impl From<rpc::forge::RedfishCreateActionRequest> for RedfishCreateAction {
    fn from(req: rpc::forge::RedfishCreateActionRequest) -> Self {
        RedfishCreateAction {
            target: req.target,
            action: req.action,
            parameters: req.parameters,
        }
    }
}

impl From<ActionRequest> for rpc::forge::RedfishAction {
    fn from(value: ActionRequest) -> Self {
        Self {
            request_id: value.request_id,
            requester: value.requester,
            approvers: value.approvers,
            approver_dates: value.approver_dates.into_iter().map(|d| d.into()).collect(),
            machine_ips: value.machine_ips,
            board_serials: value.board_serials,
            target: value.target,
            action: value.action,
            parameters: value.parameters,
            applied_at: value.applied_at.map(|t| t.into()),
            applier: value.applier,
            results: value
                .results
                .into_iter()
                .map(|r| rpc::forge::OptionalRedfishActionResult {
                    result: r.map(|r| rpc::forge::RedfishActionResult {
                        headers: r.headers,
                        status: r.status,
                        body: r.body,
                        completed_at: Some(r.completed_at.into()),
                    }),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redfish_action_id_from_rpc() {
        let rpc_id = rpc::forge::RedfishActionId { request_id: 42 };
        let id = RedfishActionId::from(rpc_id);
        assert_eq!(id.request_id, 42);
    }

    #[test]
    fn redfish_action_id_from_i64() {
        let id = RedfishActionId::from(99i64);
        assert_eq!(id.request_id, 99);
    }

    #[test]
    fn redfish_action_id_is_copy() {
        let id = RedfishActionId { request_id: 1 };
        let id2 = id;
        assert_eq!(id.request_id, id2.request_id);
    }

    #[test]
    fn redfish_list_actions_filter_from_rpc() {
        let rpc_req = rpc::forge::RedfishListActionsRequest {
            machine_ip: Some("10.0.0.1".to_string()),
        };
        let filter = RedfishListActionsFilter::from(rpc_req);
        assert_eq!(filter.machine_ip, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn redfish_create_action_from_rpc() {
        let rpc_req = rpc::forge::RedfishCreateActionRequest {
            ips: vec!["10.0.0.1".to_string()],
            action: "Reset".to_string(),
            target: "/redfish/v1/Systems/1/Actions".to_string(),
            parameters: r#"{"ResetType":"ForceRestart"}"#.to_string(),
        };
        let action = RedfishCreateAction::from(rpc_req);
        assert_eq!(action.action, "Reset");
        assert_eq!(action.target, "/redfish/v1/Systems/1/Actions");
        assert_eq!(action.parameters, r#"{"ResetType":"ForceRestart"}"#);
    }
}
