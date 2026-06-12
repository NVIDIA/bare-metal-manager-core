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

use model::redfish::{
    ActionRequest, RedfishActionId, RedfishCreateAction, RedfishListActionsFilter,
};

use crate as rpc;

impl From<rpc::forge::RedfishActionId> for RedfishActionId {
    fn from(id: rpc::forge::RedfishActionId) -> Self {
        RedfishActionId {
            request_id: id.request_id,
        }
    }
}

impl From<rpc::forge::RedfishListActionsRequest> for RedfishListActionsFilter {
    fn from(req: rpc::forge::RedfishListActionsRequest) -> Self {
        RedfishListActionsFilter {
            machine_ip: req.machine_ip,
        }
    }
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
    use std::collections::HashMap;

    use chrono::{DateTime, TimeZone, Utc};
    use model::redfish::BMCResponse;
    use rpc::Timestamp;

    use carbide_test_support::{Check, check_values};

    use super::*;

    // A fixed instant used throughout, so timestamp conversions are deterministic.
    fn instant() -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000, 0).single().unwrap()
    }

    // The proto timestamp the conversions produce for `instant()`.
    fn proto_instant() -> Timestamp {
        Timestamp::from(instant())
    }

    // A minimal `ActionRequest` with all collections empty and optionals absent;
    // rows below override only the field under test.
    fn empty_action_request() -> ActionRequest {
        ActionRequest {
            request_id: 0,
            requester: String::new(),
            approvers: vec![],
            approver_dates: vec![],
            machine_ips: vec![],
            board_serials: vec![],
            target: String::new(),
            action: String::new(),
            parameters: String::new(),
            applied_at: None,
            applier: None,
            results: vec![],
        }
    }

    // `From<rpc::forge::RedfishActionId>` carries the request id through, across sign.
    #[test]
    fn redfish_action_id_from_rpc() {
        check_values(
            [
                Check {
                    scenario: "positive request id passes through",
                    input: rpc::forge::RedfishActionId { request_id: 42 },
                    expect: 42i64,
                },
                Check {
                    scenario: "zero request id passes through",
                    input: rpc::forge::RedfishActionId { request_id: 0 },
                    expect: 0i64,
                },
                Check {
                    scenario: "negative request id passes through",
                    input: rpc::forge::RedfishActionId { request_id: -7 },
                    expect: -7i64,
                },
            ],
            |id| RedfishActionId::from(id).request_id,
        );
    }

    // `From<rpc::forge::RedfishListActionsRequest>` carries the machine ip filter,
    // present and absent.
    #[test]
    fn redfish_list_actions_filter_from_rpc() {
        check_values(
            [
                Check {
                    scenario: "machine ip present passes through",
                    input: rpc::forge::RedfishListActionsRequest {
                        machine_ip: Some("10.0.0.1".to_string()),
                    },
                    expect: Some("10.0.0.1".to_string()),
                },
                Check {
                    scenario: "machine ip absent stays absent",
                    input: rpc::forge::RedfishListActionsRequest { machine_ip: None },
                    expect: None,
                },
            ],
            |req| RedfishListActionsFilter::from(req).machine_ip,
        );
    }

    // `From<rpc::forge::RedfishCreateActionRequest>` maps action/target/parameters
    // across and drops the `ips` field, which the domain type does not hold.
    #[test]
    fn redfish_create_action_from_rpc() {
        check_values(
            [
                Check {
                    scenario: "action, target, and parameters map across",
                    input: rpc::forge::RedfishCreateActionRequest {
                        ips: vec!["10.0.0.1".to_string()],
                        action: "Reset".to_string(),
                        target: "/redfish/v1/Systems/1/Actions".to_string(),
                        parameters: r#"{"ResetType":"ForceRestart"}"#.to_string(),
                    },
                    expect: (
                        "Reset".to_string(),
                        "/redfish/v1/Systems/1/Actions".to_string(),
                        r#"{"ResetType":"ForceRestart"}"#.to_string(),
                    ),
                },
                Check {
                    scenario: "empty strings map across unchanged",
                    input: rpc::forge::RedfishCreateActionRequest {
                        ips: vec![],
                        action: String::new(),
                        target: String::new(),
                        parameters: String::new(),
                    },
                    expect: (String::new(), String::new(), String::new()),
                },
            ],
            |req| {
                let action = RedfishCreateAction::from(req);
                (action.action, action.target, action.parameters)
            },
        );
    }

    // `From<ActionRequest> for rpc::forge::RedfishAction` carries the scalar and
    // repeated string fields through unchanged.
    #[test]
    fn redfish_action_from_request_scalar_fields() {
        check_values(
            [
                Check {
                    scenario: "request id passes through",
                    input: ActionRequest {
                        request_id: -5,
                        ..empty_action_request()
                    },
                    expect: rpc::forge::RedfishAction {
                        request_id: -5,
                        ..Default::default()
                    },
                },
                Check {
                    scenario: "requester, target, action, parameters pass through",
                    input: ActionRequest {
                        requester: "alice".to_string(),
                        target: "/redfish/v1/Systems/1".to_string(),
                        action: "Reset".to_string(),
                        parameters: r#"{"ResetType":"On"}"#.to_string(),
                        ..empty_action_request()
                    },
                    expect: rpc::forge::RedfishAction {
                        requester: "alice".to_string(),
                        target: "/redfish/v1/Systems/1".to_string(),
                        action: "Reset".to_string(),
                        parameters: r#"{"ResetType":"On"}"#.to_string(),
                        ..Default::default()
                    },
                },
                Check {
                    scenario: "approvers, machine ips, board serials pass through",
                    input: ActionRequest {
                        approvers: vec!["bob".to_string(), "carol".to_string()],
                        machine_ips: vec!["10.0.0.1".to_string()],
                        board_serials: vec!["SN-1".to_string(), "SN-2".to_string()],
                        ..empty_action_request()
                    },
                    expect: rpc::forge::RedfishAction {
                        approvers: vec!["bob".to_string(), "carol".to_string()],
                        machine_ips: vec!["10.0.0.1".to_string()],
                        board_serials: vec!["SN-1".to_string(), "SN-2".to_string()],
                        ..Default::default()
                    },
                },
            ],
            rpc::forge::RedfishAction::from,
        );
    }

    // `From<ActionRequest> for rpc::forge::RedfishAction` maps the timestamp-bearing
    // fields: the repeated `approver_dates` and the optional `applied_at`/`applier`.
    #[test]
    fn redfish_action_from_request_timestamps() {
        check_values(
            [
                Check {
                    scenario: "empty approver dates stay empty",
                    input: empty_action_request(),
                    expect: vec![],
                },
                Check {
                    scenario: "approver dates convert to proto timestamps",
                    input: ActionRequest {
                        approver_dates: vec![instant()],
                        ..empty_action_request()
                    },
                    expect: vec![proto_instant()],
                },
            ],
            |req| rpc::forge::RedfishAction::from(req).approver_dates,
        );
    }

    // The optional `applied_at` timestamp: present becomes `Some(ts)`, absent stays `None`.
    #[test]
    fn redfish_action_from_request_applied_at() {
        check_values(
            [
                Check {
                    scenario: "applied_at absent stays None",
                    input: empty_action_request(),
                    expect: None,
                },
                Check {
                    scenario: "applied_at present becomes Some timestamp",
                    input: ActionRequest {
                        applied_at: Some(instant()),
                        ..empty_action_request()
                    },
                    expect: Some(proto_instant()),
                },
            ],
            |req| rpc::forge::RedfishAction::from(req).applied_at,
        );
    }

    // The optional `applier` string: present and absent.
    #[test]
    fn redfish_action_from_request_applier() {
        check_values(
            [
                Check {
                    scenario: "applier absent stays None",
                    input: empty_action_request(),
                    expect: None,
                },
                Check {
                    scenario: "applier present passes through",
                    input: ActionRequest {
                        applier: Some("operator".to_string()),
                        ..empty_action_request()
                    },
                    expect: Some("operator".to_string()),
                },
            ],
            |req| rpc::forge::RedfishAction::from(req).applier,
        );
    }

    // `results` is a vec of `Option<BMCResponse>`: each `None` arm becomes an
    // `OptionalRedfishActionResult { result: None }`, each `Some` becomes a populated
    // `RedfishActionResult` with `completed_at` always present.
    #[test]
    fn redfish_action_from_request_results() {
        let response = || BMCResponse {
            headers: HashMap::from([("Location".to_string(), "/task/1".to_string())]),
            status: "200 OK".to_string(),
            body: r#"{"ok":true}"#.to_string(),
            completed_at: instant(),
        };

        check_values(
            [
                Check {
                    scenario: "empty results stay empty",
                    input: empty_action_request(),
                    expect: vec![],
                },
                Check {
                    scenario: "a None result becomes an empty optional result",
                    input: ActionRequest {
                        results: vec![None],
                        ..empty_action_request()
                    },
                    expect: vec![rpc::forge::OptionalRedfishActionResult { result: None }],
                },
                Check {
                    scenario: "a Some result populates the inner action result",
                    input: ActionRequest {
                        results: vec![Some(response())],
                        ..empty_action_request()
                    },
                    expect: vec![rpc::forge::OptionalRedfishActionResult {
                        result: Some(rpc::forge::RedfishActionResult {
                            headers: HashMap::from([(
                                "Location".to_string(),
                                "/task/1".to_string(),
                            )]),
                            status: "200 OK".to_string(),
                            body: r#"{"ok":true}"#.to_string(),
                            completed_at: Some(proto_instant()),
                        }),
                    }],
                },
                Check {
                    scenario: "mixed Some/None results preserve order and arms",
                    input: ActionRequest {
                        results: vec![None, Some(response())],
                        ..empty_action_request()
                    },
                    expect: vec![
                        rpc::forge::OptionalRedfishActionResult { result: None },
                        rpc::forge::OptionalRedfishActionResult {
                            result: Some(rpc::forge::RedfishActionResult {
                                headers: HashMap::from([(
                                    "Location".to_string(),
                                    "/task/1".to_string(),
                                )]),
                                status: "200 OK".to_string(),
                                body: r#"{"ok":true}"#.to_string(),
                                completed_at: Some(proto_instant()),
                            }),
                        },
                    ],
                },
            ],
            |req| rpc::forge::RedfishAction::from(req).results,
        );
    }
}
