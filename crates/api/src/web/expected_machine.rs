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
use std::sync::Arc;

use askama::Template;
use axum::Json;
use axum::extract::{Query, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;

use crate::api::Api;
use crate::web::filters;

#[derive(Template)]
#[template(path = "expected_machine_show.html")]
struct ExpectedMachines {
    machines: Vec<ExpectedMachineRow>,
    active_filter: String,
    all_count: usize,
    completed_count: usize,
    unseen_count: usize,
    unexplored_count: usize,
    unlinked_count: usize,
}

#[derive(Ord, PartialOrd, Eq, PartialEq, serde::Serialize)]
struct ExpectedMachineRow {
    bmc_mac_address: String,
    interface_id: String,
    serial_number: String,
    address: String,    // The explored endpoint
    machine_id: String, // The machine
}

impl From<rpc::forge::LinkedExpectedMachine> for ExpectedMachineRow {
    fn from(l: rpc::forge::LinkedExpectedMachine) -> ExpectedMachineRow {
        ExpectedMachineRow {
            bmc_mac_address: l.bmc_mac_address,
            interface_id: l.interface_id.unwrap_or_default(),
            serial_number: l.chassis_serial_number,
            address: l.explored_endpoint_address.unwrap_or_default(),
            machine_id: l.machine_id.map(|m| m.to_string()).unwrap_or_default(),
        }
    }
}

pub async fn show_all_html(
    AxumState(api): AxumState<Arc<Api>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let filter = params.get("filter").cloned().unwrap_or("all".to_string());

    let result = match api
        .get_all_expected_machines_linked(tonic::Request::new(()))
        .await
        .map(|response| response.into_inner())
    {
        Ok(machines) => machines,
        Err(err) => {
            tracing::error!(%err, "get_all_expected_machines_linked");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading expected machines from carbide-api",
            )
                .into_response();
        }
    };

    let mut display = Vec::new();
    let all_count = result.expected_machines.len();
    let mut unseen_count = 0;
    let mut unexplored_count = 0;
    let mut unlinked_count = 0;
    for em in result.expected_machines.into_iter() {
        let no_dhcp = em.interface_id.is_none(); // no interface means it didn't DHCP
        let is_unexplored = em.explored_endpoint_address.is_none();
        let is_unlinked = em.machine_id.is_none();
        if no_dhcp {
            unseen_count += 1;
        }
        if is_unexplored {
            unexplored_count += 1;
        }
        if is_unlinked {
            unlinked_count += 1;
        }
        match filter.as_str() {
            "all" => {}
            "completed" => {
                if is_unlinked || is_unexplored {
                    continue;
                }
            }
            "unseen" => {
                if !no_dhcp {
                    continue;
                }
            }
            "unexplored" => {
                if !is_unexplored {
                    continue;
                }
            }
            "unlinked" => {
                if !is_unlinked {
                    continue;
                }
            }
            _ => {
                return (StatusCode::BAD_REQUEST, "Unknown filter").into_response();
            }
        }
        display.push(em.into());
    }
    display.sort_unstable(); // by first field in struct, which is BMC MAC address
    let tmpl = ExpectedMachines {
        all_count,
        completed_count: all_count - unlinked_count,
        unseen_count,
        unexplored_count,
        unlinked_count,
        machines: display,
        active_filter: filter,
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_expected_machine_raw_json(AxumState(api): AxumState<Arc<Api>>) -> Response {
    let result = match api
        .get_all_expected_machines(tonic::Request::new(()))
        .await
        .map(|response| response.into_inner())
    {
        Ok(machines) => machines,
        Err(err) => {
            tracing::error!(%err, "show_expected_machine_raw_json");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading expected machines from carbide-api",
            )
                .into_response();
        }
    };

    (StatusCode::OK, Json(result)).into_response()
}
