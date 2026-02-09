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

use axum::Router;
use axum::response::Response;
use axum::routing::get;
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::json::JsonExt;

pub fn add_routes(r: Router<BmcState>) -> Router<BmcState> {
    r.route("/redfish/v1/TaskService/Tasks/{task_id}", get(get_task))
}

async fn get_task() -> Response {
    json!({
        "@odata.id": "/redfish/v1/TaskService/Tasks/0",
        "@odata.type": "#Task.v1_4_3.Task",
        "Id": "0",
        "PercentComplete": 100,
        "StartTime": "2024-01-30T09:00:52+00:00",
        "TaskMonitor": "/redfish/v1/TaskService/Tasks/0/Monitor",
        "TaskState": "Completed",
        "TaskStatus": "OK"
    })
    .into_ok_response()
}

pub fn update_firmware_simple_update_task() -> Response {
    json!({
        "@odata.id": "/redfish/v1/TaskService/Tasks/0",
        "@odata.type": "#Task.v1_4_3.Task",
        "Id": "0"
    })
    .into_ok_response()
}
