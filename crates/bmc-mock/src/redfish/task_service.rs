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
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::get;
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::http;
use crate::json::JsonExt;

pub(crate) fn add_routes(r: Router<BmcState>) -> Router<BmcState> {
    r.route("/redfish/v1/TaskService/Tasks/{task_id}", get(get_task))
}

/// Return a task by ID.
///
/// Live tasks (created by upload handlers) are looked up in `UpdateServiceState`.
/// The synthetic fallback for task ID `"0"` preserves backwards compatibility with
/// legacy callers that hard-code that ID.  Any other unknown ID returns 404.
async fn get_task(State(state): State<BmcState>, Path(task_id): Path<String>) -> Response {
    if let Some(task_json) = state.update_service_state.find_task(&task_id) {
        return task_json.into_ok_response();
    }

    // Legacy fallback: some callers hard-code task ID "0".  Return a synthetic
    // completed task with the same shape as FirmwareTask::to_json.
    if task_id == "0" {
        return json!({
            "@odata.id": "/redfish/v1/TaskService/Tasks/0",
            "@odata.type": "#Task.v1_4_3.Task",
            "Id": "0",
            "PercentComplete": 100,
            "StartTime": "2024-01-30T09:00:52+00:00",
            "TaskMonitor": "/redfish/v1/TaskService/Tasks/0/Monitor",
            "TaskState": "Completed",
            "TaskStatus": "OK",
            "Messages": [{
                "MessageId": "Update.1.0.OperationTransitionedToJob",
                "Message": "Firmware staged; version will be applied after the next power-cycle.",
                "Severity": "OK"
            }]
        })
        .into_ok_response();
    }

    http::not_found()
}
