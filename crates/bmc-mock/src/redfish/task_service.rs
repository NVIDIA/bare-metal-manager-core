/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
