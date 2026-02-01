/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::borrow::Cow;

use axum::Router;
use axum::extract::{Json, Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use lazy_static::lazy_static;
use serde_json::json;

use crate::bmc_state::JobState;
use crate::json::{JsonExt, JsonPatch};
use crate::mock_machine_router::MockWrapperState;
use crate::redfish;

pub fn add_routes(r: Router<MockWrapperState>) -> Router<MockWrapperState> {
    r.route(
        "/redfish/v1/Managers/iDRAC.Embedded.1/Attributes",
        get(get_managers_oem_dell_attributes).patch(patch_managers_oem_dell_attributes),
    ).route(
        "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1",
        get(get_managers_oem_dell_attributes).patch(patch_managers_oem_dell_attributes),
    ).route(
        "/redfish/v1/Managers/iDRAC.Embedded.1/Jobs",
        post(post_dell_create_bios_job),
    ).route(
        "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs",
        post(post_dell_create_bios_job),
    ).route(
        "/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/{job_id}",
        get(get_dell_job),
    ).route(
        "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/{job_id}",
        get(get_dell_job),
    ).route(
        "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellJobService/Actions/DellJobService.DeleteJobQueue",
        post(post_delete_job_queue)
    ).route(
        "/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/EID_674_Manager.ImportSystemConfiguration",
        post(post_import_sys_configuration)
    )
}

fn attributes_resource() -> redfish::Resource<'static> {
    redfish::Resource {
        odata_id: Cow::Borrowed(
            "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1",
        ),
        odata_type: Cow::Borrowed("#DellAttributes.v1_0_0.DellAttributes"),
        name: Cow::Borrowed("OEMAttributeRegistry"),
        id: Cow::Borrowed("iDRACAttributes"),
    }
}

async fn get_managers_oem_dell_attributes(State(state): State<MockWrapperState>) -> Response {
    lazy_static! {
        // Only attributes required by libredfish:
        static ref base: serde_json::Value = attributes_resource().json_patch().patch(json!({
            "Attributes": {
                "IPMILan.1.Enable": "Enabled",
                "IPMISOL.1.BaudRate": "115200",
                "IPMISOL.1.Enable": "Enabled",
                "IPMISOL.1.MinPrivilege": "Administrator",
                "Lockdown.1.SystemLockdown": "Disabled",
                "OS-BMC.1.AdminState": "Disabled",
                "Racadm.1.Enable": "Enabled",
                "SSH.1.Enable": "Enabled",
                "SerialRedirection.1.Enable": "Enabled",
                "WebServer.1.HostHeaderCheck": "Disabled",
            }
        }));
    }
    state
        .bmc_state
        .get_dell_attrs(base.clone())
        .into_ok_response()
}

async fn patch_managers_oem_dell_attributes(
    State(mut state): State<MockWrapperState>,
    Json(attrs): Json<serde_json::Value>,
) -> Response {
    state.bmc_state.update_dell_attrs(attrs);
    json!({}).into_ok_response()
}

async fn get_dell_job(
    State(state): State<MockWrapperState>,
    Path(job_id): Path<String>,
) -> Response {
    let Some(job) = state.bmc_state.get_job(&job_id) else {
        return json!(format!("could not find iDRAC job: {job_id}"))
            .into_response(StatusCode::NOT_FOUND);
    };

    let job_state = match job.job_state {
        JobState::Scheduled => "Scheduled".to_string(),
        JobState::Completed => "Completed".to_string(),
    };

    serde_json::json!({
        "@odata.context": "/redfish/v1/$metadata#DellJob.DellJob",
        "@odata.id": format!("/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/{job_id}"),
        "@odata.type": "#DellJob.v1_5_0.DellJob",
        "ActualRunningStartTime": format!("{}", job.start_time),
        "ActualRunningStopTime": null,
        "CompletionTime": null,
        "Description": "Job Instance",
        "EndTime": "TIME_NA",
        "Id": job_id,
        "JobState": job_state,
        "JobType": job.job_type,
        "Message": job_state,
        "MessageArgs": [],
        "MessageArgs@odata.count": 0,
        "MessageId": "PR19",
        "Name": job.job_type,
        "PercentComplete": job.percent_complete(),
        "StartTime": format!("{}", job.start_time),
        "TargetSettingsURI": null
    })
    .into_ok_response()
}

pub fn create_job_with_location(mut state: MockWrapperState) -> Response {
    match state.bmc_state.add_job() {
        Ok(job_id) => json!({}).into_ok_response_with_location(
            HeaderValue::try_from(format!(
                "/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/{job_id}"
            ))
            .expect("This must be valid header value"),
        ),
        Err(e) => json!(e.to_string()).into_response(StatusCode::BAD_REQUEST),
    }
}

async fn post_dell_create_bios_job(State(state): State<MockWrapperState>) -> Response {
    create_job_with_location(state)
}

async fn post_delete_job_queue() -> Response {
    json!({}).into_ok_response()
}

async fn post_import_sys_configuration(State(state): State<MockWrapperState>) -> Response {
    create_job_with_location(state)
}
