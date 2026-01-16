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

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use http_body_util::BodyExt;
use serde_json::json;

use crate::json::JsonExt;
use crate::mock_machine_router::{MockWrapperError, MockWrapperState};

pub fn add_routes(r: Router<MockWrapperState>) -> Router<MockWrapperState> {
    r.route(
        "/redfish/v1/Managers/iDRAC.Embedded.1/Attributes",
        patch(set_idrac_attributes),
    )
        .route(
            "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1",
            get(get_managers_oem_dell_attributes).patch(patch_managers_oem_dell_attributes),
        )
        .route(
            "/redfish/v1/Managers/iDRAC.Embedded.1/Jobs",
            post(post_dell_create_bios_job),
        )
        .route(
            "/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/{job_id}",
            get(get_dell_job),
        )
        .route("/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellJobService/Actions/DellJobService.DeleteJobQueue",
               post(post_delete_job_queue))
}

async fn set_idrac_attributes() -> impl IntoResponse {
    json!({}).into_ok_response()
}

async fn get_managers_oem_dell_attributes(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
) -> impl IntoResponse {
    state
        .call_inner_router(request)
        .await
        .and_then(|response| Ok(serde_json::from_slice::<serde_json::Value>(&response)?))
        .map(|inner_json| {
            let patched_dell_attrs = state.bmc_state.get_dell_attrs(inner_json);
            patched_dell_attrs.into_ok_response()
        })
        .unwrap_or_else(|err| err.into_response())
}

async fn patch_managers_oem_dell_attributes(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
) -> impl IntoResponse {
    request
        .into_body()
        .collect()
        .await
        .map_err(MockWrapperError::from)
        .map(|v| v.to_bytes())
        .and_then(|body| Ok(serde_json::from_slice::<serde_json::Value>(&body)?))
        .map(|attrs| {
            state.bmc_state.update_dell_attrs(attrs);
            json!({}).into_ok_response()
        })
        .unwrap_or_else(|err| err.into_response())
}

async fn get_dell_job(
    State(state): State<MockWrapperState>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let Some(job) = state.bmc_state.get_job(&job_id) else {
        return json!(format!("could not find iDRAC job: {job_id}"))
            .into_response(StatusCode::NOT_FOUND);
    };

    // TODO (spyda): move this to libredfish
    let job_state = match job.job_state {
        libredfish::JobState::Scheduled => "Scheduled".to_string(),
        libredfish::JobState::Completed => "Completed".to_string(),
        _ => "Unknown".to_string(),
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

async fn post_dell_create_bios_job(State(mut state): State<MockWrapperState>) -> impl IntoResponse {
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

async fn post_delete_job_queue() -> impl IntoResponse {
    StatusCode::OK
}
