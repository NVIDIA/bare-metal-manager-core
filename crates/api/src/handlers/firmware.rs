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

use ::rpc::forge as rpc;
use chrono::TimeZone;
use itertools::Itertools;
use model::firmware::DesiredFirmwareVersions;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

pub(crate) async fn set_firmware_update_time_window(
    api: &Api,
    request: Request<rpc::SetFirmwareUpdateTimeWindowRequest>,
) -> Result<Response<rpc::SetFirmwareUpdateTimeWindowResponse>, Status> {
    let request = request.into_inner();
    let start = request.start_timestamp.unwrap_or_default().seconds;
    let end = request.end_timestamp.unwrap_or_default().seconds;
    // Sanity checks
    if start != 0 || end != 0 {
        if start == 0 || end == 0 {
            return Err(CarbideError::InvalidArgument(
                "Start and end must both be zero or nonzero".to_string(),
            )
            .into());
        }
        if start >= end {
            return Err(CarbideError::InvalidArgument("Start must precede end".to_string()).into());
        }
        if end < chrono::Utc::now().timestamp() {
            return Err(CarbideError::InvalidArgument("End occurs in the past".to_string()).into());
        }
    }

    let mut txn = api.txn_begin().await?;

    tracing::info!(
        "set_firmware_update_time_window: Setting update start/end ({:?} {:?}) for {:?}",
        chrono::Utc.timestamp_opt(start, 0),
        chrono::Utc.timestamp_opt(end, 0),
        request.machine_ids
    );

    db::machine::update_firmware_update_time_window_start_end(
        &request.machine_ids,
        chrono::Utc
            .timestamp_opt(request.start_timestamp.unwrap_or_default().seconds, 0)
            .earliest()
            .unwrap_or(chrono::Utc::now()),
        chrono::Utc
            .timestamp_opt(request.end_timestamp.unwrap_or_default().seconds, 0)
            .earliest()
            .unwrap_or(chrono::Utc::now()),
        &mut txn,
    )
    .await?;

    txn.commit().await?;

    Ok(Response::new(rpc::SetFirmwareUpdateTimeWindowResponse {}))
}

pub(crate) fn list_host_firmware(
    api: &Api,
    _request: Request<rpc::ListHostFirmwareRequest>,
) -> Result<Response<rpc::ListHostFirmwareResponse>, Status> {
    let mut ret = vec![];
    for (_, entry) in api.runtime_config.get_firmware_config().map() {
        for (component, component_info) in entry.components {
            for firmware in component_info.known_firmware {
                if firmware.default {
                    ret.push(rpc::AvailableHostFirmware {
                        vendor: entry.vendor.to_string(),
                        model: entry.model.clone(),
                        r#type: component.to_string(),
                        inventory_name_regex: component_info
                            .current_version_reported_as
                            .clone()
                            .map(|x| x.as_str().to_string())
                            .unwrap_or("UNSPECIFIED".to_string()),
                        version: firmware.version.clone(),
                        needs_explicit_start: entry.explicit_start_needed,
                    });
                }
            }
        }
    }
    Ok(Response::new(rpc::ListHostFirmwareResponse {
        available: ret,
    }))
}

pub(crate) fn get_desired_firmware_versions(
    api: &Api,
    request: Request<rpc::GetDesiredFirmwareVersionsRequest>,
) -> Result<Response<rpc::GetDesiredFirmwareVersionsResponse>, Status> {
    log_request_data(&request);

    let entries = api
        .runtime_config
        .get_firmware_config()
        .map()
        .into_values()
        .map(|firmware| {
            let vendor = firmware.vendor;
            let model = firmware.model.clone();
            let component_versions = DesiredFirmwareVersions::from(firmware).versions;

            Ok::<_, serde_json::Error>(rpc::DesiredFirmwareVersionEntry {
                vendor: vendor.to_string(),
                model,
                // Launder firmware.components through serde::value to convert FirmwareComponentType
                // to String (serde is configured to lowercase it.)
                component_versions: serde_json::from_value(serde_json::to_value(
                    component_versions,
                )?)?,
            })
        })
        .try_collect()
        .map_err(CarbideError::from)?;
    Ok(Response::new(rpc::GetDesiredFirmwareVersionsResponse {
        entries,
    }))
}
