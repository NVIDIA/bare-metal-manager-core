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
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use lazy_static::lazy_static;
use regex::{Captures, Regex};
use serde_json::json;

use crate::json::JsonExt;
use crate::mock_machine_router::MockWrapperState;
use crate::{MachineInfo, redfish};

pub fn system_collection(system_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!("/redfish/v1/Systems/{system_id}/BootOptions");
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#BootOptionCollection.BootOptionCollection"),
        name: Cow::Borrowed("Boot Options Collection"),
    }
}

pub fn add_routes(r: Router<MockWrapperState>) -> Router<MockWrapperState> {
    r.route(
        "/redfish/v1/Systems/System.Embedded.1/BootOptions",
        get(get_dell_boot_options),
    )
    .route(
        "/redfish/v1/Systems/Bluefield/BootOptions/{boot_option_id}",
        get(get_dpu_boot_options),
    )
}

lazy_static! {
    pub(crate) static ref UEFI_DEVICE_PATH_MAC_ADDRESS_REGEX: Regex =
        Regex::new(r"(?<prefix>.*MAC\()(?<mac>[[:alnum:]]+)(?<suffix>,.*)$").unwrap();
}

// Carbide relies that Dell sorts boot options in according to boot
// order. Code below simulates the same.
async fn get_dell_boot_options(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
) -> Response {
    state
        .call_inner_router(request)
        .await
        .map(|mut boot_options| {
            if let Some(boot_order) = state
                .bmc_state
                .system_state
                .boot_order_override("System.Embedded.1")
                && let Some(members) = boot_options
                    .as_object_mut()
                    .and_then(|obj| obj.get_mut("Members"))
                    .and_then(serde_json::Value::as_array_mut)
            {
                members.sort_by_key(|member| {
                    member
                        .as_object()
                        .and_then(|obj| obj.get("@odata.id"))
                        .and_then(serde_json::Value::as_str)
                        .and_then(|member_id| {
                            boot_order
                                .iter()
                                .enumerate()
                                .find(|(_, ord)| member_id.ends_with(*ord))
                                .map(|(idx, _)| idx)
                        })
                        // Push items that are not in boot order array to
                        // the end.
                        .unwrap_or(boot_order.len())
                })
            }
            boot_options.into_ok_response()
        })
        .unwrap_or_else(|err| err.into_response())
}

async fn get_dpu_boot_options(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
) -> Response {
    state
        .call_inner_router(request)
        .await
        .map(|inner_json| {
            // We only rewrite this line if it's a DPU we're mocking
            let MachineInfo::Dpu(dpu) = state.machine_info else {
                return inner_json.into_ok_response();
            };

            let Some(uefi_device_path) = inner_json
                .get("UefiDevicePath")
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
            else {
                return inner_json.into_ok_response();
            };
            let mocked_mac_no_colons = dpu
                .oob_mac_address
                .to_string()
                .replace(':', "")
                .to_ascii_uppercase();
            let updated_uefi_device_path = UEFI_DEVICE_PATH_MAC_ADDRESS_REGEX.replace(
                &uefi_device_path,
                |captures: &Captures| {
                    [
                        &captures["prefix"],
                        &mocked_mac_no_colons,
                        &captures["suffix"],
                    ]
                    .join("")
                },
            );

            inner_json
                .patch(json!({"UefiDevicePath": updated_uefi_device_path}))
                .into_ok_response()
        })
        .unwrap_or_else(|err| err.into_response())
}
