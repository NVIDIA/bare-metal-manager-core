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
use axum::response::IntoResponse;
use axum::routing::post;
use serde_json::json;

use crate::json::JsonExt;
use crate::mock_machine_router::MockWrapperState;

pub fn add_routes(r: Router<MockWrapperState>) -> Router<MockWrapperState> {
    r.route(
        "/redfish/v1/Systems/Bluefield/Oem/Nvidia/Actions/HostRshim.Set",
        post(hostrshim_set),
    )
}

async fn hostrshim_set() -> impl IntoResponse {
    json!({}).into_ok_response()
}
