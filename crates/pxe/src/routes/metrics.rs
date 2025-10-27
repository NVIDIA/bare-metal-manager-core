/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;

use crate::common::AppState;

async fn metrics(state: State<AppState>) -> impl IntoResponse {
    // Make sure the metrics are fully updated prior to rendering them
    state.prometheus_handle.run_upkeep();

    state.prometheus_handle.render()
}

pub fn get_router(path_prefix: &str) -> Router<AppState> {
    Router::new().route(path_prefix, get(metrics))
}
