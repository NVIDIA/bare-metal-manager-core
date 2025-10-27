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
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tower_http::services::ServeFile;

use crate::common::AppState;

async fn root_ca(headers: HeaderMap, state: State<AppState>) -> impl IntoResponse {
    let mut req = Request::new(Body::empty());
    *req.headers_mut() = headers;

    // the docs for this fn actually say it should return Ok(404) if the file isn't there or
    // you don't have permissions to it... but it still returns a std::io::Result so we do
    // still have to handle the apparently possible failure modes.
    match ServeFile::new_with_mime(
        &state.runtime_config.forge_root_ca_path,
        &mime::APPLICATION_OCTET_STREAM,
    )
    .try_call(req)
    .await
    {
        Ok(response) => response.into_response(),
        Err(err) => {
            eprintln!("Error reading root ca cert file: {err}");
            let response = Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("error reading root ca cert file?"))
                .unwrap();

            response.into_response()
        }
    }
}

pub fn get_router(path_prefix: &str) -> Router<AppState> {
    Router::new().route(
        format!("{}/{}", path_prefix, "root_ca").as_str(),
        get(root_ca),
    )
}
