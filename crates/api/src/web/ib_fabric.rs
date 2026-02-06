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

use std::sync::Arc;

use askama::Template;
use axum::Json;
use axum::extract::State as AxumState;
use axum::response::{Html, IntoResponse, Response};
use hyper::http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;

use crate::api::Api;

#[derive(Template)]
#[template(path = "ib_fabric_show.html")]
struct IbFabricShow {
    fabrics: Vec<IbFabricRowDisplay>,
}

struct IbFabricRowDisplay {
    id: String,
}

/// List fabrics
pub async fn show_html(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let fabrics = match fetch_ib_fabric_ids(state.clone()).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_ib_fabric_ids");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading IB fabrics",
            )
                .into_response();
        }
    };

    let tmpl = IbFabricShow {
        fabrics: fabrics
            .into_iter()
            .map(|id| IbFabricRowDisplay { id })
            .collect(),
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_all_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let fabrics = match fetch_ib_fabric_ids(state).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_ib_fabric_ids");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading IB fabrics",
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(fabrics)).into_response()
}

pub async fn fetch_ib_fabric_ids(api: Arc<Api>) -> Result<Vec<String>, tonic::Status> {
    let request = tonic::Request::new(forgerpc::IbFabricSearchFilter::default());

    let ib_fabric_ids = api
        .find_ib_fabric_ids(request)
        .await?
        .into_inner()
        .ib_fabric_ids;

    Ok(ib_fabric_ids)
}
