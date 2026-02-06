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
use rpc::forge::forge_server::Forge;

use crate::api::Api;

#[derive(Template)]
#[template(path = "domain_show.html")]
struct DomainShow {
    domains: Vec<DomainRowDisplay>,
}

struct DomainRowDisplay {
    id: String,
    name: String,
    created: String,
    updated: String,
    deleted: String,
}

impl From<::rpc::protos::dns::Domain> for DomainRowDisplay {
    fn from(d: ::rpc::protos::dns::Domain) -> Self {
        Self {
            id: d.id.unwrap_or_default().to_string(),
            name: d.name,
            created: d.created.unwrap_or_default().to_string(),
            updated: d.updated.unwrap_or_default().to_string(),
            deleted: d
                .deleted
                .map(|x| x.to_string())
                .unwrap_or("Not Deleted".to_string()),
        }
    }
}

/// List domains
pub async fn show_html(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let domains = match fetch_domains(state).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "find_domains");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading domains").into_response();
        }
    };

    let mut out = Vec::new();
    for domain in domains.domains.into_iter() {
        out.push(domain.into());
    }

    let tmpl = DomainShow { domains: out };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_all_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let domains = match fetch_domains(state).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "find_domains");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading domains").into_response();
        }
    };
    (StatusCode::OK, Json(domains)).into_response()
}

async fn fetch_domains(api: Arc<Api>) -> Result<::rpc::protos::dns::DomainList, tonic::Status> {
    let request = tonic::Request::new(rpc::protos::dns::DomainSearchQuery {
        id: None,
        name: None,
    });
    api.find_domain(request)
        .await
        .map(|response| response.into_inner())
}
