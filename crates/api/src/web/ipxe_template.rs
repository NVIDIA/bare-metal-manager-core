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
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use hyper::http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;

use crate::api::Api;

#[derive(Template)]
#[template(path = "ipxe_template_show.html")]
struct IpxeTemplateShow {
    templates: Vec<IpxeTemplateRowDisplay>,
}

struct IpxeTemplateRowDisplay {
    id: String,
    name: String,
    description: String,
    scope: String,
    required_params_count: usize,
    required_artifacts_count: usize,
}

impl From<&forgerpc::IpxeTemplate> for IpxeTemplateRowDisplay {
    fn from(tmpl: &forgerpc::IpxeTemplate) -> Self {
        let scope = forgerpc::IpxeTemplateScope::try_from(tmpl.scope)
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|_| "Unknown".to_string());
        Self {
            id: tmpl.id.as_ref().map(|u| u.to_string()).unwrap_or_default(),
            name: tmpl.name.clone(),
            description: tmpl.description.clone(),
            scope,
            required_params_count: tmpl.required_params.len(),
            required_artifacts_count: tmpl.required_artifacts.len(),
        }
    }
}

pub async fn show_html(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let templates = match fetch_templates(state).await {
        Ok(t) => t,
        Err(err) => {
            tracing::error!(%err, "list_ipxe_templates");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading iPXE templates",
            )
                .into_response();
        }
    };

    let tmpl = IpxeTemplateShow {
        templates: templates.iter().map(Into::into).collect(),
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_all_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let templates = match fetch_templates(state).await {
        Ok(t) => t,
        Err(err) => {
            tracing::error!(%err, "list_ipxe_templates");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading iPXE templates",
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(templates)).into_response()
}

async fn fetch_templates(api: Arc<Api>) -> Result<Vec<forgerpc::IpxeTemplate>, tonic::Status> {
    let request = tonic::Request::new(forgerpc::ListIpxeTemplatesRequest {});
    let response = api.list_ipxe_templates(request).await?;
    let mut templates = response.into_inner().templates;
    templates.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    Ok(templates)
}

#[derive(Template)]
#[template(path = "ipxe_template_detail.html")]
struct IpxeTemplateDetail {
    name: String,
    description: String,
    scope: String,
    required_params: Vec<String>,
    reserved_params: Vec<String>,
    required_artifacts: Vec<String>,
    template_text: String,
}

impl From<forgerpc::IpxeTemplate> for IpxeTemplateDetail {
    fn from(tmpl: forgerpc::IpxeTemplate) -> Self {
        let scope = forgerpc::IpxeTemplateScope::try_from(tmpl.scope)
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|_| "Unknown".to_string());
        Self {
            name: tmpl.name,
            description: tmpl.description,
            scope,
            required_params: tmpl.required_params,
            reserved_params: tmpl.reserved_params,
            required_artifacts: tmpl.required_artifacts,
            template_text: tmpl.template,
        }
    }
}

pub async fn detail(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(id_str): AxumPath<String>,
) -> Response {
    let (show_json, id_str) = match id_str.strip_suffix(".json") {
        Some(n) => (true, n.to_string()),
        None => (false, id_str),
    };

    let id: carbide_uuid::ipxe_template::IpxeTemplateId = match id_str.parse() {
        Ok(v) => v,
        Err(_) => return super::not_found_response(id_str),
    };

    let request = tonic::Request::new(forgerpc::GetIpxeTemplateRequest { id: Some(id) });

    let tmpl = match state.get_ipxe_template(request).await {
        Ok(resp) => resp.into_inner(),
        Err(err) if err.code() == tonic::Code::NotFound => {
            return super::not_found_response(id_str);
        }
        Err(err) => {
            tracing::error!(%err, "get_ipxe_template");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading iPXE template",
            )
                .into_response();
        }
    };

    if show_json {
        return (StatusCode::OK, Json(tmpl)).into_response();
    }

    let detail: IpxeTemplateDetail = tmpl.into();
    (StatusCode::OK, Html(detail.render().unwrap())).into_response()
}
