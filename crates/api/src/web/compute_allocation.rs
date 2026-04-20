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

use std::cmp::min;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use askama::Template;
use axum::Json;
use axum::extract::{Form, OriginalUri, Path as AxumPath, Query, State as AxumState};
use axum::response::{Html, IntoResponse, Redirect, Response};
use carbide_uuid::compute_allocation::ComputeAllocationId;
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as forgerpc};
use serde::{Deserialize, Deserializer, de};

use super::filters;
use crate::api::Api;

const DEFAULT_PAGE_RECORD_LIMIT: usize = 100;

#[derive(Template)]
#[template(path = "compute_allocation_show.html")]
struct ComputeAllocationShow {
    path: String,
    allocations: Vec<ComputeAllocationRowDisplay>,
    current_page: usize,
    previous: usize,
    next: usize,
    pages: usize,
    page_range_start: usize,
    page_range_end: usize,
    limit: usize,
}

#[derive(PartialEq, Eq)]
struct ComputeAllocationRowDisplay {
    id: String,
    tenant_organization_id: String,
    instance_type_id: String,
    count: u32,
    name: String,
    description: String,
    version: String,
    created: String,
}

impl PartialOrd for ComputeAllocationRowDisplay {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ComputeAllocationRowDisplay {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl From<forgerpc::ComputeAllocation> for ComputeAllocationRowDisplay {
    fn from(allocation: forgerpc::ComputeAllocation) -> Self {
        let created = allocation.created_at().to_string();
        let metadata = allocation.metadata.unwrap_or_default();
        let attrs = allocation.attributes.unwrap_or_default();

        ComputeAllocationRowDisplay {
            created,
            id: allocation.id.map(|i| i.to_string()).unwrap_or_default(),
            tenant_organization_id: allocation.tenant_organization_id,
            instance_type_id: attrs.instance_type_id,
            count: attrs.count,
            name: metadata.name,
            description: metadata.description,
            version: allocation.version,
        }
    }
}

#[derive(Debug, Template)]
#[template(path = "compute_allocation_detail.html")]
struct ComputeAllocationDetailDisplay {
    id: String,
    tenant_organization_id: String,
    instance_type_id: String,
    count: u32,
    name: String,
    description: String,
    version: String,
    created: String,
    created_by: String,
    updated_by: String,
    labels: String,
}

/// Serde deserialization decorator to map empty Strings to None,
fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    let opt = Option::<String>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => FromStr::from_str(s).map_err(de::Error::custom).map(Some),
    }
}

/// Struct for deserializing a request to view
/// existing ComputeAllocations
#[derive(Deserialize, Debug)]
pub struct ShowComputeAllocationParams {
    #[serde(default, deserialize_with = "empty_string_as_none")]
    limit: Option<usize>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    current_page: Option<usize>,
}

/// Handler for displaying all compute allocations.
pub async fn show(
    AxumState(api): AxumState<Arc<Api>>,
    Query(params): Query<ShowComputeAllocationParams>,
    path: OriginalUri,
) -> Response {
    let current_page = params.current_page.unwrap_or(0);

    let limit: usize = params.limit.map_or(DEFAULT_PAGE_RECORD_LIMIT, |s| {
        min(s, DEFAULT_PAGE_RECORD_LIMIT)
    });

    let (pages, allocations) = match fetch_compute_allocations(api, current_page, limit).await {
        Ok(all) => all,
        Err(err) => {
            tracing::error!(%err, "fetch_compute_allocations");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error loading compute allocations: {err}"),
            )
                .into_response();
        }
    };

    let tmpl = ComputeAllocationShow {
        path: path.path().to_string(),
        allocations,
        current_page,
        previous: current_page.saturating_sub(1),
        next: current_page.saturating_add(1),
        pages,
        page_range_start: current_page.saturating_sub(3),
        page_range_end: min(current_page.saturating_add(4), pages),
        limit,
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

/// Helper to fetch all compute allocations
/// with some pagination.
async fn fetch_compute_allocations(
    api: Arc<Api>,
    current_page: usize,
    limit: usize,
) -> Result<(usize, Vec<ComputeAllocationRowDisplay>), tonic::Status> {
    let request: tonic::Request<forgerpc::FindComputeAllocationIdsRequest> =
        tonic::Request::new(forgerpc::FindComputeAllocationIdsRequest {
            name: None,
            tenant_organization_id: None,
            instance_type_id: None,
        });

    let all_ids = api
        .find_compute_allocation_ids(request)
        .await
        .map(|response| response.into_inner())?
        .ids;

    let limit = if limit == 0 {
        DEFAULT_PAGE_RECORD_LIMIT
    } else {
        limit
    };

    if all_ids.is_empty() {
        return Ok((0, vec![]));
    }

    let pages = all_ids.len().div_ceil(limit);
    let current_record_cnt_seen = current_page.saturating_mul(limit);

    if current_record_cnt_seen > all_ids.len() {
        return Ok((pages, vec![]));
    }

    let ids_for_page = all_ids
        .into_iter()
        .skip(current_record_cnt_seen)
        .take(limit)
        .collect();

    let allocations = api
        .find_compute_allocations_by_ids(tonic::Request::new(
            forgerpc::FindComputeAllocationsByIdsRequest { ids: ids_for_page },
        ))
        .await
        .map(|response| response.into_inner())?
        .allocations;

    Ok((pages, allocations.into_iter().map(|n| n.into()).collect()))
}

/// Handler for displaying a single compute allocation.
pub async fn show_detail(
    AxumState(api): AxumState<Arc<Api>>,
    AxumPath(compute_allocation_id): AxumPath<String>,
) -> Response {
    let (show_json, compute_allocation_id) = match compute_allocation_id.strip_suffix(".json") {
        Some(compute_allocation_id) => (true, compute_allocation_id.to_string()),
        None => (false, compute_allocation_id),
    };

    let allocation_id = match compute_allocation_id.parse::<ComputeAllocationId>() {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid compute allocation id: {e}"),
            )
                .into_response();
        }
    };

    let Some(allocation) = match api
        .find_compute_allocations_by_ids(tonic::Request::new(
            forgerpc::FindComputeAllocationsByIdsRequest {
                ids: vec![allocation_id],
            },
        ))
        .await
        .map(|response| response.into_inner())
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unable to retrieve compute allocation: {e}"),
            )
                .into_response();
        }
    }
    .allocations
    .pop() else {
        return super::not_found_response(compute_allocation_id);
    };

    if show_json {
        return (StatusCode::OK, Json(allocation)).into_response();
    }

    let created = allocation.created_at().to_string();
    let created_by = allocation.created_by().to_string();
    let updated_by = allocation.updated_by().to_string();

    let attrs = allocation.attributes.unwrap_or_default();
    let metadata = allocation.metadata.unwrap_or_default();
    let labels = match serde_json::to_string_pretty(&metadata.labels) {
        Ok(l) => l,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to serialize compute allocation labels: {e}"),
            )
                .into_response();
        }
    };

    let tmpl = ComputeAllocationDetailDisplay {
        id: allocation.id.map(|i| i.to_string()).unwrap_or_default(),
        tenant_organization_id: allocation.tenant_organization_id,
        instance_type_id: attrs.instance_type_id,
        count: attrs.count,
        name: metadata.name,
        description: metadata.description,
        labels,
        version: allocation.version,
        created,
        created_by,
        updated_by,
    };

    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

/// Struct for deserializing a request to create
/// a new ComputeAllocation
#[derive(Deserialize, Debug)]
pub struct CreateComputeAllocationForm {
    id: String,
    tenant_organization_id: String,
    instance_type_id: String,
    count: u32,
    name: String,
    description: String,
    labels: String,
}

/// Handler to create a new ComputeAllocation.
pub async fn create(
    AxumState(api): AxumState<Arc<Api>>,
    Form(form): Form<CreateComputeAllocationForm>,
) -> Response {
    let id = if form.id.is_empty() {
        None
    } else {
        match form.id.parse::<ComputeAllocationId>() {
            Ok(id) => Some(id),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid compute allocation id: {e}"),
                )
                    .into_response();
            }
        }
    };
    let labels = if form.labels.is_empty() {
        "[]".to_string()
    } else {
        form.labels
    };

    let resp = match api
        .create_compute_allocation(tonic::Request::new(
            forgerpc::CreateComputeAllocationRequest {
                id,
                tenant_organization_id: form.tenant_organization_id,
                metadata: Some(forgerpc::Metadata {
                    name: form.name,
                    description: form.description,
                    labels: match serde_json::from_str(&labels) {
                        Ok(r) => r,
                        Err(e) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("Failed to deserialize labels: {e}"),
                            )
                                .into_response();
                        }
                    },
                }),
                attributes: Some(forgerpc::ComputeAllocationAttributes {
                    instance_type_id: form.instance_type_id,
                    count: form.count,
                }),
                created_by: None,
            },
        ))
        .await
        .map(|response| response.into_inner())
    {
        Ok(r) => r.allocation,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unable to create compute allocation: {e}"),
            )
                .into_response();
        }
    };

    let Some(allocation) = resp else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unexpected empty response after creating compute allocation",
        )
            .into_response();
    };

    let id = allocation.id.map(|i| i.to_string()).unwrap_or_default();
    Redirect::to(&format!("/admin/compute-allocation/{id}")).into_response()
}

/// Struct for deserializing a request to update
/// an existing ComputeAllocation
#[derive(Deserialize, Debug)]
pub struct UpdateComputeAllocationForm {
    tenant_organization_id: String,
    instance_type_id: String,
    count: u32,
    name: String,
    description: String,
    labels: String,
    version: String,
}

/// Handler for updating an existing ComputeAllocation.
pub async fn update(
    AxumState(api): AxumState<Arc<Api>>,
    AxumPath(compute_allocation_id): AxumPath<String>,
    Form(form): Form<UpdateComputeAllocationForm>,
) -> Response {
    let allocation_id = match compute_allocation_id.parse::<ComputeAllocationId>() {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid compute allocation id: {e}"),
            )
                .into_response();
        }
    };

    let labels = if form.labels.is_empty() {
        "[]".to_string()
    } else {
        form.labels
    };

    let resp = match api
        .update_compute_allocation(tonic::Request::new(
            forgerpc::UpdateComputeAllocationRequest {
                id: Some(allocation_id),
                if_version_match: Some(form.version),
                tenant_organization_id: form.tenant_organization_id,
                metadata: Some(forgerpc::Metadata {
                    name: form.name,
                    description: form.description,
                    labels: match serde_json::from_str(&labels) {
                        Ok(r) => r,
                        Err(e) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("Failed to deserialize labels: {e}"),
                            )
                                .into_response();
                        }
                    },
                }),
                attributes: Some(forgerpc::ComputeAllocationAttributes {
                    instance_type_id: form.instance_type_id,
                    count: form.count,
                }),
                updated_by: None,
            },
        ))
        .await
        .map(|response| response.into_inner())
    {
        Ok(r) => r.allocation,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unable to update compute allocation: {e}"),
            )
                .into_response();
        }
    };

    let Some(allocation) = resp else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unexpected empty response after updating compute allocation",
        )
            .into_response();
    };

    let id = allocation.id.map(|i| i.to_string()).unwrap_or_default();
    Redirect::to(&format!("/admin/compute-allocation/{id}")).into_response()
}

/// Struct for deserializing a request to delete
/// an existing ComputeAllocation
#[derive(Deserialize, Debug)]
pub struct DeleteComputeAllocationForm {
    tenant_organization_id: String,
}

/// Handler for deleting an existing ComputeAllocation.
pub async fn delete(
    AxumState(api): AxumState<Arc<Api>>,
    AxumPath(compute_allocation_id): AxumPath<String>,
    Form(form): Form<DeleteComputeAllocationForm>,
) -> Response {
    let allocation_id = match compute_allocation_id.parse::<ComputeAllocationId>() {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid compute allocation id: {e}"),
            )
                .into_response();
        }
    };

    if let Err(e) = api
        .delete_compute_allocation(tonic::Request::new(
            forgerpc::DeleteComputeAllocationRequest {
                id: Some(allocation_id),
                tenant_organization_id: form.tenant_organization_id,
            },
        ))
        .await
        .map(|response| response.into_inner())
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to delete compute allocation: {e}"),
        )
            .into_response();
    };

    Redirect::to("/admin/compute-allocation").into_response()
}
