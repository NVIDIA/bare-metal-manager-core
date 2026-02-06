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
use axum::extract::{OriginalUri, Path as AxumPath, Query, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as forgerpc};
use serde::{Deserialize, Deserializer, de};

use super::filters;
use crate::api::Api;

const DEFAULT_PAGE_RECORD_LIMIT: usize = 100;
const UNUSED_CAPABILITY_PROPERTY: &str = "(ignored)";

#[derive(Template)]
#[template(path = "instance_type_show.html")]
struct InstanceTypeShow {
    path: String,
    instance_types: Vec<InstanceTypeRowDisplay>,
    current_page: usize,
    previous: usize,
    next: usize,
    pages: usize,
    page_range_start: usize,
    page_range_end: usize,
    limit: usize,
}

#[derive(PartialEq, Eq)]
struct InstanceTypeRowDisplay {
    id: String,
    name: String,
    description: String,
    version: String,
    created: String,
}

impl PartialOrd for InstanceTypeRowDisplay {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InstanceTypeRowDisplay {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl From<forgerpc::InstanceType> for InstanceTypeRowDisplay {
    fn from(itype: forgerpc::InstanceType) -> Self {
        let created = itype.created_at().to_string();
        let metadata = itype.metadata.unwrap_or_default();

        InstanceTypeRowDisplay {
            created,
            id: itype.id,
            name: metadata.name,
            description: metadata.description,
            version: itype.version,
        }
    }
}

#[derive(Debug)]
struct InstanceTypeCapabilitiesRowDisplay {
    cap_type: String,
    name: String,
    frequency: String,
    capacity: String,
    vendor: String,
    count: String,
    hardware_revision: String,
    cores: String,
    threads: String,
    inactive_devices: String,
    device_type: String,
}

#[derive(Debug, Template)]
#[template(path = "instance_type_detail.html")]
struct InstanceTypeDetailDisplay {
    id: String,
    name: String,
    description: String,
    version: String,
    created: String,
    labels: Vec<forgerpc::Label>,
    capabilities: Vec<InstanceTypeCapabilitiesRowDisplay>,
    associated_machines: Vec<String>,
}

impl From<forgerpc::InstanceTypeMachineCapabilityFilterAttributes>
    for InstanceTypeCapabilitiesRowDisplay
{
    fn from(c: forgerpc::InstanceTypeMachineCapabilityFilterAttributes) -> Self {
        Self {
            cap_type: forgerpc::MachineCapabilityType::to_string_from_enum_i32(c.capability_type)
                .unwrap_or_else(|_| "INVALID".to_string()),
            name: c
                .name
                .unwrap_or_else(|| UNUSED_CAPABILITY_PROPERTY.to_string()),
            frequency: c
                .frequency
                .unwrap_or_else(|| UNUSED_CAPABILITY_PROPERTY.to_string()),
            capacity: c
                .capacity
                .unwrap_or_else(|| UNUSED_CAPABILITY_PROPERTY.to_string()),
            vendor: c
                .vendor
                .unwrap_or_else(|| UNUSED_CAPABILITY_PROPERTY.to_string()),
            count: c
                .count
                .map(|v| v.to_string())
                .unwrap_or_else(|| UNUSED_CAPABILITY_PROPERTY.to_string()),
            hardware_revision: c
                .hardware_revision
                .unwrap_or_else(|| UNUSED_CAPABILITY_PROPERTY.to_string()),
            cores: c
                .cores
                .map(|v| v.to_string())
                .unwrap_or_else(|| UNUSED_CAPABILITY_PROPERTY.to_string()),
            threads: c
                .threads
                .map(|v| v.to_string())
                .unwrap_or_else(|| UNUSED_CAPABILITY_PROPERTY.to_string()),
            device_type: c
                .device_type
                .map(|v| v.to_string())
                .unwrap_or_else(|| UNUSED_CAPABILITY_PROPERTY.to_string()),
            inactive_devices: c
                .inactive_devices
                .map(|v| {
                    v.items
                        .iter()
                        .map(|i| i.to_string())
                        .collect::<Vec<String>>()
                        .join(", ")
                })
                .unwrap_or_else(|| UNUSED_CAPABILITY_PROPERTY.to_string()),
        }
    }
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
/// existing instance types
#[derive(Deserialize, Debug)]
pub struct ShowInstanceTypeParams {
    #[serde(default, deserialize_with = "empty_string_as_none")]
    limit: Option<usize>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    current_page: Option<usize>,
}

/// Handler for displaying all instance types
pub async fn show(
    AxumState(api): AxumState<Arc<Api>>,
    Query(params): Query<ShowInstanceTypeParams>,
    path: OriginalUri,
) -> Response {
    let current_page = params.current_page.unwrap_or(0);

    let limit: usize = params.limit.map_or(DEFAULT_PAGE_RECORD_LIMIT, |s| {
        min(s, DEFAULT_PAGE_RECORD_LIMIT)
    });

    let (pages, instance_types) = match fetch_instance_types(api, current_page, limit).await {
        Ok(all) => all,
        Err(err) => {
            tracing::error!(%err, "fetch_itypes");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error loading instance types: {err}"),
            )
                .into_response();
        }
    };

    let tmpl = InstanceTypeShow {
        path: path.path().to_string(),
        instance_types,
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

/// Helper to fetch all instance types
/// with some pagination.
async fn fetch_instance_types(
    api: Arc<Api>,
    current_page: usize,
    limit: usize,
) -> Result<(usize, Vec<InstanceTypeRowDisplay>), tonic::Status> {
    let request: tonic::Request<forgerpc::FindInstanceTypeIdsRequest> =
        tonic::Request::new(forgerpc::FindInstanceTypeIdsRequest {});

    let all_ids = api
        .find_instance_type_ids(request)
        .await
        .map(|response| response.into_inner())?
        .instance_type_ids;

    // Handling the case of getting a nonsensical limit.
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

    // Just handles the other case of someone messing around with the
    // query params and suddenly setting a limit that makes
    // current_record_cnt_seen no longer make sense.
    if current_record_cnt_seen > all_ids.len() {
        return Ok((pages, vec![]));
    }

    let ids_for_page = all_ids
        .into_iter()
        .skip(current_record_cnt_seen)
        .take(limit)
        .collect();

    let itypes = api
        .find_instance_types_by_ids(tonic::Request::new(
            forgerpc::FindInstanceTypesByIdsRequest {
                instance_type_ids: ids_for_page,
            },
        ))
        .await
        .map(|response| response.into_inner())?
        .instance_types;

    Ok((pages, itypes.into_iter().map(|n| n.into()).collect()))
}

/// Handler for displaying a single instance type.
pub async fn show_detail(
    AxumState(api): AxumState<Arc<Api>>,
    AxumPath(instance_type_id): AxumPath<String>,
) -> Response {
    let (show_json, instance_type_id) = match instance_type_id.strip_suffix(".json") {
        Some(instance_type_id) => (true, instance_type_id.to_string()),
        None => (false, instance_type_id),
    };

    // Grab the basic details for the instance type
    let Some(itype) = match api
        .find_instance_types_by_ids(tonic::Request::new(
            forgerpc::FindInstanceTypesByIdsRequest {
                instance_type_ids: vec![instance_type_id.clone()],
            },
        ))
        .await
        .map(|response| response.into_inner())
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unable to retrieve instance type: {e}"),
            )
                .into_response();
        }
    }
    .instance_types
    .pop() else {
        return (StatusCode::NOT_FOUND, "Requested instance type not found").into_response();
    };

    if show_json {
        return (StatusCode::OK, Json(itype)).into_response();
    }

    // Prepare some values for template vars
    let created = itype.created_at().to_string();

    let metadata = itype.metadata.unwrap_or_default();

    let associated_machine_ids = match api
        .find_machine_ids(tonic::Request::new(forgerpc::MachineSearchConfig {
            instance_type_id: Some(instance_type_id.clone()),
            ..Default::default()
        }))
        .await
    {
        Ok(response) => response.into_inner().machine_ids,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Unable to retrieve associated Machine ID for instance type ID {instance_type_id}: {e}"
                ),
            )
                .into_response();
        }
    };

    // Set up the final template object
    let tmpl = InstanceTypeDetailDisplay {
        id: itype.id,
        name: metadata.name,
        description: metadata.description,
        labels: metadata.labels,
        capabilities: itype
            .attributes
            .map(|a| {
                a.desired_capabilities
                    .into_iter()
                    .map(InstanceTypeCapabilitiesRowDisplay::from)
                    .collect()
            })
            .unwrap_or_default(),
        version: itype.version,
        created,
        associated_machines: associated_machine_ids
            .into_iter()
            .map(|m| m.to_string())
            .collect(),
    };

    // Away we go
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}
