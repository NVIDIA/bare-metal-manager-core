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
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as forgerpc};
use serde::{Deserialize, Deserializer, de};

use super::filters;
use crate::api::Api;

const DEFAULT_PAGE_RECORD_LIMIT: usize = 100;

#[derive(Template)]
#[template(path = "network_security_group_show.html")]
struct NetworkSecurityGroupShow {
    path: String,
    network_security_groups: Vec<NetworkSecurityGroupRowDisplay>,
    current_page: usize,
    previous: usize,
    next: usize,
    pages: usize,
    page_range_start: usize,
    page_range_end: usize,
    limit: usize,
}

#[derive(PartialEq, Eq)]
struct NetworkSecurityGroupRowDisplay {
    id: String,
    tenant_organization_id: String,
    name: String,
    description: String,
    version: String,
    created: String,
}

impl PartialOrd for NetworkSecurityGroupRowDisplay {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NetworkSecurityGroupRowDisplay {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl From<forgerpc::NetworkSecurityGroup> for NetworkSecurityGroupRowDisplay {
    fn from(nsg: forgerpc::NetworkSecurityGroup) -> Self {
        let created = nsg.created_at().to_string();
        let metadata = nsg.metadata.unwrap_or_default();

        NetworkSecurityGroupRowDisplay {
            created,
            id: nsg.id,
            tenant_organization_id: nsg.tenant_organization_id,
            name: metadata.name,
            description: metadata.description,
            version: nsg.version,
        }
    }
}

#[derive(Debug)]
struct NetworkSecurityGroupPropagation {
    object_id: String,
    object_type: String,
    object_status: String,
    unpropagated_instance_ids: Vec<String>,
}

#[derive(Debug, Template)]
#[template(path = "network_security_group_detail.html")]
struct NetworkSecurityGroupDetailDisplay {
    id: String,
    tenant_organization_id: String,
    name: String,
    description: String,
    version: String,
    created: String,
    created_by: String,
    updated_by: String,
    stateful_egress: bool,
    labels: String,
    rules: String,
    attachments: forgerpc::NetworkSecurityGroupAttachments,
    propagation: Vec<NetworkSecurityGroupPropagation>,
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
/// existing NSGs
#[derive(Deserialize, Debug)]
pub struct ShowNetworkSecurityGroupParams {
    #[serde(default, deserialize_with = "empty_string_as_none")]
    limit: Option<usize>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    current_page: Option<usize>,
}

/// Handler for displaying all network security groups
pub async fn show(
    AxumState(api): AxumState<Arc<Api>>,
    Query(params): Query<ShowNetworkSecurityGroupParams>,
    path: OriginalUri,
) -> Response {
    let current_page = params.current_page.unwrap_or(0);

    let limit: usize = params.limit.map_or(DEFAULT_PAGE_RECORD_LIMIT, |s| {
        min(s, DEFAULT_PAGE_RECORD_LIMIT)
    });

    let (pages, network_security_groups) =
        match fetch_network_security_groups(api, current_page, limit).await {
            Ok(all) => all,
            Err(err) => {
                tracing::error!(%err, "fetch_nsgs");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Error loading network security groups: {err}"),
                )
                    .into_response();
            }
        };

    let tmpl = NetworkSecurityGroupShow {
        path: path.path().to_string(),
        network_security_groups,
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

/// Helper to fetch all network security groups
/// with some pagination.
async fn fetch_network_security_groups(
    api: Arc<Api>,
    current_page: usize,
    limit: usize,
) -> Result<(usize, Vec<NetworkSecurityGroupRowDisplay>), tonic::Status> {
    let request: tonic::Request<forgerpc::FindNetworkSecurityGroupIdsRequest> =
        tonic::Request::new(forgerpc::FindNetworkSecurityGroupIdsRequest {
            name: None,
            tenant_organization_id: None,
        });

    let all_ids = api
        .find_network_security_group_ids(request)
        .await
        .map(|response| response.into_inner())?
        .network_security_group_ids;

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

    let nsgs = api
        .find_network_security_groups_by_ids(tonic::Request::new(
            forgerpc::FindNetworkSecurityGroupsByIdsRequest {
                tenant_organization_id: None,
                network_security_group_ids: ids_for_page,
            },
        ))
        .await
        .map(|response| response.into_inner())?
        .network_security_groups;

    Ok((pages, nsgs.into_iter().map(|n| n.into()).collect()))
}

/// Handler for displaying a single network security group.
/// It will include some extra details like any objects
/// that are using the NSG and propagation status for those
/// objects.
pub async fn show_detail(
    AxumState(api): AxumState<Arc<Api>>,
    AxumPath(network_security_group_id): AxumPath<String>,
) -> Response {
    let (show_json, network_security_group_id) =
        match network_security_group_id.strip_suffix(".json") {
            Some(network_security_group_id) => (true, network_security_group_id.to_string()),
            None => (false, network_security_group_id),
        };

    // Grab the basic details for the NSG
    let Some(nsg) = match api
        .find_network_security_groups_by_ids(tonic::Request::new(
            forgerpc::FindNetworkSecurityGroupsByIdsRequest {
                tenant_organization_id: None,
                network_security_group_ids: vec![network_security_group_id.clone()],
            },
        ))
        .await
        .map(|response| response.into_inner())
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unable to retrieve network security group: {e}"),
            )
                .into_response();
        }
    }
    .network_security_groups
    .pop() else {
        return (
            StatusCode::NOT_FOUND,
            "Requested network security group not found",
        )
            .into_response();
    };

    if show_json {
        return (StatusCode::OK, Json(nsg)).into_response();
    }

    // Prepare some values for template vars
    let created = nsg.created_at().to_string();
    let created_by = nsg.created_by().to_string();
    let updated_by = nsg.updated_by().to_string();

    let attrs = nsg.attributes.unwrap_or_default();

    let rules = match serde_json::to_string_pretty(&attrs.rules) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to serialize network security group rules: {e}"),
            )
                .into_response();
        }
    };

    let metadata = nsg.metadata.unwrap_or_default();
    let labels = match serde_json::to_string_pretty(&metadata.labels) {
        Ok(l) => l,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to serialize network security group labels: {e}"),
            )
                .into_response();
        }
    };

    // Find any objects that are using this NSG
    let attachments = match api
        .get_network_security_group_attachments(tonic::Request::new(
            forgerpc::GetNetworkSecurityGroupAttachmentsRequest {
                network_security_group_ids: vec![network_security_group_id.clone()],
            },
        ))
        .await
        .map(|response| response.into_inner())
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unable to retrieve network security group attachment details: {e}"),
            )
                .into_response();
        }
    }
    .attachments
    .pop()
    .unwrap_or_default();

    let mut propagation = Vec::<NetworkSecurityGroupPropagation>::new();

    // If there are any attachments, get propagation details
    // for any objects that are using this NSG.
    if !attachments.vpc_ids.is_empty() || !attachments.instance_ids.is_empty() {
        let propagations = match api
            .get_network_security_group_propagation_status(tonic::Request::new(
                forgerpc::GetNetworkSecurityGroupPropagationStatusRequest {
                    vpc_ids: attachments.vpc_ids.clone(),
                    instance_ids: attachments.instance_ids.clone(),
                    network_security_group_ids: Some(forgerpc::NetworkSecurityGroupIdList {
                        ids: vec![network_security_group_id],
                    }),
                },
            ))
            .await
            .map(|response| response.into_inner())
        {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Unable to retrieve network security group attachment details: {e}"),
                )
                    .into_response();
            }
        };

        // Prepare the propagation details for the template

        for propagation_status in propagations.instances {
            propagation.push(NetworkSecurityGroupPropagation {
                object_status: propagation_status.status().as_str_name().to_string(),
                object_id: propagation_status.id,
                object_type: "INSTANCE".to_string(),
                unpropagated_instance_ids: propagation_status.unpropagated_instance_ids,
            })
        }

        for propagation_status in propagations.vpcs {
            propagation.push(NetworkSecurityGroupPropagation {
                object_status: propagation_status.status().as_str_name().to_string(),
                object_id: propagation_status.id,
                object_type: "VPC".to_string(),
                unpropagated_instance_ids: propagation_status.unpropagated_instance_ids,
            })
        }
    }

    // Set up the final template object
    let tmpl = NetworkSecurityGroupDetailDisplay {
        id: nsg.id,
        tenant_organization_id: nsg.tenant_organization_id,
        name: metadata.name,
        description: metadata.description,
        labels,
        rules,
        stateful_egress: attrs.stateful_egress,
        version: nsg.version,
        created,
        created_by,
        updated_by,
        attachments,
        propagation,
    };

    // Away we go
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

/// Struct for deserializing a request to create
/// a new NSG
#[derive(Deserialize, Debug)]
pub struct CreateNetworkSecurityGroupForm {
    id: String,
    tenant_organization_id: String,
    name: String,
    stateful_egress: Option<bool>,
    description: String,
    labels: String,
    rules: String,
}

// Handler to create a new NSG
pub async fn create(
    AxumState(api): AxumState<Arc<Api>>,
    Form(form): Form<CreateNetworkSecurityGroupForm>,
) -> Response {
    let id = if form.id.is_empty() {
        None
    } else {
        Some(form.id)
    };
    let labels = if form.labels.is_empty() {
        "[]".to_string()
    } else {
        form.labels
    };
    let network_security_group_attributes = if form.rules.is_empty() {
        None
    } else {
        Some(forgerpc::NetworkSecurityGroupAttributes {
            stateful_egress: form.stateful_egress.unwrap_or_default(),
            rules: match serde_json::from_str(&form.rules) {
                Ok(r) => r,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to deserialize rules: {e}"),
                    )
                        .into_response();
                }
            },
        })
    };

    let resp = match api
        .create_network_security_group(tonic::Request::new(
            forgerpc::CreateNetworkSecurityGroupRequest {
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
                network_security_group_attributes,
            },
        ))
        .await
        .map(|response| response.into_inner())
    {
        Ok(r) => r.network_security_group,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unable to retrieve network security group: {e}"),
            )
                .into_response();
        }
    };

    let Some(nsg) = resp else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unexpected empty response after creating network security group",
        )
            .into_response();
    };

    Redirect::to(&format!("/admin/network-security-group/{}", nsg.id)).into_response()
}

/// Struct for deserializing a request to update
/// an existing NSG
#[derive(Deserialize, Debug)]
pub struct UpdateNetworkSecurityGroupForm {
    tenant_organization_id: String,
    name: String,
    stateful_egress: Option<bool>,

    description: String,
    labels: String,
    rules: String,
    version: String,
}

// Handler for updating an existing NSG
pub async fn update(
    AxumState(api): AxumState<Arc<Api>>,
    AxumPath(network_security_group_id): AxumPath<String>,
    Form(form): Form<UpdateNetworkSecurityGroupForm>,
) -> Response {
    let labels = if form.labels.is_empty() {
        "[]".to_string()
    } else {
        form.labels
    };

    let network_security_group_attributes = if form.rules.is_empty() {
        None
    } else {
        Some(forgerpc::NetworkSecurityGroupAttributes {
            stateful_egress: form.stateful_egress.unwrap_or_default(),

            rules: match serde_json::from_str(&form.rules) {
                Ok(r) => r,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to deserialize rules: {e}"),
                    )
                        .into_response();
                }
            },
        })
    };

    let resp = match api
        .update_network_security_group(tonic::Request::new(
            forgerpc::UpdateNetworkSecurityGroupRequest {
                id: network_security_group_id,
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
                network_security_group_attributes,
            },
        ))
        .await
        .map(|response| response.into_inner())
    {
        Ok(r) => r.network_security_group,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unable to retrieve network security group: {e}"),
            )
                .into_response();
        }
    };

    let Some(nsg) = resp else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unexpected empty response after creating network security group",
        )
            .into_response();
    };

    Redirect::to(&format!("/admin/network-security-group/{}", nsg.id)).into_response()
}

/// Struct for deserializing a request to delete
/// an existing NSG
#[derive(Deserialize, Debug)]
pub struct DeleteNetworkSecurityGroupForm {
    tenant_organization_id: String,
}

// Handler for deleting an existing NSG
pub async fn delete(
    AxumState(api): AxumState<Arc<Api>>,
    AxumPath(network_security_group_id): AxumPath<String>,
    Form(form): Form<DeleteNetworkSecurityGroupForm>,
) -> Response {
    if let Err(e) = api
        .delete_network_security_group(tonic::Request::new(
            forgerpc::DeleteNetworkSecurityGroupRequest {
                id: network_security_group_id,
                tenant_organization_id: form.tenant_organization_id,
            },
        ))
        .await
        .map(|response| response.into_inner())
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to delete network security group: {e}"),
        )
            .into_response();
    };

    Redirect::to("/admin/network-security-group").into_response()
}
