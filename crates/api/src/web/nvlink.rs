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

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::Json;
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use carbide_uuid::nvlink::NvLinkPartitionId;
use hyper::http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;
use uuid::Uuid;

//use super::filters;
use crate::api::Api;

#[derive(serde::Serialize, Template)]
#[template(path = "nvlink_partition_show.html")]
struct LogicalPartitionShow {
    partitions: Vec<LogicalPartitionRowDisplay>,
}

#[derive(serde::Serialize)]
struct LogicalPartitionRowDisplay {
    id: String,
    name: String,
    state: String,
    physical_partitions: usize,
}

#[derive(serde::Serialize, Clone)]
struct ShowLogicalPartition {
    partition: forgerpc::NvLinkLogicalPartition,
    physical_partitions: Vec<ShowPhysicalPartition>,
}
#[derive(serde::Serialize, Clone)]
struct ShowPhysicalPartition {
    partition: forgerpc::NvLinkPartition,
    members: Vec<ShowPartitionMember>,
}
#[derive(serde::Serialize, Clone)]
struct ShowPartitionMember {
    machine_id: String,
    gpu_id: String,
}

impl From<ShowLogicalPartition> for LogicalPartitionRowDisplay {
    fn from(show: ShowLogicalPartition) -> Self {
        Self {
            id: show.partition.id.map(|i| i.to_string()).unwrap_or_default(),
            name: show
                .partition
                .config
                .unwrap_or_default()
                .metadata
                .unwrap_or_default()
                .name,
            state: forgerpc::TenantState::try_from(show.partition.status.unwrap_or_default().state)
                .unwrap_or_default()
                .as_str_name()
                .to_string(),
            physical_partitions: show.physical_partitions.len(),
        }
    }
}
#[derive(serde::Serialize, Clone)]
struct ShowPhysicalPartitionDetail {
    id: String,
    name: String,
    nmx_m_id: String,
    members: Vec<ShowPartitionMember>,
}

#[derive(Template)]
#[template(path = "logical_partition_detail.html")]
struct LogicalPartitionDetail {
    id: String,
    name: String,
    state: String,
    physical_partitions: Vec<ShowPhysicalPartitionDetail>,
}

impl From<ShowLogicalPartition> for LogicalPartitionDetail {
    fn from(show: ShowLogicalPartition) -> Self {
        let mut physical_partitions = Vec::new();
        for s in show.physical_partitions {
            let pp = ShowPhysicalPartitionDetail {
                id: s.partition.id.map(|i| i.to_string()).unwrap_or_default(),
                name: s.partition.name,
                nmx_m_id: s.partition.nmx_m_id,
                members: s.members,
            };
            physical_partitions.push(pp);
        }
        Self {
            id: show.partition.id.map(|i| i.to_string()).unwrap_or_default(),
            name: show
                .partition
                .config
                .unwrap_or_default()
                .metadata
                .unwrap_or_default()
                .name,
            state: forgerpc::TenantState::try_from(show.partition.status.unwrap_or_default().state)
                .unwrap_or_default()
                .as_str_name()
                .to_string(),
            physical_partitions,
        }
    }
}

/// List logical partitions
pub async fn show_nvlink_logical_partitions_html(
    AxumState(state): AxumState<Arc<Api>>,
) -> Response {
    let partitions = match fetch_logical_partitions(state.clone(), false, None).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_logical_partitions");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading logical partitions",
            )
                .into_response();
        }
    };

    let tmpl = LogicalPartitionShow {
        partitions: partitions.into_iter().map(Into::into).collect(),
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_nvlink_logical_partitions_json(
    AxumState(state): AxumState<Arc<Api>>,
) -> impl IntoResponse {
    let partitions = match fetch_logical_partitions(state, false, None).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_logical_partitions");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json("Error loading logical_partitions".to_string()),
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(partitions)).into_response()
}

/// View Logical Partition details
pub async fn detail(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(partition_id): AxumPath<String>,
) -> Response {
    let (show_json, partition_id) = match partition_id.strip_suffix(".json") {
        Some(partition_id) => (true, partition_id.to_string()),
        None => (false, partition_id),
    };

    let partitionid = match Uuid::parse_str(&partition_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Logical Partition id {partition_id} could not be parsed into UUID Err {e}"
                ),
            )
                .into_response();
        }
    };
    let partitions = match fetch_logical_partitions(state.clone(), true, Some(partitionid)).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_logical_partitions");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading logical partitions",
            )
                .into_response();
        }
    };

    if show_json {
        return (StatusCode::OK, Json(partitions[0].clone())).into_response();
    }

    let tmpl: LogicalPartitionDetail = partitions[0].clone().into();
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

async fn fetch_logical_partitions(
    api: Arc<Api>,
    detail: bool,
    pid: Option<Uuid>,
) -> Result<Vec<ShowLogicalPartition>, tonic::Status> {
    let request =
        tonic::Request::new(rpc::forge::NvLinkLogicalPartitionSearchFilter { name: None });
    let mut show_partitions = Vec::<ShowLogicalPartition>::new();

    let partition_ids = api
        .find_nv_link_logical_partition_ids(request)
        .await?
        .into_inner()
        .partition_ids;
    if partition_ids.is_empty() {
        return Ok(show_partitions);
    }

    let mut partitions = Vec::new();
    if let Some(pid) = pid {
        let request_partitions =
            tonic::Request::new(rpc::forge::NvLinkLogicalPartitionsByIdsRequest {
                partition_ids: vec![pid.into()],
                include_history: false,
            });
        let next_partitions = api
            .find_nv_link_logical_partitions_by_ids(request_partitions)
            .await
            .map(|response| response.into_inner())?;
        partitions.extend(next_partitions.partitions.into_iter());
    } else {
        let mut offset = 0;
        while offset != partition_ids.len() {
            const PAGE_SIZE: usize = 100;
            let page_size = PAGE_SIZE.min(partition_ids.len() - offset);
            let next_ids = &partition_ids[offset..offset + page_size];
            let request_partitions =
                tonic::Request::new(rpc::forge::NvLinkLogicalPartitionsByIdsRequest {
                    partition_ids: next_ids.to_vec(),
                    include_history: false,
                });
            let next_partitions = api
                .find_nv_link_logical_partitions_by_ids(request_partitions)
                .await
                .map(|response| response.into_inner())?;

            partitions.extend(next_partitions.partitions.into_iter());
            offset += page_size;
        }
    }

    let request = tonic::Request::new(rpc::forge::NvLinkPartitionSearchFilter {
        name: None,
        tenant_organization_id: None,
    });

    let mut map: HashMap<_, Vec<forgerpc::NvLinkPartition>> = HashMap::new();
    let mut member_map: HashMap<NvLinkPartitionId, Vec<ShowPartitionMember>> = HashMap::new();

    let ids = api
        .find_nv_link_partition_ids(request)
        .await
        .map(|response| response.into_inner())
        .unwrap();

    if !ids.partition_ids.is_empty() {
        let request = tonic::Request::new(forgerpc::NvLinkPartitionsByIdsRequest {
            partition_ids: ids.partition_ids,
            include_history: false,
        });

        let physical_partitions = api
            .find_nv_link_partitions_by_ids(request)
            .await
            .map(|response| response.into_inner())
            .unwrap();

        if detail {
            let request = tonic::Request::new(forgerpc::MachineSearchConfig {
                include_dpus: false,
                include_history: false,
                include_predicted_host: false,
                only_maintenance: false,
                exclude_hosts: false,
                only_quarantine: false,
                instance_type_id: None,
                mnnvl_only: true,
            });

            let machine_ids = api
                .find_machine_ids(request)
                .await?
                .into_inner()
                .machine_ids;

            let mut machines = Vec::new();
            let mut offset = 0;
            while offset != machine_ids.len() {
                const PAGE_SIZE: usize = 100;
                let page_size = PAGE_SIZE.min(machine_ids.len() - offset);
                let next_ids = &machine_ids[offset..offset + page_size];
                let next_vpcs = api
                    .find_machines_by_ids(tonic::Request::new(forgerpc::MachinesByIdsRequest {
                        machine_ids: next_ids.to_vec(),
                        include_history: false,
                    }))
                    .await?
                    .into_inner();

                machines.extend(next_vpcs.machines.into_iter());
                offset += page_size;
            }

            for m in machines {
                if let Some(status) = m.nvlink_status_observation {
                    for gpu in &status.gpu_status {
                        if let Some(partition_id) = &gpu.partition_id {
                            member_map.entry(*partition_id).or_default().push(
                                ShowPartitionMember {
                                    machine_id: m.id.unwrap_or_default().to_string(),
                                    gpu_id: gpu.guid.to_string(),
                                },
                            );
                        }
                    }
                }
            }
        }

        for lp in &partitions {
            if let Some(ref lp_id) = lp.id {
                let matching_partitions: Vec<forgerpc::NvLinkPartition> = physical_partitions
                    .partitions
                    .iter()
                    .filter(|p| p.logical_partition_id.as_ref() == Some(lp_id))
                    .cloned()
                    .collect();
                map.insert(*lp_id, matching_partitions);
            }
        }
    }

    for lp in partitions {
        let ph_p = lp.id.and_then(|id| map.get(&id)).cloned();
        let mut show_physical_partitions = Vec::new();
        if let Some(ph_p) = ph_p {
            for p in ph_p {
                let m = p.id.and_then(|id| member_map.get(&id));
                if let Some(m) = m {
                    show_physical_partitions.push(ShowPhysicalPartition {
                        partition: p,
                        members: m.to_vec(),
                    })
                } else {
                    show_physical_partitions.push(ShowPhysicalPartition {
                        partition: p,
                        members: vec![],
                    })
                }
            }
        }

        let show_lp = ShowLogicalPartition {
            partition: lp.clone(),
            physical_partitions: show_physical_partitions,
        };
        show_partitions.push(show_lp);
    }

    Ok(show_partitions)
}
