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
#[template(path = "sku_show.html")]
struct SkuShow {
    skus: Vec<SkuRowDisplay>,
}

struct SkuRowDisplay {
    id: String,
    machines_associated_count: usize,
    architecture: String,
    model: String,
    vendor: String,
    num_cpus: usize,
    num_gpus: usize,
    num_ib_devices: usize,
    memory_capacity: String,
}

impl From<forgerpc::Sku> for SkuRowDisplay {
    fn from(sku: forgerpc::Sku) -> Self {
        let components = sku.components.as_ref();
        let chassis = components.and_then(|c| c.chassis.as_ref());
        Self {
            id: sku.id,
            machines_associated_count: sku.machines_associated_count as _,
            architecture: chassis.map(|c| c.architecture.clone()).unwrap_or_default(),
            model: chassis.map(|c| c.model.clone()).unwrap_or_default(),
            vendor: chassis.map(|c| c.vendor.clone()).unwrap_or_default(),
            num_cpus: components
                .map(|c| c.cpus.iter().map(|c| c.count as usize).sum::<usize>())
                .unwrap_or_default(),
            num_gpus: components
                .map(|c| c.gpus.iter().map(|g| g.count as usize).sum::<usize>())
                .unwrap_or_default(),
            num_ib_devices: components
                .map(|c| {
                    c.infiniband_devices
                        .iter()
                        .map(|ib| ib.count as usize)
                        .sum::<usize>()
                })
                .unwrap_or_default(),
            memory_capacity: components
                .map(|c| {
                    c.memory
                        .iter()
                        .map(|m| m.capacity_mb as u64 * m.count as u64)
                        .sum::<u64>()
                })
                .map(|cap_mb| format!("{} GiB", cap_mb as f64 / 1024.0))
                .unwrap_or_default(),
        }
    }
}

/// List SKUs
pub async fn show_html(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let skus = match fetch_skus(state.clone()).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_skus");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading skus").into_response();
        }
    };

    let tmpl = SkuShow {
        skus: skus.into_iter().map(Into::into).collect(),
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let skus = match fetch_skus(state).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_skus");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading SKUs").into_response();
        }
    };
    (StatusCode::OK, Json(skus)).into_response()
}

async fn fetch_skus(api: Arc<Api>) -> Result<Vec<forgerpc::Sku>, tonic::Status> {
    let request = tonic::Request::new(());

    let sku_ids = api.get_all_sku_ids(request).await?.into_inner().ids;

    let mut skus = Vec::new();
    let mut offset = 0;
    while offset != sku_ids.len() {
        const PAGE_SIZE: usize = 100;
        let page_size = PAGE_SIZE.min(sku_ids.len() - offset);
        let next_ids = &sku_ids[offset..offset + page_size];
        let request = tonic::Request::new(forgerpc::SkuIdList {
            ids: next_ids.to_vec(),
        });
        let next_skus = api
            .get_skus_for_ids(request)
            .await
            .map(|response| response.into_inner())?;

        skus.extend(next_skus.skus.into_iter());
        offset += page_size;
    }

    skus.sort_unstable_by(|sku1, sku2| sku1.id.cmp(&sku2.id));

    Ok(skus)
}

#[derive(Template)]
#[template(path = "sku_detail.html")]
struct SkuDetail {
    id: String,
    description: String,
    created: String,
    components_json: String,
    machines_associated_count: usize,
}

impl From<forgerpc::Sku> for SkuDetail {
    fn from(sku: forgerpc::Sku) -> Self {
        Self {
            id: sku.id,
            description: sku.description.unwrap_or_default(),
            created: sku.created.map(|c| c.to_string()).unwrap_or_default(),
            components_json: sku
                .components
                .map(|c| {
                    serde_json::to_string_pretty(&c).unwrap_or_else(|_e| "Invalid JSON".to_string())
                })
                .unwrap_or_default(),
            machines_associated_count: sku.machines_associated_count as _,
        }
    }
}

/// View SKU details
pub async fn detail(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(sku_id): AxumPath<String>,
) -> Response {
    let request = tonic::Request::new(forgerpc::SkuIdList {
        ids: vec![sku_id.clone()],
    });
    let sku = match state
        .get_skus_for_ids(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(l) if l.skus.is_empty() => {
            return super::not_found_response(sku_id);
        }
        Ok(l) if l.skus.len() != 1 => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("SKU list for {sku_id} returned {} SKUs", l.skus.len()),
            )
                .into_response();
        }
        Ok(mut l) => l.skus.remove(0),
        Err(err) if err.code() == tonic::Code::NotFound => {
            return super::not_found_response(sku_id);
        }
        Err(err) => {
            tracing::error!(%err, "get_skus_for_ids");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading SKUs").into_response();
        }
    };

    let tmpl: SkuDetail = sku.into();
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}
