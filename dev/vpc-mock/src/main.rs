/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

/* A very basic HTTP server that pretends to be the Kubernetes API
 * for get / create of VPC objects.
 *
 * It's main purpose is to expose what gets sent Carbide->VPC when a network
 * segment is created.
 *
 * To use it run carbide-api with `--kubernetes` flag. See docker-compose.yaml comment.
 */

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use tracing::debug;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::fmt::Layer;
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() {
    let env_filter = EnvFilter::from_default_env().add_directive(LevelFilter::DEBUG.into());

    tracing_subscriber::registry()
        .with(Layer::default().compact())
        .with(env_filter)
        .init();

    let resource_group_state = Arc::new(Mutex::new(HashSet::new()));
    let leaf_state = Arc::new(Mutex::new(HashSet::new()));

    let app = Router::new()
        .route("/version", get(version))

        // Resource group
        .route("/apis/resource.vpc.forge.gitlab-master.nvidia.com/v1alpha1/namespaces/forge-system/resourcegroups/:rg_id", get(get_resource_group)).with_state(resource_group_state.clone())
        .route("/apis/resource.vpc.forge.gitlab-master.nvidia.com/v1alpha1/namespaces/forge-system/resourcegroups", post(create_resource_group)).with_state(resource_group_state.clone())

        // Leaf
        .route("/apis/networkfabric.vpc.forge.gitlab-master.nvidia.com/v1alpha1/namespaces/forge-system/leafs", get(get_leafs))
        .route("/apis/networkfabric.vpc.forge.gitlab-master.nvidia.com/v1alpha1/namespaces/forge-system/leafs", post(create_leaf)).with_state(leaf_state.clone())
        .route("/apis/networkfabric.vpc.forge.gitlab-master.nvidia.com/v1alpha1/namespaces/forge-system/leafs/:leaf_id", get(get_leaf)).with_state(leaf_state.clone())
        .route("/apis/networkfabric.vpc.forge.gitlab-master.nvidia.com/v1alpha1/namespaces/forge-system/leafs/:leaf_id/status", get(get_leaf_status)).with_state(leaf_state.clone())

        .fallback(fallback);

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let config = RustlsConfig::from_pem_file(root.join("cert.pem"), root.join("key.pem"))
        .await
        .unwrap();

    let addr = SocketAddr::from(([0, 0, 0, 0], 7272));
    debug!("Listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn fallback(uri: Uri) -> impl IntoResponse {
    debug!("general handler: {:?}", uri);
    (StatusCode::NOT_FOUND, format!("No route for {}", uri))
}

const RESOURCE_GROUP_NOT_FOUND_JSON: &str = include_str!("../json/resource_group_not_found.json");
const RESOURCE_GROUP_FOUND_JSON: &str = include_str!("../json/resource_group_table.json");

async fn get_resource_group(
    State(state): State<Arc<Mutex<HashSet<String>>>>,
    AxumPath(rg_id): AxumPath<String>,
) -> impl IntoResponse {
    debug!("get_resource_group {rg_id}");
    match state.lock().unwrap().get(&rg_id) {
        None => (StatusCode::NOT_FOUND, RESOURCE_GROUP_NOT_FOUND_JSON),
        Some(_) => (StatusCode::OK, RESOURCE_GROUP_FOUND_JSON),
    }
}

async fn create_resource_group(
    State(state): State<Arc<Mutex<HashSet<String>>>>,
    Query(params): Query<HashMap<String, String>>,
    body: String,
) -> impl IntoResponse {
    debug!("create_resource_group. PARAMS: {params:?}. BODY: {body}");

    let rg_id = get_name(&body);
    state.lock().unwrap().insert(rg_id);
    (
        StatusCode::CREATED,
        include_str!("../json/resource_group_created.json"),
    )
}

fn get_name(body: &str) -> String {
    let body_json: HashMap<String, serde_json::Value> = serde_json::from_str(body).unwrap();
    body_json
        .get("metadata")
        .unwrap()
        .as_object()
        .unwrap()
        .get("name")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

async fn version() -> impl IntoResponse {
    (StatusCode::OK, include_str!("../json/version.json"))
}

const LEAF_NOT_FOUND_JSON: &str = include_str!("../json/leaf_not_found.json");
const LEAF_FOUND_JSON: &str = include_str!("../json/leaf_table.json");

async fn get_leafs(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    debug!("get_leafs {params:?}");
    (StatusCode::NOT_FOUND, LEAF_NOT_FOUND_JSON)
}

async fn get_leaf(
    State(state): State<Arc<Mutex<HashSet<String>>>>,
    AxumPath(leaf_id): AxumPath<String>,
) -> impl IntoResponse {
    debug!("get_leaf {leaf_id}"); // note that it ends in ".leaf", e.g. d5c58cdd-a1d1-4a13-83fd-74b8f539dff8.leaf
    match state.lock().unwrap().get(&leaf_id) {
        None => (StatusCode::NOT_FOUND, LEAF_NOT_FOUND_JSON),
        Some(_) => (StatusCode::OK, LEAF_FOUND_JSON),
    }
}

async fn get_leaf_status(
    State(_state): State<Arc<Mutex<HashSet<String>>>>,
    AxumPath(leaf_id): AxumPath<String>,
) -> impl IntoResponse {
    debug!("get_leaf_status {leaf_id}");
    (StatusCode::OK, include_str!("../json/leaf_status.json"))
}

async fn create_leaf(
    State(state): State<Arc<Mutex<HashSet<String>>>>,
    Query(params): Query<HashMap<String, String>>,
    body: String,
) -> impl IntoResponse {
    debug!("create_leaf. PARAMS: {params:?}. BODY: {body}");
    let leaf_id = get_name(&body);
    state.lock().unwrap().insert(leaf_id);
    (
        StatusCode::CREATED,
        include_str!("../json/leaf_created.json"),
    )
}
