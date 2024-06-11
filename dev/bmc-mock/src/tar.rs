/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

/// The TAR files used here are a full crawl of a servers' Redfish tree using
/// redfish-mockup-creator.
/// https://gitlab-master.nvidia.com/nvmetal/libredfish/-/tree/forge/tests/mockups?ref_type=heads
///
/// There is one for each vendor we support in the libredfish repo.
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::Read;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use flate2::read::GzDecoder;

const MAX_HISTORY_ENTRIES: usize = 1000;

#[derive(Clone)]
struct BmcState {
    entries: Arc<Mutex<HashMap<String, String>>>,
    history: Arc<Mutex<HashMap<String, VecDeque<String>>>>,
}

pub fn tar_router(p: &std::path::Path) -> eyre::Result<Router> {
    let mut entries = HashMap::new();

    let f = GzDecoder::new(File::open(p)?);
    let mut archive = tar::Archive::new(f);
    for r in archive.entries().unwrap() {
        let mut r = r.unwrap();
        let name = r
            .path()
            .unwrap()
            .display()
            .to_string()
            .replace("/index.json", "");
        if name.ends_with('/') {
            // ignore directories
            continue;
        }
        let mut s = String::with_capacity(r.size() as usize);
        let _ = r.read_to_string(&mut s)?;
        entries.insert(name, s);
    }

    let state = BmcState {
        entries: Arc::new(Mutex::new(entries)),
        history: Arc::new(Mutex::new(HashMap::default())),
    };
    Ok(Router::new()
        .route("/history", get(get_history_macs))
        .route("/history/:mac", get(get_history))
        .route("/*path", get(get_from_tar).patch(set_any).post(set_any))
        .with_state(state))
}

async fn get_history_macs(AxumState(shared_state): AxumState<BmcState>) -> impl IntoResponse {
    let history_map = shared_state.history.lock().unwrap();
    (
        StatusCode::OK,
        serde_json::to_string_pretty(&history_map.keys().collect::<Vec<&String>>()).unwrap(),
    )
}

async fn get_history(
    AxumState(shared_state): AxumState<BmcState>,
    AxumPath(mac_address): AxumPath<String>,
) -> impl IntoResponse {
    let mut history_map = shared_state.history.lock().unwrap();
    match history_map.get_mut(&mac_address) {
        None => {
            tracing::trace!("No history for mac address: {mac_address}");
            (
                StatusCode::NOT_FOUND,
                serde_json::to_string("no history for mac address").unwrap(),
            )
        }
        Some(history) => {
            tracing::trace!("Found history for mac address: {mac_address}");
            (
                StatusCode::OK,
                serde_json::to_string_pretty(history).unwrap(),
            )
        }
    }
}

fn append_history(
    history: Arc<Mutex<HashMap<String, VecDeque<String>>>>,
    mac_address: &str,
    path: &String,
) {
    let mut history_map = history.lock().unwrap();
    let history = match history_map.get_mut(mac_address) {
        None => {
            tracing::trace!("New history for mac address: {mac_address}");
            history_map.insert(mac_address.to_owned(), VecDeque::default());
            history_map.get_mut(mac_address).unwrap()
        }
        Some(history) => {
            tracing::trace!("Found history for mac address: {mac_address}");
            history
        }
    };
    history.push_back(path.to_owned());
    while history.len() > MAX_HISTORY_ENTRIES {
        history.pop_front();
    }
}
/// Read redfish data from the tar
async fn get_from_tar(
    AxumState(shared_state): AxumState<BmcState>,
    AxumPath(mut path): AxumPath<String>,
    request: Request<Body>,
) -> impl IntoResponse {
    if path.ends_with('/') {
        path.pop();
    };

    let really_to_mac = request
        .headers()
        .get("x-really-to-mac")
        .map_or("", |v| v.to_str().unwrap());
    append_history(shared_state.history.clone(), really_to_mac, &path);

    match shared_state.entries.lock().unwrap().get(&path) {
        None => (StatusCode::NOT_FOUND, path),
        Some(s) => {
            if really_to_mac.is_empty() {
                tracing::trace!("{path}");
            } else {
                tracing::trace!("{path} for {really_to_mac}");
            }
            (StatusCode::OK, s.clone())
        }
    }
}

/// Accept any POST or PATCH
async fn set_any(
    AxumState(shared_state): AxumState<BmcState>,
    AxumPath(path): AxumPath<String>,
    request: Request<Body>,
) -> impl IntoResponse {
    tracing::info!("Set: {path}");
    let really_to_mac = request
        .headers()
        .get("x-really-to-mac")
        .map_or("", |v| v.to_str().unwrap());
    append_history(shared_state.history.clone(), really_to_mac, &path);

    StatusCode::OK
}
