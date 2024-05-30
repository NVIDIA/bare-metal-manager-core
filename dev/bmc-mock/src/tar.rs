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
use std::collections::HashMap;
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

#[derive(Clone)]
struct BmcState {
    entries: Arc<Mutex<HashMap<String, String>>>,
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
    };
    Ok(Router::new()
        .route("/*path", get(get_from_tar).patch(set_any).post(set_any))
        .with_state(state))
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
    match shared_state.entries.lock().unwrap().get(&path) {
        None => (StatusCode::NOT_FOUND, path),
        Some(s) => {
            if let Some(really_to_ip) = request.headers().get("x-really-to-ip") {
                let really_to_ip = really_to_ip.to_str().unwrap_or_default();
                let really_to_mac = request
                    .headers()
                    .get("x-really-to-mac")
                    .map_or("", |mac| mac.to_str().ok().unwrap_or_default());
                tracing::trace!("{path} for {really_to_ip} ({really_to_mac})");
            } else {
                tracing::trace!("{path}");
            }
            (StatusCode::OK, s.clone())
        }
    }
}

/// Accept any POST or PATCH
async fn set_any(AxumPath(path): AxumPath<String>) -> impl IntoResponse {
    tracing::info!("Set: {path}");
    StatusCode::OK
}
