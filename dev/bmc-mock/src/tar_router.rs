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
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time;

use crate::SetSystemPowerReq;
use axum::body::Body;
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use bytes::Buf;
use eyre::Context;
use flate2::read::GzDecoder;
use regex::Regex;
use serde::Deserialize;

const MAX_HISTORY_ENTRIES: usize = 1000;
pub type EntryMap = Arc<Mutex<HashMap<String, String>>>;
type HistoryMap = Arc<Mutex<HashMap<String, VecDeque<String>>>>;

const POWER_CYLE_TIME_SECS: u64 = 5;

#[derive(Clone, Default)]
struct BmcState {
    is_on: Arc<AtomicBool>,
    off_until: Arc<Mutex<Option<time::SystemTime>>>,
    entries: EntryMap,
    history: HistoryMap,
}

/// Allows callers to specify an in-memory tar (like via include_bytes!()) or a path to one on the
/// filesystem.
pub enum TarGzOption<'a> {
    Disk(&'a PathBuf),
    Memory(&'a [u8]),
}

impl TarGzOption<'_> {
    fn path(&self) -> Option<&PathBuf> {
        match self {
            TarGzOption::Disk(path) => Some(path),
            TarGzOption::Memory(_) => None,
        }
    }
}

/// Create a mock of
pub fn tar_router(
    targz: TarGzOption,
    existing_tars: Option<&mut HashMap<std::path::PathBuf, EntryMap>>,
) -> eyre::Result<Router> {
    // Check if we've already read this tar.gz
    let maybe_cached_entries = if let Some(existing_tars) = existing_tars.as_ref() {
        targz.path().and_then(|p| existing_tars.get(p).cloned())
    } else {
        None
    };

    let entries = match maybe_cached_entries {
        Some(entries) => entries,
        None => {
            let mut _owned_gz_data = None; // make sure data sent to gz_decoder lives long enough
            let gz_decoder = match targz {
                TarGzOption::Disk(path) => {
                    _owned_gz_data = Some(
                        std::fs::read(path)
                            .wrap_err(format!("cannot read file by path: {path:?}"))?,
                    );
                    GzDecoder::new(_owned_gz_data.as_ref().unwrap().reader())
                }
                TarGzOption::Memory(bytes) => GzDecoder::new(bytes.reader()),
            };

            let entries = tar::Archive::new(gz_decoder)
                .entries()
                .unwrap()
                .map(Result::unwrap)
                .filter_map(|mut entry| {
                    let name = entry
                        .path()
                        .unwrap()
                        .display()
                        .to_string()
                        .replace("/index.json", "");
                    if name.ends_with('/') {
                        // ignore directories
                        None
                    } else {
                        let mut s = String::with_capacity(entry.size() as usize);
                        let _ = entry.read_to_string(&mut s).unwrap();
                        Some((name, s))
                    }
                })
                .collect::<HashMap<_, _>>();
            let entries = Arc::new(Mutex::new(entries));

            // cache what we just built
            if let (Some(path), Some(existing_tars)) = (targz.path(), existing_tars) {
                existing_tars.insert(path.clone(), entries.clone());
            }

            entries
        }
    };

    let bmc_state = BmcState {
        is_on: Arc::new(AtomicBool::new(true)),
        entries,
        ..Default::default()
    };

    Ok(Router::new()
        .route("/history", get(get_history_macs))
        .route("/history/:mac", get(get_history))
        .route("/*path", get(get_from_tar).patch(set_any).post(set_any))
        .fallback(not_found_handler)
        .with_state(bmc_state))
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
        Some(history) => (
            StatusCode::OK,
            serde_json::to_string_pretty(history).unwrap(),
        ),
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
        Some(history) => history,
    };
    history.push_back(path.to_owned());
    while history.len() > MAX_HISTORY_ENTRIES {
        history.pop_front();
    }
}

lazy_static::lazy_static! {
    static ref GET_SYSTEM_RE: Regex = Regex::new(r#"Systems/[A-Za-z0-9\-_.~]+$"#).unwrap();
    static ref GET_MANAGER_RE: Regex = Regex::new(r#"Managers/[A-Za-z0-9\-_.~]+$"#).unwrap();
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

    maybe_power_back_on(&shared_state);

    let really_to_mac = request
        .headers()
        .get("x-really-to-mac")
        .map_or("", |v| v.to_str().unwrap());
    append_history(shared_state.history.clone(), really_to_mac, &path);

    match shared_state.entries.lock().unwrap().get(&path) {
        None => {
            // This is expected for UpdateService/FirmwareInventory
            tracing::trace!("Not found: {path}");
            (StatusCode::NOT_FOUND, path)
        }
        Some(s) => {
            if really_to_mac.is_empty() {
                tracing::trace!("Get: {path}");
            } else {
                tracing::trace!("Get: {path} for {really_to_mac}");
            }
            if GET_SYSTEM_RE.is_match(&path) || GET_MANAGER_RE.is_match(&path) {
                // TODO Parse it as JSON. This works for now
                if !shared_state.is_on.load(Ordering::Relaxed) {
                    tracing::debug!("Reporting powered off");
                    let on = r#""PowerState": "On","#;
                    let off = r#""PowerState": "Off","#;
                    return (StatusCode::OK, s.replace(on, off));
                }
            }
            (StatusCode::OK, s.clone())
        }
    }
}

fn maybe_power_back_on(state: &BmcState) {
    let mut off_until = state.off_until.lock().unwrap();
    if let Some(off_timeout) = *off_until {
        if off_timeout < time::SystemTime::now() {
            *off_until = None;
            state.is_on.store(true, Ordering::Relaxed);
            tracing::debug!("Powered back on");
        }
    }
}

fn set_system_power(shared_state: BmcState, req: SetSystemPowerReq) {
    tracing::debug!("Power action: {:?}", req.reset_type);
    use super::SystemPowerControl::*;
    match req.reset_type {
        On | ForceOn => {
            // Permanently on
            shared_state.is_on.store(true, Ordering::Relaxed);
            *shared_state.off_until.lock().unwrap() = None;
        }
        GracefulShutdown | ForceOff | Nmi | Suspend => {
            // Permanently off
            shared_state.is_on.store(false, Ordering::Relaxed);
            *shared_state.off_until.lock().unwrap() = None;
        }
        GracefulRestart | ForceRestart => {
            // Reboot. These don't affect power state, On or Off.
        }
        Pause | Resume => {
            // Unhandled
        }
        PowerCycle => {
            // Reboot but also cut the power
            //
            // Off for POWER_CYLE_TIME_SECS (might need to adjust)
            // Switched back on in get_from_tar's maybe_power_back_on
            shared_state.is_on.store(false, Ordering::Relaxed);
            let t = time::SystemTime::now() + time::Duration::from_secs(POWER_CYLE_TIME_SECS);
            *shared_state.off_until.lock().unwrap() = Some(t);
        }
        PushPowerButton => {
            // Presumably toggle power
            let current = shared_state.is_on.load(Ordering::SeqCst);
            shared_state.is_on.store(!current, Ordering::SeqCst);
            *shared_state.off_until.lock().unwrap() = None;
        }
    }
}

/// Accept any POST or PATCH
async fn set_any(
    AxumState(shared_state): AxumState<BmcState>,
    AxumPath(mut path): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if path.ends_with('/') {
        path.pop();
    };
    tracing::debug!("Set: {path}");
    let really_to_mac = headers
        .get("x-really-to-mac")
        .map_or("", |v| v.to_str().unwrap());
    append_history(shared_state.history.clone(), really_to_mac, &path);

    // This can't be its own route because of https://github.com/tokio-rs/axum/issues/1986
    if path.ends_with("Actions/ComputerSystem.Reset") {
        let power_req = SetSystemPowerReq::deserialize(body).unwrap();
        set_system_power(shared_state, power_req);
    }

    StatusCode::OK
}

// We should never get here, but axum's matchit bug means we sometimes do: https://github.com/tokio-rs/axum/issues/1986
async fn not_found_handler(req: Request<Body>) -> (StatusCode, String) {
    tracing::warn!("fallback: No route for {} {}", req.method(), req.uri());
    (
        StatusCode::NOT_FOUND,
        format!("No route for {} {}", req.method(), req.uri()),
    )
}
