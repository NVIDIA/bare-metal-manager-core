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

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::{get, patch, post};
use mac_address::MacAddress;
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::json::{JsonExt, JsonPatch};
use crate::{http, redfish};

#[derive(Clone)]
pub struct BluefieldState {
    mode: Arc<Mutex<ModeState>>,
    base_mac: MacAddress,
}

struct ModeState {
    nic_mode: bool,
    /// A `Mode.Set` queues the requested mode here. A real BlueField applies it
    /// only after the host power-cycles, so it lands on `nic_mode` on the next
    /// `PowerOn` event (see `BmcState::on_event`), not immediately.
    pending_nic_mode: Option<bool>,
}

impl BluefieldState {
    pub fn new(nic_mode: bool, base_mac: MacAddress) -> Self {
        Self {
            mode: Arc::new(Mutex::new(ModeState {
                nic_mode,
                pending_nic_mode: None,
            })),
            base_mac,
        }
    }

    /// Whether the BlueField currently reports NIC mode.
    pub fn nic_mode(&self) -> bool {
        self.mode.lock().unwrap().nic_mode
    }

    /// Queue a `Mode.Set`; it takes effect on the next power cycle.
    fn stage_mode(&self, nic_mode: bool) {
        self.mode.lock().unwrap().pending_nic_mode = Some(nic_mode);
    }

    /// Apply a queued `Mode.Set`, if any -- called on power-on, the point at
    /// which a real BlueField picks up a staged mode change.
    pub fn apply_pending_mode(&self) {
        let mut mode = self.mode.lock().unwrap();
        if let Some(pending) = mode.pending_nic_mode.take() {
            mode.nic_mode = pending;
        }
    }
}

pub fn resource() -> redfish::Resource<'static> {
    redfish::Resource {
        odata_id: Cow::Borrowed("/redfish/v1/Systems/Bluefield/Oem/Nvidia"),
        odata_type: Cow::Borrowed("#NvidiaComputerSystem.v1_0_0.NvidiaComputerSystem"),
        // Neither BF2 nor BF-3 provide Id & Name in the resource We
        // simulate this behavior by removing these fields from final answer.
        id: Cow::Borrowed(""),
        name: Cow::Borrowed(""),
    }
}
const SYSTEMS_OEM_RESOURCE_DELETE_FIELDS: &[&str] = &["Id", "Name"];

pub fn add_routes(r: Router<BmcState>) -> Router<BmcState> {
    r.route(&resource().odata_id, get(get_oem_nvidia))
        .route(
            // TODO: This is BF-3 only.
            &format!("{}/Actions/HostRshim.Set", resource().odata_id),
            post(hostrshim_set),
        )
        .route(
            // BF-3 OEM mode flip. Staged here and applied on the next power
            // cycle, the same as real hardware.
            &format!("{}/Actions/Mode.Set", resource().odata_id),
            post(mode_set),
        )
        .route(
            "/redfish/v1/Managers/Bluefield_BMC/Oem/Nvidia",
            patch(patch_managers_oem_nvidia),
        )
}

async fn hostrshim_set() -> Response {
    json!({}).into_ok_response()
}

async fn get_oem_nvidia(State(state): State<BmcState>) -> Response {
    let redfish::oem::State::NvidiaBluefield(state) = state.oem_state else {
        return http::not_found();
    };
    let mode = if state.nic_mode() {
        "NicMode"
    } else {
        "DpuMode"
    };
    resource()
        .json_patch()
        .patch(json!({
            "Mode": mode,
            "BaseMAC": state.base_mac.to_string().replace(":", ""),
        }))
        .delete_fields(SYSTEMS_OEM_RESOURCE_DELETE_FIELDS)
        .into_ok_response()
}

async fn patch_managers_oem_nvidia() -> Response {
    // This is used by enable_rshim_bmc() of libredfish client.
    json!({}).into_ok_response()
}

/// BF-3 OEM `Mode.Set`: queue a DPU/NIC mode flip. Like real hardware, the
/// change is staged and only takes effect on the next power cycle (applied in
/// `BmcState::on_event` on `PowerOn`), so a read-back before then still shows
/// the old mode.
async fn mode_set(
    State(state): State<BmcState>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Response {
    let redfish::oem::State::NvidiaBluefield(bluefield) = state.oem_state else {
        return http::not_found();
    };
    let Some(nic_mode) = parse_requested_mode(&body) else {
        return http::bad_request("Mode.Set requires a `Mode` of `NicMode` or `DpuMode`");
    };
    bluefield.stage_mode(nic_mode);
    // No response payload -- 204, per Redfish for an action with nothing to return.
    http::ok_no_content()
}

/// Parse a `Mode.Set` body into the requested NIC-mode flag, validating
/// strictly: `Some(true)` for `NicMode`, `Some(false)` for `DpuMode`, `None`
/// for a missing or unrecognized value. A real BF-3 rejects those, and a strict
/// mock turns a drifted client payload into a loud failure rather than a
/// silently wrong flip.
fn parse_requested_mode(body: &serde_json::Value) -> Option<bool> {
    match body.get("Mode").and_then(|mode| mode.as_str()) {
        Some(mode) if mode.eq_ignore_ascii_case("NicMode") => Some(true),
        Some(mode) if mode.eq_ignore_ascii_case("DpuMode") => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_set_is_staged_and_applied_on_power_on() {
        // Starts in DPU mode.
        let bf = BluefieldState::new(false, MacAddress::new([0, 0, 0, 0, 0, 1]));
        assert!(!bf.nic_mode());

        // A `Mode.Set` to NIC mode is staged, not applied immediately -- a
        // read-back still reports DPU mode, like a real BF-3 before its power
        // cycle.
        bf.stage_mode(true);
        assert!(!bf.nic_mode());

        // The next power-on applies the staged mode.
        bf.apply_pending_mode();
        assert!(bf.nic_mode());

        // A power-on with nothing staged leaves the mode untouched.
        bf.apply_pending_mode();
        assert!(bf.nic_mode());
    }

    #[test]
    fn parse_requested_mode_validates_strictly() {
        assert_eq!(
            parse_requested_mode(&serde_json::json!({ "Mode": "NicMode" })),
            Some(true)
        );
        assert_eq!(
            parse_requested_mode(&serde_json::json!({ "Mode": "DpuMode" })),
            Some(false)
        );
        // Case-insensitive, matching the handler.
        assert_eq!(
            parse_requested_mode(&serde_json::json!({ "Mode": "nicmode" })),
            Some(true)
        );
        // Missing or unrecognized -> rejected (the handler returns 400).
        assert_eq!(parse_requested_mode(&serde_json::json!({})), None);
        assert_eq!(
            parse_requested_mode(&serde_json::json!({ "Mode": "bogus" })),
            None
        );
    }
}
