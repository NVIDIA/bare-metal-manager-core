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
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::oneshot;

use crate::bmc_state::BmcState;
use crate::bug::InjectedBugs;
use crate::json::JsonExt;
use crate::redfish::manager::ManagerState;
use crate::{MachineInfo, PowerControl, SystemPowerControl, middleware_router, redfish};

#[derive(Debug)]
pub enum BmcCommand {
    SetSystemPower {
        request: SystemPowerControl,
        reply: Option<oneshot::Sender<SetSystemPowerResult>>,
    },
}

pub type SetSystemPowerResult = Result<(), SetSystemPowerError>;

#[derive(Debug, thiserror::Error)]
pub enum SetSystemPowerError {
    #[error("Mock BMC reported bad request when setting system power: {0}")]
    BadRequest(String),
    #[error("Mock BMC failed to send power command: {0}")]
    CommandSendError(String),
}

trait AddRoutes {
    fn add_routes(self, f: impl FnOnce(Self) -> Self) -> Self
    where
        Self: Sized;
}

impl AddRoutes for Router<BmcState> {
    fn add_routes(self, f: impl FnOnce(Self) -> Self) -> Self {
        f(self)
    }
}

/// Return an axum::Router that mocks various redfish calls to match
/// the provided MachineInfo.
pub fn machine_router(
    machine_info: MachineInfo,
    power_control: Arc<dyn PowerControl>,
    mat_host_id: String,
) -> Router {
    let system_config = machine_info.system_config(power_control);
    let chassis_config = machine_info.chassis_config();
    let update_service_config = machine_info.update_service_config();
    let bmc_vendor = machine_info.bmc_vendor();
    let oem_state = machine_info.oem_state();
    let router = Router::new()
        // Couple routes for bug injection.
        .route(
            "/InjectedBugs",
            get(get_injected_bugs).post(post_injected_bugs),
        )
        .add_routes(crate::redfish::service_root::add_routes)
        .add_routes(crate::redfish::chassis::add_routes)
        .add_routes(crate::redfish::manager::add_routes)
        .add_routes(crate::redfish::update_service::add_routes)
        .add_routes(crate::redfish::task_service::add_routes)
        .add_routes(crate::redfish::account_service::add_routes)
        .add_routes(|routes| crate::redfish::computer_system::add_routes(routes, bmc_vendor));
    let router = match &machine_info {
        MachineInfo::Dpu(_) => {
            router.add_routes(crate::redfish::oem::nvidia::bluefield::add_routes)
        }
        MachineInfo::Host(_) => router.add_routes(crate::redfish::oem::dell::idrac::add_routes),
    };
    let manager = Arc::new(ManagerState::new(&machine_info.manager_config()));
    let system_state = Arc::new(crate::redfish::computer_system::SystemState::from_config(
        system_config,
    ));
    let chassis_state = Arc::new(crate::redfish::chassis::ChassisState::from_config(
        chassis_config,
    ));
    let update_service_state = Arc::new(
        crate::redfish::update_service::UpdateServiceState::from_config(update_service_config),
    );
    let injected_bugs = Arc::new(InjectedBugs::default());
    let router = router.with_state(BmcState {
        bmc_vendor,
        oem_state,
        manager,
        system_state,
        chassis_state,
        update_service_state,
        injected_bugs: injected_bugs.clone(),
    });
    let router_with_expansion = redfish::expander_router::append(router);
    middleware_router::append(mat_host_id, router_with_expansion, injected_bugs)
}

async fn get_injected_bugs(State(state): State<BmcState>) -> Response {
    state.injected_bugs.get().into_ok_response()
}

async fn post_injected_bugs(
    State(state): State<BmcState>,
    Json(bug_args): Json<serde_json::Value>,
) -> Response {
    state
        .injected_bugs
        .update(bug_args)
        .map(|_| state.injected_bugs.get().into_ok_response())
        .unwrap_or_else(|err| {
            serde_json::json!({"error": format!("{err:?}")}).into_response(StatusCode::BAD_REQUEST)
        })
}
