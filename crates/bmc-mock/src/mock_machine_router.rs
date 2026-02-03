/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::{mpsc, oneshot};

use crate::bmc_state::BmcState;
use crate::bug::InjectedBugs;
use crate::json::JsonExt;
use crate::redfish::manager::ManagerState;
use crate::{MachineInfo, PowerControl, SetSystemPowerReq, middleware_router};

#[derive(Clone)]
pub(crate) struct MockWrapperState {
    pub machine_info: MachineInfo,
    pub bmc_state: BmcState,
}

#[derive(Debug)]
pub enum BmcCommand {
    SetSystemPower {
        request: SetSystemPowerReq,
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

impl AddRoutes for Router<MockWrapperState> {
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
    let router = router.with_state(MockWrapperState {
        machine_info,
        bmc_state: BmcState {
            bmc_vendor,
            jobs: Arc::new(Mutex::new(HashMap::new())),
            manager,
            system_state,
            chassis_state,
            update_service_state,
            dell_attrs: Arc::new(Mutex::new(serde_json::json!({}))),
            injected_bugs: injected_bugs.clone(),
        },
    });
    middleware_router::append(mat_host_id, router, injected_bugs)
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum MockWrapperError {
    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Axum error on inner request: {0}")]
    Axum(#[from] axum::Error),
    #[error("Infallible error: {0}")]
    Infallible(#[from] Infallible),
    #[error("{0}")]
    SetSystemPower(#[from] SetSystemPowerError),
    #[error("Error sending to BMC command channel: {0}")]
    BmcCommandSendError(#[from] mpsc::error::SendError<BmcCommand>),
    #[error("Error receiving from BMC command channel: {0}")]
    BmcCommandReceiveError(#[from] oneshot::error::RecvError),
}

impl IntoResponse for MockWrapperError {
    fn into_response(self) -> axum::response::Response {
        match self {
            MockWrapperError::SetSystemPower(e) => {
                let status = match e {
                    SetSystemPowerError::BadRequest(_) => StatusCode::BAD_REQUEST,
                    SetSystemPowerError::CommandSendError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (status, e.to_string()).into_response()
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response(),
        }
    }
}

async fn get_injected_bugs(State(state): State<MockWrapperState>) -> Response {
    state.bmc_state.injected_bugs.get().into_ok_response()
}

async fn post_injected_bugs(
    State(state): State<MockWrapperState>,
    Json(bug_args): Json<serde_json::Value>,
) -> Response {
    state
        .bmc_state
        .injected_bugs
        .update(bug_args)
        .map(|_| state.bmc_state.injected_bugs.get().into_ok_response())
        .unwrap_or_else(|err| {
            serde_json::json!({"error": format!("{err:?}")}).into_response(StatusCode::BAD_REQUEST)
        })
}
