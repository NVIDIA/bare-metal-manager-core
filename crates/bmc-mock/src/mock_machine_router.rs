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
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::{mpsc, oneshot};

use crate::bmc_state::BmcState;
use crate::bug::InjectedBugs;
use crate::json::JsonExt;
use crate::redfish::manager::ManagerState;
use crate::{
    MachineInfo, PowerControl, SetSystemPowerReq, call_router_with_new_request, middleware_router,
};

#[derive(Clone)]
pub(crate) struct MockWrapperState {
    pub machine_info: MachineInfo,
    inner_router: Router,
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

/// Return an axum::Router that mocks various redfish calls to match the provided MachineInfo.
/// Any redfish calls not explicitly mocked will be delegated to inner_router (typically a tar_router.)
///
// TODO: This router is now more and more coupled to a particular tar_router (dell_poweredge_r750.tar.gz).
// At this point this module no longer can be said to wrap any old tar router, but instead only works with
// the Dell router. At the very least we may want to rename this module.
pub fn wrap_router_with_mock_machine(
    inner_router: Router,
    machine_info: MachineInfo,
    power_control: Arc<dyn PowerControl>,
    mat_host_id: String,
) -> Router {
    let system_config = machine_info.system_config(power_control);
    let chassis_config = machine_info.chassis_config();
    let router = Router::new()
        // Couple routes for bug injection.
        .route(
            "/InjectedBugs",
            get(get_injected_bugs).post(post_injected_bugs),
        )
        .add_routes(crate::redfish::chassis::add_routes)
        .add_routes(crate::redfish::manager::add_routes)
        .add_routes(crate::redfish::boot_options::add_routes)
        .add_routes(crate::redfish::update_service::add_routes)
        .add_routes(crate::redfish::task_service::add_routes)
        .add_routes(crate::redfish::secure_boot::add_routes)
        .add_routes(crate::redfish::account_service::add_routes)
        .add_routes(|routes| {
            crate::redfish::computer_system::add_routes(routes, system_config.bmc_vendor)
        })
        .add_routes(crate::redfish::bios::add_routes);
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
    let injected_bugs = Arc::new(InjectedBugs::default());
    let router = router
        .fallback(fallback_to_inner_router)
        .with_state(MockWrapperState {
            machine_info,
            inner_router,
            bmc_state: BmcState {
                jobs: Arc::new(Mutex::new(HashMap::new())),
                secure_boot_enabled: Arc::new(AtomicBool::new(false)),
                manager,
                system_state,
                chassis_state,
                bios: Arc::new(Mutex::new(serde_json::json!({}))),
                dell_attrs: Arc::new(Mutex::new(serde_json::json!({}))),
                injected_bugs: injected_bugs.clone(),
            },
        });
    middleware_router::append(mat_host_id, router, injected_bugs)
}

impl MockWrapperState {
    /// See docs in `call_router_with_new_request`
    pub(crate) async fn call_inner_router(
        &mut self,
        request: Request<Body>,
    ) -> Result<serde_json::Value, MockWrapperError> {
        let (method, uri) = (request.method().clone(), request.uri().clone());
        let response = self.proxy_inner(request).await;
        let status = response.status();
        let response_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        if !status.is_success() {
            Err(MockWrapperError::InnerRequest(
                method,
                Box::new(uri),
                status,
                String::from_utf8_lossy(&response_bytes).to_string(),
            ))
        } else {
            serde_json::from_slice::<serde_json::Value>(&response_bytes)
                .map_err(MockWrapperError::from)
        }
    }

    pub(crate) async fn proxy_inner(&mut self, request: Request<Body>) -> Response {
        call_router_with_new_request(&mut self.inner_router, request).await
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum MockWrapperError {
    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Axum error on inner request: {0}")]
    Axum(#[from] axum::Error),
    #[error("Infallible error: {0}")]
    Infallible(#[from] Infallible),
    #[error("Inner request {0} {1} failed with HTTP error {2}: {3}")]
    InnerRequest(Method, Box<Uri>, StatusCode, String),
    #[error("{0}")]
    SetSystemPower(#[from] SetSystemPowerError),
    #[error("Error sending to BMC command channel: {0}")]
    BmcCommandSendError(#[from] mpsc::error::SendError<BmcCommand>),
    #[error("Error receiving from BMC command channel: {0}")]
    BmcCommandReceiveError(#[from] oneshot::error::RecvError),
}

impl IntoResponse for MockWrapperError {
    fn into_response(self) -> axum::response::Response {
        // Don't log errors if the upstream request was the one that failed
        if !matches!(self, MockWrapperError::InnerRequest(_, _, _, _)) {
            tracing::error!("Mock machine router failure: {}", self.to_string());
        }

        match self {
            MockWrapperError::InnerRequest(_, _, status_code, body_bytes) => {
                // Use the error's status code instead of INTERNAL_SERVER_ERROR
                (status_code, body_bytes).into_response()
            }
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

pub(crate) async fn fallback_to_inner_router(
    mut state: State<MockWrapperState>,
    request: Request<Body>,
) -> Response {
    state
        .call_inner_router(request)
        .await
        .map(|v| v.into_ok_response())
        .unwrap_or_else(|err| err.into_response())
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
