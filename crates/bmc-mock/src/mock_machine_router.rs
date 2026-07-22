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

use axum::Router;
use tokio::sync::oneshot;

use crate::auth_router::Authorizer;
use crate::bmc_state::BmcState;
use crate::injection::InjectionStore;
use crate::redfish::manager::ManagerState;
use crate::{
    Callbacks, HostHardwareType, MachineInfo, SystemPowerControl, auth_router, middleware_router,
    redfish,
};

#[derive(Debug)]
pub enum BmcCommand {
    SetSystemPower {
        request: SystemPowerControl,
        reply: Option<oneshot::Sender<SetSystemPowerResult>>,
    },
    StateRefreshIndication,
}

pub type SetSystemPowerResult = Result<(), SetSystemPowerError>;

#[derive(Debug, thiserror::Error)]
pub enum SetSystemPowerError {
    #[error("mock BMC reported bad request when setting system power: {0}")]
    BadRequest(String),
    #[error("mock BMC failed to send power command: {0}")]
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
    machine_info: &MachineInfo,
    callbacks: Arc<dyn Callbacks>,
    mat_host_id: String,
    redfish_auth: bool,
) -> (Router, BmcState) {
    machine_router_with_injection_store(
        machine_info,
        callbacks,
        mat_host_id,
        redfish_auth,
        Arc::new(InjectionStore::new()),
    )
}

/// Return a machine router backed by a caller-provided injection store.
pub fn machine_router_with_injection_store(
    machine_info: &MachineInfo,
    callbacks: Arc<dyn Callbacks>,
    mat_host_id: String,
    redfish_auth: bool,
    injection: Arc<InjectionStore>,
) -> (Router, BmcState) {
    let system_config = machine_info.system_config(callbacks.clone());
    let chassis_config = machine_info.chassis_config();
    let update_service_config = machine_info.update_service_config();
    let bmc_vendor = machine_info.bmc_vendor();
    let bmc_product = machine_info.bmc_product();
    let bmc_redfish_version = machine_info.bmc_redfish_version();
    let oem_state = machine_info.oem_state();
    let factory_default_account = machine_info.factory_default_account();
    let router = Router::new()
        .add_routes(crate::injection::add_routes)
        .add_routes(crate::redfish::service_root::add_routes)
        .add_routes(crate::redfish::chassis::add_routes)
        .add_routes(crate::redfish::manager::add_routes)
        .add_routes(crate::redfish::update_service::add_routes)
        .add_routes(crate::redfish::task_service::add_routes)
        .add_routes(crate::redfish::telemetry_service::add_routes)
        .add_routes(crate::redfish::account_service::add_routes)
        .add_routes(crate::redfish::session_service::add_routes)
        .add_routes(|routes| crate::redfish::computer_system::add_routes(routes, bmc_vendor))
        .add_routes(crate::ipmi::add_routes);
    let router = match machine_info {
        MachineInfo::Dpu(_) => {
            router.add_routes(crate::redfish::oem::nvidia::bluefield::add_routes)
        }
        MachineInfo::Host(_) => router
            .add_routes(crate::redfish::oem::dell::idrac::add_routes)
            .add_routes(crate::redfish::oem::supermicro::manager::add_routes),
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
    let account_service_state = Arc::new(
        crate::redfish::account_service::AccountServiceState::new(factory_default_account),
    );
    let session_service_state =
        Arc::new(crate::redfish::session_service::SessionServiceState::new());
    let state = BmcState {
        bmc_vendor,
        bmc_product,
        bmc_redfish_version,
        oem_state,
        manager,
        system_state,
        chassis_state,
        update_service_state,
        account_service_state,
        session_service_state,
        injection: injection.clone(),
        callbacks: Some(callbacks.clone()),
        exposes_computer_systems: machine_info.exposes_computer_systems(),
    };
    let account_service_state = state.account_service_state.clone();
    let session_service_state = state.session_service_state.clone();
    let permit_factory_default_password = matches!(
        &machine_info,
        MachineInfo::Host(h) if matches!(
            h.hw_type,
            HostHardwareType::LiteOnPowerShelf | HostHardwareType::DeltaPowerShelf
        )
    );
    let router = ([
        Box::new(redfish::expander_router::append),
        Box::new(move |router| {
            if redfish_auth {
                let authorizer = Authorizer::new(account_service_state, session_service_state);
                let authorizer = if permit_factory_default_password {
                    authorizer.permit_factory_default_password()
                } else {
                    authorizer
                };
                auth_router::append(router, authorizer)
            } else {
                router
            }
        }),
        Box::new(move |router| {
            middleware_router::append(mat_host_id, router, injection, callbacks)
        }),
    ] as [Box<dyn FnOnce(axum::Router) -> axum::Router>; _])
        .into_iter()
        .fold(router.with_state(state.clone()), |router, f| f(router));
    (router, state)
}
