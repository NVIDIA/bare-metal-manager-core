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

use db::db_read::PgPoolReader;
use libredfish::Redfish;
use model::machine::Machine;
use model::resource_pool::common::IbPools;
use sqlx::PgPool;

use crate::cfg::file::CarbideConfig;
use crate::dpa::handler::DpaInfo;
use crate::ib::IBFabricManager;
use crate::ipmitool::IPMITool;
use crate::rack::rms_client::RmsApi;
use crate::redfish::RedfishClientPool;
use crate::state_controller::state_handler::StateHandlerError;

/// Services that are accessible to all statehandlers within carbide-core
#[derive(Clone)]
pub struct CommonStateHandlerServices {
    /// Postgres database pool
    pub db_pool: PgPool,

    /// Postgres database pool that can be passed directly to read-only db functions without a
    /// transaction
    pub db_reader: PgPoolReader,

    /// API for interaction with Libredfish
    pub redfish_client_pool: Arc<dyn RedfishClientPool>,

    /// API for interaction with Forge IBFabricManager
    pub ib_fabric_manager: Arc<dyn IBFabricManager>,

    /// Resource pools for ib pkey allocation/release.
    pub ib_pools: IbPools,

    /// An implementation of the IPMITool that understands how to reboot a machine
    pub ipmi_tool: Arc<dyn IPMITool>,

    /// Access to the site config
    pub site_config: Arc<CarbideConfig>,

    pub dpa_info: Option<Arc<DpaInfo>>,

    /// Rack Manager Service client
    /// Optional for now, but will be required in the future.
    #[allow(dead_code)]
    pub rms_client: Option<Arc<dyn RmsApi>>,
}

impl CommonStateHandlerServices {
    pub async fn create_redfish_client_from_machine(
        &self,
        machine: &Machine,
    ) -> Result<Box<dyn Redfish>, StateHandlerError> {
        Ok(self
            .redfish_client_pool
            .create_client_from_machine(machine, &self.db_pool)
            .await?)
    }
}
