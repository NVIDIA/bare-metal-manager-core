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

use carbide_ib_fabric::ib::IBFabricManager;
use carbide_ipmi::IPMITool;
use carbide_redfish::libredfish::RedfishClientPool;
use db::db_read::PgPoolReader;
use forge_secrets::credentials::CredentialManager;
use libredfish::Redfish;
use librms::RmsApi;
use model::machine::Machine;
use model::resource_pool::common::IbPools;
use sqlx::PgPool;

use crate::cfg::file::CarbideConfig;
use crate::dpa::handler::DpaInfo;
use crate::rack::rms_client::SwitchSystemImageRmsClient;
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
    pub rms_client: Option<Arc<dyn RmsApi>>,

    /// Shared client for switch system image RPCs that are not yet exposed through
    /// librms::RmsApi.
    pub switch_system_image_rms_client: Option<Arc<dyn SwitchSystemImageRmsClient>>,

    /// Credential manager (Vault) for fetching BMC credentials
    pub credential_manager: Arc<dyn CredentialManager>,
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
