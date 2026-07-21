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

use carbide_health_metrics::PerObjectMetricsRegistry;
use carbide_ipmi::IPMITool;
use carbide_redfish::libredfish::RedfishClientPool;
use carbide_secrets::credentials::CredentialManager;
use component_manager::component_manager::ComponentManager;
use db::db_read::PgPoolReader;
use libredfish::Redfish;
use model::machine::Machine;
use sqlx::PgPool;
use state_controller::state_handler::{StateHandlerContextObjects, StateHandlerError};

use crate::config::MachineStateHandlerSiteConfig;
use crate::metrics::MachineMetrics;

pub struct MachineStateHandlerContextObjects {}

impl StateHandlerContextObjects for MachineStateHandlerContextObjects {
    type Services = MachineStateHandlerServices;
    type ObjectMetrics = MachineMetrics;
}

#[derive(Clone)]
pub struct MachineStateHandlerServices {
    pub db_pool: PgPool,
    /// Postgres database pool that can be passed directly to read-only db functions without a
    /// transaction
    pub db_reader: PgPoolReader,
    /// API for interaction with Libredfish
    pub redfish_client_pool: Arc<dyn RedfishClientPool>,
    /// An implementation of the IPMITool that understands how to reboot a machine
    pub ipmi_tool: Arc<dyn IPMITool>,
    /// Configuration used by MachineStateHandler.
    pub site_config: Arc<MachineStateHandlerSiteConfig>,
    /// Optional Component Manager backend for rack-scale maintenance operations.
    pub component_manager: Option<Arc<ComponentManager>>,
    pub credential_manager: Arc<dyn CredentialManager>,
    /// Shared registry backing the generic per-object health metrics.
    pub per_object_metrics_registry: Arc<PerObjectMetricsRegistry>,
}

impl MachineStateHandlerServices {
    pub async fn create_redfish_client_from_machine(
        &self,
        machine: &Machine,
    ) -> Result<Box<dyn Redfish>, StateHandlerError> {
        let addr = machine
            .bmc_addr()
            .ok_or_else(|| StateHandlerError::MissingData {
                object_id: machine.id.to_string(),
                missing: "BMC Endpoint Information (bmc_info.ip)",
            })?;
        let bmc_access_info = db::machine_interface::lookup_bmc_access_info(
            &self.db_pool,
            addr.ip(),
            Some(addr.port()),
        )
        .await?;
        self.redfish_client_pool
            .client_by_info(&bmc_access_info)
            .await
            .map_err(StateHandlerError::from)
    }
}
