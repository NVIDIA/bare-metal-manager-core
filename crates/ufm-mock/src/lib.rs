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

mod auth;
mod config;
mod http;
mod inventory;
mod metrics;
mod reconcile;
mod state;

use std::sync::Arc;

pub use auth::{UFM_MOCK_AUTH_TOKEN_ENV, UfmAuthToken};
use axum::Router;
use carbide_axum_utils::injection::InjectionStore;
pub use config::{
    FabricConfig, FailureAction, InventoryConfig, InventorySourceConfig, SmConfig,
    StandaloneConfig, TlsConfig, UfmMockConfig,
};
pub use inventory::{
    EpochId, Generation, Guid, InfinibandPortState, InvalidGuid, InventoryId, InventoryMachine,
    InventoryPort, InventoryProvider, InventorySnapshot, MachineId, MatId,
};
use opentelemetry::metrics::Meter;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::http::HttpState;
use crate::metrics::Metrics;
use crate::state::Fabric;

/// UFM mock shared by hosted and standalone execution.
///
/// Construction creates topology state and HTTP routes but does not choose where inventory comes
/// from. The embedding process makes that choice when it starts reconciliation.
#[derive(Clone)]
pub struct UfmMock {
    fabric: Fabric,
    http: HttpState,
    injection: Arc<InjectionStore>,
    metrics: Metrics,
}

impl UfmMock {
    /// Creates a mock from non-secret configuration and a separately supplied authentication
    /// token.
    pub fn new(
        config: &UfmMockConfig,
        auth_token: &UfmAuthToken,
        meter: &Meter,
    ) -> eyre::Result<Self> {
        let metrics = Metrics::new(meter);
        let fabric = Fabric::new(config.fabric.clone());
        let injection = Arc::new(InjectionStore::new());
        let http = HttpState::new(fabric.clone(), auth_token)?;
        Ok(Self {
            fabric,
            http,
            injection,
            metrics,
        })
    }

    pub fn router(&self) -> Router {
        self.http.clone().router(Arc::clone(&self.injection))
    }

    /// Starts reconciliation for configured HTTP sources and an optional in-process source.
    ///
    /// Machine-a-tron passes its control state as `local_provider` when local inventory is
    /// enabled. The standalone binary passes `None`, leaving configured static HTTP sources as
    /// its only source of inventory.
    pub fn start_reconciliation(
        &self,
        config: InventoryConfig,
        local_provider: Option<Arc<dyn InventoryProvider>>,
        cancellation: CancellationToken,
    ) -> JoinHandle<()> {
        reconcile::start(
            self.fabric.clone(),
            self.metrics.clone(),
            config,
            local_provider,
            cancellation,
        )
    }

    pub fn apply_inventory(&self, snapshot: InventorySnapshot) -> eyre::Result<()> {
        let outcome = self
            .fabric
            .reconcile(snapshot, inventory::InventoryLease::LOCAL)?;
        self.metrics.record_reconciliation(outcome.metric_label());
        Ok(())
    }
}
