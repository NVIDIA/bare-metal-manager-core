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

mod bmc;
mod io_util;
mod metrics;
mod ssh_cert_parsing;
mod ssh_server;

mod console_logger;
mod frontend;

// pub mods are only ones used by main.rs and integration tests
pub mod config;
pub mod shutdown_handle;

// Used by fuzz tests
use std::sync::Arc;

pub use bmc::vendor::{EscapeSequence, IPMITOOL_ESCAPE_SEQUENCE};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::metrics::MetricsState;
use crate::shutdown_handle::{ReadyHandle, ShutdownHandle};

pub static POWER_RESET_COMMAND: &str = "power reset";

/// Run a ssh-console server in the background, returning a [`SpawnHandle`] once the service is
/// healthy and ready. When the handle is dropped, the server will exit.
pub async fn spawn(config: Config) -> Result<SpawnHandle, SpawnError> {
    let config = Arc::new(config);
    let metrics = Arc::new(MetricsState::new());
    let forge_api_client = config.make_forge_api_client();

    // 1) Start BMC client pool
    let mut bmc_client_pool =
        bmc::client_pool::spawn(config.clone(), forge_api_client.clone(), &metrics.meter);
    bmc_client_pool
        .wait_until_ready()
        .await
        .map_err(|_| SpawnError::ClientPoolUnknownFailure)?;

    // 2) Start SSH server itself
    let server = ssh_server::spawn(
        config.clone(),
        forge_api_client.clone(),
        bmc_client_pool.connection_store(),
        &metrics.meter,
    )
    .await?;

    // 3) Start metrics server
    let metrics_handle = metrics::spawn(config.clone(), metrics).await?;

    // 4) Wait for a shutdown signal, then shut down the above
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join_handle = tokio::spawn(async move {
        shutdown_rx.await.ok();
        metrics_handle.shutdown_and_wait().await;
        bmc_client_pool.shutdown_and_wait().await;
        server.shutdown_and_wait().await;
    });

    Ok(SpawnHandle {
        shutdown_tx,
        join_handle,
    })
}

#[derive(thiserror::Error, Debug)]
pub enum SpawnError {
    #[error("Unknown failure spawning BMC client pool")]
    ClientPoolUnknownFailure,
    #[error("Error spawning SSH server: {0}")]
    SshServerSpawn(#[from] ssh_server::SpawnError),
    #[error("Error spawning metrics server: {0}")]
    MetricsSpawn(#[from] metrics::SpawnError),
}

pub struct SpawnHandle {
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

impl ShutdownHandle<()> for SpawnHandle {
    fn into_parts(self) -> (oneshot::Sender<()>, JoinHandle<()>) {
        (self.shutdown_tx, self.join_handle)
    }
}
