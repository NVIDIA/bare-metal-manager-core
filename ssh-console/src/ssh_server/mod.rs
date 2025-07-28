/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::config::Config;
use crate::metrics::MetricsState;
use crate::{ReadyHandle, ShutdownHandle};
use eyre::Context;
use russh::{MethodKind, MethodSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;
use tokio::task::JoinHandle;

mod backend_connection;
mod backend_pool;
mod backend_session;
mod connection_state;
mod console_logger;
pub(crate) mod frontend;
mod metrics_service;
mod server;

/// Run a ssh-console server in the background, returning a [`SpawnHandle`]. When the handle is
/// dropped, the server will exit.
pub async fn spawn(config: Config, metrics: Arc<MetricsState>) -> eyre::Result<SpawnHandle> {
    let config = Arc::new(config);
    let host_key =
        russh::keys::PrivateKey::read_openssh_file(&config.host_key_path).with_context(|| {
            format!(
                "Error reading host key file at {}",
                config.host_key_path.display()
            )
        })?;

    let server = server::new(config.clone(), &metrics.meter);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();

    let server_join_handle = tokio::spawn(server.run(
        Arc::new(russh::server::Config {
            keys: vec![host_key],
            // We only accept PublicKey auth (certificates are a kind of PublicKey auth)
            methods: MethodSet::from([MethodKind::PublicKey].as_slice()),
            nodelay: true,
            auth_rejection_time: Duration::from_millis(30),
            ..Default::default()
        }),
        ready_tx,
        shutdown_rx,
    ));

    let metrics_join_handle = metrics_service::spawn(config, metrics)
        .await
        .context("Error spawning metrics server")?;

    let join_handle = tokio::spawn(async move {
        // First wait for the server to finish, then shut down metrics.
        let result = server_join_handle.await.expect("task panicked");
        metrics_join_handle.shutdown_and_wait().await;
        result
    });

    Ok(SpawnHandle {
        shutdown_tx,
        join_handle,
        ready_rx: Some(ready_rx),
    })
}

pub struct SpawnHandle {
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<eyre::Result<()>>,
    ready_rx: Option<oneshot::Receiver<()>>,
}

impl ShutdownHandle<eyre::Result<()>> for SpawnHandle {
    fn into_parts(self) -> (oneshot::Sender<()>, JoinHandle<eyre::Result<()>>) {
        (self.shutdown_tx, self.join_handle)
    }
}

impl ReadyHandle for SpawnHandle {
    fn take_ready_rx(&mut self) -> Option<Receiver<()>> {
        self.ready_rx.take()
    }
}
