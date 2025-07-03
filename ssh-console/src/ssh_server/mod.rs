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
use eyre::Context;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

mod backend;
mod frontend;
mod server;

/// Run a ssh-console server in the background, returning a [`SpawnHandle`]. When the handle is
/// dropped, the server will exit.
pub async fn spawn(config: Config) -> eyre::Result<SpawnHandle> {
    let config = Arc::new(config);
    let host_key =
        russh::keys::PrivateKey::read_openssh_file(&config.host_key_path).with_context(|| {
            format!(
                "Error reading host key file at {}",
                config.host_key_path.display()
            )
        })?;

    let listener = TcpListener::bind(config.listen_address)
        .await
        .with_context(|| format!("Error listening on {}", config.listen_address))?;

    tracing::info!("listening on {}", config.listen_address);

    let server = server::new(config);

    let (tx, rx) = tokio::sync::oneshot::channel();
    let join_handle = tokio::spawn(server.run(
        Arc::new(russh::server::Config {
            keys: vec![host_key],
            ..Default::default()
        }),
        listener,
        rx,
    ));

    Ok(SpawnHandle {
        _stop_tx: tx,
        join_handle,
    })
}

pub struct SpawnHandle {
    _stop_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<eyre::Result<()>>,
}

impl SpawnHandle {
    /// Wait indefinitely for the service to finish. This will only return if there is a bug which
    /// causes the server's event loop to return an error.
    pub async fn wait_forever(self) -> eyre::Result<()> {
        self.join_handle.await.expect("service task panicked")
    }
}
