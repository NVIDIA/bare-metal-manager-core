/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use axum::{Router, ServiceExt};
use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tower::Layer;
use tower_http::normalize_path::NormalizePathLayer;

use crate::combined_service::CombinedService;

pub enum ListenerOrAddress {
    Listener(TcpListener),
    Address(SocketAddr),
}

impl ListenerOrAddress {
    pub fn address(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Listener(l) => l.local_addr(),
            Self::Address(a) => Ok(*a),
        }
    }
}

/// Multiplexed HTTP routers on a single IP/port.
///
/// HTTP header `forwarded` is used to route the request to the
/// appropriate entry.
///
/// Note: that this code is not BMC-mock specific and potentially can
/// be separate crate if needed.
#[derive(Debug)]
pub struct CombinedServer {
    join_handle: Option<JoinHandle<std::io::Result<()>>>,
    axum_handle: axum_server::Handle,
    pub address: SocketAddr,
}

impl Drop for CombinedServer {
    fn drop(&mut self) {
        if let Some(join_handle) = self.join_handle.take()
            && !join_handle.is_finished()
        {
            tracing::info!("Stopping BMC Mock at {}", self.address);
            self.axum_handle.shutdown();
            join_handle.abort()
        }
    }
}

impl CombinedServer {
    pub fn run(
        name: &str,
        routers_by_ip_address: Arc<RwLock<HashMap<String, Router>>>,
        listener_or_address: Option<ListenerOrAddress>,
        server_config: rustls::ServerConfig,
    ) -> Self {
        let config = RustlsConfig::from_config(Arc::new(server_config));

        let axum_handle = axum_server::Handle::new();

        let (addr, server) = match listener_or_address {
            Some(ListenerOrAddress::Address(addr)) => (
                addr,
                axum_server::bind_rustls(addr, config).handle(axum_handle.clone()),
            ),
            Some(ListenerOrAddress::Listener(listener)) => (
                listener.local_addr().unwrap(),
                axum_server::from_tcp_rustls(listener, config).handle(axum_handle.clone()),
            ),
            None => {
                let addr = SocketAddr::from(([0, 0, 0, 0], 1266));
                (
                    addr,
                    axum_server::bind_rustls(addr, config).handle(axum_handle.clone()),
                )
            }
        };
        tracing::info!("Listening on {}", addr);

        let service = CombinedService::new(routers_by_ip_address);

        // Inject middleware to normalize request URIs by dropping the trailing slash
        let service = NormalizePathLayer::trim_trailing_slash().layer(service);
        let join_handle = tokio::task::Builder::new()
            .name(name)
            .spawn(async move {
                server
                    .serve(service.into_make_service())
                    .await
                    .inspect_err(|e| {
                        tracing::error!("BMC mock could not listen on address {}: {}", addr, e)
                    })?;
                Ok(())
            })
            .expect("tokio spawn error");
        Self {
            axum_handle,
            join_handle: Some(join_handle),
            address: addr,
        }
    }

    pub async fn stop(&mut self) -> std::io::Result<()> {
        if let Some(join_handle) = self.join_handle.take() {
            self.axum_handle.shutdown();
            join_handle.await.expect("join error")
        } else {
            Ok(())
        }
    }

    pub async fn wait(&mut self) -> std::io::Result<()> {
        if let Some(join_handle) = self.join_handle.take() {
            join_handle.await.expect("join error")
        } else {
            Ok(())
        }
    }
}
