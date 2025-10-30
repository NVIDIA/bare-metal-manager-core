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
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::time::Duration;

use eyre::Context;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::rt::TokioExecutor;
use size::Size;
use ssh_console::config::Defaults;
use temp_dir::TempDir;

use crate::util::fixtures::{
    API_CA_CERT, API_CLIENT_CERT, API_CLIENT_KEY, AUTHORIZED_KEYS_PATH, SSH_HOST_KEY,
};

#[derive(Default)]
pub struct ConfigOverrides {
    pub reconnect_interval_base: Option<Duration>,
    pub reconnect_interval_max: Option<Duration>,
    pub successful_connection_minimum_duration: Option<Duration>,
}

pub async fn spawn(
    carbide_port: u16,
    config_overrides: Option<ConfigOverrides>,
) -> eyre::Result<NewSshConsoleHandle> {
    let listen_address = {
        // Pick an open port
        let l = TcpListener::bind("127.0.0.1:0")?;
        l.local_addr()?
            .to_socket_addrs()?
            .next()
            .expect("No socket available")
    };
    let metrics_address = {
        // Pick an open port
        let l = TcpListener::bind("127.0.0.1:0")?;
        l.local_addr()?
            .to_socket_addrs()?
            .next()
            .expect("No socket available")
    };

    let logs_dir = TempDir::new().context("error creating temp dir for console logs")?;

    let config = ssh_console::config::Config {
        listen_address,
        metrics_address,
        carbide_uri: format!("https://localhost:{carbide_port}")
            .try_into()
            .expect("Invalid URI?"),
        authorized_keys_path: Some(AUTHORIZED_KEYS_PATH.clone()),
        host_key_path: SSH_HOST_KEY.clone(),
        override_bmcs: None,
        dpus: false,
        insecure: false,
        override_bmc_ssh_port: Some(2222),
        override_ipmi_port: Some(1623),
        insecure_ipmi_ciphers: true,
        forge_root_ca_path: API_CA_CERT.clone(),
        client_cert_path: API_CLIENT_CERT.clone(),
        client_key_path: API_CLIENT_KEY.clone(),
        openssh_certificate_ca_fingerprints: vec![],
        admin_certificate_role: None,
        api_poll_interval: Duration::from_secs(1),
        console_logging_enabled: true,
        console_logs_path: logs_dir.path().to_path_buf(),
        override_bmc_ssh_host: None,
        // Eagerly retry if the connection was only open a short while (needed for tests to avoid
        // long backoff intervals.)
        reconnect_interval_base: config_overrides
            .as_ref()
            .and_then(|c| c.reconnect_interval_base)
            .unwrap_or(Defaults::reconnect_interval_base()),
        reconnect_interval_max: config_overrides
            .as_ref()
            .and_then(|c| c.reconnect_interval_max)
            .unwrap_or(Defaults::reconnect_interval_max()),
        successful_connection_minimum_duration: config_overrides
            .as_ref()
            .and_then(|c| c.successful_connection_minimum_duration)
            .unwrap_or(Duration::ZERO),
        log_rotate_max_rotated_files: 3,
        log_rotate_max_size: Size::from_kib(10),
        hosts: true,
        openssh_certificate_authorization: ssh_console::config::Defaults::cert_authorization(),
    };

    let spawn_handle = ssh_console::spawn(config).await?;

    Ok(NewSshConsoleHandle {
        addr: listen_address,
        metrics_address,
        // Make sure the logs dir doesn't drop.
        logs_dir,
        spawn_handle,
    })
}

pub struct NewSshConsoleHandle {
    pub addr: SocketAddr,
    pub metrics_address: SocketAddr,
    pub logs_dir: TempDir,
    pub spawn_handle: ssh_console::SpawnHandle,
}

pub async fn get_metrics(addr: SocketAddr) -> eyre::Result<String> {
    use http_body_util::BodyExt;
    String::from_utf8_lossy(
        hyper_util::client::legacy::Builder::new(TokioExecutor::new())
            .build_http::<Full<Bytes>>()
            .get(format!("http://{addr}/metrics").try_into().unwrap())
            .await
            .context("Error fetching metrics")?
            .into_body()
            .collect()
            .await
            .context("Error fetching metrics body")?
            .to_bytes()
            .as_ref(),
    )
    .parse()
    .context("Error parsing prometheus metrics")
}
