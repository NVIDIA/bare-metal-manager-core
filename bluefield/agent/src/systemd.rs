/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::env;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

use eyre::WrapErr;
use tokio::net::UnixDatagram as TokioUnixDatagram;

/// Tell systemd we have started
pub async fn notify_start() -> eyre::Result<()> {
    sd_notify("READY=1\n").await
}

/// Tell systemd we are still alive.
/// We must do this at least every WatchdogSec or else systemd will us SIGABRT and restart us.
pub async fn notify_watchdog() -> eyre::Result<()> {
    if env::var("WATCHDOG_USEC").is_err() {
        tracing::trace!("systemd watchdog disabled");
        return Ok(());
    }
    sd_notify("WATCHDOG=1\n").await
}

/// Tell systemd we are stopping
pub async fn notify_stop() -> eyre::Result<()> {
    sd_notify("STOPPING=1\n").await
}

async fn sd_notify(msg: &str) -> eyre::Result<()> {
    let mut sock_path = match env::var("NOTIFY_SOCKET") {
        Ok(path) if !path.is_empty() => path,
        _ => {
            tracing::trace!("Not started by systemd, skip sd_notify");
            return Ok(());
        }
    };

    let sock = UnixDatagram::unbound()?;
    sock.set_nonblocking(true)?;
    let addr = if sock_path.as_bytes()[0] == b'@' {
        unsafe {
            // abstract sockets must start with nul byte
            sock_path.as_mut_vec()[0] = 0;
        }
        SocketAddr::from_abstract_name(sock_path.as_bytes())
            .wrap_err_with(|| format!("invalid abstract socket name {sock_path}"))?
    } else {
        SocketAddr::from_pathname(&sock_path)
            .wrap_err_with(|| format!("invalid socket name {sock_path}"))?
    };
    sock.connect_addr(&addr)?;
    // Convert it to a tokio socket because we want this to be stuck if tokio's
    // epoll / mio reactor is stuck.
    let tokio_sock = TokioUnixDatagram::from_std(sock)?;
    let sent = tokio_sock
        .send(msg.as_bytes())
        .await
        .wrap_err("socket send error")?;
    if sent != msg.len() {
        eyre::bail!("Short send {sent} / {}", msg.len());
    }
    Ok(())
}
