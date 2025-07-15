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

//! ssh-console - BMC Serial Console Proxy
//!
//! This crate provides an SSH server that acts as a proxy to BMC (Baseboard Management Controller)
//! serial consoles. It supports multiple BMC vendors (Dell, Lenovo, HPE) and handles authentication
//! through either OpenSSH certificates or public key validation via a carbide-api.
//!
//! ## Architecture
//!
//! - [`ssh_server::server`]: Responsible for running the service itself
//! - [`ssh_server::frontend`]: Handles SSH client connections and authentication
//! - [`ssh_server::backend`]: Manages connections to BMC devices and serial console activation
//! - [`config`]: Configuration management with TOML file support
//! - [`bmc_vendor`]: Vendor-specific BMC interaction logic

pub mod bmc_vendor;
pub(crate) mod io_util;
mod ssh_server;

// pub mods are only ones used by main.rs and integration tests
pub mod config;

use eyre::Context;
use russh::ChannelMsg;
pub use ssh_server::{SpawnHandle, spawn};
use tokio::sync::oneshot;

/// Take a russh::ChannelMsg being sent in either direction from the frontend or backend, and call
/// the appropriate method on the underlying channel.
///
/// This is the main proxy logic between the client SSH connection and the server SSH connection.
/// This whole thing would be unnecessary if [`russh::channels::ChanelWriteHalf::send_msg`] were
/// public. :(
pub(crate) async fn proxy_channel_message<S>(
    channel_msg: &russh::ChannelMsg,
    channel: &russh::Channel<S>,
) -> eyre::Result<()>
where
    S: From<(russh::ChannelId, russh::ChannelMsg)> + Send + Sync + 'static,
{
    match channel_msg {
        ChannelMsg::Open { .. } => {}
        ChannelMsg::Data { data } => {
            channel
                .data(data.iter().as_slice())
                .await
                .context("error sending data")?;
        }
        ChannelMsg::ExtendedData { data, ext } => {
            channel
                .extended_data(*ext, data.iter().as_slice())
                .await
                .context("error sending extended data")?;
        }
        ChannelMsg::Eof => {
            channel.eof().await.context("error sending eof")?;
        }
        ChannelMsg::Close => {
            channel.close().await.context("error sending close")?;
        }
        ChannelMsg::RequestPty {
            want_reply,
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
            terminal_modes,
        } => {
            channel
                .request_pty(
                    *want_reply,
                    term,
                    *col_width,
                    *row_height,
                    *pix_width,
                    *pix_height,
                    terminal_modes,
                )
                .await
                .context("error sending pty request")?;
        }
        ChannelMsg::RequestShell { want_reply } => {
            channel
                .request_shell(*want_reply)
                .await
                .context("error sending shell request")?;
        }
        ChannelMsg::Signal { signal } => {
            channel
                .signal(signal.clone())
                .await
                .context("error sending signal")?;
        }
        ChannelMsg::WindowChange {
            col_width,
            row_height,
            pix_width,
            pix_height,
        } => {
            channel
                .window_change(*col_width, *row_height, *pix_width, *pix_height)
                .await
                .context("error sending window change")?;
        }
        _ => {
            tracing::debug!("Ignoring unknown channel message {channel_msg:?}");
        }
    }

    Ok(())
}

/// Convenience trait for a task with a shutdown handle (in the form of a [`oneshot::Sender<()>`])
///
/// The shutdown handle must be treated such that dropping it means "shut down now", (because any
/// call which is awaiting the channel will immediately return.) By convention, dropping the
/// channel and sending the shutdown message mean the same thing.
pub trait ShutdownHandle<R> {
    fn into_parts(self) -> (oneshot::Sender<()>, tokio::task::JoinHandle<R>);

    fn shutdown_and_wait(self) -> impl std::future::Future<Output = R> + Send
    where
        Self: Send + Sized,
        R: Send,
    {
        async move {
            let (shutdown_tx, join_handle) = self.into_parts();
            // Let the shutdown handle drop, which causes any reads to finish (semantically the same as
            // sending an empty tuple over the channel, both mean "shut down now").
            std::mem::drop(shutdown_tx);
            join_handle.await.expect("task panicked")
        }
    }
}
