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

use crate::shutdown_handle::ShutdownHandle;
use russh::ChannelMsg;
use russh::server::Msg;
use std::sync::Arc;
use tokio::sync::oneshot::Sender;
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

/// Proxy messages from the BMC to the user's connection.
pub fn spawn(
    mut from_bmc_rx: broadcast::Receiver<Arc<ChannelMsg>>,
    to_frontend_tx: russh::ChannelWriteHalf<Msg>,
    peer_addr: String,
) -> Handle {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                res = from_bmc_rx.recv() => match res {
                    Ok(msg) => {
                        match proxy_channel_message(msg.as_ref(), &to_frontend_tx).await {
                            Ok(()) => {}
                            Err(error) => {
                                tracing::debug!(
                                    peer_addr,
                                    %error,
                                    "error sending message to frontend, likely disconnected"
                                );
                                break;
                            }
                        }
                    }
                    Err(_) => {
                        tracing::debug!(peer_addr, "client channel closed when writing message from BMC");
                        break;
                    }
                },
                _ = &mut shutdown_rx => {
                    break;
                }
            }
        }
        to_frontend_tx.close().await.ok();
    });

    Handle {
        shutdown_tx,
        join_handle,
    }
}

pub struct Handle {
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

impl ShutdownHandle<()> for Handle {
    fn into_parts(self) -> (Sender<()>, JoinHandle<()>) {
        (self.shutdown_tx, self.join_handle)
    }
}

/// Take a russh::ChannelMsg being sent in either direction from the frontend or the BMC, and call
/// the appropriate method on the underlying russh channel.
///
/// This is the main proxy logic between the frontend SSH connection and the backend BMC connection.
/// This whole thing would be unnecessary if [`russh::channels::ChanelWriteHalf::send_msg`] were
/// public. :(
pub(crate) async fn proxy_channel_message<S>(
    channel_msg: &russh::ChannelMsg,
    channel: &russh::ChannelWriteHalf<S>,
) -> Result<(), MessageProxyError>
where
    S: From<(russh::ChannelId, russh::ChannelMsg)> + Send + Sync + 'static,
{
    use MessageProxyError::*;
    match channel_msg {
        ChannelMsg::Open { .. } => {}
        ChannelMsg::Data { data } => {
            channel
                .data(data.iter().as_slice())
                .await
                .map_err(|error| Sending {
                    what: "data",
                    error,
                })?;
        }
        ChannelMsg::ExtendedData { data, ext } => {
            channel
                .extended_data(*ext, data.iter().as_slice())
                .await
                .map_err(|error| Sending {
                    what: "extended data",
                    error,
                })?;
        }
        ChannelMsg::Eof => {
            channel
                .eof()
                .await
                .map_err(|error| Sending { what: "eof", error })?;
        }
        ChannelMsg::Close => {
            channel.close().await.map_err(|error| Sending {
                what: "close",
                error,
            })?;
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
                .map_err(|error| Sending {
                    what: "pty request",
                    error,
                })?;
        }
        ChannelMsg::RequestShell { want_reply } => {
            channel
                .request_shell(*want_reply)
                .await
                .map_err(|error| Sending {
                    what: "shell request",
                    error,
                })?;
        }
        ChannelMsg::Signal { signal } => {
            channel
                .signal(signal.clone())
                .await
                .map_err(|error| Sending {
                    what: "signal",
                    error,
                })?;
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
                .map_err(|error| Sending {
                    what: "window change",
                    error,
                })?;
        }
        _ => {
            tracing::debug!("Ignoring unknown channel message {channel_msg:?}");
        }
    }

    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum MessageProxyError {
    #[error("error sending {what}: {error}")]
    Sending {
        what: &'static str,
        error: russh::Error,
    },
}

#[derive(Debug)]
pub enum ChannelMsgOrExec {
    ChannelMsg(ChannelMsg),
    Exec {
        command: Vec<u8>,
        reply_tx: oneshot::Sender<ExecReply>,
    },
}

#[derive(Debug)]
pub struct ExecReply {
    pub output: Vec<u8>,
    pub exit_status: u32,
}
