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
use crate::ssh_server::backend_connection::{BackendConnectionKind, ConnectionDetails};
use crate::ssh_server::backend_pool::BackendPoolMetrics;
use crate::ssh_server::connection_state::{AtomicConnectionState, ConnectionState};
use crate::ssh_server::server::ServerMetrics;
use crate::ssh_server::{backend_connection, console_logger};
use crate::{ChannelMsgOrExec, ExecReply, ReadyHandle, ShutdownHandle};
use forge_uuid::machine::MachineId;
use futures_util::FutureExt;
use opentelemetry::KeyValue;
use russh::ChannelMsg;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{MutexGuard, broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

/// Retry interval the first time we see a failure
static RETRY_BASE_DURATION: Duration = Duration::from_secs(10);
/// Max retry interval after subsequent failures
static RETRY_MAX_DURATION: Duration = Duration::from_secs(600);

/// Spawn a connection to the given backend in the background, returning a handle. Connections will
/// be retried indefinitely, with exponential backoff, until a shutdown is signaled (ie. by dropping
/// the BackendSessionHandle.)
pub fn spawn(
    connection_details: ConnectionDetails,
    config: Arc<Config>,
    metrics: Arc<BackendPoolMetrics>,
) -> BackendSessionHandle {
    // Shutdown handle for the retry loop that is retrying this connection
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    // Channel frontends can use to send messages to the backend
    let (to_backend_msg_tx, to_backend_msg_rx) = mpsc::channel::<ChannelMsgOrExec>(1);
    // Channel that broadcasts messages to any subscribed frontends
    let (broadcast_to_frontend_tx, broadcast_to_frontend_rx) =
        broadcast::channel::<Arc<ChannelMsg>>(4096);

    // Always consume messages from the frontend broadcast channel, even if there are no frontends.
    dev_null(broadcast_to_frontend_rx);

    let connection_state = Arc::new(AtomicConnectionState::default());
    let machine_id = connection_details.machine_id();
    let kind = connection_details.kind();

    let metrics_attrs = vec![KeyValue::new("machine_id", machine_id.to_string())];
    metrics.bmc_recovery_attempts.record(0, &metrics_attrs);
    metrics.bmc_rx_errors_total.add(0, &metrics_attrs);
    metrics.bmc_tx_errors_total.add(0, &metrics_attrs);
    metrics.bmc_bytes_received_total.add(0, &metrics_attrs);

    let backend_session = BackendSession {
        connection_details,
        config,
        connection_state: connection_state.clone(),
        broadcast_to_frontend_tx: broadcast_to_frontend_tx.clone(),
        shutdown_rx,
        to_backend_msg_rx,
        metrics,
    };

    let join_handle = tokio::spawn(backend_session.run());

    BackendSessionHandle {
        to_backend_msg_tx,
        broadcast_to_frontend_tx,
        machine_id,
        shutdown_tx,
        join_handle,
        connection_state,
        kind,
    }
}

struct BackendSession {
    connection_details: ConnectionDetails,
    config: Arc<Config>,
    connection_state: Arc<AtomicConnectionState>,
    shutdown_rx: oneshot::Receiver<()>,
    broadcast_to_frontend_tx: broadcast::Sender<Arc<ChannelMsg>>,
    to_backend_msg_rx: mpsc::Receiver<ChannelMsgOrExec>,
    metrics: Arc<BackendPoolMetrics>,
}

impl BackendSession {
    async fn run(mut self) {
        let machine_id = self.connection_details.machine_id();
        let metrics_attrs = vec![KeyValue::new("machine_id", machine_id.to_string())];

        // Spawn a task to write logs for this console, if configured.
        let logger_handle = if self.config.console_logging_enabled {
            Some(console_logger::spawn(
                machine_id,
                self.connection_details.addr(),
                self.broadcast_to_frontend_tx.subscribe(),
                self.config.as_ref(),
            ))
        } else {
            None
        };

        // Spawn a message relay for communicating status to the user if the backend is
        // disconnected.
        let backend_msg_tx_placeholder = BackendMessageTxPlaceholder::default();
        let backend_message_relay = relay_input_to_backend(
            self.broadcast_to_frontend_tx.clone(),
            self.connection_state.clone(),
            self.to_backend_msg_rx,
            backend_msg_tx_placeholder.clone(),
        );

        // Connect and reconnect, in a loop, until the session is shut down
        let mut retry_time = Duration::ZERO;
        let mut retries = 0;
        'retry: loop {
            self.metrics
                .bmc_recovery_attempts
                .record(retries, metrics_attrs.as_slice());
            if retries == 0 {
                self.connection_state.store(ConnectionState::Connecting);
            } else {
                self.connection_state
                    .store(ConnectionState::ConnectionError);
            }
            retries += 1;

            // Subsequent retries should sleep for RETRY_BASE_DURATION and double from there
            // until we successfully connect.
            tokio::time::sleep(retry_time).await;
            retry_time = next_retry_backoff(retry_time);
            let try_start_time = Instant::now();

            let spawn_result = match &self.connection_details {
                ConnectionDetails::Ssh(ssh_connection_details) => backend_connection::ssh::spawn(
                    ssh_connection_details.clone(),
                    self.broadcast_to_frontend_tx.clone(),
                    self.metrics.clone(),
                ),
                ConnectionDetails::Ipmi(ipmi_connection_details) => {
                    backend_connection::ipmi::spawn(
                        ipmi_connection_details.clone(),
                        self.broadcast_to_frontend_tx.clone(),
                        self.config.clone(),
                        self.metrics.clone(),
                    )
                }
            };

            // These channels and handle are only for this particular connection attempt
            let mut backend_connection_handle = match spawn_result {
                Ok(handle) => handle,
                Err(error) => {
                    tracing::error!(
                        ?error,
                        %machine_id,
                        "error spawning backend connection, will retry in {}s",
                        retry_time.as_secs()
                    );
                    continue 'retry;
                }
            };

            if backend_connection_handle.wait_until_ready().await.is_ok() {
                // Successfully ready, give the backend channel to the message relay and set the
                // state to Connected. (if ready_rx is not ok, then the tx must have been dropped,
                // and we'll report errors and retry below.)
                backend_msg_tx_placeholder
                    .replace(Some(backend_connection_handle.to_backend_msg_tx))
                    .await;
                self.connection_state.store(ConnectionState::Connected);
            }

            // Turn the actual backend connection JoinHandle into a shared future, so we can check
            // the result from multiple select arms.
            let connection_result = async move {
                backend_connection_handle
                    .join_handle
                    .await
                    .expect("task panicked")
                    .map_err(Arc::new)
            }
            .shared();

            tokio::select! {
                // If we're shutting down, shut down this connection attempt
                _ = &mut self.shutdown_rx => {
                    tracing::info!(%machine_id, "shutting down backend connection");
                    backend_connection_handle.shutdown_tx.send(()).ok();
                    if let Err(error) = connection_result.await {
                        tracing::error!(%machine_id, error = ?error.as_ref(), "backend connection failed while shutting down");
                    };
                    break 'retry;
                }

                // The connection should go forever, so if it doesn't, retry.
                res = connection_result.clone() => {
                    let connection_time = try_start_time.elapsed();
                    if connection_time > self.config.successful_connection_minimum_duration {
                        tracing::debug!(%machine_id, "last connection lasted {}s, resetting backoff to 0s", connection_time.as_secs());
                        retry_time = Duration::ZERO;
                    }
                    let error_string = res.err().map(|e| format!("{:?}", e.as_ref())).unwrap_or("<none>".to_string());
                    tracing::warn!(%machine_id, error = error_string, "connection to backend closed, will retry in {}s", retry_time.as_secs());
                }
            }
        }

        // Clean up: Shut down message relay and logger
        backend_message_relay.shutdown_and_wait().await;
        if let Some(logger_handle) = logger_handle {
            logger_handle.shutdown_and_wait().await;
        }
    }
}

/// Spawn a task which will take messages from to_backend_msg_rx and either relay them to a
/// backend connection, *or* reply to the user saying the backend is disconnected, depending on
/// whether the backend connection is healthy.
///
/// - `backend_msg_tx_placeholder`: A shareable placeholder for a channel to send   messages to
///   the backend, once the backend connection is ready.
fn relay_input_to_backend(
    broadcast_to_frontend_tx: broadcast::Sender<Arc<ChannelMsg>>,
    connection_state: Arc<AtomicConnectionState>,
    mut to_backend_msg_rx: mpsc::Receiver<ChannelMsgOrExec>,
    backend_msg_tx_placeholder: BackendMessageTxPlaceholder,
) -> MessageRelayHandle {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

    let join_handle = tokio::spawn({
        async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    Some(msg) = to_backend_msg_rx.recv() => {
                        let backend_tx_guard =
                            if let ConnectionState::Connected = connection_state.load() {
                                Some(backend_msg_tx_placeholder.lock().await)
                            } else {
                                None
                            };

                        // If we're connected, relay the message
                        if let Some(tx) =
                            backend_tx_guard.as_ref().and_then(|guard| guard.as_ref())
                        {
                            tx.send(msg).await.ok();
                        } else {
                            match msg {
                                ChannelMsgOrExec::ChannelMsg(ChannelMsg::Data { data }) => {
                                    // Otherwise, when the user types a newline, inform them the backend
                                    // is not connected
                                    if data.contains(&b'\r') || data.contains(&b'\n') {
                                        broadcast_to_frontend_tx
                                            .send(
                                                ChannelMsg::Data {
                                                    data: b"--- BMC console not connected ---\r\n"
                                                        .to_vec()
                                                        .into(),
                                                }
                                                .into(),
                                            )
                                            .ok();
                                    }
                                }
                                ChannelMsgOrExec::Exec { reply_tx, .. } => {
                                    reply_tx.send(ExecReply {
                                        output: b"BMC console not connected\r\n".to_vec(),
                                        exit_status: 1,
                                    }).ok();
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    });

    MessageRelayHandle {
        shutdown_tx,
        join_handle,
    }
}

struct MessageRelayHandle {
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

#[derive(Default, Clone)]
struct BackendMessageTxPlaceholder(Arc<tokio::sync::Mutex<Option<mpsc::Sender<ChannelMsgOrExec>>>>);

impl BackendMessageTxPlaceholder {
    #[inline]
    async fn replace(&self, value: Option<mpsc::Sender<ChannelMsgOrExec>>) {
        *self.lock().await = value;
    }

    #[inline]
    async fn lock(&self) -> MutexGuard<'_, Option<mpsc::Sender<ChannelMsgOrExec>>> {
        self.0.lock().await
    }
}

impl ShutdownHandle<()> for MessageRelayHandle {
    fn into_parts(self) -> (oneshot::Sender<()>, JoinHandle<()>) {
        (self.shutdown_tx, self.join_handle)
    }
}

/// Consume all the messages of a broadcast::Receiver, doing nothing with them, until the channel is
/// closed. This is a quick and dirty way to prevent a backend's to_frontend_tx channel from
/// returning failures due to nobody listening. (Listeners may come and go, as logging is optional.)
fn dev_null<T: Clone + Send + 'static>(mut rx: broadcast::Receiver<T>) {
    tokio::spawn(async move {
        loop {
            if rx.recv().await.is_err() {
                return;
            };
        }
    });
}

/// Calculate the next exponential backoff duration for retrying connections to a console
fn next_retry_backoff(prev: Duration) -> Duration {
    static BASE_F64: f64 = RETRY_BASE_DURATION.as_secs_f64();
    static MAX_F64: f64 = RETRY_MAX_DURATION.as_secs_f64();

    if prev == Duration::ZERO {
        return RETRY_BASE_DURATION;
    }

    // Sleep a random interval between prev and prev * 3
    let upper = (prev.as_secs_f64() * 3.0).min(MAX_F64);
    Duration::from_secs_f64(rand::random_range(BASE_F64..upper))
}

pub struct BackendSessionHandle {
    machine_id: MachineId,
    kind: BackendConnectionKind,
    /// Writer to send messages (including data) to backend
    to_backend_msg_tx: mpsc::Sender<ChannelMsgOrExec>,
    // Hold a copy of the tx for broadcasting to frontends, so that we can subscribe to it multiple
    // times.
    broadcast_to_frontend_tx: broadcast::Sender<Arc<ChannelMsg>>,
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
    pub connection_state: Arc<AtomicConnectionState>, // pub for metrics gathering
}

impl ShutdownHandle<()> for BackendSessionHandle {
    fn into_parts(self) -> (oneshot::Sender<()>, JoinHandle<()>) {
        (self.shutdown_tx, self.join_handle)
    }
}

impl BackendSessionHandle {
    pub fn subscribe(&self, metrics: Arc<ServerMetrics>) -> BackendSubscription {
        tracing::debug!("new backend subscription");
        metrics.total_clients.add(1, &[]);
        metrics.bmc_clients.add(
            1,
            &[KeyValue::new("machine_id", self.machine_id.to_string())],
        );

        BackendSubscription {
            machine_id: self.machine_id,
            to_frontend_msg_weak_tx: self.broadcast_to_frontend_tx.downgrade(),
            to_backend_msg_tx: self.to_backend_msg_tx.clone(),
            metrics,
            kind: self.kind,
        }
    }
}

/// An individual "subscription" to a backend connection, expected to be used by a frontend. Metrics are affected when one is created or dropped.
pub struct BackendSubscription {
    pub machine_id: MachineId,
    pub to_frontend_msg_weak_tx: broadcast::WeakSender<Arc<ChannelMsg>>,
    pub to_backend_msg_tx: mpsc::Sender<ChannelMsgOrExec>,
    pub kind: BackendConnectionKind,
    // Not pub, to make sure we go through BackendSessionHandle::subscribe() to build, so we get the
    // right metrics
    metrics: Arc<ServerMetrics>,
}

impl Drop for BackendSubscription {
    // Decrement metrics when dropping
    fn drop(&mut self) {
        tracing::debug!("dropping backend subscription");
        self.metrics.total_clients.add(-1, &[]);
        self.metrics.bmc_clients.add(
            -1,
            &[KeyValue::new("machine_id", self.machine_id.to_string())],
        );
    }
}
