use crate::config::Config;
use crate::ssh_server::backend;
use crate::ssh_server::backend::{BackendHandle, ConnectionDetails, lookup_connection_details};
use eyre::Context;
use futures::FutureExt;
use futures_util::future;
use rpc::forge_api_client::ForgeApiClient;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A BackendPool stores and reuses a single connection to each backend.
#[derive(Default)]
pub struct BackendPool {
    // The keys are the SockedAddr of the backend, which effectively dedupes cases where backends
    // are accessible via multiple strings (instance ID vs machine ID).
    members: Mutex<HashMap<SocketAddr, SharedBackendHandle>>,
}

// Connections to backends are stored as "shared" futures. These can be waited on repeatedly
// (yielding a clone of the original each time), by multiple threads simultaneously. The first
// attempt to connect stores the future while holding the `members` mutex, then releases the mutex
// and waits on the future. If multiple connections are attempted simultaneously, subsequent
// attempts will wait on the same future.
type SharedBackendHandle =
    future::Shared<future::BoxFuture<'static, Result<Arc<BackendHandle>, ConnectionError>>>;

impl Debug for BackendPool {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("BackendPool"))
    }
}

impl BackendPool {
    /// Get a connection to the given backend, or re-use an existing one if it's available. If a
    /// connection exists, but has been disconnected, a reconnect will be performed automatically.
    pub async fn ensure_connected(
        &self,
        machine_or_instance_id: &str,
        config: &Arc<Config>,
        forge_api_client: &ForgeApiClient,
    ) -> eyre::Result<Arc<BackendHandle>> {
        let connection_details = Arc::new(
            lookup_connection_details(machine_or_instance_id, config, forge_api_client)
                .await
                .context("error looking up connection details")?,
        );
        let addr = connection_details.addr();

        let backend_handle_future = self
            .get_or_create_connection(&connection_details, config)
            .await;

        let result = match backend_handle_future.await {
            Ok(backend) => {
                if backend.to_backend_msg_tx.is_closed() {
                    tracing::info!("backend channel closed, reconnecting");
                    self.members.lock().await.remove(&addr);
                    self.get_or_create_connection(&connection_details, config)
                        .await
                        .await
                } else {
                    Ok(backend)
                }
            }
            Err(e) => {
                tracing::info!("connection error, will reconnect on next try: {e:?}");
                // Allow reconnecting on the next try
                self.members.lock().await.remove(&addr);
                Err(e)
            }
        };

        result.context("error connecting to backend")
    }

    async fn get_or_create_connection(
        &self,
        connection_details: &Arc<ConnectionDetails>,
        config: &Arc<Config>,
    ) -> future::Shared<future::BoxFuture<'static, Result<Arc<BackendHandle>, ConnectionError>>>
    {
        // Only hold the mutex while we _create_ the future, not while we wait on it.
        let mut members = self.members.lock().await;
        members
            .entry(connection_details.addr())
            .or_insert_with(|| {
                let connection_details = connection_details.clone();
                let config = config.clone();
                async move {
                    backend::spawn(&connection_details, &config)
                        .await
                        .map_err(ConnectionError::from)
                }
                .boxed()
                .shared()
            })
            .clone()
    }
}

/// Newtype wrpper around Arc<eyre::Error> to make it clone-able for use in a future::Shared.
#[derive(Debug, Clone)]
struct ConnectionError(Arc<eyre::Error>);

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl From<eyre::Error> for ConnectionError {
    fn from(eyre_error: eyre::Error) -> Self {
        ConnectionError(eyre_error.into())
    }
}
