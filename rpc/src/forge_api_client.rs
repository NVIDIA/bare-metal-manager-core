use crate::forge_tls_client;
use crate::forge_tls_client::{
    ApiConfig, ForgeClientConfig, ForgeClientT, ForgeTlsClientResult, RetryConfig,
};
use chrono::{DateTime, Utc};
use std::fs;
use std::ops::Deref;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct ForgeApiClient {
    inner: Arc<ForgeApiClientInner>,
}

#[derive(Debug)]
struct ForgeApiClientInner {
    url: String,
    client_config: ForgeClientConfig,
    retry_config: RetryConfig,
    connection: Mutex<Option<InnerConnection>>,
}

#[derive(Debug)]
struct InnerConnection {
    client: ForgeClientT,
    created: SystemTime,
}

impl ForgeApiClient {
    pub fn new(api_config: &ApiConfig<'_>) -> Self {
        Self {
            inner: Arc::new(ForgeApiClientInner {
                url: api_config.url.to_owned(),
                client_config: api_config.client_config.clone(),
                retry_config: api_config.retry_config,
                connection: Mutex::new(None),
            }),
        }
    }

    pub async fn connect_eagerly(&self) -> ForgeTlsClientResult<()> {
        self.connection().await.map(|_| ())
    }

    /// Causes this client to drop its internal ForgeClientT and construct a new one from the
    /// original configuration passed to it. This will cause client certificates to be reloaded.
    pub async fn reload_config(&self) -> ForgeTlsClientResult<()> {
        self.inner.connection.lock().await.take();
        self.connect_eagerly().await?;
        Ok(())
    }

    pub async fn connection(&self) -> ForgeTlsClientResult<ForgeClientT> {
        let mut guard = self.inner.connection.lock().await;

        // If the on-disk cert is newer than the connection, drop it and reload it
        if let Some(connection) = guard.deref() {
            if let Some(ref client_cert) = self.inner.client_config.client_cert {
                if let Ok(mtime) = fs::metadata(&client_cert.cert_path).and_then(|m| m.modified()) {
                    if mtime > connection.created {
                        let old_cert_date = DateTime::<Utc>::from(connection.created);
                        let new_cert_date = DateTime::<Utc>::from(mtime);
                        tracing::info!(
                            cert_path = &client_cert.cert_path,
                            %old_cert_date,
                            %new_cert_date,
                            "ForgeApiClient: Reconnecting to pick up newer client certificate"
                        );
                        guard.take();
                    }
                } else if let Ok(mtime) =
                    fs::metadata(&client_cert.key_path).and_then(|m| m.modified())
                {
                    // Just in case the cert and key are created some amount of time apart and we
                    // last constructed a client with the new cert but the old key...
                    if mtime > connection.created {
                        let old_key_date = DateTime::<Utc>::from(connection.created);
                        let new_key_date = DateTime::<Utc>::from(mtime);
                        tracing::info!(
                            key_path = &client_cert.key_path,
                            %old_key_date,
                            %new_key_date,
                            "ForgeApiClient: Reconnecting to pick up newer client key"
                        );
                        guard.take();
                    }
                }
            }
        }

        match guard.deref() {
            Some(connection) => Ok(connection.client.clone()),
            None => {
                let client = forge_tls_client::ForgeTlsClient::retry_build(
                    &ApiConfig::new(&self.inner.url, &self.inner.client_config)
                        .with_retry_config(self.inner.retry_config),
                )
                .await?;
                guard.replace(InnerConnection {
                    client: client.clone(),
                    created: SystemTime::now(),
                });
                Ok(client)
            }
        }
    }

    pub fn url(&self) -> &String {
        &self.inner.url
    }

    // NOTE: The remaining methods on this type are generated from protobuf and can be found in `protos/forge_api_client.rs`.
}
