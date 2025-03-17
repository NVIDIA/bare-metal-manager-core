use crate::forge_tls_client::{
    ApiConfig, ForgeClientConfig, ForgeClientT, ForgeTlsClient, RetryConfig,
};
pub use crate::protos::forge_api_client::ForgeApiClient;
use chrono::{DateTime, Utc};
use std::fs;
use std::time::SystemTime;
use tonic::Status;

impl ForgeApiClient {
    pub fn new(api_config: &ApiConfig<'_>) -> Self {
        Self::build(ForgeTlsConnectionProvider {
            url: api_config.url.to_string(),
            client_config: api_config.client_config.clone(),
            retry_config: api_config.retry_config,
        })
    }
}

#[derive(Debug)]
struct ForgeTlsConnectionProvider {
    url: String,
    client_config: ForgeClientConfig,
    retry_config: RetryConfig,
}

#[async_trait::async_trait]
impl tonic_client_wrapper::ConnectionProvider<ForgeClientT> for ForgeTlsConnectionProvider {
    async fn provide_connection(&self) -> Result<ForgeClientT, Status> {
        ForgeTlsClient::retry_build(
            &ApiConfig::new(&self.url, &self.client_config).with_retry_config(self.retry_config),
        )
        .await
        .map_err(Into::into)
    }

    async fn connection_is_stale(&self, last_connected: SystemTime) -> bool {
        if let Some(ref client_cert) = self.client_config.client_cert {
            if let Ok(mtime) = fs::metadata(&client_cert.cert_path).and_then(|m| m.modified()) {
                if mtime > last_connected {
                    let old_cert_date = DateTime::<Utc>::from(last_connected);
                    let new_cert_date = DateTime::<Utc>::from(mtime);
                    tracing::info!(
                        cert_path = &client_cert.cert_path,
                        %old_cert_date,
                        %new_cert_date,
                        "ForgeApiClient: Reconnecting to pick up newer client certificate"
                    );
                    true
                } else {
                    false
                }
            } else if let Ok(mtime) = fs::metadata(&client_cert.key_path).and_then(|m| m.modified())
            {
                // Just in case the cert and key are created some amount of time apart and we
                // last constructed a client with the new cert but the old key...
                if mtime > last_connected {
                    let old_key_date = DateTime::<Utc>::from(last_connected);
                    let new_key_date = DateTime::<Utc>::from(mtime);
                    tracing::info!(
                        key_path = &client_cert.key_path,
                        %old_key_date,
                        %new_key_date,
                        "ForgeApiClient: Reconnecting to pick up newer client key"
                    );
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    fn connection_url(&self) -> &str {
        self.url.as_str()
    }
}
