/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::collections::HashMap;
use std::env;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use eyre::{ContextCompat, WrapErr, eyre};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter};
use rand::Rng;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::sleep;
use vaultrs::api::kv2::requests::SetSecretRequestOptions;
use vaultrs::api::pki::requests::GenerateCertificateRequest;
use vaultrs::client::{
    VaultClient, VaultClientSettings, VaultClientSettingsBuilder, VaultClientSettingsBuilderError,
};
use vaultrs::error::ClientError;
use vaultrs::{kv2, pki};

use crate::SecretsError;
use crate::certificates::{Certificate, CertificateProvider};
use crate::credentials::{CredentialKey, CredentialProvider, Credentials};

#[derive(Clone, Debug)]
enum ForgeVaultAuthenticationType {
    Root(String),
    ServiceAccount(PathBuf),
}

#[derive(Clone, Debug)]
struct ForgeVaultAuthentication {
    expiry: Instant,
}

enum ForgeVaultAuthenticationStatus {
    Authenticated(ForgeVaultAuthentication, Arc<VaultClient>),
    Initialized,
}

#[derive(Debug, Clone)]
struct ForgeVaultClientConfig {
    pub auth_type: ForgeVaultAuthenticationType,
    pub vault_address: String,
    pub kv_mount_location: String,
    pub pki_mount_location: String,
    pub pki_role_name: String,
    pub vault_root_ca_path: String,
}

#[derive(Debug, Clone)]
pub struct ForgeVaultMetrics {
    pub vault_requests_total_counter: Counter<u64>,
    pub vault_requests_succeeded_counter: Counter<u64>,
    pub vault_requests_failed_counter: Counter<u64>,
    pub vault_token_gauge: Gauge<f64>,
    pub vault_request_duration_histogram: Histogram<u64>,
}

struct RefresherMessage {
    response_tx: tokio::sync::oneshot::Sender<Result<Arc<VaultClient>, eyre::Report>>,
}

pub struct ForgeVaultClient {
    vault_metrics: ForgeVaultMetrics,
    vault_client_config: ForgeVaultClientConfig,
    vault_refresher_tx: Sender<RefresherMessage>,
}

fn create_vault_client_settings<S>(
    token: S,
    vault_client_config: &ForgeVaultClientConfig,
) -> Result<VaultClientSettings, eyre::ErrReport>
where
    S: Into<String>,
{
    let mut vault_client_settings_builder = VaultClientSettingsBuilder::default();
    let vault_client_settings_builder = vault_client_settings_builder
        .token(token)
        .address(vault_client_config.vault_address.clone())
        .timeout(Some(Duration::from_secs(60)));

    let vault_client_settings_builder =
        if Path::new(&vault_client_config.vault_root_ca_path).exists() {
            vault_client_settings_builder
                .ca_certs(vec![vault_client_config.vault_root_ca_path.clone()])
                .verify(true)
        } else {
            vault_client_settings_builder.verify(false)
        };

    Ok(vault_client_settings_builder.build()?)
}

async fn vault_token_refresh(
    vault_client_config: &ForgeVaultClientConfig,
    vault_metrics: &ForgeVaultMetrics,
) -> Result<(ForgeVaultAuthentication, Arc<VaultClient>), eyre::ErrReport> {
    let (vault_token, vault_token_expiry_secs) = match vault_client_config.auth_type {
        ForgeVaultAuthenticationType::Root(ref root_token) => {
            (
                root_token.clone(),
                60 * 60 * 24 * 365 * 10, /*root token never expires just use ten years*/
            )
        }
        ForgeVaultAuthenticationType::ServiceAccount(ref service_account_token_path) => {
            let jwt = std::fs::read_to_string(service_account_token_path)
                .wrap_err("service_account_token_file_read")?
                .trim()
                .to_string();

            let vault_client_settings = create_vault_client_settings(
                "silly vaultrs bugs make me sad",
                vault_client_config,
            )?;
            let vault_client = VaultClient::new(vault_client_settings)?;
            vault_metrics
                .vault_requests_total_counter
                .add(1, &[KeyValue::new("request_type", "service_account_login")]);
            let time_started_vault_request = Instant::now();
            let vault_response = vaultrs::auth::kubernetes::login(
                &vault_client,
                "kubernetes",
                "carbide-api",
                jwt.as_str(),
            )
            .await;
            let elapsed_request_duration = time_started_vault_request.elapsed().as_millis() as u64;
            vault_metrics.vault_request_duration_histogram.record(
                elapsed_request_duration,
                &[KeyValue::new("request_type", "service_account_login")],
            );
            let auth_info = vault_response
                .inspect_err(|err| {
                    record_vault_client_error(err, "service_account_login", vault_metrics);
                })
                .wrap_err("Failed to execute kubernetes service account login request")?;

            vault_metrics
                .vault_requests_succeeded_counter
                .add(1, &[KeyValue::new("request_type", "service_account_login")]);
            // start refreshing before it expires
            let lease_expiry_secs = (0.9 * auth_info.lease_duration as f64) as u64;
            (auth_info.client_token, lease_expiry_secs)
        }
    };

    tracing::info!("successfully refreshed vault token, with lifetime: {vault_token_expiry_secs}");

    let vault_client_settings = create_vault_client_settings(vault_token, vault_client_config)?;
    let vault_client = VaultClient::new(vault_client_settings)?;

    // validate that we can actually _use_ the token before we give it back
    let mut attempts = 3;

    let now = SystemTime::now();
    let timestamp_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let kv_mount_location = vault_client_config.kv_mount_location.as_str();
    let data = HashMap::from([("timestamp_seconds", timestamp_secs.to_string())]);
    while kv2::set(
        &vault_client,
        kv_mount_location,
        "machines/token_refresh/current_token",
        &data,
    )
    .await
    .is_err()
    {
        attempts -= 1;
        if attempts <= 0 {
            tracing::error!(
                "Vault token renewal check: error reading kv mount location config, giving up after max attempts"
            );
            break;
        }
        tracing::error!(
            "Vault token renewal check: error reading kv mount location config, waiting for token to be good"
        );
        sleep(Duration::from_secs(2)).await;
    }

    Ok((
        ForgeVaultAuthentication {
            expiry: Instant::now() + Duration::from_secs(vault_token_expiry_secs),
        },
        Arc::new(vault_client),
    ))
}

async fn maybe_refresh_vault_client(
    vault_client_config: &ForgeVaultClientConfig,
    vault_metrics: &ForgeVaultMetrics,
    vault_auth_status: ForgeVaultAuthenticationStatus,
) -> Result<(ForgeVaultAuthentication, Arc<VaultClient>), eyre::ErrReport> {
    let refresh_fut = vault_token_refresh(vault_client_config, vault_metrics);
    match vault_auth_status {
        ForgeVaultAuthenticationStatus::Initialized => refresh_fut.await,
        ForgeVaultAuthenticationStatus::Authenticated(authentication, client) => {
            let time_remaining_until_refresh = authentication
                .expiry
                .saturating_duration_since(Instant::now());

            vault_metrics
                .vault_token_gauge
                .record(time_remaining_until_refresh.as_secs_f64(), &[]);

            if Instant::now() >= authentication.expiry {
                refresh_fut.await
            } else {
                Ok((authentication, client))
            }
        }
    }
}

async fn vault_refresher_loop(
    mut vault_refresher_rx: Receiver<RefresherMessage>,
    vault_client_config: ForgeVaultClientConfig,
    vault_metrics: ForgeVaultMetrics,
) {
    let mut auth_status = ForgeVaultAuthenticationStatus::Initialized;
    while let Some(message) = vault_refresher_rx.recv().await {
        match maybe_refresh_vault_client(&vault_client_config, &vault_metrics, auth_status).await {
            Ok((auth, client)) => {
                message.response_tx.send(Ok(client.clone())).ok();
                auth_status = ForgeVaultAuthenticationStatus::Authenticated(auth, client);
            }
            Err(error) => {
                message.response_tx.send(Err(error)).ok();
                auth_status = ForgeVaultAuthenticationStatus::Initialized; // force a refresh until it works
            }
        }
    }
}

impl From<ClientError> for SecretsError {
    fn from(value: ClientError) -> Self {
        SecretsError::GenericError(value.into())
    }
}

impl From<VaultClientSettingsBuilderError> for SecretsError {
    fn from(value: VaultClientSettingsBuilderError) -> Self {
        SecretsError::GenericError(value.into())
    }
}

impl ForgeVaultClient {
    fn new(vault_client_config: ForgeVaultClientConfig, vault_metrics: ForgeVaultMetrics) -> Self {
        let (vault_refresher_tx, vault_refresher_rx) = tokio::sync::mpsc::channel(1);
        let vault_client_config_clone = vault_client_config.clone();
        let vault_metrics_clone = vault_metrics.clone();
        tokio::spawn(async move {
            vault_refresher_loop(
                vault_refresher_rx,
                vault_client_config_clone,
                vault_metrics_clone,
            )
            .await;
        });
        Self {
            vault_metrics,
            vault_client_config,
            vault_refresher_tx,
        }
    }

    async fn vault_client(&self) -> Result<Arc<VaultClient>, eyre::Report> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let message = RefresherMessage { response_tx: tx };

        self.vault_refresher_tx
            .send(message)
            .await
            .map_err(|err| eyre!(err))
            .wrap_err("sender error from background vault refresher loop")?;

        rx.await
            .map_err(|err| eyre!(err))
            .wrap_err("receiver error from background vault refresher loop")?
    }
}

#[async_trait]
trait VaultTask<T> {
    async fn execute(
        &self,
        vault_client: Arc<VaultClient>,
        vault_metrics: &ForgeVaultMetrics,
    ) -> Result<T, SecretsError>;
}

struct GetCredentialsHelper<'key, 'location> {
    pub kv_mount_location: &'location String,
    pub key: &'key CredentialKey,
}

#[async_trait]
impl VaultTask<Option<Credentials>> for GetCredentialsHelper<'_, '_> {
    async fn execute(
        &self,
        vault_client: Arc<VaultClient>,
        vault_metrics: &ForgeVaultMetrics,
    ) -> Result<Option<Credentials>, SecretsError> {
        vault_metrics
            .vault_requests_total_counter
            .add(1, &[KeyValue::new("request_type", "get_credentials")]);

        let time_started_vault_request = Instant::now();
        let vault_response = kv2::read(
            vault_client.deref(),
            self.kv_mount_location,
            self.key.to_key_str().as_ref(),
        )
        .await;
        let elapsed_request_duration = time_started_vault_request.elapsed().as_millis() as u64;
        vault_metrics.vault_request_duration_histogram.record(
            elapsed_request_duration,
            &[KeyValue::new("request_type", "get_credentials")],
        );

        let credentials = match vault_response {
            // If pasword is empty we treat it the same as missing credentials
            Ok(Credentials::UsernamePassword {
                username: _,
                password,
            }) if password.is_empty() => Ok(None),
            Ok(creds) => Ok(Some(creds)),
            Err(ce) => {
                let status_code = record_vault_client_error(&ce, "get_credentials", vault_metrics);
                match status_code {
                    Some(404) => {
                        // Not found errors are common and of no concern
                        tracing::debug!(
                            "Credentials not found for key ({})",
                            self.key.to_key_str().as_ref()
                        );
                        Ok(None)
                    }
                    _ => {
                        tracing::error!(
                            "Error getting credentials ({}). Error: {ce:?}",
                            self.key.to_key_str().as_ref()
                        );
                        Err(SecretsError::GenericError(ce.into()))
                    }
                }
            }
        };

        vault_metrics
            .vault_requests_succeeded_counter
            .add(1, &[KeyValue::new("request_type", "get_credentials")]);
        credentials
    }
}

/// Tracks client errors if an invocation to a Vault server failed
///
/// Returns the status code of the HTTP request if available
fn record_vault_client_error(
    err: &ClientError,
    request_type: &'static str,
    vault_metrics: &ForgeVaultMetrics,
) -> Option<u16> {
    let status_code = match err {
        ClientError::APIError { code, errors: _ } => Some(*code),
        _ => None,
    };

    vault_metrics.vault_requests_failed_counter.add(
        1,
        &[
            KeyValue::new("request_type", request_type),
            KeyValue::new(
                "http.response.status_code",
                status_code.map(|code| code.to_string()).unwrap_or_default(),
            ),
        ],
    );

    status_code
}

struct SetCredentialsHelper<'key, 'location> {
    pub kv_mount_location: &'location String,
    pub key: &'key CredentialKey,
    pub credentials: &'key Credentials,
    pub allow_overwrite: bool,
}

#[async_trait]
impl VaultTask<()> for SetCredentialsHelper<'_, '_> {
    async fn execute(
        &self,
        vault_client: Arc<VaultClient>,
        vault_metrics: &ForgeVaultMetrics,
    ) -> Result<(), SecretsError> {
        vault_metrics
            .vault_requests_total_counter
            .add(1, &[KeyValue::new("request_type", "set_credentials")]);

        let time_started_vault_request = Instant::now();

        let vault_response = if self.allow_overwrite {
            kv2::set(
                vault_client.deref(),
                self.kv_mount_location,
                self.key.to_key_str().as_ref(),
                &self.credentials,
            )
            .await
        } else {
            // Setting the cas key to 0 is the officially documented way of create-only writes. Per
            // vault docs:
            // > If set to 0 a write will only be allowed if the key doesn't exist as unset keys do
            // > not have any version information.
            let options = SetSecretRequestOptions { cas: 0 };

            kv2::set_with_options(
                vault_client.deref(),
                self.kv_mount_location,
                self.key.to_key_str().as_ref(),
                &self.credentials,
                options,
            )
            .await
        };

        let elapsed_request_duration = time_started_vault_request.elapsed().as_millis() as u64;
        vault_metrics.vault_request_duration_histogram.record(
            elapsed_request_duration,
            &[KeyValue::new("request_type", "set_credentials")],
        );

        let _secret_version_metadata = vault_response.map_err(|err| {
            record_vault_client_error(&err, "set_credentials", vault_metrics);
            tracing::error!("Error setting credentials. Error: {err:?}");
            err
        })?;

        vault_metrics
            .vault_requests_succeeded_counter
            .add(1, &[KeyValue::new("request_type", "set_credentials")]);
        Ok(())
    }
}

struct DeleteCredentialsHelper<'key, 'location> {
    pub kv_mount_location: &'location String,
    pub key: &'key CredentialKey,
}

#[async_trait]
impl VaultTask<()> for DeleteCredentialsHelper<'_, '_> {
    async fn execute(
        &self,
        vault_client: Arc<VaultClient>,
        vault_metrics: &ForgeVaultMetrics,
    ) -> Result<(), SecretsError> {
        vault_metrics
            .vault_requests_total_counter
            .add(1, &[KeyValue::new("request_type", "delete_credentials")]);

        let time_started_vault_request = Instant::now();
        let vault_response = kv2::delete_metadata(
            vault_client.deref(),
            self.kv_mount_location,
            self.key.to_key_str().as_ref(),
        )
        .await;

        let elapsed_request_duration = time_started_vault_request.elapsed().as_millis() as u64;
        vault_metrics.vault_request_duration_histogram.record(
            elapsed_request_duration,
            &[KeyValue::new("request_type", "delete_credentials")],
        );

        let _secret_version_metadata = vault_response.map_err(|err| {
            record_vault_client_error(&err, "delete_credentials", vault_metrics);
            tracing::error!("Error deleting credentials. Error: {err:?}");
            err
        })?;

        vault_metrics
            .vault_requests_succeeded_counter
            .add(1, &[KeyValue::new("request_type", "delete_credentials")]);
        Ok(())
    }
}

#[async_trait]
impl CredentialProvider for ForgeVaultClient {
    async fn get_credentials(
        &self,
        key: &CredentialKey,
    ) -> Result<Option<Credentials>, SecretsError> {
        let kv_mount_location = &self.vault_client_config.kv_mount_location;
        let get_credentials_helper = GetCredentialsHelper {
            kv_mount_location,
            key,
        };
        let vault_client = self.vault_client().await?;
        get_credentials_helper
            .execute(vault_client, &self.vault_metrics)
            .await
    }

    async fn set_credentials(
        &self,
        key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), SecretsError> {
        let kv_mount_location = &self.vault_client_config.kv_mount_location;
        let set_credentials_helper = SetCredentialsHelper {
            key,
            credentials,
            kv_mount_location,
            allow_overwrite: true,
        };
        let vault_client = self.vault_client().await?;
        set_credentials_helper
            .execute(vault_client, &self.vault_metrics)
            .await
    }

    async fn create_credentials(
        &self,
        key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), SecretsError> {
        let kv_mount_location = &self.vault_client_config.kv_mount_location;
        let set_credentials_helper = SetCredentialsHelper {
            key,
            credentials,
            kv_mount_location,
            allow_overwrite: false,
        };
        let vault_client = self.vault_client().await?;
        set_credentials_helper
            .execute(vault_client, &self.vault_metrics)
            .await
    }

    async fn delete_credentials(&self, key: &CredentialKey) -> Result<(), SecretsError> {
        let kv_mount_location = &self.vault_client_config.kv_mount_location;
        let delete_credentials_helper = DeleteCredentialsHelper {
            key,
            kv_mount_location,
        };
        let vault_client = self.vault_client().await?;
        delete_credentials_helper
            .execute(vault_client, &self.vault_metrics)
            .await
    }
}

struct GetCertificateHelper {
    /// Used to form URI-type SANs for this certificate
    unique_identifier: String,
    pki_mount_location: String,
    pki_role_name: String,
    /// Alternative requested DNS-type SANs for this certificate
    alt_names: Option<String>,
    /// Requested expiration date of this certificate
    /// Duration format: https://developer.hashicorp.com/vault/docs/concepts/duration-format
    /// Accept numeric value with suffix such as  s-seconds, m-minutes, h-hours, d-days
    ttl: Option<String>,
}

#[async_trait]
impl VaultTask<Certificate> for GetCertificateHelper {
    async fn execute(
        &self,
        vault_client: Arc<VaultClient>,
        vault_metrics: &ForgeVaultMetrics,
    ) -> Result<Certificate, SecretsError> {
        vault_metrics
            .vault_requests_total_counter
            .add(1, &[KeyValue::new("request_type", "get_certificate")]);

        let trust_domain = "forge.local";
        let namespace = "forge-system";

        // spiffe://<trust_domain>/<namespace>/machine/<stable_machine_id>
        let spiffe_id = format!(
            "spiffe://{}/{}/machine/{}",
            trust_domain, namespace, self.unique_identifier,
        );

        let ttl = if self.ttl.is_some() {
            self.ttl.clone().unwrap()
        } else {
            // this is to setup a baseline skew of between 60 - 100% of 30 days,
            // so that not all boxes will renew (or expire) at the same time.
            let max_hours = 720; // 24 * 30
            let min_hours = 432; // 24 * 30 * 0.6
            let mut rng = rand::rng();
            format!("{}h", rng.random_range(min_hours..max_hours))
        };

        let mut certificate_request_builder = GenerateCertificateRequest::builder();
        certificate_request_builder
            .mount(self.pki_mount_location.clone())
            .role(self.pki_role_name.clone())
            .uri_sans(spiffe_id)
            .alt_names(self.alt_names.clone().unwrap_or_default())
            .ttl(ttl);

        let time_started_vault_request = Instant::now();
        let vault_response = pki::cert::generate(
            vault_client.deref(),
            self.pki_mount_location.as_str(),
            self.pki_role_name.as_str(),
            Some(&mut certificate_request_builder),
        )
        .await;
        let elapsed_request_duration = time_started_vault_request.elapsed().as_millis() as u64;
        vault_metrics.vault_request_duration_histogram.record(
            elapsed_request_duration,
            &[KeyValue::new("request_type", "get_certificate")],
        );

        let generate_certificate_response = vault_response.inspect_err(|err| {
            record_vault_client_error(err, "get_certificate", vault_metrics);
        })?;

        vault_metrics
            .vault_requests_succeeded_counter
            .add(1, &[KeyValue::new("request_type", "get_certificate")]);

        Ok(Certificate {
            issuing_ca: generate_certificate_response.issuing_ca.into_bytes(),
            public_key: generate_certificate_response.certificate.into_bytes(),
            private_key: generate_certificate_response.private_key.into_bytes(),
        })
    }
}

#[async_trait]
impl CertificateProvider for ForgeVaultClient {
    async fn get_certificate(
        &self,
        unique_identifier: &str,
        alt_names: Option<String>,
        ttl: Option<String>,
    ) -> Result<Certificate, SecretsError> {
        let get_certificate_helper = GetCertificateHelper {
            unique_identifier: unique_identifier.to_string(),
            pki_mount_location: self.vault_client_config.pki_mount_location.clone(),
            pki_role_name: self.vault_client_config.pki_role_name.clone(),
            alt_names,
            ttl,
        };
        let vault_client = self.vault_client().await?;
        get_certificate_helper
            .execute(vault_client, &self.vault_metrics)
            .await
    }
}

#[derive(Default, Debug, Clone)]
pub struct VaultConfig {
    pub address: Option<String>,
    pub kv_mount_location: Option<String>,
    pub pki_mount_location: Option<String>,
    pub pki_role_name: Option<String>,
    pub token: Option<String>,
}

impl VaultConfig {
    pub fn address(&self) -> eyre::Result<String> {
        self.address
            .clone()
            .or(env::var("VAULT_ADDR").ok())
            .context("VAULT_ADDR")
    }

    pub fn kv_mount_location(&self) -> eyre::Result<String> {
        self.kv_mount_location
            .clone()
            .or(env::var("VAULT_KV_MOUNT_LOCATION").ok())
            .context("VAULT_KV_MOUNT_LOCATION")
    }

    pub fn pki_mount_location(&self) -> eyre::Result<String> {
        self.pki_mount_location
            .clone()
            .or(env::var("VAULT_PKI_MOUNT_LOCATION").ok())
            .context("VAULT_PKI_MOUNT_LOCATION")
    }

    pub fn pki_role_name(&self) -> eyre::Result<String> {
        self.pki_role_name
            .clone()
            .or(env::var("VAULT_PKI_ROLE_NAME").ok())
            .context("VAULT_PKI_ROLE_NAME")
    }

    pub fn token(&self) -> eyre::Result<String> {
        self.token
            .clone()
            .or(env::var("VAULT_TOKEN").ok())
            .context("VAULT_TOKEN")
    }
}

pub fn create_vault_client(
    vault_config: &VaultConfig,
    meter: Meter,
) -> eyre::Result<Arc<ForgeVaultClient>> {
    let vault_root_ca_path = "/var/run/secrets/forge-roots/ca.crt".to_string();
    let service_account_token_path =
        Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token");
    let auth_type = if service_account_token_path.exists() {
        ForgeVaultAuthenticationType::ServiceAccount(service_account_token_path.to_owned())
    } else {
        ForgeVaultAuthenticationType::Root(vault_config.token()?)
    };

    let vault_requests_total_counter = meter
        .u64_counter("carbide-api.vault.requests_attempted")
        .with_description("The amount of tls connections that were attempted")
        .build();
    let vault_requests_succeeded_counter = meter
        .u64_counter("carbide-api.vault.requests_succeeded")
        .with_description("The amount of tls connections that were successful")
        .build();
    let vault_requests_failed_counter = meter
        .u64_counter("carbide-api.vault.requests_failed")
        .with_description("The amount of tcp connections that were failures")
        .build();
    let vault_token_time_remaining_until_refresh_gauge = meter
        .f64_gauge("carbide-api.vault.token_time_until_refresh")
        .with_description(
            "The amount of time, in seconds, until the vault token is required to be refreshed",
        )
        .with_unit("s")
        .build();
    let vault_request_duration_histogram = meter
        .u64_histogram("carbide-api.vault.request_duration")
        .with_description("the duration of outbound vault requests, in milliseconds")
        .with_unit("ms")
        .build();

    let forge_vault_metrics = ForgeVaultMetrics {
        vault_requests_total_counter,
        vault_requests_succeeded_counter,
        vault_requests_failed_counter,
        vault_token_gauge: vault_token_time_remaining_until_refresh_gauge,
        vault_request_duration_histogram,
    };

    let vault_client_config = ForgeVaultClientConfig {
        auth_type,
        vault_address: vault_config.address()?,
        kv_mount_location: vault_config.kv_mount_location()?,
        pki_mount_location: vault_config.pki_mount_location()?,
        pki_role_name: vault_config.pki_role_name()?,
        vault_root_ca_path,
    };

    let forge_vault_client = ForgeVaultClient::new(vault_client_config, forge_vault_metrics);
    Ok(Arc::new(forge_vault_client))
}
