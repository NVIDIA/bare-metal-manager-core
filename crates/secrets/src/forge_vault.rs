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
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use carbide_instrument::{Event, LabelValue, emit};
use eyre::{ContextCompat, WrapErr, eyre};
use opentelemetry::StringValue;
use opentelemetry::metrics::{Gauge, Meter};
use rand::RngExt;
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
use crate::credentials::{
    CredentialKey, CredentialManager, CredentialReader, CredentialWriter, Credentials,
};

const DEFAULT_VAULT_CA_PATH: &str = "/var/run/secrets/forge-roots/ca.crt";
const VAULT_CACERT_ENV_VAR: &str = "VAULT_CACERT";
const DEFAULT_SPIFFE_TRUST_DOMAIN: &str = "nico.local";
const DEFAULT_SPIFFE_MACHINE_BASE_PATH: &str = "/forge-system/machine/";
const VAULT_SPIFFE_TRUST_DOMAIN_ENV_VAR: &str = "VAULT_SPIFFE_TRUST_DOMAIN";
const VAULT_SPIFFE_MACHINE_BASE_PATH_ENV_VAR: &str = "VAULT_SPIFFE_MACHINE_BASE_PATH";

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
    spiffe_trust_domain: String,
    spiffe_machine_base_path: String,
    vault_root_ca_path: String,
}

// Resolve Vault CA path from a specified path first, then
// from `VAULT_CACERT` for local dev flows such as `vault server -dev-tls`.
fn resolve_vault_root_ca_path(configured_path: &str) -> Result<String, eyre::Report> {
    if Path::new(configured_path).exists() {
        return Ok(configured_path.to_string());
    }

    match env::var(VAULT_CACERT_ENV_VAR) {
        Ok(env_path) if Path::new(&env_path).exists() => Ok(env_path),
        Ok(env_path) => {
            tracing::error!(
                %env_path,
                "VAULT_CACERT does not exist. Refusing to connect without TLS verification.",
            );
            Err(eyre!("vault root CA not found"))
        }
        Err(_) => {
            tracing::error!(
                configured_path,
                "Vault root CA not found. Refusing to connect without TLS verification.",
            );
            Err(eyre!("vault root CA not found"))
        }
    }
}

impl ForgeVaultClientConfig {
    pub fn vault_root_ca_path(&self) -> Result<String, eyre::Report> {
        resolve_vault_root_ca_path(&self.vault_root_ca_path)
    }
}

/// Get the kubernetes ServiceAccount name from a ServiceAccount token.
///
/// The token itself is a JWT, and the ServiceAccount name is in the
/// `["kubernetes.io"]["serviceaccount"]["name"]` key path within the JWT's payload.
///
/// Documentation on the payload is here:
/// https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection
fn service_account_role_name_from_jwt(jwt: &str) -> Result<String, eyre::Report> {
    let payload = jwt
        .split('.')
        .nth(1)
        .context("service account jwt missing payload")?;
    let decoded_payload = URL_SAFE_NO_PAD
        .decode(payload)
        .wrap_err("failed to decode service account jwt payload")?;
    let json_value = serde_json::from_slice::<serde_json::Value>(&decoded_payload)
        .wrap_err("failed to parse service account jwt payload")?;
    json_value["kubernetes.io"]["serviceaccount"]["name"]
        .as_str()
        .wrap_err("JWT payload does not contain /kubernetes.io/serviceaccount/name")
        .map(str::to_string)
}

/// Builds a machine SPIFFE URI SAN matching site `[auth.trust]` path layout.
///
/// `machine_base_path` is the path segment after the trust domain, e.g. `/forge-system/machine/`.
pub(crate) fn machine_spiffe_uri(
    trust_domain: &str,
    machine_base_path: &str,
    machine_id: &str,
) -> String {
    let base = machine_base_path.trim().trim_matches('/');
    if base.is_empty() {
        format!("spiffe://{trust_domain}/{machine_id}")
    } else {
        format!("spiffe://{trust_domain}/{base}/{machine_id}")
    }
}

/// The Vault request kind, as the bounded `request_type` label carried by the
/// attempted / succeeded / failed counters and the duration histogram. Each
/// variant renders to the exact snake_case string the metrics have always
/// reported, so the variant names are the label contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
enum VaultRequestType {
    ServiceAccountLogin,
    GetCredentials,
    SetCredentials,
    DeleteCredentials,
    GetCertificate,
}

/// The HTTP status code of a failed Vault request, as the bounded
/// `http_response_status_code` label on the failure counter: the status code
/// rendered as a string, or the empty string when the client error carried no
/// HTTP response. HTTP status codes are a closed set, so this is a bounded
/// label value; the hand-written `LabelValue` impl is the reviewed escape hatch
/// for a bounded-but-not-enum value, and reproduces the previous
/// `code.to_string()`-or-empty rendering byte for byte.
struct VaultFailureStatusCode(Option<u16>);

impl LabelValue for VaultFailureStatusCode {
    fn label_value(&self) -> StringValue {
        StringValue::from(self.0.map(|code| code.to_string()).unwrap_or_default())
    }
}

/// A Vault request was attempted. Metric-only (`log = off`): counted, never
/// logged.
#[derive(Event)]
#[event(
    name = "carbide_api_vault_requests_attempted_total",
    component = "nico-api",
    log = off,
    metric = counter,
    describe = "Number of attempted Vault requests"
)]
struct VaultRequestAttempted {
    #[label]
    request_type: VaultRequestType,
}

/// A Vault request succeeded. Metric-only (`log = off`): counted, never logged.
#[derive(Event)]
#[event(
    name = "carbide_api_vault_requests_succeeded_total",
    component = "nico-api",
    log = off,
    metric = counter,
    describe = "Number of successful Vault requests"
)]
struct VaultRequestSucceeded {
    #[label]
    request_type: VaultRequestType,
}

/// A Vault request failed. Metric-only (`log = off`): the callers keep their
/// own `tracing` error/debug lines unchanged; this event only moves the failure
/// counter beside them. `http_response_status_code` is the HTTP status when the
/// client error carried one, and empty otherwise.
#[derive(Event)]
#[event(
    name = "carbide_api_vault_requests_failed_total",
    component = "nico-api",
    log = off,
    metric = counter,
    describe = "Number of failed Vault requests"
)]
struct VaultRequestFailed {
    #[label]
    request_type: VaultRequestType,
    #[label]
    http_response_status_code: VaultFailureStatusCode,
}

/// The wall-clock duration of an outbound Vault request, in whole
/// milliseconds. Metric-only (`log = off`).
#[derive(Event)]
#[event(
    name = "carbide_api_vault_request_duration_milliseconds",
    component = "nico-api",
    log = off,
    metric = histogram,
    describe = "Duration of outbound Vault requests, in milliseconds"
)]
struct VaultRequestDuration {
    #[label]
    request_type: VaultRequestType,
    #[observation]
    duration_ms: u64,
}

/// The one Vault metric that stays a hand-rolled OpenTelemetry instrument: a
/// periodic state gauge for the time remaining on the current token, recorded
/// from the refresher loop rather than emitted per request.
#[derive(Debug, Clone)]
pub struct ForgeVaultMetrics {
    pub vault_token_gauge: Gauge<f64>,
}

struct RefresherMessage {
    response_tx: tokio::sync::oneshot::Sender<Result<Arc<VaultClient>, eyre::Report>>,
}

pub struct ForgeVaultClient {
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

    let ca_path = vault_client_config.vault_root_ca_path()?;

    let vault_client_settings_builder = vault_client_settings_builder
        .ca_certs(vec![ca_path])
        .verify(true);

    Ok(vault_client_settings_builder.build()?)
}

async fn vault_token_refresh(
    vault_client_config: &ForgeVaultClientConfig,
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

            // Multiple services use this crate (carbide-secrets), so figure out what service account
            // to use to auth to vault. The token JWT contains the service account name in the decoded
            // JSON, so we can just read that.
            let role_name =
                service_account_role_name_from_jwt(&jwt).wrap_err("service_account_role_name")?;

            let vault_client_settings = create_vault_client_settings(
                "silly vaultrs bugs make me sad",
                vault_client_config,
            )?;
            let vault_client = VaultClient::new(vault_client_settings)?;
            emit(VaultRequestAttempted {
                request_type: VaultRequestType::ServiceAccountLogin,
            });
            let time_started_vault_request = Instant::now();
            let vault_response = vaultrs::auth::kubernetes::login(
                &vault_client,
                "kubernetes",
                role_name.as_str(),
                jwt.as_str(),
            )
            .await;
            let elapsed_request_duration = time_started_vault_request.elapsed().as_millis() as u64;
            emit(VaultRequestDuration {
                request_type: VaultRequestType::ServiceAccountLogin,
                duration_ms: elapsed_request_duration,
            });
            let auth_info = vault_response
                .inspect_err(|err| {
                    record_vault_client_error(err, VaultRequestType::ServiceAccountLogin);
                })
                .wrap_err("failed to execute kubernetes service account login request")?;

            emit(VaultRequestSucceeded {
                request_type: VaultRequestType::ServiceAccountLogin,
            });
            // start refreshing before it expires
            let lease_expiry_secs = (0.9 * auth_info.lease_duration as f64) as u64;
            (auth_info.client_token, lease_expiry_secs)
        }
    };

    tracing::info!(
        vault_token_expiry_seconds = vault_token_expiry_secs,
        "successfully refreshed vault token"
    );

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
    let refresh_fut = vault_token_refresh(vault_client_config);
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
        tokio::spawn(async move {
            vault_refresher_loop(vault_refresher_rx, vault_client_config_clone, vault_metrics)
                .await;
        });
        Self {
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
    async fn execute(&self, vault_client: Arc<VaultClient>) -> Result<T, SecretsError>;
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
    ) -> Result<Option<Credentials>, SecretsError> {
        emit(VaultRequestAttempted {
            request_type: VaultRequestType::GetCredentials,
        });

        let time_started_vault_request = Instant::now();
        let vault_response = kv2::read(
            vault_client.deref(),
            self.kv_mount_location,
            self.key.to_key_str().as_ref(),
        )
        .await;
        let elapsed_request_duration = time_started_vault_request.elapsed().as_millis() as u64;
        emit(VaultRequestDuration {
            request_type: VaultRequestType::GetCredentials,
            duration_ms: elapsed_request_duration,
        });

        match vault_response {
            Ok(creds) => {
                emit(VaultRequestSucceeded {
                    request_type: VaultRequestType::GetCredentials,
                });
                Ok(Some(creds))
            }
            Err(ce) => {
                let status_code = record_vault_client_error(&ce, VaultRequestType::GetCredentials);
                match status_code {
                    Some(404) => {
                        // Not found errors are common and of no concern
                        tracing::debug!(
                            credential_key = %self.key.to_key_str(),
                            "Credentials not found",
                        );
                        Ok(None)
                    }
                    _ => {
                        tracing::error!(
                            credential_key = %self.key.to_key_str(),
                            error = ?ce,
                            "Error getting credentials",
                        );
                        Err(SecretsError::GenericError(ce.into()))
                    }
                }
            }
        }
    }
}

/// Tracks client errors if an invocation to a Vault server failed
///
/// Returns the status code of the HTTP request if available
fn record_vault_client_error(err: &ClientError, request_type: VaultRequestType) -> Option<u16> {
    let status_code = match err {
        ClientError::APIError { code, errors: _ } => Some(*code),
        _ => None,
    };

    emit(VaultRequestFailed {
        request_type,
        http_response_status_code: VaultFailureStatusCode(status_code),
    });

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
    async fn execute(&self, vault_client: Arc<VaultClient>) -> Result<(), SecretsError> {
        emit(VaultRequestAttempted {
            request_type: VaultRequestType::SetCredentials,
        });

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
        emit(VaultRequestDuration {
            request_type: VaultRequestType::SetCredentials,
            duration_ms: elapsed_request_duration,
        });

        let _secret_version_metadata = vault_response.map_err(|err| {
            record_vault_client_error(&err, VaultRequestType::SetCredentials);
            tracing::error!(error = ?err, "Error setting credentials");
            err
        })?;

        emit(VaultRequestSucceeded {
            request_type: VaultRequestType::SetCredentials,
        });
        Ok(())
    }
}

struct DeleteCredentialsHelper<'key, 'location> {
    pub kv_mount_location: &'location String,
    pub key: &'key CredentialKey,
}

#[async_trait]
impl VaultTask<()> for DeleteCredentialsHelper<'_, '_> {
    async fn execute(&self, vault_client: Arc<VaultClient>) -> Result<(), SecretsError> {
        emit(VaultRequestAttempted {
            request_type: VaultRequestType::DeleteCredentials,
        });

        let time_started_vault_request = Instant::now();
        let vault_response = kv2::delete_metadata(
            vault_client.deref(),
            self.kv_mount_location,
            self.key.to_key_str().as_ref(),
        )
        .await;

        let elapsed_request_duration = time_started_vault_request.elapsed().as_millis() as u64;
        emit(VaultRequestDuration {
            request_type: VaultRequestType::DeleteCredentials,
            duration_ms: elapsed_request_duration,
        });

        let _secret_version_metadata = vault_response.map_err(|err| {
            record_vault_client_error(&err, VaultRequestType::DeleteCredentials);
            tracing::error!(error = ?err, "Error deleting credentials");
            err
        })?;

        emit(VaultRequestSucceeded {
            request_type: VaultRequestType::DeleteCredentials,
        });
        Ok(())
    }
}

#[async_trait]
impl CredentialReader for ForgeVaultClient {
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
        get_credentials_helper.execute(vault_client).await
    }
}

#[async_trait]
impl CredentialWriter for ForgeVaultClient {
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
        set_credentials_helper.execute(vault_client).await
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
        set_credentials_helper.execute(vault_client).await
    }

    async fn delete_credentials(&self, key: &CredentialKey) -> Result<(), SecretsError> {
        let kv_mount_location = &self.vault_client_config.kv_mount_location;
        let delete_credentials_helper = DeleteCredentialsHelper {
            key,
            kv_mount_location,
        };
        let vault_client = self.vault_client().await?;
        delete_credentials_helper.execute(vault_client).await
    }
}

impl CredentialManager for ForgeVaultClient {}

struct GetCertificateHelper {
    /// Used to form URI-type SANs for this certificate
    unique_identifier: String,
    pki_mount_location: String,
    pki_role_name: String,
    spiffe_trust_domain: String,
    spiffe_machine_base_path: String,
    /// Alternative requested DNS-type SANs for this certificate
    alt_names: Option<String>,
    /// Requested expiration date of this certificate
    /// Duration format: https://developer.hashicorp.com/vault/docs/concepts/duration-format
    /// Accept numeric value with suffix such as  s-seconds, m-minutes, h-hours, d-days
    ttl: Option<String>,
}

#[async_trait]
impl VaultTask<Certificate> for GetCertificateHelper {
    async fn execute(&self, vault_client: Arc<VaultClient>) -> Result<Certificate, SecretsError> {
        emit(VaultRequestAttempted {
            request_type: VaultRequestType::GetCertificate,
        });

        let spiffe_id = machine_spiffe_uri(
            &self.spiffe_trust_domain,
            &self.spiffe_machine_base_path,
            &self.unique_identifier,
        );

        let ttl = if let Some(ttl) = self.ttl.clone() {
            ttl
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
        emit(VaultRequestDuration {
            request_type: VaultRequestType::GetCertificate,
            duration_ms: elapsed_request_duration,
        });

        let generate_certificate_response = vault_response.inspect_err(|err| {
            record_vault_client_error(err, VaultRequestType::GetCertificate);
        })?;

        emit(VaultRequestSucceeded {
            request_type: VaultRequestType::GetCertificate,
        });

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
            spiffe_trust_domain: self.vault_client_config.spiffe_trust_domain.clone(),
            spiffe_machine_base_path: self.vault_client_config.spiffe_machine_base_path.clone(),
            alt_names,
            ttl,
        };
        let vault_client = self.vault_client().await?;
        get_certificate_helper.execute(vault_client).await
    }
}

/// How a bulk enumeration treats vault errors other than 404 (which always
/// just means "nothing here").
#[derive(Clone, Copy, PartialEq, Eq)]
enum EnumerationMode {
    /// Warn and keep going. Fine for diagnostics, where a partial answer
    /// beats none.
    BestEffort,
    /// Fail the whole enumeration. Required when the caller will act on
    /// the result as if it were complete -- the one-time import writes a
    /// permanent completion marker, so a silently dropped subtree would
    /// become silently lost credentials.
    Strict,
}

impl ForgeVaultClient {
    /// list_secrets returns all secret paths in the
    /// KV mount.
    pub async fn list_secrets(&self) -> Result<Vec<String>, SecretsError> {
        let paths = self
            .list_secrets_for_path("", EnumerationMode::BestEffort)
            .await?;
        tracing::info!(
            secret_path_count = paths.len(),
            "listed all vault secret paths"
        );
        Ok(paths)
    }

    /// list_secrets_for_prefix returns all secret
    /// paths under the given CredentialPrefix.
    pub async fn list_secrets_for_prefix(
        &self,
        prefix: &crate::credentials::CredentialPrefix,
    ) -> Result<Vec<String>, SecretsError> {
        let paths = self
            .list_secrets_for_path(prefix.as_str(), EnumerationMode::BestEffort)
            .await?;
        tracing::info!(
            prefix = prefix.as_str(),
            secret_path_count = paths.len(),
            "listed vault secret paths for prefix"
        );
        Ok(paths)
    }

    /// list_secrets_for_path recursively lists all secret paths under the
    /// given path prefix in the KV mount.
    async fn list_secrets_for_path(
        &self,
        path_prefix: &str,
        mode: EnumerationMode,
    ) -> Result<Vec<String>, SecretsError> {
        let vault_client = self.vault_client().await?;
        let mount = &self.vault_client_config.kv_mount_location;

        let mut paths = Vec::new();
        let mut stack = vec![path_prefix.to_string()];

        while let Some(dir) = stack.pop() {
            let entries = match kv2::list(vault_client.deref(), mount, &dir).await {
                Ok(e) => e,
                Err(ClientError::APIError { code: 404, .. }) => continue,
                Err(e) if mode == EnumerationMode::Strict => {
                    return Err(SecretsError::GenericError(eyre!(
                        "failed to list vault path {dir:?}: {e}"
                    )));
                }
                Err(e) => {
                    tracing::warn!(
                        prefix = %dir,
                        error = %e,
                        "failed to list vault path"
                    );
                    continue;
                }
            };

            for entry in entries {
                if entry.ends_with('/') {
                    let subdir = if dir.is_empty() {
                        entry
                    } else {
                        format!("{dir}{entry}")
                    };
                    stack.push(subdir);
                } else {
                    let full = if dir.is_empty() {
                        entry
                    } else {
                        format!("{dir}{entry}")
                    };
                    paths.push(full);
                }
            }
        }

        Ok(paths)
    }

    /// get_secrets returns all secrets in the KV mount (paths plus
    /// credentials), skipping unreadable entries with a warning.
    pub async fn get_secrets(&self) -> Result<Vec<(String, Credentials)>, SecretsError> {
        let paths = self
            .list_secrets_for_path("", EnumerationMode::BestEffort)
            .await?;
        self.read_secrets(&paths, EnumerationMode::BestEffort).await
    }

    /// get_secrets_strict returns all secrets in the KV mount, failing on
    /// the first list or read error instead of skipping. The one-time
    /// Postgres import uses this so a vault hiccup aborts the import --
    /// and leaves the completion marker unwritten -- rather than quietly
    /// importing a subset.
    pub async fn get_secrets_strict(&self) -> Result<Vec<(String, Credentials)>, SecretsError> {
        let paths = self
            .list_secrets_for_path("", EnumerationMode::Strict)
            .await?;
        self.read_secrets(&paths, EnumerationMode::Strict).await
    }

    /// get_secrets_for_prefix returns all secrets
    /// under the given CredentialPrefix.
    pub async fn get_secrets_for_prefix(
        &self,
        prefix: &crate::credentials::CredentialPrefix,
    ) -> Result<Vec<(String, Credentials)>, SecretsError> {
        let paths = self
            .list_secrets_for_path(prefix.as_str(), EnumerationMode::BestEffort)
            .await?;
        self.read_secrets(&paths, EnumerationMode::BestEffort).await
    }

    /// get_secrets_for_path returns all secrets under
    /// the given path prefix.
    pub async fn get_secrets_for_path(
        &self,
        path_prefix: &str,
    ) -> Result<Vec<(String, Credentials)>, SecretsError> {
        let paths = self
            .list_secrets_for_path(path_prefix, EnumerationMode::BestEffort)
            .await?;
        self.read_secrets(&paths, EnumerationMode::BestEffort).await
    }

    /// read_secrets reads credentials from vault for each path. 404s are
    /// always skipped (deleted between list and read); other errors follow
    /// the enumeration mode.
    async fn read_secrets(
        &self,
        paths: &[String],
        mode: EnumerationMode,
    ) -> Result<Vec<(String, Credentials)>, SecretsError> {
        let vault_client = self.vault_client().await?;
        let mount = &self.vault_client_config.kv_mount_location;

        let mut secrets = Vec::with_capacity(paths.len());
        for path in paths {
            match kv2::read::<Credentials>(vault_client.deref(), mount, path).await {
                Ok(creds) => {
                    secrets.push((path.clone(), creds));
                }
                Err(ClientError::APIError { code: 404, .. }) => {
                    tracing::debug!(
                        path = %path,
                        "vault secret not found"
                    );
                }
                Err(e) if mode == EnumerationMode::Strict => {
                    return Err(SecretsError::GenericError(eyre!(
                        "failed to read vault secret {path:?}: {e}"
                    )));
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path,
                        error = %e,
                        "failed to read vault secret"
                    );
                }
            }
        }

        Ok(secrets)
    }
}

#[derive(Default, Debug, Clone)]
pub struct VaultConfig {
    pub address: Option<String>,
    pub kv_mount_location: Option<String>,
    pub pki_mount_location: Option<String>,
    pub pki_role_name: Option<String>,
    pub token: Option<String>,
    pub vault_cacert: Option<String>,
    /// SPIFFE trust domain for machine PKI URI SANs. Defaults to `nico.local`.
    pub spiffe_trust_domain: Option<String>,
    /// Path prefix after the trust domain, e.g. `/forge-system/machine/`.
    pub spiffe_machine_base_path: Option<String>,
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

    pub fn vault_cacert(&self) -> eyre::Result<String> {
        self.vault_cacert
            .clone()
            .or(env::var(VAULT_CACERT_ENV_VAR).ok())
            .context("VAULT_CACERT")
    }

    pub fn spiffe_trust_domain(&self) -> String {
        self.spiffe_trust_domain
            .clone()
            .or_else(|| env::var(VAULT_SPIFFE_TRUST_DOMAIN_ENV_VAR).ok())
            .unwrap_or_else(|| DEFAULT_SPIFFE_TRUST_DOMAIN.to_string())
    }

    pub fn spiffe_machine_base_path(&self) -> String {
        self.spiffe_machine_base_path
            .clone()
            .or_else(|| env::var(VAULT_SPIFFE_MACHINE_BASE_PATH_ENV_VAR).ok())
            .unwrap_or_else(|| DEFAULT_SPIFFE_MACHINE_BASE_PATH.to_string())
    }
}

pub fn create_vault_client(
    vault_config: &VaultConfig,
    meter: Meter,
) -> eyre::Result<Arc<ForgeVaultClient>> {
    let configured_ca_path = vault_config
        .vault_cacert()
        .unwrap_or_else(|_| DEFAULT_VAULT_CA_PATH.to_string());

    let vault_root_ca_path = resolve_vault_root_ca_path(configured_ca_path.as_str())?;

    let service_account_token_path =
        Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token");
    let auth_type = if service_account_token_path.exists() {
        ForgeVaultAuthenticationType::ServiceAccount(service_account_token_path.to_owned())
    } else {
        ForgeVaultAuthenticationType::Root(vault_config.token()?)
    };

    // The attempted / succeeded / failed counters and the request-duration
    // histogram are now `carbide-instrument` events (the `VaultRequest*` types);
    // only the token-refresh state gauge stays a hand-rolled instrument.
    let vault_token_time_remaining_until_refresh_gauge = meter
        .f64_gauge("carbide-api.vault.token_time_until_refresh")
        .with_description(
            "The amount of time, in seconds, until the Vault token is required to be refreshed",
        )
        .with_unit("s")
        .build();

    let forge_vault_metrics = ForgeVaultMetrics {
        vault_token_gauge: vault_token_time_remaining_until_refresh_gauge,
    };

    let vault_client_config = ForgeVaultClientConfig {
        auth_type,
        vault_address: vault_config.address()?,
        kv_mount_location: vault_config.kv_mount_location()?,
        pki_mount_location: vault_config.pki_mount_location()?,
        pki_role_name: vault_config.pki_role_name()?,
        spiffe_trust_domain: vault_config.spiffe_trust_domain(),
        spiffe_machine_base_path: vault_config.spiffe_machine_base_path(),
        vault_root_ca_path,
    };

    let forge_vault_client = ForgeVaultClient::new(vault_client_config, forge_vault_metrics);
    Ok(Arc::new(forge_vault_client))
}

/// Build raw vaultrs client settings for a separate vault consumer (the
/// Transit KMS provider), with the same address, CA trust, and timeout that
/// `ForgeVaultClient` itself connects with. Without the CA wiring, a
/// vaultrs client only trusts public roots and fails TLS against a
/// site-CA-signed vault.
///
/// Authentication is NOT at parity with `ForgeVaultClient`: this requires a
/// static vault token in the config and does not support the Kubernetes
/// service-account login flow. Deployments using SA auth cannot configure a
/// transit KMS provider until that lands.
pub fn create_raw_vault_client_settings(
    vault_config: &VaultConfig,
) -> eyre::Result<VaultClientSettings> {
    let configured_ca_path = vault_config
        .vault_cacert()
        .unwrap_or_else(|_| DEFAULT_VAULT_CA_PATH.to_string());
    let ca_path = resolve_vault_root_ca_path(configured_ca_path.as_str())?;

    let mut builder = VaultClientSettingsBuilder::default();
    builder
        .token(vault_config.token()?)
        .address(vault_config.address()?)
        .timeout(Some(Duration::from_secs(60)))
        .ca_certs(vec![ca_path])
        .verify(true);
    builder
        .build()
        .map_err(|e| eyre!("vault client settings: {e}"))
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use serde_json::json;

    use super::{machine_spiffe_uri, service_account_role_name_from_jwt};

    #[test]
    fn machine_spiffe_uri_uses_trust_domain_and_base_path() {
        assert_eq!(
            machine_spiffe_uri("forge.local", "/forge-system/machine/", "abc-123"),
            "spiffe://forge.local/forge-system/machine/abc-123"
        );
        assert_eq!(
            machine_spiffe_uri("nico.local", "/forge-system/machine/", "abc-123"),
            "spiffe://nico.local/forge-system/machine/abc-123"
        );
        assert_eq!(
            machine_spiffe_uri("forge.local", "forge-system/machine", "abc-123"),
            "spiffe://forge.local/forge-system/machine/abc-123"
        );
    }

    #[test]
    fn vault_config_spiffe_trust_domain_defaults_to_nico_local() {
        use super::VaultConfig;

        let config = VaultConfig::default();
        assert_eq!(config.spiffe_trust_domain(), "nico.local");
    }

    fn jwt_from_payload(payload_value: serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_value.to_string());
        format!("{header}.{payload}.")
    }

    fn jwt_with_account(account: serde_json::Value) -> String {
        jwt_from_payload(json!({
          "aud": [
            "https://kubernetes.default.svc"
          ],
          "exp": 1731613413,
          "iat": 1700077413,
          "iss": "https://kubernetes.default.svc",
          "jti": "ea28ed49-2e11-4280-9ec5-bc3d1d84661a",
          "kubernetes.io": {
            "namespace": "kube-system",
            "node": {
              "name": "127.0.0.1",
              "uid": "58456cb0-dd00-45ed-b797-5578fdceaced"
            },
            "pod": {
              "name": "coredns-69cbfb9798-jv9gn",
              "uid": "778a530c-b3f4-47c0-9cd5-ab018fb64f33"
            },
            "serviceaccount": {
              "name": account,
              "uid": "a087d5a0-e1dd-43ec-93ac-f13d89cd13af"
            },
            "warnafter": 1700081020
          },
          "nbf": 1700077413,
          // The service account is also in the `sub` field. We don't read it, but let's mock it faithfully.
          "sub": format!("system:serviceaccount:kube-system:{account}"),
        }))
    }

    #[test]
    fn extracts_service_account_name_from_kubernetes_jwt_subject() {
        let jwt = jwt_with_account("carbide-bmc-proxy".into());
        let role_name = service_account_role_name_from_jwt(&jwt).unwrap();
        assert_eq!(role_name, "carbide-bmc-proxy");
    }

    #[test]
    fn rejects_unexpected_jwt_subject_format() {
        let jwt = jwt_with_account(serde_json::Value::Null);
        assert!(service_account_role_name_from_jwt(&jwt).is_err());
    }

    #[test]
    fn rejects_random_json() {
        let jwt = jwt_from_payload(json!({"foo": ["bar"]}));
        assert!(service_account_role_name_from_jwt(&jwt).is_err());
    }

    /// The `request_type` label values are the metric's contract: each variant
    /// renders to the exact snake_case string the vault counters and histogram
    /// have always reported.
    #[test]
    fn vault_request_type_renders_expected_label_values() {
        use carbide_instrument::LabelValue;
        use carbide_test_support::{Check, check_values};

        use super::VaultRequestType;

        check_values(
            [
                Check {
                    scenario: "service account login",
                    input: VaultRequestType::ServiceAccountLogin,
                    expect: "service_account_login".to_string(),
                },
                Check {
                    scenario: "get credentials",
                    input: VaultRequestType::GetCredentials,
                    expect: "get_credentials".to_string(),
                },
                Check {
                    scenario: "set credentials",
                    input: VaultRequestType::SetCredentials,
                    expect: "set_credentials".to_string(),
                },
                Check {
                    scenario: "delete credentials",
                    input: VaultRequestType::DeleteCredentials,
                    expect: "delete_credentials".to_string(),
                },
                Check {
                    scenario: "get certificate",
                    input: VaultRequestType::GetCertificate,
                    expect: "get_certificate".to_string(),
                },
            ],
            |request_type| request_type.label_value().to_string(),
        );
    }

    /// The failure counter's `http_response_status_code` label: an HTTP status
    /// rendered as a string, or the empty string when the client error carried
    /// no HTTP response. Pins both the code strings and the empty case.
    #[test]
    fn vault_failure_status_code_renders_codes_and_empty() {
        use carbide_instrument::LabelValue;
        use carbide_test_support::{Check, check_values};

        use super::VaultFailureStatusCode;

        check_values(
            [
                Check {
                    scenario: "no http response renders empty",
                    input: VaultFailureStatusCode(None),
                    expect: String::new(),
                },
                Check {
                    scenario: "not found",
                    input: VaultFailureStatusCode(Some(404)),
                    expect: "404".to_string(),
                },
                Check {
                    scenario: "forbidden",
                    input: VaultFailureStatusCode(Some(403)),
                    expect: "403".to_string(),
                },
                Check {
                    scenario: "server error",
                    input: VaultFailureStatusCode(Some(500)),
                    expect: "500".to_string(),
                },
            ],
            |status| status.label_value().to_string(),
        );
    }

    /// Builds a `VaultClient` pointed at a plaintext `mockito` server, so the
    /// get-credentials helper's real `kv2::read` round-trips through a response
    /// we control. An `http://` address skips TLS, so no CA wiring is needed.
    fn mock_backed_vault_client(
        server: &mockito::ServerGuard,
    ) -> std::sync::Arc<vaultrs::client::VaultClient> {
        use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

        let settings = VaultClientSettingsBuilder::default()
            .address(server.url())
            .token("test-token")
            .verify(false)
            .build()
            .expect("vault client settings for mock server");
        std::sync::Arc::new(VaultClient::new(settings).expect("vault client for mock server"))
    }

    /// A failed `get_credentials` read counts the attempt, times it once, and
    /// moves ONLY the failed counter (carrying the HTTP status code) -- never
    /// the succeeded counter -- while a successful read moves the succeeded
    /// counter and leaves the failed one alone. Regression: the helper used to
    /// emit `VaultRequestSucceeded` unconditionally after the response match, so
    /// a failed read double-counted as both failed and succeeded, corrupting the
    /// success/error split for `request_type="get_credentials"`.
    #[tokio::test]
    async fn get_credentials_failed_read_counts_failed_not_succeeded() {
        use carbide_instrument::testing::MetricsCapture;

        use super::{GetCredentialsHelper, VaultTask};
        use crate::credentials::CredentialKey;

        let mount = "secret".to_string();
        let key = CredentialKey::UfmAuth {
            fabric: "regression".to_string(),
        };
        let get = &[("request_type", "get_credentials")][..];
        let failed_403 = &[
            ("request_type", "get_credentials"),
            ("http_response_status_code", "403"),
        ][..];

        // A non-404 error (here 403) must surface as an error and move the
        // failed counter with its status code -- and must NOT move succeeded.
        {
            let mut server = mockito::Server::new_async().await;
            let _mock = server
                .mock("GET", mockito::Matcher::Any)
                .with_status(403)
                .with_header("content-type", "application/json")
                .with_body(r#"{"errors":["permission denied"]}"#)
                .create_async()
                .await;

            let helper = GetCredentialsHelper {
                kv_mount_location: &mount,
                key: &key,
            };

            let metrics = MetricsCapture::start();
            let result = helper.execute(mock_backed_vault_client(&server)).await;

            assert!(result.is_err(), "a 403 read must surface as an error");
            assert_eq!(
                metrics.counter_delta("carbide_api_vault_requests_failed_total", failed_403),
                1.0,
                "a failed read must move the failed counter once with its status code; exposition:\n{}",
                metrics.render()
            );
            assert_eq!(
                metrics.counter_delta("carbide_api_vault_requests_succeeded_total", get),
                0.0,
                "a failed read must not move the succeeded counter",
            );
            assert_eq!(
                metrics.counter_delta("carbide_api_vault_requests_attempted_total", get),
                1.0,
                "every read counts exactly one attempt",
            );
            assert_eq!(
                metrics
                    .histogram_count_delta("carbide_api_vault_request_duration_milliseconds", get),
                1,
                "every read records exactly one duration observation",
            );
        }

        // A successful read moves the succeeded counter and leaves the failed
        // series untouched.
        {
            let mut server = mockito::Server::new_async().await;
            let _mock = server
                .mock("GET", mockito::Matcher::Any)
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    r#"{"request_id":"test","lease_id":"","lease_duration":0,"renewable":false,"data":{"data":{"UsernamePassword":{"username":"u","password":"p"}},"metadata":{"created_time":"2024-01-01T00:00:00Z","deletion_time":"","custom_metadata":null,"destroyed":false,"version":1}}}"#,
                )
                .create_async()
                .await;

            let helper = GetCredentialsHelper {
                kv_mount_location: &mount,
                key: &key,
            };

            let metrics = MetricsCapture::start();
            let result = helper.execute(mock_backed_vault_client(&server)).await;

            assert!(
                matches!(&result, Ok(Some(_))),
                "a 200 read with a valid body must succeed, got {result:?}"
            );
            assert_eq!(
                metrics.counter_delta("carbide_api_vault_requests_succeeded_total", get),
                1.0,
                "a successful read must move the succeeded counter once; exposition:\n{}",
                metrics.render()
            );
            assert_eq!(
                metrics.counter_delta("carbide_api_vault_requests_failed_total", failed_403),
                0.0,
                "a successful read must not move the failed counter",
            );
            assert_eq!(
                metrics.counter_delta("carbide_api_vault_requests_attempted_total", get),
                1.0,
                "every read counts exactly one attempt",
            );
            assert_eq!(
                metrics
                    .histogram_count_delta("carbide_api_vault_request_duration_milliseconds", get),
                1,
                "every read records exactly one duration observation",
            );
        }
    }
}
