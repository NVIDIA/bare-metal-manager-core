use std::env;
use std::marker::PhantomData;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use eyre::WrapErr;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter};
use rand::Rng;
use tokio::sync::RwLock;
use vaultrs::api::pki::requests::GenerateCertificateRequest;
use vaultrs::client::{VaultClient, VaultClientSettings, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use vaultrs::{kv2, pki};

use crate::certificates::{Certificate, CertificateProvider};
use crate::credentials::{CredentialKey, CredentialProvider, Credentials};

#[derive(Clone, Debug)]
pub enum ForgeVaultAuthenticationType {
    Root(String),
    ServiceAccount(PathBuf),
}

#[derive(Clone, Debug)]
pub struct ForgeVaultAuthentication {
    pub token: String,
    pub expiry: Instant,
}

pub enum ForgeVaultAuthenticationStatus {
    Authenticated(ForgeVaultAuthentication, VaultClient),
    Initialized,
}

#[derive(Debug, Clone)]
pub struct ForgeVaultClientConfig {
    pub auth_type: ForgeVaultAuthenticationType,
    pub vault_address: String,
    pub kv_mount_location: String,
    pub pki_mount_location: String,
    pub pki_role_name: String,
    pub vault_root_ca_path: String,
}

pub struct ForgeVaultMetrics {
    pub vault_requests_total_counter: Counter<u64>,
    pub vault_requests_succeeded_counter: Counter<u64>,
    pub vault_requests_failed_counter: Counter<u64>,
    pub vault_token_gauge: Gauge<f64>,
    pub vault_request_duration_histogram: Histogram<u64>,
}

pub struct ForgeVaultClient {
    vault_metrics: ForgeVaultMetrics,
    vault_client_config: ForgeVaultClientConfig,
    vault_auth_status: RwLock<ForgeVaultAuthenticationStatus>,
}

impl ForgeVaultClient {
    pub fn new(
        vault_client_config: ForgeVaultClientConfig,
        vault_metrics: ForgeVaultMetrics,
    ) -> Self {
        Self {
            vault_metrics,
            vault_client_config,
            vault_auth_status: RwLock::new(ForgeVaultAuthenticationStatus::Initialized),
        }
    }
}

#[async_trait]
pub trait VaultTask<T> {
    async fn execute(
        &self,
        vault_client: &VaultClient,
        vault_metrics: &ForgeVaultMetrics,
    ) -> Result<T, eyre::Report>;
}

pub struct VaultTaskHelper<V, T>
where
    V: VaultTask<T>,
{
    task: V,
    phantom: PhantomData<T>,
}

impl<V, T> VaultTaskHelper<V, T>
where
    V: VaultTask<T>,
{
    pub fn new(task: V) -> Self {
        Self {
            task,
            phantom: PhantomData,
        }
    }

    fn create_vault_client_settings<S>(
        &self,
        token: S,
        forge_vault_client: &ForgeVaultClient,
    ) -> Result<VaultClientSettings, eyre::ErrReport>
    where
        S: Into<String>,
    {
        let mut vault_client_settings_builder = VaultClientSettingsBuilder::default();
        let vault_client_settings_builder = vault_client_settings_builder
            .token(token)
            .address(forge_vault_client.vault_client_config.vault_address.clone())
            .timeout(Some(Duration::from_secs(60)));

        let vault_client_settings_builder =
            if Path::new(&forge_vault_client.vault_client_config.vault_root_ca_path).exists() {
                vault_client_settings_builder
                    .ca_certs(vec![
                        forge_vault_client
                            .vault_client_config
                            .vault_root_ca_path
                            .clone(),
                    ])
                    .verify(true)
            } else {
                vault_client_settings_builder.verify(false)
            };

        Ok(vault_client_settings_builder.build()?)
    }

    async fn vault_token_refresh(
        &self,
        forge_vault_client: &ForgeVaultClient,
    ) -> Result<(), eyre::ErrReport> {
        let (vault_token, vault_token_expiry_secs) =
            match forge_vault_client.vault_client_config.auth_type {
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

                    let vault_client_settings = self.create_vault_client_settings(
                        "silly vaultrs bugs make me sad",
                        forge_vault_client,
                    )?;
                    let vault_client = VaultClient::new(vault_client_settings)?;
                    forge_vault_client
                        .vault_metrics
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
                    let elapsed_request_duration =
                        time_started_vault_request.elapsed().as_millis() as u64;
                    forge_vault_client
                        .vault_metrics
                        .vault_request_duration_histogram
                        .record(
                            elapsed_request_duration,
                            &[KeyValue::new("request_type", "service_account_login")],
                        );
                    let auth_info = vault_response
                        .inspect_err(|err| {
                            record_vault_client_error(
                                err,
                                "service_account_login",
                                &forge_vault_client.vault_metrics,
                            );
                        })
                        .wrap_err("Failed to execute kubernetes service account login request")?;

                    forge_vault_client
                        .vault_metrics
                        .vault_requests_succeeded_counter
                        .add(1, &[KeyValue::new("request_type", "service_account_login")]);
                    // start refreshing before it expires
                    let lease_expiry_secs = (0.9 * auth_info.lease_duration as f64) as u64;
                    (auth_info.client_token, lease_expiry_secs)
                }
            };

        tracing::info!(
            "successfully refreshed vault token, with lifetime: {vault_token_expiry_secs}"
        );

        let vault_client_settings =
            self.create_vault_client_settings(vault_token.clone(), forge_vault_client)?;
        let vault_client = VaultClient::new(vault_client_settings)?;

        {
            let mut vault_auth_status = forge_vault_client.vault_auth_status.write().await;
            *vault_auth_status = ForgeVaultAuthenticationStatus::Authenticated(
                ForgeVaultAuthentication {
                    expiry: Instant::now() + Duration::from_secs(vault_token_expiry_secs),
                    token: vault_token,
                },
                vault_client,
            );
        }
        Ok(())
    }

    pub async fn vault_client_setup(
        &self,
        vault_client: &ForgeVaultClient,
    ) -> Result<(), eyre::ErrReport> {
        let refresh_required = {
            let vault_auth_status = vault_client.vault_auth_status.read().await;
            match *vault_auth_status {
                ForgeVaultAuthenticationStatus::Initialized => true,
                ForgeVaultAuthenticationStatus::Authenticated(ref authentication, ref _client) => {
                    let time_remaining_until_refresh = authentication
                        .expiry
                        .saturating_duration_since(Instant::now());
                    vault_client
                        .vault_metrics
                        .vault_token_gauge
                        .record(time_remaining_until_refresh.as_secs_f64(), &[]);

                    Instant::now() >= authentication.expiry
                }
            }
        };

        if refresh_required {
            self.vault_token_refresh(vault_client).await?;
        }

        Ok(())
    }

    pub async fn execute(self, vault_client: &ForgeVaultClient) -> Result<T, eyre::Report> {
        self.vault_client_setup(vault_client).await?;
        let vault_metrics = &vault_client.vault_metrics;
        let auth_status = vault_client.vault_auth_status.read().await;
        if let ForgeVaultAuthenticationStatus::Authenticated(_, vault_client) = auth_status.deref()
        {
            self.task.execute(vault_client, vault_metrics).await
        } else {
            Err(eyre::eyre!("vault wasn't initialized?"))
        }
    }
}

pub struct GetCredentialsHelper {
    pub kv_mount_location: String,
    pub key: CredentialKey,
}

#[async_trait]
impl VaultTask<Credentials> for GetCredentialsHelper {
    async fn execute(
        &self,
        vault_client: &VaultClient,
        vault_metrics: &ForgeVaultMetrics,
    ) -> Result<Credentials, eyre::Report> {
        vault_metrics
            .vault_requests_total_counter
            .add(1, &[KeyValue::new("request_type", "get_credentials")]);

        let time_started_vault_request = Instant::now();
        let vault_response = kv2::read(
            vault_client,
            &self.kv_mount_location,
            self.key.to_key_str().as_str(),
        )
        .await;
        let elapsed_request_duration = time_started_vault_request.elapsed().as_millis() as u64;
        vault_metrics.vault_request_duration_histogram.record(
            elapsed_request_duration,
            &[KeyValue::new("request_type", "get_credentials")],
        );

        let credentials = vault_response.map_err(|err| {
            let status_code = record_vault_client_error(&err, "get_credentials", vault_metrics);
            match status_code {
                Some(404) => {
                    // Not found errors are common and of no concern
                    tracing::debug!(
                        "Credentials not found for key ({})",
                        self.key.to_key_str().as_str()
                    );
                }
                _ => {
                    tracing::error!(
                        "Error getting credentials ({}). Error: {err:?}",
                        self.key.to_key_str().as_str()
                    );
                }
            }

            err
        })?;

        vault_metrics
            .vault_requests_succeeded_counter
            .add(1, &[KeyValue::new("request_type", "get_credentials")]);
        Ok(credentials)
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

pub struct SetCredentialsHelper {
    pub kv_mount_location: String,
    pub key: CredentialKey,
    pub credentials: Credentials,
}

#[async_trait]
impl VaultTask<()> for SetCredentialsHelper {
    async fn execute(
        &self,
        vault_client: &VaultClient,
        vault_metrics: &ForgeVaultMetrics,
    ) -> Result<(), eyre::Report> {
        vault_metrics
            .vault_requests_total_counter
            .add(1, &[KeyValue::new("request_type", "set_credentials")]);

        let time_started_vault_request = Instant::now();
        let vault_response = kv2::set(
            vault_client,
            &self.kv_mount_location,
            self.key.to_key_str().as_str(),
            &self.credentials,
        )
        .await;
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

#[async_trait]
impl CredentialProvider for ForgeVaultClient {
    async fn get_credentials(&self, key: CredentialKey) -> Result<Credentials, eyre::Report> {
        let kv_mount_location = self.vault_client_config.kv_mount_location.clone();
        let get_credentials_helper = GetCredentialsHelper {
            kv_mount_location,
            key,
        };
        let vault_task_helper = VaultTaskHelper::new(get_credentials_helper);
        vault_task_helper.execute(self).await
    }

    async fn set_credentials(
        &self,
        key: CredentialKey,
        credentials: Credentials,
    ) -> Result<(), eyre::Report> {
        let kv_mount_location = self.vault_client_config.kv_mount_location.clone();
        let set_credentials_helper = SetCredentialsHelper {
            key,
            credentials,
            kv_mount_location,
        };
        let vault_task_helper = VaultTaskHelper::new(set_credentials_helper);
        vault_task_helper.execute(self).await
    }
}

pub struct GetCertificateHelper {
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
        vault_client: &VaultClient,
        vault_metrics: &ForgeVaultMetrics,
    ) -> Result<Certificate, eyre::Report> {
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
            vault_client,
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
    ) -> Result<Certificate, eyre::Report> {
        let get_certificate_helper = GetCertificateHelper {
            unique_identifier: unique_identifier.to_string(),
            pki_mount_location: self.vault_client_config.pki_mount_location.clone(),
            pki_role_name: self.vault_client_config.pki_role_name.clone(),
            alt_names,
            ttl,
        };
        let vault_task_helper = VaultTaskHelper::new(get_certificate_helper);
        vault_task_helper.execute(self).await
    }
}

pub async fn create_vault_client(meter: Meter) -> eyre::Result<Arc<ForgeVaultClient>> {
    let vault_address = env::var("VAULT_ADDR").wrap_err("VAULT_ADDR")?;
    let kv_mount_location =
        env::var("VAULT_KV_MOUNT_LOCATION").wrap_err("VAULT_KV_MOUNT_LOCATION")?;
    let pki_mount_location =
        env::var("VAULT_PKI_MOUNT_LOCATION").wrap_err("VAULT_PKI_MOUNT_LOCATION")?;
    let pki_role_name = env::var("VAULT_PKI_ROLE_NAME").wrap_err("VAULT_PKI_ROLE_NAME")?;

    let vault_root_ca_path = "/var/run/secrets/forge-roots/ca.crt".to_string();
    let service_account_token_path =
        Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token");
    let auth_type = if service_account_token_path.exists() {
        ForgeVaultAuthenticationType::ServiceAccount(service_account_token_path.to_owned())
    } else {
        ForgeVaultAuthenticationType::Root(env::var("VAULT_TOKEN").wrap_err("VAULT_TOKEN")?)
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
        vault_address,
        kv_mount_location,
        pki_mount_location,
        pki_role_name,
        vault_root_ca_path,
    };

    let forge_vault_client = ForgeVaultClient::new(vault_client_config, forge_vault_metrics);
    Ok(Arc::new(forge_vault_client))
}
