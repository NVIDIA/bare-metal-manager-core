use std::any::Any;
use std::marker::PhantomData;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use eyre::WrapErr;
use opentelemetry::metrics::{Counter, Histogram, ObservableGauge, Observer};
use opentelemetry::KeyValue;
use rand::Rng;
use tokio::sync::RwLock;
use vaultrs::api::pki::requests::GenerateCertificateRequest;
use vaultrs::client::{VaultClient, VaultClientSettings, VaultClientSettingsBuilder};
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

pub trait GaugeMetric: Clone {
    fn observe(
        observer: &dyn Observer,
        instrument: &ObservableGauge<Self>,
        measurement: Self,
        attributes: &[KeyValue],
    );
}
impl GaugeMetric for u64 {
    fn observe(
        observer: &dyn Observer,
        instrument: &ObservableGauge<Self>,
        measurement: Self,
        attributes: &[KeyValue],
    ) {
        observer.observe_u64(instrument, measurement, attributes);
    }
}
impl GaugeMetric for f64 {
    fn observe(
        observer: &dyn Observer,
        instrument: &ObservableGauge<Self>,
        measurement: Self,
        attributes: &[KeyValue],
    ) {
        observer.observe_f64(instrument, measurement, attributes);
    }
}
impl GaugeMetric for i64 {
    fn observe(
        observer: &dyn Observer,
        instrument: &ObservableGauge<Self>,
        measurement: Self,
        attributes: &[KeyValue],
    ) {
        observer.observe_i64(instrument, measurement, attributes);
    }
}

pub trait GaugeHolder: Send + Sync {
    type MetricType: GaugeMetric;

    fn gauge(&self) -> &ObservableGauge<Self::MetricType>;
    fn value(&self) -> &ArcSwapOption<Self::MetricType>;

    fn attributes(&self) -> &[KeyValue] {
        &[]
    }
    fn emit_observable(&self) -> Arc<dyn Any> {
        self.gauge().as_any()
    }
    fn observe_callback(&self, observer: &dyn Observer) {
        if let Some(value) = self.value().load_full() {
            Self::MetricType::observe(observer, self.gauge(), (*value).clone(), self.attributes());
        }
    }
}
pub struct VaultTokenGaugeHolder {
    gauge: ObservableGauge<u64>,
    value: ArcSwapOption<u64>,
}

impl VaultTokenGaugeHolder {
    pub fn new(gauge: ObservableGauge<u64>) -> Self {
        Self {
            gauge,
            value: ArcSwapOption::default(),
        }
    }
}
impl GaugeHolder for VaultTokenGaugeHolder {
    type MetricType = u64;

    fn gauge(&self) -> &ObservableGauge<Self::MetricType> {
        &self.gauge
    }

    fn value(&self) -> &ArcSwapOption<Self::MetricType> {
        &self.value
    }
}

pub struct ForgeVaultMetrics {
    pub vault_requests_total_counter: Counter<u64>,
    pub vault_requests_succeeded_counter: Counter<u64>,
    pub vault_requests_failed_counter: Counter<u64>,
    pub vault_token_gauge_holder: Arc<VaultTokenGaugeHolder>,
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
                    .ca_certs(vec![forge_vault_client
                        .vault_client_config
                        .vault_root_ca_path
                        .clone()])
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
                        .map_err(|err| {
                            forge_vault_client
                                .vault_metrics
                                .vault_requests_failed_counter
                                .add(1, &[KeyValue::new("request_type", "service_account_login")]);

                            err
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
                        .vault_token_gauge_holder
                        .value
                        .store(Some(Arc::new(time_remaining_until_refresh.as_secs())));

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
        if let ForgeVaultAuthenticationStatus::Authenticated(_, ref vault_client) =
            auth_status.deref()
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
            vault_metrics
                .vault_requests_failed_counter
                .add(1, &[KeyValue::new("request_type", "get_credentials")]);
            tracing::error!(
                "Error getting credentials ({}). Error: {err:?}",
                self.key.to_key_str().as_str()
            );
            err
        })?;

        vault_metrics
            .vault_requests_succeeded_counter
            .add(1, &[KeyValue::new("request_type", "get_credentials")]);
        Ok(credentials)
    }
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
            vault_metrics
                .vault_requests_failed_counter
                .add(1, &[KeyValue::new("request_type", "set_credentials")]);
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

pub struct GetCertificateHelper<S: AsRef<str> + Sync + Send> {
    unique_identifier: S,
    pki_mount_location: String,
    pki_role_name: String,
}

#[async_trait]
impl<S> VaultTask<Certificate> for GetCertificateHelper<S>
where
    S: AsRef<str> + Sync + Send,
{
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
            trust_domain,
            namespace,
            self.unique_identifier.as_ref()
        );

        let ttl = {
            // this is to setup a baseline skew of between 60 - 100% of 30 days,
            // so that not all boxes will renew (or expire) at the same time.
            let max_hours = 720; // 24 * 30
            let min_hours = 432; // 24 * 30 * 0.6
            let mut rng = rand::thread_rng();
            rng.gen_range(min_hours..max_hours)
        };

        let mut certificate_request_builder = GenerateCertificateRequest::builder();
        certificate_request_builder
            .mount(self.pki_mount_location.clone())
            .role(self.pki_role_name.clone())
            .uri_sans(spiffe_id)
            .ttl(format!("{ttl}h"));

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

        let generate_certificate_response = vault_response.map_err(|err| {
            vault_metrics
                .vault_requests_failed_counter
                .add(1, &[KeyValue::new("request_type", "get_certificate")]);
            err
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
    async fn get_certificate<S>(&self, unique_identifier: S) -> Result<Certificate, eyre::Report>
    where
        S: AsRef<str> + Send + Sync,
    {
        let get_certificate_helper = GetCertificateHelper {
            unique_identifier,
            pki_mount_location: self.vault_client_config.pki_mount_location.clone(),
            pki_role_name: self.vault_client_config.pki_role_name.clone(),
        };
        let vault_task_helper = VaultTaskHelper::new(get_certificate_helper);
        vault_task_helper.execute(self).await
    }
}
