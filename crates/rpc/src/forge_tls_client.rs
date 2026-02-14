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
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eyre::Result;
use forge_http_connector::connector::ForgeHttpConnector;
use forge_http_connector::resolver::{ForgeResolver, ForgeResolverOpts};
use forge_tls::client_config::ClientCert;
use hickory_resolver::config::ResolverConfig;
use hyper::body::Incoming;
use hyper_util::client::legacy;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tonic::body::Body;
use tonic::transport::Uri;
use tower::ServiceExt;
use tower::util::BoxCloneService;
use tryhard::backoff_strategies::FixedBackoff;
use tryhard::{NoOnRetry, RetryFutureConfig};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::forge::VersionRequest;
use crate::forge_resolver::resolver::ResolverError;
use crate::forge_tls_client::ConfigurationError::CouldNotReadRootCa;
use crate::protos::forge::forge_client::ForgeClient;
use crate::protos::nmx_c::nmx_controller_client::NmxControllerClient;
use crate::{forge_resolver, protos};

pub type NmxCClientT = NmxControllerClient<
    BoxCloneService<
        hyper::Request<Body>,
        hyper::Response<Incoming>,
        hyper_util::client::legacy::Error,
    >,
>;

pub type ForgeClientT = ForgeClient<
    BoxCloneService<
        hyper::Request<Body>,
        hyper::Response<Incoming>,
        hyper_util::client::legacy::Error,
    >,
>;

//this code was copy and pasted from the implementation of the same struct in sqlx::core,
//and is only necessary for as long as we're optionally validating TLS
#[derive(Debug)]
pub struct DummyTlsVerifier {
    print_warning: bool,
}

impl Default for DummyTlsVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl DummyTlsVerifier {
    #[cfg(not(test))]
    pub fn new() -> Self {
        Self {
            // Warnings are suppressed if this is running in a unit-test
            print_warning: std::env::var_os("CARGO_MANIFEST_DIR").is_none(),
        }
    }

    #[cfg(test)]
    pub fn new() -> Self {
        Self {
            // Warnings are suppressed if this is running in a unit-test
            print_warning: false,
        }
    }
}

pub const DEFAULT_DOMAIN: &str = "forge.local";

const VRF_NAME: &str = "mgmt";

impl ServerCertVerifier for DummyTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.print_warning {
            eprintln!(
                "IGNORING SERVER CERT, Please ensure that I am removed to actually validate TLS."
            );
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if self.print_warning {
            eprintln!(
                "IGNORING SERVER CERT, Please ensure that I am removed to actually validate TLS."
            );
        }
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if self.print_warning {
            eprintln!(
                "IGNORING SERVER CERT, Please ensure that I am removed to actually validate TLS."
            );
        }
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[derive(Clone, Debug, Default)]
pub struct ForgeClientConfig {
    pub root_ca_path: String,
    pub client_cert: Option<ClientCert>,
    pub enforce_tls: bool,
    pub use_mgmt_vrf: bool,
    pub max_decoding_message_size: Option<usize>,
    pub socks_proxy: Option<String>,
    pub connect_retries_max: Option<u32>,
    pub connect_retries_interval: Option<Duration>,
}

impl ForgeClientConfig {
    pub fn new(root_ca_path: String, client_cert: Option<ClientCert>) -> Self {
        let mut disabled = std::env::var("DISABLE_TLS_ENFORCEMENT").is_ok();
        if client_cert.is_none() {
            disabled = true;
        }
        let max_decoding_message_size = std::env::var("TONIC_MAX_DECODING_MESSAGE_SIZE")
            .ok()
            .and_then(|ms| ms.parse::<usize>().ok());

        Self {
            root_ca_path,
            client_cert,
            enforce_tls: !disabled,
            use_mgmt_vrf: false,
            max_decoding_message_size,
            socks_proxy: None,

            // Default connect retry configuration to start.
            // We can change this if needed, or just make it
            // easier to set at initialization time (callers
            // can also call set_connect_retries_max and
            // set_connect_retries_interval on the ForgeHttpConnector
            // to override).
            //
            // TODO(chet): Really, what would be nice here is,
            // when I go and clean up the previous retry_build
            // stuff, to leverage the prevalance of ApiConfig
            // across the codebase (which has a RetryConfig), and
            // leverage that as the driver for this config, which
            // was the point anyway. It'l be cleaner as a separate
            // MR though, I think.
            connect_retries_max: Some(3),
            connect_retries_interval: Some(Duration::from_secs(20)),
        }
    }

    /// This is required when using `ForgeTlsConfig` on a DPU to communicate with site-controller.
    /// The mgmt interface exists in the mgmt VRF. `use_mgmt_vrf` sets the
    /// `SO_BINDTODEVICE` socket option on the client socket used when performing DNS queries
    /// and establishing a TCP connection with site-controller.
    pub fn use_mgmt_vrf(self) -> Result<Self, eyre::Report> {
        let ignore_mgmt_vrf = std::env::var("IGNORE_MGMT_VRF").is_ok();

        let use_mgmt_vrf = match ignore_mgmt_vrf {
            true => {
                log::debug!("ignore_mgmt_vrf is {ignore_mgmt_vrf} not using mgmt vrf: {VRF_NAME}");
                false
            }

            false => {
                log::debug!("ignore_mgmt_vrf is {ignore_mgmt_vrf} using mgmt vrf: {VRF_NAME}");
                true
            }
        };

        let max_decoding_message_size = std::env::var("TONIC_MAX_DECODING_MESSAGE_SIZE")
            .ok()
            .and_then(|ms| ms.parse::<usize>().ok());

        let res = Self {
            use_mgmt_vrf,
            max_decoding_message_size,
            ..self
        };

        log::debug!("ForgeClientConfig {res:?}");

        Ok(res)
    }

    pub fn client_cert_expiry(&self) -> Option<i64> {
        if let Some((client_certs, _key)) = self.read_client_cert() {
            if let Some(client_public_key) = client_certs.first() {
                if let Ok((_rem, cert)) = X509Certificate::from_der(client_public_key) {
                    Some(cert.validity.not_after.timestamp())
                } else {
                    None // couldn't parse certificate to x509
                }
            } else {
                None // no cert in client certs vec
            }
        } else {
            None // no certs parsed from disk
        }
    }

    pub fn read_client_cert(
        &self,
    ) -> Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        if let Some(client_cert) = self.client_cert.as_ref() {
            let certs = {
                let fd = match std::fs::File::open(&client_cert.cert_path) {
                    Ok(fd) => fd,
                    Err(_) => return None,
                };
                let mut buf = std::io::BufReader::new(&fd);

                let mut errors = vec![];

                let valid_certificates = rustls_pemfile::certs(&mut buf)
                    .filter_map(|result| match result {
                        Ok(v) => Some(Ok(v)),
                        Err(err) => match err.kind() {
                            std::io::ErrorKind::InvalidData => {
                                errors.push(err);
                                None
                            }
                            _ => Some(Err(err)),
                        },
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap_or_else(|err| {
                        errors.push(err);
                        vec![]
                    });

                if !errors.is_empty() {
                    tracing::warn!( certs = ?errors, "Found error parsing one or more certificates");
                }

                valid_certificates
            };

            let key = {
                let fd = match std::fs::File::open(&client_cert.key_path) {
                    Ok(fd) => fd,
                    Err(_) => return None,
                };
                let mut buf = std::io::BufReader::new(&fd);

                use rustls_pemfile::Item;

                match rustls_pemfile::read_one(&mut buf) {
                    Ok(Some(item)) => match item {
                        Item::Pkcs1Key(key) => Some(key.into()),
                        Item::Pkcs8Key(key) => Some(key.into()),
                        Item::Sec1Key(key) => Some(key.into()),
                        _ => None,
                    },
                    _ => None,
                }
            };

            let key = match key {
                Some(key) => key,
                None => {
                    // tracing::error!("Rustls error: no keys?");
                    return None;
                }
            };

            Some((certs, key))
        } else {
            None
        }
    }

    pub fn socks_proxy(&mut self, socks_proxy: Option<String>) {
        self.socks_proxy = socks_proxy;
    }
}

// RetryConfig is intended to be a generic
// set of parameters used for defining retries.
// Since the use cases right now all seem to fit
// into a fixed retry interval, this supports
// as such. If this ends up evolving into
// something where we also want exponential
// backoff, we can add it.
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    pub retries: u32,
    pub interval: Duration,
}

impl Default for RetryConfig {
    // default returns the default retry configuration,
    // which is 10 second intervals up to 60 times.
    // The initial use case for this was connect failures,
    // where if we're in a situation with connection
    // failures, we don't want to be overly aggressive
    // with retries (but probably want to be persistent).
    fn default() -> Self {
        Self {
            retries: 60,
            interval: Duration::from_secs(10),
        }
    }
}

// ApiConfig holds configuration used to connect
// to a given Carbide API URL, including the client
// configuration itself, as well as retry config.
#[derive(Debug, Clone, Copy)]
pub struct ApiConfig<'a> {
    pub url: &'a str,
    pub additional_urls: &'a [String],
    pub client_config: &'a ForgeClientConfig,
    pub retry_config: RetryConfig,
}

impl<'a> ApiConfig<'a> {
    // new creates a new ApiConfig, for the given
    // Carbide API URL and ForgeClientConfig, with
    // a default retry configuration.
    pub fn new(url: &'a str, client_config: &'a ForgeClientConfig) -> Self {
        Self {
            url,
            additional_urls: &[],
            client_config,
            retry_config: RetryConfig::default(),
        }
    }

    pub fn new_with_multiple_urls(
        url: &'a str,
        additional_urls: &'a [String],
        client_config: &'a ForgeClientConfig,
        retry_config: RetryConfig,
    ) -> Self {
        Self {
            url,
            additional_urls,
            client_config,
            retry_config,
        }
    }

    // with_retry_config allows a caller to set their
    // own RetryConfig beyond the default.
    pub fn with_retry_config(self, retry_config: RetryConfig) -> Self {
        Self {
            url: self.url,
            additional_urls: self.additional_urls,
            client_config: self.client_config,
            retry_config,
        }
    }

    // retry_config converts the generic RetryConfig into the
    // implementation-specific retry type, which as of now is
    // a tryhard::RetryFutureConfig.
    fn retry_config(&self) -> RetryFutureConfig<FixedBackoff, NoOnRetry> {
        RetryFutureConfig::new(self.retry_config.retries).fixed_backoff(self.retry_config.interval)
    }
}

#[derive(Clone, Debug)]
pub struct ForgeTlsClient<'a> {
    forge_client_config: &'a ForgeClientConfig,
}

impl<'a> ForgeTlsClient<'a> {
    pub fn new(forge_client_config: &'a ForgeClientConfig) -> Self {
        Self {
            forge_client_config,
        }
    }

    /// retry_build creates a new ForgeTlsClient from
    /// the given API URL and ForgeClientConfig, then attempts to build
    /// and return a client, integrating retries into the
    /// building attempts.
    pub async fn retry_build(api_config: &ApiConfig<'a>) -> ForgeTlsClientResult<ForgeClientT> {
        // In the retrying function, if the ForgeTlsClient just fails to even build, return _that_
        // error early by putting it in the Ok(Err(e)) variant, so that tryhard doesn't keep
        // retrying a configuration error.
        let result: Result<Result<ForgeClientT, ForgeTlsClientError>, ForgeTlsClientError> =
            tryhard::retry_fn(|| async move {
                let mut client = match ForgeTlsClient::new(api_config.client_config)
                    .build(api_config.url)
                    .await
                {
                    Ok(client) => client,
                    // Don't let tryhard retry this, just push the error into the Ok variant
                    Err(e) => return Ok(Err(e)),
                };

                // The thing we actually want to retry is a test connection
                client
                    .version(tonic::Request::new(VersionRequest {
                        display_config: false,
                    }))
                    .await
                    .inspect_err(|err| {
                        tracing::error!(
                            "error connecting client to forge api (url: {}), will retry: {}",
                            api_config.url,
                            err
                        );
                    })
                    .map_err(|e| ForgeTlsClientError::Connection(e.to_string()))?;

                // ok, ok
                Ok(Ok(client))
            })
            .with_config(api_config.retry_config())
            .await
            .inspect_err(|err| {
                tracing::error!(
                    "error connecting client to forge api (url: {}, attempts: {}): {}",
                    api_config.url,
                    api_config.retry_config.retries,
                    err
                );
            });

        match result {
            Ok(Ok(client)) => Ok(client),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(e),
        }
    }

    /// Builds a new Client for for the Forge API which uses a HTTPS/TLS connector
    /// and appropriate certificates for connecting to the API server.
    ///
    /// Note that calling this API will not establish any connection.
    /// The connection attempt happens lazily at the first request.
    /// Note also that if TLS certificates would not change, only a single client
    /// would be required for the whole application - since hyper already manages
    /// connection establishment internally.
    /// However using a fresh client could avoid getting a stale connection from
    /// a pool.
    pub async fn build<S: AsRef<str>>(&self, url: S) -> ForgeTlsClientResult<ForgeClientT> {
        let uri = Uri::from_str(url.as_ref()).map_err(|e| ConfigurationError::InvalidUri {
            uri_string: url.as_ref().to_string(),
            error: e,
        })?;

        let connector = self.build_https_client(url.as_ref()).await?;

        // ping interval + ping timeout should add up to less than tcp_user_timeout,
        // so that the application gets a chance to fix things before the kernel.
        let hyper_client = legacy::Client::builder(TokioExecutor::new())
            .http2_only(true)
            // Send a PING frame every this
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            // The server will have this much time to respond with a PONG
            .http2_keep_alive_timeout(Duration::from_secs(15))
            // Send PING even when no active http2 streams
            .http2_keep_alive_while_idle(true)
            // How many connections will be kept open, per host.
            // We never make more than a single connection to carbide at a time.
            .pool_max_idle_per_host(2)
            .timer(TokioTimer::new())
            .build(connector)
            .boxed_clone();

        let mut forge_client = ForgeClient::with_origin(hyper_client, uri);

        if let Some(max_decoding_message_size) = self.forge_client_config.max_decoding_message_size
        {
            forge_client = forge_client.max_decoding_message_size(max_decoding_message_size);
        }

        Ok(forge_client)
    }

    pub async fn build_https_client<S: AsRef<str>>(
        &self,
        url: S,
    ) -> ForgeHttpsClientResult<hyper_rustls::HttpsConnector<ForgeHttpConnector>> {
        let mut roots = RootCertStore::empty();
        let uri = Uri::from_str(url.as_ref()).map_err(|e| ConfigurationError::InvalidUri {
            uri_string: url.as_ref().to_string(),
            error: e,
        })?;

        // only check for the root cert if the uri we were given is actually HTTPS.  That lets tests function properly.
        if let Some(scheme) = uri.scheme()
            && scheme == &tonic::codegen::http::uri::Scheme::HTTPS
        {
            // TODO: by reading the pemfile every time, we're automatically getting hot-reload
            // TODO: -- but we could use inotify in order to make this more performant.
            match tokio::fs::read(&self.forge_client_config.root_ca_path).await {
                Ok(pem_file) => {
                    let mut cert_cursor = std::io::Cursor::new(&pem_file[..]);
                    let (_added, _ignored) = roots.add_parsable_certificates(
                        rustls_pemfile::certs(&mut cert_cursor).filter_map(|cert| cert.ok()),
                    );
                }
                Err(error) => {
                    return Err(CouldNotReadRootCa {
                        path: self.forge_client_config.root_ca_path.clone(),
                        error,
                    }
                    .into());
                }
            }
        }

        let base_config_builder = || {
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
        };

        let tls = {
            let builder = || {
                if self.forge_client_config.enforce_tls {
                    base_config_builder().with_root_certificates(roots)
                } else {
                    base_config_builder()
                        .dangerous()
                        .with_custom_certificate_verifier(std::sync::Arc::new(
                            DummyTlsVerifier::new(),
                        ))
                }
            };

            if let Some(cert_expiry) = self.forge_client_config.client_cert_expiry() {
                let start = SystemTime::now();
                let current_time = start
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");
                if current_time.as_secs() > cert_expiry.try_into().unwrap() {
                    tracing::error!(
                        "Client certificate is expired, perhaps you need to regenerate your cert?"
                    );
                    return Err(ConfigurationError::InvalidClientCert(
                        rustls::Error::InvalidCertificate(rustls::CertificateError::Expired),
                    )
                    .into());
                }
            }

            if let Some((certs, key)) = self.forge_client_config.read_client_cert() {
                builder()
                    .with_client_auth_cert(certs, key)
                    .map_err(ConfigurationError::InvalidClientCert)?
            } else {
                builder().with_no_client_auth()
            }
        };

        let forge_resolv_config =
            forge_resolver::resolver::ForgeResolveConf::with_system_resolv_conf()
                .map_err(ConfigurationError::Resolver)?;
        let forge_resolver_config = forge_resolver::resolver::into_forge_resolver_config(
            forge_resolv_config.parsed_configuration(),
        )
        .map_err(ConfigurationError::Resolver)?;

        let resolver_config = ResolverConfig::from_parts(
            forge_resolver_config.0.domain,
            forge_resolver_config.0.search_domain,
            forge_resolver_config.0.inner.into_inner(),
        );
        // Five seconds is the default, but setting anyway for documentation and future proofing
        let mut resolver_opts = ForgeResolverOpts::default().timeout(Duration::from_secs(5));
        if self.forge_client_config.use_mgmt_vrf {
            resolver_opts = resolver_opts.use_mgmt_vrf();
        }
        let resolver = ForgeResolver::with_config_and_options(resolver_config, resolver_opts);
        let mut http = ForgeHttpConnector::new_with_resolver(resolver);
        if self.forge_client_config.use_mgmt_vrf {
            http.set_interface("mgmt".to_string());
        }
        http.set_socks5_proxy(self.forge_client_config.socks_proxy.clone());
        http.enforce_http(false);

        // Wait this long for `connect` syscall to return.
        // Hyper implements this by wrapping the call in `tokio::time::timeout`.
        http.set_connect_timeout(Some(Duration::from_secs(5)));

        // Set TCP timeouts. The interactions are non-obvious, but here are the basics:
        // - An established socket with in-flight data will timeout exactly TCP_USER_TIMEOUT
        // after data is first lost.
        // - An idle socket will send its first probe when it's been idle for TCP_KEEPIDLE. If
        // the probe is not ACKed, it will timeout about TCP_USER_TIMEOUT after first data loss.
        // - This formula should be maintained: TCP_USER_TIMEOUT < TCP_KEEPIDLE + TCP_KEEPINTVL * TCP_KEEPCNT
        // where `<` means "just slightly lower than".
        //
        // The values below mean:
        // - Disconnect broken active sockets after 30s
        // - Disconnect broken idle sockets after 32s (first retry wakeup that's > tcp_user_time)
        //
        // If HTTP/2 PING (further down) is working the keepalive should never trigger, but if tokio borks the
        // kernel should unwedge the socket.
        //
        // All the details: https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/
        http.set_tcp_user_timeout(Some(Duration::from_secs(30)));
        http.set_keepalive_time(Some(Duration::from_secs(20))); // TCP_KEEPIDLE
        http.set_keepalive_interval(Some(Duration::from_secs(4)));
        http.set_keepalive_retries(Some(3)); // initial probe at 20s, then 24s, 28s and 32s

        http.set_connect_retries_max(self.forge_client_config.connect_retries_max);
        http.set_connect_retries_interval(self.forge_client_config.connect_retries_interval);

        let connector = tower::ServiceBuilder::new()
            .layer_fn(move |s| {
                let tls = tls.clone();

                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_tls_config(tls)
                    .https_or_http()
                    .enable_http2()
                    .wrap_connector(s)
            })
            .service(http);
        Ok(connector)
    }

    /// Builds a new Client for the NMX-C API which uses a HTTPS/TLS connector
    ///
    /// Note that calling this API will not establish any connection.
    /// The connection attempt happens lazily at the first request.
    /// Note also that if TLS certificates would not change, only a single client
    /// would be required for the whole application - since hyper already manages
    /// connection establishment internally.
    /// However using a fresh client could avoid getting a stale connection from
    /// a pool.
    pub async fn build_nmx_c_client<S: AsRef<str>>(
        &self,
        url: S,
    ) -> ForgeTlsClientResult<NmxCClientT> {
        let uri = Uri::from_str(url.as_ref()).map_err(|e| ConfigurationError::InvalidUri {
            uri_string: url.as_ref().to_string(),
            error: e,
        })?;
        let connector = self.build_https_client(url.as_ref()).await?;

        // ping interval + ping timeout should add up to less than tcp_user_timeout,
        // so that the application gets a chance to fix things before the kernel.
        let hyper_client = legacy::Client::builder(TokioExecutor::new())
            .http2_only(true)
            // Send a PING frame every this
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            // The server will have this much time to respond with a PONG
            .http2_keep_alive_timeout(Duration::from_secs(15))
            // Send PING even when no active http2 streams
            .http2_keep_alive_while_idle(true)
            // How many connections will be kept open, per host.
            // We never make more than a single connection to carbide at a time.
            .pool_max_idle_per_host(2)
            .timer(TokioTimer::new())
            .build(connector)
            .boxed_clone();

        let mut nmx_c_client = NmxControllerClient::with_origin(hyper_client, uri);

        if let Some(max_decoding_message_size) = self.forge_client_config.max_decoding_message_size
        {
            nmx_c_client = nmx_c_client.max_decoding_message_size(max_decoding_message_size);
        }

        Ok(nmx_c_client)
    }

    pub async fn retry_build_nmx_c(
        api_config: &ApiConfig<'a>,
    ) -> ForgeTlsClientResult<NmxCClientT> {
        // In the retrying function, if the ForgeTlsClient just fails to even build, return _that_
        // error early by putting it in the Ok(Err(e)) variant, so that tryhard doesn't keep
        // retrying a configuration error.
        let result: Result<Result<NmxCClientT, ForgeTlsClientError>, ForgeTlsClientError> =
            tryhard::retry_fn(|| async move {
                let mut client = match ForgeTlsClient::new(api_config.client_config)
                    .build_nmx_c_client(api_config.url)
                    .await
                {
                    Ok(client) => client,
                    // Don't let tryhard retry this, just push the error into the Ok variant
                    Err(e) => return Ok(Err(e)),
                };

                // The thing we actually want to retry is a test connection
                client
                    .hello(tonic::Request::new(protos::nmx_c::ClientHello {
                        gateway_id: "".to_string(),
                        major_version: i32::from(
                            protos::nmx_c::ProtoMsgMajorVersion::ProtoMsgMajorVersion,
                        ),
                        minor_version: i32::from(
                            protos::nmx_c::ProtoMsgMinorVersion::ProtoMsgMinorVersion,
                        ),
                    }))
                    .await
                    .inspect_err(|err| {
                        tracing::error!(
                            "error connecting client to forge api (url: {}), will retry: {}",
                            api_config.url,
                            err
                        );
                    })
                    .map_err(|e| ForgeTlsClientError::Connection(e.to_string()))?;

                // ok, ok
                Ok(Ok(client))
            })
            .with_config(api_config.retry_config())
            .await
            .inspect_err(|err| {
                tracing::error!(
                    "error connecting client to nmx-c api (url: {}, attempts: {}): {}",
                    api_config.url,
                    api_config.retry_config.retries,
                    err
                );
            });

        match result {
            Ok(Ok(client)) => Ok(client),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(e),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ForgeTlsClientError {
    #[error("ConnectError error: {0}")]
    Connection(String),
    #[error("Configuration error: {0}")]
    Configuration(#[from] ConfigurationError),
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigurationError {
    #[error("Invalid URI {uri_string}: {error}")]
    InvalidUri {
        uri_string: String,
        error: hyper::http::uri::InvalidUri,
    },
    #[error("Could not read Root CA cert at {path}: {error}")]
    CouldNotReadRootCa { path: String, error: io::Error },
    #[error("Invalid client cert: {0}")]
    InvalidClientCert(rustls::Error),
    #[error("Error configuring resolver: {0}")]
    Resolver(#[from] ResolverError),
}

impl From<ForgeTlsClientError> for tonic::Status {
    fn from(value: ForgeTlsClientError) -> Self {
        tonic::Status::unavailable(value.to_string())
    }
}

pub type ForgeTlsClientResult<T> = Result<T, ForgeTlsClientError>;
pub type ForgeHttpsClientResult<T> = Result<T, ForgeTlsClientError>;

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use forge_http_connector::connector::ConnectorMetrics;
    use hyper_rustls::HttpsConnector;

    use super::*;

    #[tokio::test]
    // test_max_retries builds up an instance of hyper client using
    // the ForgeHttpConnector, which is the same configuration used
    // for creating a ForgeTlsClient. In this case, it is NOT
    // used to create a ForgeTlsClient, but instead is used directly
    // to make an HTTP call (so we maintain access to the underlying
    // connector for querying retry count.
    async fn test_max_retries() {
        let max_retries = 3; // 4 total attempts

        // Set up all of the resolver config stuff
        // to pass to the ForgeHttpConnector.
        let forge_resolv_config =
            forge_resolver::resolver::ForgeResolveConf::with_system_resolv_conf().unwrap();
        let forge_resolver_config = forge_resolver::resolver::into_forge_resolver_config(
            forge_resolv_config.parsed_configuration(),
        )
        .unwrap();

        let resolver_config = ResolverConfig::from_parts(
            forge_resolver_config.0.domain,
            forge_resolver_config.0.search_domain,
            forge_resolver_config.0.inner.into_inner(),
        );

        let resolver_opts = ForgeResolverOpts::default().timeout(Duration::from_secs(5));
        let resolver = ForgeResolver::with_config_and_options(resolver_config, resolver_opts);

        // Create the ConnectorMetrics instance used for
        // collecting some stats for connections that go
        // through the ForgeHttpConnector.
        let mut metrics = ConnectorMetrics::default();

        // Now create the ForgeHttpConnector, setting our
        // test-specific `max_retries` with a 1 second interval,
        // and passing it our Connectormetrics.
        let mut http = ForgeHttpConnector::new_with_resolver(resolver);
        http.set_connect_retries_max(Some(max_retries));
        http.set_connect_retries_interval(Some(Duration::from_secs(1)));
        http.set_metrics(metrics.clone());

        // And now make our new connector, which is an
        // implementation of tower_service::Service.
        let connector = tower::ServiceBuilder::new()
            .layer_fn(move |s| {
                let tls = ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(DummyTlsVerifier::new()))
                .with_no_client_auth();

                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_tls_config(tls)
                    .https_or_http()
                    .enable_http2()
                    .wrap_connector(s)
            })
            .service(http);

        // And then create a new hyper HTTP client with the connector.
        let hyper_client: legacy::Client<HttpsConnector<ForgeHttpConnector>, Body> =
            legacy::Client::builder(TokioExecutor::new()).build(connector);

        // We're finally here. Fire off an HTTP request. Behind he scenes,
        // the ForgeHttpConnector is going to attempt to connect, fail, and
        // subsequently fire off 3 retries. This assumes you don't have
        // anything listening on :12345. If you do, this test will obviously
        // fail, because the connection will be successful. :P
        let uri = "http://localhost:12345".parse::<Uri>().unwrap();
        let _ = hyper_client.get(uri).await;

        // If you're curious to see what metrics are collected,
        // uncomment this when you run the test with --nocapture.
        // println!("{:?}", metrics.lock(unwrapped.attempts_by_addr.get).unwrap());

        // Make sure attempts, errors, and successes are all as expected.
        assert_eq!(metrics.get_total_attempts(), max_retries + 1);
        assert_eq!(metrics.get_total_errors(), max_retries + 1);
        assert_eq!(metrics.get_total_successes(), 0);

        // And make sure by_addr metrics are working as well. This
        // assumes localhost resolves to 127.0.0.1.
        let addr = SocketAddr::from_str("127.0.0.1:12345").unwrap();
        let attempts_for_addr = metrics.get_attempts_for_addr(&addr);
        let successes_for_addr = metrics.get_successes_for_addr(&addr);
        let errors_for_addr = metrics.get_errors_for_addr(&addr);

        assert!(attempts_for_addr.is_some());
        assert!(errors_for_addr.is_some());

        // This one *is* none!
        assert!(successes_for_addr.is_none());

        assert_eq!(attempts_for_addr.unwrap(), max_retries + 1);
        assert_eq!(errors_for_addr.unwrap(), max_retries + 1);
    }
}
