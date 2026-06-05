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

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{AddrParseError, IpAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::middleware::{Next, from_fn_with_state};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use bytes::Bytes;
use carbide_authn::SpiffeContext;
use carbide_authn::middleware::{
    AuthContext, Authorization, CertDescriptionMiddleware, ConnectionAttributes, Principal,
};
use carbide_utils::HostPortPair;
use forge_tls::client_config::ClientCert;
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use mac_address::{MacAddress, MacParseError};
use opentelemetry::KeyValue;
use opentelemetry::metrics::Meter;
use rpc::forge;
use rpc::forge::find_bmc_ips_request::LookupBy;
use rpc::forge_api_client::ForgeApiClient;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, rustls};
use tokio_util::sync::CancellationToken;
use tower_http::add_extension::AddExtensionLayer;

use crate::config::{AuthConfig, TlsConfig};

const TLS_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const MAX_BODY_SIZE: usize = 8 * 1024 * 1024; // 8MiB body size limit (matches nginx ingress controller defaults)

#[derive(thiserror::Error, Debug)]
pub enum BmcProxyError {
    #[error("Error resolving BMC information through Carbide API: {0}")]
    Api(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Internal error proxying request: {0}")]
    InternalProxying(String),
    #[error("No credentials found for BMC IP address: {0}")]
    NoCredentials(IpAddr),
    #[error("Error spawning listener: {0}")]
    Listen(std::io::Error),
    #[error("Error loading TLS config: {0}")]
    TlsConfig(String),
}

pub struct BmcProxyParams {
    pub config: Arc<crate::Config>,
    pub meter: Meter,
}

#[derive(Clone)]
struct BmcProxyState {
    config: Arc<crate::Config>,
    meter: Meter,
    api_client: ForgeApiClient,
    credential_cache: CredentialCache,
    client_cache: HttpClientCache,
    ip_cache: LookupToIpCache,
}

type CredentialCache = Arc<Mutex<HashMap<IpAddr, BmcCredentials>>>;
type HttpClientCache = Arc<Mutex<HashMap<IpAddr, reqwest::Client>>>;
type LookupToIpCache = Arc<Mutex<HashMap<LookupBy, IpAddr>>>;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum ForwardedTarget<'a> {
    Ip(IpAddr),
    Mac(MacAddress),
    Serial(&'a str),
}

#[derive(thiserror::Error, Debug)]
enum ForwardedHeaderParseError {
    #[error("Invalid IP in Forwarded host header: {0}")]
    Ip(#[from] AddrParseError),
    #[error("Invalid MAC address in Forwarded host header: {0}")]
    Mac(#[from] MacParseError),
}

impl BmcProxyState {
    fn allows(&self, request: &Request<Body>) -> bool {
        let Some(auth_context) = request.extensions().get::<AuthContext<()>>() else {
            tracing::error!("BUG: No AuthContext middleware found, all requests will be denied");
            return false;
        };

        let principal_ids = request_principal_ids(auth_context);
        let allowed = principal_ids.iter().any(|principal| {
            self.config
                .auth
                .acls
                .allows(principal, request.method(), request.uri().path())
        });

        if !allowed {
            tracing::info!(
                principals = ?principal_ids,
                path = request.uri().path(),
                method = request.method().as_str(),
                "Request denied by BMC proxy ACLs"
            );
        }

        allowed
    }
}

pub async fn start(
    params: BmcProxyParams,
    cancel_token: CancellationToken,
    join_set: &mut JoinSet<()>,
) -> Result<(), BmcProxyError> {
    // Destructure params to save typing
    let BmcProxyParams { config, meter } = params;

    tracing::info!(
        address = config.listen.to_string(),
        build_version = carbide_version::v!(build_version),
        build_date = carbide_version::v!(build_date),
        rust_version = carbide_version::v!(rust_version),
        "Start carbide BMC proxy",
    );

    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(BmcProxyError::Listen)?;

    let client_config = ForgeClientConfig::new(
        config.carbide_api.root_ca.clone(),
        Some(ClientCert {
            cert_path: config.carbide_api.client_cert.clone(),
            key_path: config.carbide_api.client_key.clone(),
        }),
    );
    let api_config = ApiConfig::new(config.carbide_api.api_url.as_str(), &client_config);
    let api_client = ForgeApiClient::new(&api_config);

    let state = BmcProxyState {
        config,
        api_client,
        credential_cache: Default::default(),
        client_cache: Default::default(),
        ip_cache: Default::default(),
        meter,
    };

    let app = Router::new()
        .route("/", get(root_url))
        .route("/{*path}", any(proxy_request))
        .with_state(state.clone())
        .layer(from_fn_with_state(state.clone(), authorize_proxy_request))
        .layer(cert_description_layer::<()>(&state.config.auth)?);

    let tls_acceptor = RefreshableTlsAcceptor::new(state.config.tls.clone()).await?;

    let bmc_proxy = BmcProxy {
        app,
        listener,
        state,
        tls_acceptor,
    };

    join_set
        .build_task()
        .name("bmc-proxy listener")
        .spawn(bmc_proxy.run(cancel_token))
        // Safety: will only fail if outside tokio runtime
        .expect("Error spawning bmc-proxy listener");

    Ok(())
}

#[derive(Clone)]
struct RefreshableTlsAcceptor {
    acceptor: TlsAcceptor,
    refreshed_at: Instant,
}

impl RefreshableTlsAcceptor {
    fn is_fresh(&self) -> bool {
        self.refreshed_at.elapsed() < TLS_REFRESH_INTERVAL
    }

    async fn new(config: TlsConfig) -> Result<Self, BmcProxyError> {
        tokio::task::Builder::new()
            .name("get_tls_acceptor refresh")
            .spawn_blocking(move || get_tls_acceptor(&config))
            .expect("Failed to spawn blocking task")
            .await
            .expect("task panicked")
    }
}

struct BmcProxy {
    app: Router,
    listener: TcpListener,
    state: BmcProxyState,
    tls_acceptor: RefreshableTlsAcceptor,
}

impl BmcProxy {
    async fn run(mut self, cancel_token: CancellationToken) {
        let http = auto::Builder::new(TokioExecutor::new());

        let connection_total_counter = self
            .state
            .meter
            .u64_counter("carbide-bmc-proxy.tls.connection_attempted")
            .with_description("The amount of tls connections that were attempted")
            .build();
        let connection_succeeded_counter = self
            .state
            .meter
            .u64_counter("carbide-bmc-proxy.tls.connection_success")
            .with_description("The amount of tls connections that were successful")
            .build();
        let connection_failed_counter = self
            .state
            .meter
            .u64_counter("carbide-bmc-proxy.tls.connection_fail")
            .with_description("The amount of tcp connections that were failures")
            .build();

        while let Some(incoming_connection) = cancel_token
            .run_until_cancelled(self.listener.accept())
            .await
        {
            connection_total_counter.add(1, &[]);
            let (conn, addr) = match incoming_connection {
                Ok(incoming) => incoming,
                Err(e) => {
                    tracing::error!(error = %e, "Error accepting connection");
                    connection_failed_counter
                        .add(1, &[KeyValue::new("reason", "tcp_connection_failure")]);
                    continue;
                }
            };

            let tls_acceptor = if self.tls_acceptor.is_fresh() {
                self.tls_acceptor.acceptor.clone()
            } else {
                self.tls_acceptor =
                    match RefreshableTlsAcceptor::new(self.state.config.tls.clone()).await {
                        Ok(acceptor) => acceptor,
                        Err(e) => {
                            tracing::error!("Error reloading TLS certificate, will retry: {e}");
                            connection_failed_counter
                                .add(1, &[KeyValue::new("reason", "tls_certificate_invalid")]);
                            continue;
                        }
                    };
                self.tls_acceptor.acceptor.clone()
            };

            // Spawn task to handle request
            let http = http.clone();
            let app = self.app.clone();
            let connection_succeeded_counter = connection_succeeded_counter.clone();
            let connection_failed_counter = connection_failed_counter.clone();

            tokio::task::Builder::new()
                .name("http conn handler")
                .spawn(
                    async move {
                        match tls_acceptor.accept(conn).await {
                            Ok(conn) => {
                                let conn = TokioIo::new(conn);
                                connection_succeeded_counter.add(1, &[]);

                                let (_, session) = conn.inner().get_ref();
                                let connection_attributes = {
                                    let peer_address = addr;
                                    let peer_certificates =
                                        session.peer_certificates().unwrap_or_default().to_vec();
                                    Arc::new(ConnectionAttributes {
                                        peer_address,
                                        peer_certificates,
                                    })
                                };
                                let conn_attrs_extension_layer =
                                    AddExtensionLayer::new(connection_attributes);

                                let app_with_ext = tower::ServiceBuilder::new()
                                    .layer(conn_attrs_extension_layer)
                                    .service(app);

                                if let Err(error) = http
                                    .serve_connection(conn, TowerToHyperService::new(app_with_ext))
                                    .await
                                {
                                    tracing::debug!(%error, "error servicing tls http request: {error:?}");
                                }
                            }
                            Err(error) => {
                                tracing::error!(%error, address = %addr, "error accepting tls connection");
                                connection_failed_counter
                                    .add(1, &[KeyValue::new("reason", "tls_connection_failure")]);
                            }
                        }
                    }
                )
                // Safety: This only fails if run outside the tokio runtime
                .expect("could not spawn task to handle HTTP connection");
        }

        tracing::info!("carbide-bmc-proxy shutting down");
    }
}

fn get_tls_acceptor(tls_config: &TlsConfig) -> Result<RefreshableTlsAcceptor, BmcProxyError> {
    let certs = {
        let fd = match std::fs::File::open(&tls_config.identity_pemfile_path) {
            Ok(fd) => fd,
            Err(e) => {
                return Err(BmcProxyError::TlsConfig(format!(
                    "Could not open identity PEM at {}: {}",
                    tls_config.identity_pemfile_path, e
                )));
            }
        };
        let mut buf = std::io::BufReader::new(&fd);
        rustls_pemfile::certs(&mut buf).collect::<Result<Vec<_>, _>>()
    }
    .map_err(|e| {
        BmcProxyError::TlsConfig(format!(
            "Error loading identity PEM at {}: {}",
            tls_config.identity_pemfile_path, e
        ))
    })?;

    let key = std::fs::File::open(&tls_config.identity_keyfile_path)
        .map_err(|e| {
            BmcProxyError::TlsConfig(format!(
                "Could not open key file at {}: {}",
                tls_config.identity_keyfile_path, e
            ))
        })
        .and_then(|fd| {
            let mut buf = std::io::BufReader::new(&fd);
            rustls_pemfile::ec_private_keys(&mut buf)
                .next()
                .ok_or_else(|| {
                    BmcProxyError::TlsConfig(format!(
                        "No keys found in key file at {}",
                        tls_config.identity_keyfile_path
                    ))
                })
        })?
        .map_err(|e| {
            BmcProxyError::TlsConfig(format!(
                "Error parsing key file at {}: {}",
                tls_config.identity_keyfile_path, e
            ))
        })?;

    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let roots = {
        let mut roots = RootCertStore::empty();
        let pem_file = std::fs::read(&tls_config.root_cafile_path).map_err(|e| {
            BmcProxyError::TlsConfig(format!(
                "error reading root ca cert file at {}: {}",
                tls_config.root_cafile_path, e
            ))
        })?;
        let mut cert_cursor = std::io::Cursor::new(&pem_file[..]);
        let certs_to_add = rustls_pemfile::certs(&mut cert_cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                BmcProxyError::TlsConfig(format!(
                    "error parsing root ca cert file at {}: {}",
                    tls_config.root_cafile_path, e
                ))
            })?;
        let (_added, _ignored) = roots.add_parsable_certificates(certs_to_add);

        if let Ok(pem_file) = std::fs::read(&tls_config.admin_root_cafile_path) {
            let mut cert_cursor = std::io::Cursor::new(&pem_file[..]);
            let certs_to_add = rustls_pemfile::certs(&mut cert_cursor)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    BmcProxyError::TlsConfig(format!(
                        "error parsing admin ca cert file at {}: {}",
                        tls_config.admin_root_cafile_path, error
                    ))
                })?;
            let (_added, _ignored) = roots.add_parsable_certificates(certs_to_add);
        }
        Arc::new(roots)
    };

    let client_cert_verifier =
        WebPkiClientVerifier::builder_with_provider(roots, crypto_provider.clone())
            .allow_unauthenticated()
            .allow_unknown_revocation_status()
            .build()
            .map_err(|e| {
                BmcProxyError::TlsConfig(format!(
                    "Could not build client cert verifier. Does root CA file at {} contain no root trust anchors? {}",
                    tls_config.root_cafile_path,
                    e
                ))
            })?;

    let mut tls = ServerConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(certs, rustls_pki_types::PrivateKeyDer::Sec1(key))
        .map_err(|e| {
            BmcProxyError::TlsConfig(format!("Rustls error building server config: {e}",))
        })?;

    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(tls));
    Ok(RefreshableTlsAcceptor {
        acceptor,
        refreshed_at: Instant::now(),
    })
}

pub fn cert_description_layer<AZ: Authorization>(
    auth_config: &AuthConfig,
) -> Result<CertDescriptionMiddleware<AZ>, BmcProxyError> {
    tracing::info!("TrustConfig rendered from config: {:?}", auth_config.trust);
    let spiffe_context = SpiffeContext::try_from(auth_config.trust.clone()).map_err(|e| {
        BmcProxyError::InvalidConfiguration(format!(
            "Invalid trust config in bmc-proxy config toml file: {e}"
        ))
    })?;

    Ok(CertDescriptionMiddleware::new(
        auth_config.cli_certs.clone(),
        spiffe_context,
    ))
}

async fn root_url() -> &'static str {
    const ROOT_CONTENTS: &str = if carbide_version::literal!(build_version).is_empty() {
        "Carbide BMC proxy development build\n"
    } else {
        concat!(
            "Carbide BMC proxy ",
            carbide_version::literal!(build_version),
            "\n"
        )
    };
    ROOT_CONTENTS
}

async fn proxy_request(
    State(state): State<BmcProxyState>,
    request: Request<Body>,
) -> Result<Response<Body>, Response<Body>> {
    if !state.allows(&request) {
        return Ok(error_response((StatusCode::FORBIDDEN, "Forbidden").into()));
    }
    let (parts, body) = request.into_parts();
    let forwarded_target = forwarded_header_value(&parts.headers)
        .map_err(|e| error_response((StatusCode::BAD_REQUEST, e.to_string()).into()))?
        .ok_or_else(|| {
            error_response(
                (
                    StatusCode::BAD_REQUEST,
                    "missing Forwarded host/mac/serial in request header",
                )
                    .into(),
            )
        })?;

    let target_ip = match ip_for_forwarded_target(&forwarded_target, &state).await {
        Ok(Some(ip)) => ip,
        Ok(None) => {
            return Err(error_response(
                (
                    StatusCode::BAD_REQUEST,
                    "Could not find BMC from forwarded header",
                )
                    .into(),
            ));
        }
        Err(e) => {
            return Err(error_response(
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Failure looking up BMC IP from target: {e}"),
                )
                    .into(),
            ));
        }
    };

    let path_and_query = parts
        .uri
        .into_parts()
        .path_and_query
        .ok_or_else(|| error_response((StatusCode::BAD_REQUEST, "missing path").into()))?;

    let mut bmc_client_info = create_client(
        target_ip,
        &state.api_client,
        &state.credential_cache,
        &state.client_cache,
        &state.config.bmc_proxy,
    )
    .await
    .map_err(|e| error_response((StatusCode::BAD_GATEWAY, e.to_string()).into()))?;

    copy_request_headers(&parts.headers, &mut bmc_client_info.header_map);

    let body = axum::body::to_bytes(body, MAX_BODY_SIZE)
        .await
        .map_err(|e| error_response((StatusCode::BAD_REQUEST, e.to_string()).into()))?;

    let mut upstream_uri_parts = bmc_client_info.base_upstream_uri.into_parts();
    upstream_uri_parts.path_and_query = Some(path_and_query);
    let upstream_uri = Uri::from_parts(upstream_uri_parts)
        .map_err(|e| error_response((StatusCode::BAD_REQUEST, e.to_string()).into()))?;

    let upstream_request = bmc_client_info
        .http_client
        .request(parts.method.clone(), upstream_uri.to_string())
        .headers(bmc_client_info.header_map);
    let mut upstream_request = bmc_client_info
        .credentials
        .apply_to_request(upstream_request)
        .map_err(|e| {
            error_response((StatusCode::BAD_GATEWAY, format!("invalid credentials: {e}")).into())
        })?;

    if method_supports_body(&parts.method) {
        upstream_request = upstream_request.body(body);
    }

    let upstream_response = upstream_request
        .send()
        .await
        .map_err(|e| error_response((StatusCode::BAD_GATEWAY, e.to_string()).into()))?;

    let status = upstream_response.status();
    let headers = upstream_response.headers().clone();
    let body = upstream_response
        .bytes()
        .await
        .map_err(|e| error_response((StatusCode::BAD_GATEWAY, e.to_string()).into()))?;

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        evict_cached_credentials(target_ip, &state.credential_cache).await;
    }

    Ok(build_response(status, &headers, body))
}

async fn ip_for_forwarded_target(
    forwarded_target: &ForwardedTarget<'_>,
    state: &BmcProxyState,
) -> Result<Option<IpAddr>, tonic::Status> {
    let lookup_by = match forwarded_target {
        ForwardedTarget::Ip(ip) => {
            // No need to look up
            return Ok(Some(*ip));
        }
        ForwardedTarget::Mac(mac) => LookupBy::MacAddress(mac.to_string()),
        ForwardedTarget::Serial(serial) => LookupBy::Serial(serial.to_string()),
    };

    if let Some(ip) = state.ip_cache.lock().await.get(&lookup_by) {
        return Ok(Some(*ip));
    }

    let lookup_by_str = match &lookup_by {
        LookupBy::Serial(serial) => format!("Serial number {serial}"),
        LookupBy::MacAddress(mac) => format!("MAC address {mac}"),
    };

    let ips = state
        .api_client
        .find_bmc_ips(forge::FindBmcIpsRequest {
            lookup_by: Some(lookup_by.clone()),
        })
        .await?
        .bmc_ips
        .iter()
        .filter_map(|s| {
            IpAddr::from_str(s)
                .inspect_err(|e| tracing::error!("Invalid IP address returned by API: {e}"))
                .ok()
        })
        .collect::<Vec<_>>();

    if ips.is_empty() {
        return Ok(None);
    }

    let (v4_ips, v6_ips): (Vec<IpAddr>, Vec<IpAddr>) = ips.into_iter().partition(|ip| ip.is_ipv4());

    let ip = match (v4_ips.len(), v6_ips.len()) {
        (0, 1..) => {
            if v6_ips.len() > 1 {
                tracing::warn!(
                    "Multiple IPv6 BMC IP's found for {} ({}), using first one",
                    lookup_by_str,
                    v6_ips
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            v6_ips.into_iter().next()
        }
        _ => {
            // TODO: We may want to be smart about when to pick IPv6 vs IPv4, but for now just pick IPv4
            // first, in case of broken dual-stack setups.
            if v4_ips.len() > 1 {
                tracing::warn!(
                    "Multiple IPv4 BMC IP's found for {} ({}), using first one",
                    lookup_by_str,
                    v4_ips
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            v4_ips.into_iter().next()
        }
    };

    if let Some(ip) = ip {
        state.ip_cache.lock().await.insert(lookup_by, ip);
    }
    Ok(ip)
}

async fn authorize_proxy_request(
    State(state): State<BmcProxyState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let auth_context = request
        .extensions()
        .get::<AuthContext<()>>()
        .ok_or_else(|| {
            tracing::warn!(
                "authorize_proxy_request found a request with no AuthContext in its extensions"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let present_principals = request_principal_ids(auth_context);

    let allowed = present_principals
        .iter()
        .any(|principal| state.config.allowed_principals.contains(principal));

    if allowed {
        Ok(next.run(request).await)
    } else {
        tracing::info!(
            allowed_principals = ?state.config.allowed_principals,
            present_principals = ?present_principals,
            path = request.uri().path(),
            "Request denied by BMC proxy principal allow-list"
        );
        Err(StatusCode::FORBIDDEN)
    }
}

fn request_principal_ids(auth_context: &AuthContext<()>) -> Vec<String> {
    let mut principals = auth_context
        .principals
        .iter()
        .map(Principal::as_identifier)
        .collect::<Vec<_>>();
    principals.push(Principal::Anonymous.as_identifier());
    principals
}

fn build_response(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    body: Bytes,
) -> Response<Body> {
    let mut response = Response::builder().status(status);
    for (name, value) in headers {
        if is_hop_by_hop_header(name.as_str()) || name == reqwest::header::CONTENT_LENGTH {
            continue;
        }
        response = response.header(name, value);
    }
    response.body(Body::from(body)).unwrap()
}

fn copy_request_headers(source: &HeaderMap, dest: &mut HeaderMap) {
    for (name, value) in source {
        if is_hop_by_hop_header(name.as_str())
            || *name == axum::http::header::HOST
            || *name == axum::http::header::AUTHORIZATION
            || name.as_str().eq_ignore_ascii_case("forwarded")
            || *name == axum::http::header::CONTENT_LENGTH
        {
            continue;
        }
        dest.append(name.clone(), value.clone());
    }
}

fn method_supports_body(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD)
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn forwarded_header_value(
    headers: &HeaderMap,
) -> Result<Option<ForwardedTarget<'_>>, ForwardedHeaderParseError> {
    let values = headers.get_all("forwarded");
    for raw_value in values {
        let Ok(raw_value) = raw_value.to_str() else {
            continue;
        };
        for element in raw_value.split(',') {
            for pair in element.split(';') {
                let Some((key, value)) = pair.trim().split_once('=') else {
                    continue;
                };
                let key = key.trim();
                if key.eq_ignore_ascii_case("host") {
                    return Ok(Some(ForwardedTarget::Ip(parse_forwarded_host_value(
                        value.trim(),
                    )?)));
                } else if key.eq_ignore_ascii_case("mac") {
                    return Ok(Some(ForwardedTarget::Mac(MacAddress::from_str(
                        value.trim(),
                    )?)));
                } else if key.eq_ignore_ascii_case("serial") {
                    return Ok(Some(ForwardedTarget::Serial(value.trim())));
                }
            }
        }
    }
    Ok(None)
}

fn parse_forwarded_host_value(value: &str) -> Result<IpAddr, AddrParseError> {
    let value = value.trim_matches('"');

    let result = IpAddr::from_str(value);
    if let Ok(ip) = result {
        return Ok(ip);
    }

    // If it failed to parse, maybe it's a bracked ipv6 address, support that
    if let Some(rest) = value.strip_prefix('[')
        && let Some((host, _)) = rest.split_once(']')
    {
        IpAddr::from_str(host)
    } else {
        // Nope, just return the failure
        result
    }
}

fn error_response(error: ProxyError) -> Response<Body> {
    (error.status, error.message).into_response()
}

struct ProxyError {
    status: StatusCode,
    message: String,
}

impl From<(StatusCode, String)> for ProxyError {
    fn from((status, message): (StatusCode, String)) -> Self {
        Self { status, message }
    }
}

impl From<(StatusCode, &'static str)> for ProxyError {
    fn from((status, message): (StatusCode, &'static str)) -> Self {
        Self {
            status,
            message: message.to_string(),
        }
    }
}

struct BmcClientInfo {
    pub http_client: reqwest::Client,
    pub header_map: HeaderMap,
    pub credentials: BmcCredentials,
    pub base_upstream_uri: Uri,
}

#[derive(Clone, PartialEq, Eq)]
enum BmcCredentials {
    UsernamePassword { username: String, password: String },
    SessionToken { token: String },
}

impl BmcCredentials {
    fn apply_to_request(
        self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, http::header::InvalidHeaderValue> {
        match self {
            Self::UsernamePassword { username, password } => {
                Ok(request.basic_auth(username, Some(password)))
            }
            Self::SessionToken { token } => {
                Ok(request.header("X-Auth-Token", http::HeaderValue::from_str(&token)?))
            }
        }
    }
}

impl TryFrom<forge::BmcCredentials> for BmcCredentials {
    type Error = BmcProxyError;

    fn try_from(value: forge::BmcCredentials) -> Result<Self, Self::Error> {
        match value.r#type {
            Some(forge::bmc_credentials::Type::UsernamePassword(value)) => {
                Ok(Self::UsernamePassword {
                    username: value.username,
                    password: value.password,
                })
            }
            Some(forge::bmc_credentials::Type::SessionToken(value)) => {
                Ok(Self::SessionToken { token: value.token })
            }
            None => Err(BmcProxyError::Api(
                "missing credential type in API response".to_string(),
            )),
        }
    }
}

async fn create_client(
    ip: IpAddr,
    api_client: &ForgeApiClient,
    credential_cache: &CredentialCache,
    client_cache: &HttpClientCache,
    bmc_proxy: &Option<HostPortPair>,
) -> Result<BmcClientInfo, BmcProxyError> {
    let (host, port, add_custom_header) = match bmc_proxy {
        // No override
        None => (Cow::<str>::Owned(ip.to_string()), None, false),
        // Override the host and port
        Some(HostPortPair::HostAndPort(h, p)) => (Cow::Borrowed(h.as_str()), Some(*p), true),
        // Only override the host
        Some(HostPortPair::HostOnly(h)) => (Cow::Borrowed(h.as_str()), None, true),
        // Only override the port
        Some(HostPortPair::PortOnly(p)) => (Cow::Owned(ip.to_string()), Some(*p), false),
    };
    let mut header_map = HeaderMap::new();
    if add_custom_header {
        header_map.insert("forwarded", format!("host={ip}").parse().unwrap());
    }
    let http_client = get_http_client(ip, client_cache).await?;

    let credentials = get_bmc_credentials(ip, api_client, credential_cache).await?;

    let base_authority = match (host, port) {
        (host, Some(port)) => Cow::Owned(format!("{}:{}", host, port)),
        (host, None) => host,
    };

    let base_upstream_uri = Uri::builder()
        .scheme("https")
        .authority(base_authority.as_ref())
        .path_and_query("/")
        .build()
        .map_err(|e| {
            BmcProxyError::InternalProxying(format!("Error building upstream URI: {e}"))
        })?;

    Ok(BmcClientInfo {
        http_client,
        header_map,
        credentials,
        base_upstream_uri,
    })
}

async fn get_bmc_credentials(
    ip: IpAddr,
    api_client: &ForgeApiClient,
    credential_cache: &CredentialCache,
) -> Result<BmcCredentials, BmcProxyError> {
    if let Some(credentials) = credential_cache.lock().await.get(&ip).cloned() {
        tracing::debug!(%ip, "Using cached BMC credentials");
        return Ok(credentials);
    }

    tracing::debug!(%ip, "Fetching BMC credentials from Carbide API");
    let bmc_mac_address = api_client
        .find_mac_address_by_bmc_ip(forge::BmcIp {
            bmc_ip: ip.to_string(),
        })
        .await
        .map_err(|e| BmcProxyError::Api(e.to_string()))?
        .mac_address;

    let credentials: BmcCredentials = api_client
        .get_bmc_credentials(forge::GetBmcCredentialsRequest {
            mac_addr: bmc_mac_address,
        })
        .await
        .map_err(|e| BmcProxyError::Api(e.to_string()))?
        .credentials
        .ok_or(BmcProxyError::NoCredentials(ip))?
        .try_into()?;

    credential_cache
        .lock()
        .await
        .insert(ip, credentials.clone());
    Ok(credentials)
}

fn build_http_client() -> Result<reqwest::Client, BmcProxyError> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .connect_timeout(std::time::Duration::from_secs(5)) // Limit connections to 5 seconds
        .timeout(std::time::Duration::from_secs(60)) // Limit the overall request to 60 seconds
        .pool_max_idle_per_host(4)
        .build()
        .map_err(|err| {
            tracing::error!(%err, "build_http_client");
            BmcProxyError::InternalProxying(format!("Http building failed: {err}"))
        })
}

async fn get_http_client(
    ip: IpAddr,
    client_cache: &HttpClientCache,
) -> Result<reqwest::Client, BmcProxyError> {
    let mut client_cache = client_cache.lock().await;
    if let Some(client) = client_cache.get(&ip) {
        tracing::debug!(%ip, "Using cached BMC HTTP client");
        return Ok(client.clone());
    }

    tracing::debug!(%ip, "Creating cached BMC HTTP client");
    let client = build_http_client()?;
    client_cache.insert(ip, client.clone());
    Ok(client)
}

async fn evict_cached_credentials(ip: IpAddr, credential_cache: &CredentialCache) {
    if credential_cache.lock().await.remove(&ip).is_some() {
        tracing::info!(%ip, "Evicted cached BMC credentials after upstream auth failure");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::Arc;

    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use mac_address::MacAddress;
    use opentelemetry::global;
    use rpc::forge::find_bmc_ips_request::LookupBy;
    use rpc::forge_api_client::ForgeApiClient;
    use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
    use tokio::sync::Mutex;

    use super::{
        BmcCredentials, BmcProxyState, CredentialCache, ForwardedTarget, evict_cached_credentials,
        forwarded_header_value, ip_for_forwarded_target, parse_forwarded_host_value,
    };

    fn test_state_with_ip_cache(ip_cache: HashMap<LookupBy, IpAddr>) -> BmcProxyState {
        let client_config = ForgeClientConfig::default();
        let api_config = ApiConfig::new("https://example.com", &client_config);

        BmcProxyState {
            config: Arc::new(
                crate::Config::parse(
                    r#"
                        [tls]
                        identity_pemfile_path = ""
                        identity_keyfile_path = ""
                        root_cafile_path = ""
                        admin_root_cafile_path = ""

                        [auth]
                    "#,
                )
                .expect("test config should parse"),
            ),
            meter: global::meter("carbide-bmc-proxy-test"),
            api_client: ForgeApiClient::new(&api_config),
            credential_cache: Default::default(),
            client_cache: Default::default(),
            ip_cache: Arc::new(Mutex::new(ip_cache)),
        }
    }

    #[test]
    fn parses_forwarded_ipv4() {
        assert_eq!(
            parse_forwarded_host_value("10.0.0.5").unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[test]
    fn parses_forwarded_ipv6_with_port() {
        assert_eq!(
            parse_forwarded_host_value("\"[2001:db8::1]:443\"").unwrap(),
            IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap())
        );
    }

    #[test]
    fn finds_forwarded_host_among_parameters() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("forwarded"),
            HeaderValue::from_static("proto=https;host=10.1.2.3;for=10.0.0.1"),
        );
        assert_eq!(
            forwarded_header_value(&headers).unwrap().unwrap(),
            ForwardedTarget::Ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
        );
    }

    #[test]
    fn finds_forwarded_mac_target() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("forwarded"),
            HeaderValue::from_static("proto=https;mac=00:11:22:33:44:55;for=10.0.0.1"),
        );

        assert_eq!(
            forwarded_header_value(&headers).unwrap().unwrap(),
            ForwardedTarget::Mac(MacAddress::from_str("00:11:22:33:44:55").unwrap()),
        );
    }

    #[test]
    fn finds_forwarded_serial_target() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("forwarded"),
            HeaderValue::from_static("proto=https; serial = DGX-A100-0001 ; for=10.0.0.1"),
        );

        assert_eq!(
            forwarded_header_value(&headers).unwrap().unwrap(),
            ForwardedTarget::Serial("DGX-A100-0001"),
        );
    }

    #[test]
    fn rejects_invalid_forwarded_mac_target() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("forwarded"),
            HeaderValue::from_static("mac=not-a-mac-address"),
        );

        assert!(matches!(
            forwarded_header_value(&headers),
            Err(super::ForwardedHeaderParseError::Mac(_))
        ));
    }

    #[tokio::test]
    async fn forwarded_ip_target_resolves_without_lookup() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let state = test_state_with_ip_cache(HashMap::new());

        assert_eq!(
            ip_for_forwarded_target(&ForwardedTarget::Ip(ip), &state)
                .await
                .unwrap(),
            Some(ip)
        );
    }

    #[tokio::test]
    async fn forwarded_mac_target_resolves_from_ip_cache() {
        let mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let state =
            test_state_with_ip_cache(HashMap::from([(LookupBy::MacAddress(mac.to_string()), ip)]));

        assert_eq!(
            ip_for_forwarded_target(&ForwardedTarget::Mac(mac), &state)
                .await
                .unwrap(),
            Some(ip)
        );
    }

    #[tokio::test]
    async fn forwarded_serial_target_resolves_from_ip_cache() {
        let serial = "DGX-A100-0001";
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let state =
            test_state_with_ip_cache(HashMap::from([(LookupBy::Serial(serial.to_string()), ip)]));

        assert_eq!(
            ip_for_forwarded_target(&ForwardedTarget::Serial(serial), &state)
                .await
                .unwrap(),
            Some(ip)
        );
    }

    #[test]
    fn bmc_username_password_credentials_use_basic_auth() {
        let request = reqwest::Client::new().get("https://example.com/redfish/v1");
        let request = BmcCredentials::UsernamePassword {
            username: "admin".to_string(),
            password: "secret".to_string(),
        }
        .apply_to_request(request)
        .expect("credentials should apply")
        .build()
        .expect("request should build");

        let auth = request
            .headers()
            .get(http::header::AUTHORIZATION)
            .expect("authorization header should be present");
        assert!(auth.to_str().unwrap().starts_with("Basic "));
    }

    #[test]
    fn bmc_session_token_credentials_use_redfish_token_header() {
        let request = reqwest::Client::new().get("https://example.com/redfish/v1");
        let request = BmcCredentials::SessionToken {
            token: "token-123".to_string(),
        }
        .apply_to_request(request)
        .expect("credentials should apply")
        .build()
        .expect("request should build");

        assert_eq!(request.headers().get("X-Auth-Token").unwrap(), "token-123");
    }

    #[tokio::test]
    async fn evict_cached_credentials_removes_entry_for_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let credential_cache: CredentialCache = Arc::new(Mutex::new(HashMap::new()));
        credential_cache.lock().await.insert(
            ip,
            BmcCredentials::UsernamePassword {
                username: "admin".to_string(),
                password: "secret".to_string(),
            },
        );

        evict_cached_credentials(ip, &credential_cache).await;

        assert!(!credential_cache.lock().await.contains_key(&ip));
    }
}
