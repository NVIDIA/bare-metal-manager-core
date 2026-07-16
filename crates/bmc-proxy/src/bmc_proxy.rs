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
use carbide_authn::SpiffeContext;
use carbide_authn::middleware::{
    AuthContext, Authorization, CertDescriptionMiddleware, ConnectionAttributes, Principal,
};
use carbide_instrument::{Event, LabelValue, emit};
use carbide_utils::HostPortPair;
use forge_tls::client_config::ClientCert;
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use mac_address::{MacAddress, MacParseError};
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
use crate::metrics::{MethodLabel, UpstreamRequestCompleted, UpstreamStatus};

const TLS_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const MAX_BODY_SIZE: usize = 8 * 1024 * 1024; // 8MiB body size limit (matches nginx ingress controller defaults)

#[derive(thiserror::Error, Debug)]
pub enum BmcProxyError {
    #[error("error resolving BMC information through carbide API: {0}")]
    Api(String),
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("internal error proxying request: {0}")]
    InternalProxying(String),
    #[error("no credentials found for BMC IP address: {0}")]
    NoCredentials(IpAddr),
    #[error("error spawning listener: {0}")]
    Listen(std::io::Error),
    #[error("error loading TLS config: {0}")]
    TlsConfig(String),
}

pub struct BmcProxyParams {
    pub config: Arc<crate::Config>,
}

#[derive(Clone)]
struct BmcProxyState {
    config: Arc<crate::Config>,
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
    #[error("invalid IP in forwarded host header: {0}")]
    Ip(#[from] AddrParseError),
    #[error("invalid MAC address in forwarded host header: {0}")]
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
    let BmcProxyParams { config } = params;

    tracing::info!(
        listen_address = config.listen.to_string(),
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

/// An inbound connection was accepted from the listener, before it is served.
/// Counted, never logged.
#[derive(Event)]
#[event(
    name = "carbide_bmc_proxy_tls_connection_attempted_total",
    component = "nico-bmc-proxy",
    log = off,
    metric = counter,
    describe = "Number of inbound TLS connection attempts"
)]
struct TlsConnectionAttempted;

/// The TLS handshake completed and the connection was handed to the HTTP
/// stack. Counted, never logged.
#[derive(Event)]
#[event(
    name = "carbide_bmc_proxy_tls_connection_success_total",
    component = "nico-bmc-proxy",
    log = off,
    metric = counter,
    describe = "Number of successful TLS connections"
)]
struct TlsConnectionSucceeded;

/// Why an inbound connection failed, as the bounded `reason` label. The
/// rendered strings are the metric's contract: each variant renders to the
/// snake_case value the counter has always reported, byte for byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
enum ConnectionFailReason {
    /// The TCP accept itself errored.
    TcpConnectionFailure,
    /// The TLS acceptor could not be reloaded from disk.
    TlsCertificateInvalid,
    /// The TLS handshake errored.
    TlsConnectionFailure,
}

/// An inbound connection failed before it could be served -- the TCP accept
/// errored, the TLS acceptor could not be reloaded, or the TLS handshake
/// errored. Metric-only: the `tracing::error!` beside each emit remains the log;
/// the `reason` label distinguishes which leg failed.
#[derive(Event)]
#[event(
    name = "carbide_bmc_proxy_tls_connection_fail_total",
    component = "nico-bmc-proxy",
    log = off,
    metric = counter,
    describe = "Number of failed inbound TCP connections"
)]
struct TlsConnectionFailed {
    #[label]
    reason: ConnectionFailReason,
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

        while let Some(incoming_connection) = cancel_token
            .run_until_cancelled(self.listener.accept())
            .await
        {
            emit(TlsConnectionAttempted);
            let (conn, addr) = match incoming_connection {
                Ok(incoming) => incoming,
                Err(e) => {
                    tracing::error!(error = %e, "Error accepting connection");
                    emit(TlsConnectionFailed {
                        reason: ConnectionFailReason::TcpConnectionFailure,
                    });
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
                            tracing::error!(
                                error = %e,
                                "Error reloading TLS certificate, will retry",
                            );
                            emit(TlsConnectionFailed {
                                reason: ConnectionFailReason::TlsCertificateInvalid,
                            });
                            continue;
                        }
                    };
                self.tls_acceptor.acceptor.clone()
            };

            // Spawn task to handle request
            let http = http.clone();
            let app = self.app.clone();

            tokio::task::Builder::new()
                .name("http conn handler")
                .spawn(async move {
                    match tls_acceptor.accept(conn).await {
                        Ok(conn) => {
                            let conn = TokioIo::new(conn);
                            emit(TlsConnectionSucceeded);

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
                                tracing::debug!(
                                    %error,
                                    error_debug = ?error,
                                    "error servicing tls http request",
                                );
                            }
                        }
                        Err(error) => {
                            tracing::error!(
                                %error,
                                peer_address = %addr,
                                "error accepting tls connection"
                            );
                            emit(TlsConnectionFailed {
                                reason: ConnectionFailReason::TlsConnectionFailure,
                            });
                        }
                    }
                })
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
    tracing::info!(trust_config = ?auth_config.trust, "TrustConfig rendered from config");
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

    let started = Instant::now();
    let upstream_result = upstream_request.send().await;
    emit(UpstreamRequestCompleted {
        method: MethodLabel::from(&parts.method),
        status: UpstreamStatus::from_result(&upstream_result),
        took: started.elapsed(),
    });
    let upstream_response = upstream_result
        .map_err(|e| error_response((StatusCode::BAD_GATEWAY, e.to_string()).into()))?;

    let status = upstream_response.status();
    let headers = upstream_response.headers().clone();
    let body = Body::from_stream(upstream_response.bytes_stream());

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
                .inspect_err(|e| tracing::error!(error = %e, "Invalid IP address returned by API"))
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
                    lookup_by = %lookup_by_str,
                    ip_addresses = ?v6_ips,
                    "Multiple IPv6 BMC IP's found, using first one",
                );
            }
            v6_ips.into_iter().next()
        }
        _ => {
            // TODO: We may want to be smart about when to pick IPv6 vs IPv4, but for now just pick IPv4
            // first, in case of broken dual-stack setups.
            if v4_ips.len() > 1 {
                tracing::warn!(
                    lookup_by = %lookup_by_str,
                    ip_addresses = ?v4_ips,
                    "Multiple IPv4 BMC IP's found, using first one",
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
    body: Body,
) -> Response<Body> {
    let mut response = Response::builder().status(status);
    for (name, value) in headers {
        if is_hop_by_hop_header(name.as_str()) || name == reqwest::header::CONTENT_LENGTH {
            continue;
        }
        response = response.header(name, value);
    }
    response.body(body).unwrap()
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
    // Redfish services can accept DELETE payloads, so only the methods this
    // proxy treats as bodyless are excluded.
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
        tracing::debug!(bmc_ip_address = %ip, "Using cached BMC credentials");
        return Ok(credentials);
    }

    tracing::debug!(bmc_ip_address = %ip, "Fetching BMC credentials from Carbide API");
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
            tracing::error!(error = %err, "build_http_client");
            BmcProxyError::InternalProxying(format!("Http building failed: {err}"))
        })
}

async fn get_http_client(
    ip: IpAddr,
    client_cache: &HttpClientCache,
) -> Result<reqwest::Client, BmcProxyError> {
    let mut client_cache = client_cache.lock().await;
    if let Some(client) = client_cache.get(&ip) {
        tracing::debug!(bmc_ip_address = %ip, "Using cached BMC HTTP client");
        return Ok(client.clone());
    }

    tracing::debug!(bmc_ip_address = %ip, "Creating cached BMC HTTP client");
    let client = build_http_client()?;
    client_cache.insert(ip, client.clone());
    Ok(client)
}

async fn evict_cached_credentials(ip: IpAddr, credential_cache: &CredentialCache) {
    if credential_cache.lock().await.remove(&ip).is_some() {
        tracing::info!(bmc_ip_address = %ip, "Evicted cached BMC credentials after upstream auth failure");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
    use bytes::Bytes;
    use carbide_authn::middleware::{AuthContext, ExternalUserInfo, Principal};
    use carbide_test_support::Outcome::{Fails, Yields};
    use carbide_test_support::{Case, check_cases_async, scenarios, value_scenarios};
    use carbide_utils::HostPortPair;
    use http_body_util::BodyExt;
    use mac_address::MacAddress;
    use rpc::forge;
    use rpc::forge::find_bmc_ips_request::LookupBy;
    use rpc::forge_api_client::ForgeApiClient;
    use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
    use tokio::sync::Mutex;
    use tokio_stream::iter;

    use super::{
        BmcCredentials, BmcProxyState, CredentialCache, ForwardedTarget, build_response,
        copy_request_headers, create_client, evict_cached_credentials, forwarded_header_value,
        get_http_client, ip_for_forwarded_target, is_hop_by_hop_header, method_supports_body,
        parse_forwarded_host_value, request_principal_ids,
    };

    #[derive(Clone, Copy)]
    enum ForwardedHeaderCase {
        Missing,
        InvalidUtf8ThenHost,
        HostAmongParameters,
        HostInLaterElement,
        QuotedIpv4Host,
        Mac,
        Serial,
        InvalidHost,
        InvalidMac,
    }

    #[derive(Debug, PartialEq)]
    enum ForwardedTargetSummary {
        None,
        Ip(String),
        Mac(String),
        Serial(String),
        Error(&'static str),
    }

    #[derive(Clone, Copy)]
    enum HeaderCopyCase {
        ContentType,
        Custom,
        Host,
        Authorization,
        Forwarded,
        ContentLength,
        Connection,
        Upgrade,
    }

    #[derive(Clone, Copy)]
    enum ProxyOverrideCase {
        Direct,
        HostOnly,
        PortOnly,
        HostAndPort,
    }

    #[derive(Debug, PartialEq)]
    enum CredentialSummary {
        UsernamePassword { username: String, password: String },
        SessionToken { token: String },
    }

    #[derive(Debug, PartialEq)]
    struct ClientSummary {
        base_upstream_uri: String,
        forwarded_header: Option<String>,
        credentials: CredentialSummary,
    }

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
            api_client: ForgeApiClient::new(&api_config),
            credential_cache: Default::default(),
            client_cache: Default::default(),
            ip_cache: Arc::new(Mutex::new(ip_cache)),
        }
    }

    fn forwarded_headers(case: ForwardedHeaderCase) -> HeaderMap {
        let mut headers = HeaderMap::new();
        match case {
            ForwardedHeaderCase::Missing => {}
            ForwardedHeaderCase::InvalidUtf8ThenHost => {
                headers.append(
                    HeaderName::from_static("forwarded"),
                    HeaderValue::from_bytes(&[0xff]).expect("non-UTF8 header value"),
                );
                headers.append(
                    HeaderName::from_static("forwarded"),
                    HeaderValue::from_static("proto=https;host=10.1.2.3"),
                );
            }
            ForwardedHeaderCase::HostAmongParameters => {
                headers.insert(
                    HeaderName::from_static("forwarded"),
                    HeaderValue::from_static("proto=https;host=10.1.2.3;for=10.0.0.1"),
                );
            }
            ForwardedHeaderCase::HostInLaterElement => {
                headers.insert(
                    HeaderName::from_static("forwarded"),
                    HeaderValue::from_static("for=10.0.0.1, proto=https; host=10.2.3.4"),
                );
            }
            ForwardedHeaderCase::QuotedIpv4Host => {
                headers.insert(
                    HeaderName::from_static("forwarded"),
                    HeaderValue::from_static(r#"host="10.3.4.5""#),
                );
            }
            ForwardedHeaderCase::Mac => {
                headers.insert(
                    HeaderName::from_static("forwarded"),
                    HeaderValue::from_static("proto=https;mac=00:11:22:33:44:55;for=10.0.0.1"),
                );
            }
            ForwardedHeaderCase::Serial => {
                headers.insert(
                    HeaderName::from_static("forwarded"),
                    HeaderValue::from_static("proto=https; serial = DGX-A100-0001 ; for=10.0.0.1"),
                );
            }
            ForwardedHeaderCase::InvalidHost => {
                headers.insert(
                    HeaderName::from_static("forwarded"),
                    HeaderValue::from_static("host=not-an-ip"),
                );
            }
            ForwardedHeaderCase::InvalidMac => {
                headers.insert(
                    HeaderName::from_static("forwarded"),
                    HeaderValue::from_static("mac=not-a-mac-address"),
                );
            }
        }
        headers
    }

    fn summarize_forwarded_header(case: ForwardedHeaderCase) -> ForwardedTargetSummary {
        match forwarded_header_value(&forwarded_headers(case)) {
            Ok(Some(ForwardedTarget::Ip(ip))) => ForwardedTargetSummary::Ip(ip.to_string()),
            Ok(Some(ForwardedTarget::Mac(mac))) => ForwardedTargetSummary::Mac(mac.to_string()),
            Ok(Some(ForwardedTarget::Serial(serial))) => {
                ForwardedTargetSummary::Serial(serial.to_string())
            }
            Ok(None) => ForwardedTargetSummary::None,
            Err(super::ForwardedHeaderParseError::Ip(_)) => ForwardedTargetSummary::Error("ip"),
            Err(super::ForwardedHeaderParseError::Mac(_)) => ForwardedTargetSummary::Error("mac"),
        }
    }

    fn header_for_copy_case(case: HeaderCopyCase) -> (HeaderName, HeaderValue) {
        match case {
            HeaderCopyCase::ContentType => (
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            HeaderCopyCase::Custom => (
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_static("request-1"),
            ),
            HeaderCopyCase::Host => (
                axum::http::header::HOST,
                HeaderValue::from_static("bmc.example.com"),
            ),
            HeaderCopyCase::Authorization => (
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer secret"),
            ),
            HeaderCopyCase::Forwarded => (
                HeaderName::from_static("forwarded"),
                HeaderValue::from_static("host=10.0.0.1"),
            ),
            HeaderCopyCase::ContentLength => (
                axum::http::header::CONTENT_LENGTH,
                HeaderValue::from_static("42"),
            ),
            HeaderCopyCase::Connection => (
                axum::http::header::CONNECTION,
                HeaderValue::from_static("keep-alive"),
            ),
            HeaderCopyCase::Upgrade => (
                axum::http::header::UPGRADE,
                HeaderValue::from_static("websocket"),
            ),
        }
    }

    fn copied_header_names(case: HeaderCopyCase) -> Vec<String> {
        let (name, value) = header_for_copy_case(case);
        let mut source = HeaderMap::new();
        source.insert(name, value);
        let mut dest = HeaderMap::new();

        copy_request_headers(&source, &mut dest);

        dest.keys().map(|name| name.to_string()).collect()
    }

    fn summarize_credentials(credentials: BmcCredentials) -> CredentialSummary {
        match credentials {
            BmcCredentials::UsernamePassword { username, password } => {
                CredentialSummary::UsernamePassword { username, password }
            }
            BmcCredentials::SessionToken { token } => CredentialSummary::SessionToken { token },
        }
    }

    fn proxy_override(case: ProxyOverrideCase) -> Option<HostPortPair> {
        match case {
            ProxyOverrideCase::Direct => None,
            ProxyOverrideCase::HostOnly => Some(HostPortPair::HostOnly("proxy.local".to_string())),
            ProxyOverrideCase::PortOnly => Some(HostPortPair::PortOnly(8443)),
            ProxyOverrideCase::HostAndPort => {
                Some(HostPortPair::HostAndPort("proxy.local".to_string(), 8443))
            }
        }
    }

    async fn summarize_created_client(case: ProxyOverrideCase) -> Result<ClientSummary, String> {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        // Prepopulate the cache so this test never falls through to the real
        // ForgeApiClient path.
        let credential_cache: CredentialCache = Arc::new(Mutex::new(HashMap::from([(
            ip,
            BmcCredentials::UsernamePassword {
                username: "admin".to_string(),
                password: "secret".to_string(),
            },
        )])));
        let client_cache = Default::default();
        let client_config = ForgeClientConfig::default();
        let api_config = ApiConfig::new("https://example.com", &client_config);
        let api_client = ForgeApiClient::new(&api_config);

        create_client(
            ip,
            &api_client,
            &credential_cache,
            &client_cache,
            &proxy_override(case),
        )
        .await
        .map(|client| ClientSummary {
            base_upstream_uri: client.base_upstream_uri.to_string(),
            forwarded_header: client.header_map.get("forwarded").map(|value| {
                value
                    .to_str()
                    .expect("forwarded header is UTF-8")
                    .to_string()
            }),
            credentials: summarize_credentials(client.credentials),
        })
        .map_err(|error| error.to_string())
    }

    #[test]
    fn forwarded_host_value_parsing() {
        value_scenarios!(
            run = |value| {
                parse_forwarded_host_value(value)
                    .ok()
                    .map(|ip| ip.to_string())
            };
            "IPv4" {
                "10.0.0.5" => Some("10.0.0.5".to_string()),
            }

            "raw IPv6" {
                "2001:db8::1" => Some("2001:db8::1".to_string()),
            }

            "quoted bracketed IPv6 with port" {
                "\"[2001:db8::1]:443\"" => Some("2001:db8::1".to_string()),
            }

            "bracketed IPv6 without port" {
                "[2001:db8::2]" => Some("2001:db8::2".to_string()),
            }

            "hostname rejected" {
                "bmc.example.com" => None,
            }

            "IPv4 with port rejected" {
                "10.0.0.5:443" => None,
            }
        );
    }

    #[test]
    fn forwarded_header_targets() {
        value_scenarios!(
            run = summarize_forwarded_header;
            "missing forwarded header" {
                ForwardedHeaderCase::Missing => ForwardedTargetSummary::None,
            }

            "invalid UTF-8 value skipped" {
                ForwardedHeaderCase::InvalidUtf8ThenHost => ForwardedTargetSummary::Ip("10.1.2.3".to_string()),
            }

            "host among parameters" {
                ForwardedHeaderCase::HostAmongParameters => ForwardedTargetSummary::Ip("10.1.2.3".to_string()),
            }

            "host in later element" {
                ForwardedHeaderCase::HostInLaterElement => ForwardedTargetSummary::Ip("10.2.3.4".to_string()),
            }

            "quoted IPv4 host" {
                ForwardedHeaderCase::QuotedIpv4Host => ForwardedTargetSummary::Ip("10.3.4.5".to_string()),
            }

            "MAC target" {
                ForwardedHeaderCase::Mac => ForwardedTargetSummary::Mac("00:11:22:33:44:55".to_string()),
            }

            "serial target" {
                ForwardedHeaderCase::Serial => ForwardedTargetSummary::Serial("DGX-A100-0001".to_string()),
            }

            "invalid host" {
                ForwardedHeaderCase::InvalidHost => ForwardedTargetSummary::Error("ip"),
            }

            "invalid MAC" {
                ForwardedHeaderCase::InvalidMac => ForwardedTargetSummary::Error("mac"),
            }
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

    #[test]
    fn body_method_support() {
        value_scenarios!(
            run = |method| method_supports_body(&method);
            "GET has no upstream body" {
                Method::GET => false,
            }

            "HEAD has no upstream body" {
                Method::HEAD => false,
            }

            "POST supports body" {
                Method::POST => true,
            }

            "PUT supports body" {
                Method::PUT => true,
            }

            "PATCH supports body" {
                Method::PATCH => true,
            }

            "DELETE supports body for Redfish compatibility" {
                Method::DELETE => true,
            }
        );
    }

    #[test]
    fn hop_by_hop_header_detection() {
        value_scenarios!(
            run = is_hop_by_hop_header;
            "connection" {
                "connection" => true,
            }

            "case-insensitive keep-alive" {
                "Keep-Alive" => true,
            }

            "proxy authenticate" {
                "proxy-authenticate" => true,
            }

            "proxy authorization" {
                "proxy-authorization" => true,
            }

            "te" {
                "te" => true,
            }

            "trailer" {
                "trailer" => true,
            }

            "transfer encoding" {
                "transfer-encoding" => true,
            }

            "upgrade" {
                "upgrade" => true,
            }

            "content type is safe" {
                "content-type" => false,
            }
        );
    }

    #[test]
    fn request_header_copying_filters_proxy_owned_headers() {
        value_scenarios!(
            run = copied_header_names;
            "content type copied" {
                HeaderCopyCase::ContentType => vec!["content-type".to_string()],
            }

            "custom header copied" {
                HeaderCopyCase::Custom => vec!["x-request-id".to_string()],
            }

            "host filtered" {
                HeaderCopyCase::Host => vec![],
            }

            "authorization filtered" {
                HeaderCopyCase::Authorization => vec![],
            }

            "forwarded filtered" {
                HeaderCopyCase::Forwarded => vec![],
            }

            "content length filtered" {
                HeaderCopyCase::ContentLength => vec![],
            }

            "connection filtered" {
                HeaderCopyCase::Connection => vec![],
            }

            "upgrade filtered" {
                HeaderCopyCase::Upgrade => vec![],
            }
        );
    }

    #[test]
    fn request_principal_identifiers_include_anonymous_fallback() {
        value_scenarios!(
            run = |principals| {
                request_principal_ids(&AuthContext {
                    principals,
                    authorization: None,
                })
            };
            "no authenticated principals" {
                vec![] => vec!["anonymous".to_string()],
            }

            "service principal" {
                vec![Principal::SpiffeServiceIdentifier(
                    "forge-system/carbide-api".to_string(),
                )] => vec![
                    "spiffe-service-id/forge-system/carbide-api".to_string(),
                    "anonymous".to_string(),
                ],
            }

            "machine and external user principals" {
                vec![
                    // Machine identities currently authorize by type token;
                    // the concrete machine id is intentionally not included.
                    Principal::SpiffeMachineIdentifier("machine-1".to_string()),
                    Principal::ExternalUser(ExternalUserInfo::new(
                        Some("nvidia".to_string()),
                        "admin".to_string(),
                        Some("chet".to_string()),
                    )),
                ] => vec![
                    "spiffe-machine-id".to_string(),
                    "external-role/admin".to_string(),
                    "anonymous".to_string(),
                ],
            }
        );
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
    fn bmc_credentials_convert_from_api_response() {
        scenarios!(
            run = |credentials| {
                BmcCredentials::try_from(credentials)
                    .map(summarize_credentials)
                    .map_err(|error| error.to_string())
            };
            "username and password" {
                forge::BmcCredentials {
                    r#type: Some(forge::bmc_credentials::Type::UsernamePassword(
                        forge::UsernamePassword {
                            username: "admin".to_string(),
                            password: "secret".to_string(),
                        },
                    )),
                } => Yields(CredentialSummary::UsernamePassword {
                    username: "admin".to_string(),
                    password: "secret".to_string(),
                }),
            }

            "session token" {
                forge::BmcCredentials {
                    r#type: Some(forge::bmc_credentials::Type::SessionToken(
                        forge::SessionToken {
                            token: "token-123".to_string(),
                        },
                    )),
                } => Yields(CredentialSummary::SessionToken {
                    token: "token-123".to_string(),
                }),
            }

            "missing credential type" {
                forge::BmcCredentials { r#type: None } => Fails,
            }
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
    async fn http_clients_are_cached_per_ip() {
        let cache = Default::default();
        let first_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let second_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));

        get_http_client(first_ip, &cache)
            .await
            .expect("first client");
        get_http_client(first_ip, &cache)
            .await
            .expect("cached client");
        assert_eq!(cache.lock().await.len(), 1);

        get_http_client(second_ip, &cache)
            .await
            .expect("second client");
        assert_eq!(cache.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn client_creation_applies_proxy_overrides() {
        check_cases_async(
            [
                Case {
                    scenario: "direct BMC IP",
                    input: ProxyOverrideCase::Direct,
                    expect: Yields(ClientSummary {
                        base_upstream_uri: "https://10.0.0.5/".to_string(),
                        forwarded_header: None,
                        credentials: CredentialSummary::UsernamePassword {
                            username: "admin".to_string(),
                            password: "secret".to_string(),
                        },
                    }),
                },
                Case {
                    scenario: "proxy host only",
                    input: ProxyOverrideCase::HostOnly,
                    expect: Yields(ClientSummary {
                        base_upstream_uri: "https://proxy.local/".to_string(),
                        forwarded_header: Some("host=10.0.0.5".to_string()),
                        credentials: CredentialSummary::UsernamePassword {
                            username: "admin".to_string(),
                            password: "secret".to_string(),
                        },
                    }),
                },
                Case {
                    scenario: "proxy port only",
                    input: ProxyOverrideCase::PortOnly,
                    expect: Yields(ClientSummary {
                        base_upstream_uri: "https://10.0.0.5:8443/".to_string(),
                        forwarded_header: None,
                        credentials: CredentialSummary::UsernamePassword {
                            username: "admin".to_string(),
                            password: "secret".to_string(),
                        },
                    }),
                },
                Case {
                    scenario: "proxy host and port",
                    input: ProxyOverrideCase::HostAndPort,
                    expect: Yields(ClientSummary {
                        base_upstream_uri: "https://proxy.local:8443/".to_string(),
                        forwarded_header: Some("host=10.0.0.5".to_string()),
                        credentials: CredentialSummary::UsernamePassword {
                            username: "admin".to_string(),
                            password: "secret".to_string(),
                        },
                    }),
                },
            ],
            summarize_created_client,
        )
        .await;
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

    #[tokio::test]
    async fn build_response_keeps_safe_headers_and_streams_body() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            reqwest::header::CONTENT_LENGTH,
            HeaderValue::from_static("999"),
        );
        headers.insert(
            reqwest::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );

        let body = Body::from_stream(iter([
            Result::<Bytes, Infallible>::Ok(Bytes::from_static(br#"{"value":"#)),
            Result::<Bytes, Infallible>::Ok(Bytes::from_static(br#""ok"}"#)),
        ]));

        let response = build_response(reqwest::StatusCode::OK, &headers, body);

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .unwrap(),
            "application/json"
        );
        assert!(
            !response
                .headers()
                .contains_key(reqwest::header::CONTENT_LENGTH)
        );
        assert!(!response.headers().contains_key(reqwest::header::CONNECTION));

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from_static(br#"{"value":"ok"}"#));
    }

    /// The `reason` label values are the metric's contract: each variant
    /// renders to the exact snake_case string the fail counter has always
    /// reported. The failure path is not exercised by the metrics endpoint
    /// tests, so this is what locks those bytes.
    #[test]
    fn connection_fail_reason_renders_expected_label_values() {
        use carbide_instrument::LabelValue;
        use carbide_test_support::{Check, check_values};

        use super::ConnectionFailReason;

        check_values(
            [
                Check {
                    scenario: "tcp accept failure",
                    input: ConnectionFailReason::TcpConnectionFailure,
                    expect: "tcp_connection_failure".to_string(),
                },
                Check {
                    scenario: "tls certificate reload failure",
                    input: ConnectionFailReason::TlsCertificateInvalid,
                    expect: "tls_certificate_invalid".to_string(),
                },
                Check {
                    scenario: "tls handshake failure",
                    input: ConnectionFailReason::TlsConnectionFailure,
                    expect: "tls_connection_failure".to_string(),
                },
            ],
            |reason| reason.label_value().to_string(),
        );
    }
}
