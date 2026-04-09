use std::borrow::Cow;
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
use carbide_spiffe::SpiffeContext;
use carbide_spiffe::middleware::{
    AuthContext, CertDescriptionMiddleware, ConnectionAttributes, Principal,
};
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialManager, CredentialReader, Credentials,
};
use forge_secrets::{CredentialConfig, create_credential_manager};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper::server::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Meter;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, rustls};
use tokio_util::sync::CancellationToken;
use tower_http::add_extension::AddExtensionLayer;
use utils::HostPortPair;

use crate::config::{AuthConfig, TlsConfig};

#[derive(thiserror::Error, Debug)]
pub enum BmcProxyError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Error creating credential manager: {0}")]
    CredentialManager(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Internal error proxying request: {0}")]
    InternalProxying(String),
    #[error("Unknown BMC IP address: {0}")]
    UnknownBmcIp(IpAddr),
    #[error("No credentials found for BMC IP address: {0}")]
    NoCredentials(IpAddr),
    #[error("Error spawning listener: {0}")]
    Listen(std::io::Error),
    #[error("Error loading TLS config: {0}")]
    TlsConfig(String),
}

pub struct BmcProxyParams {
    pub config: Arc<crate::Config>,
    pub credential_config: CredentialConfig,
    pub meter: Meter,
    pub pg_pool: PgPool,
}

#[derive(Clone)]
struct BmcProxyState {
    config: Arc<crate::Config>,
    meter: Meter,
    pg_pool: PgPool,
    credential_manager: Arc<dyn CredentialManager>,
}

pub async fn start(
    params: BmcProxyParams,
    cancel_token: CancellationToken,
    join_set: &mut JoinSet<()>,
) -> Result<(), BmcProxyError> {
    // Destructure params to save typing
    let BmcProxyParams {
        config,
        credential_config,
        meter,
        pg_pool,
    } = params;

    tracing::info!(
        address = config.listen.to_string(),
        build_version = carbide_version::v!(build_version),
        build_date = carbide_version::v!(build_date),
        rust_version = carbide_version::v!(rust_version),
        "Start carbide-api BMC proxy",
    );

    let credential_manager = create_credential_manager(&credential_config, meter.clone())
        .await
        .map_err(|e| BmcProxyError::CredentialManager(e.to_string()))?;

    let proxy_state = BmcProxyState {
        config,
        pg_pool,
        credential_manager,
        meter,
    };

    join_set
        .build_task()
        .name("bmc-proxy listener")
        .spawn(async move {
            run(proxy_state, cancel_token)
                .await
                // Safety: If this errors out, we want to crash
                .expect("Error running bmc-proxy listener");
        })
        // Safety: will only fail if outside tokio runtime
        .expect("Error spawning bmc-proxy listener");

    Ok(())
}

#[derive(Clone)]
struct TlsAcceptorWithTimestamp {
    acceptor: TlsAcceptor,
    refreshed_at: Instant,
}

async fn run(state: BmcProxyState, cancel_token: CancellationToken) -> Result<(), BmcProxyError> {
    let app = Router::new()
        .route("/", get(root_url))
        .route("/{*path}", any(proxy_request))
        .with_state(state.clone())
        .layer(from_fn_with_state(state.clone(), authorize_proxy_request))
        .layer(cert_description_layer::<()>(&state.config.auth)?);

    let listener = TcpListener::bind(state.config.listen)
        .await
        .map_err(BmcProxyError::Listen)?;
    let http = http2::Builder::new(TokioExecutor::new());

    let connection_total_counter = state
        .meter
        .u64_counter("carbide-api.tls.connection_attempted")
        .with_description("The amount of tls connections that were attempted")
        .build();
    let connection_succeeded_counter = state
        .meter
        .u64_counter("carbide-api.tls.connection_success")
        .with_description("The amount of tls connections that were successful")
        .build();
    let connection_failed_counter = state
        .meter
        .u64_counter("carbide-api.tls.connection_fail")
        .with_description("The amount of tcp connections that were failures")
        .build();

    let mut tls_acceptor_with_timestamp: Option<TlsAcceptorWithTimestamp> = None;
    let tls_refresh_interval = Duration::from_secs(5 * 60);

    while let Some(incoming_connection) = cancel_token.run_until_cancelled(listener.accept()).await
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

        let tls_acceptor = match tls_acceptor_with_timestamp.as_mut() {
            Some(tls_acceptor) if tls_acceptor.refreshed_at.elapsed() < tls_refresh_interval => {
                tls_acceptor.clone()
            }
            _ => {
                tracing::info!("Refreshing certs");
                let acceptor = tokio::task::Builder::new()
                    .name("get_tls_acceptor refresh")
                    .spawn_blocking({
                        let config = state.config.clone();
                        move || get_tls_acceptor(&config.tls)
                    })
                    .expect("Failed to spawn blocking task")
                    .await
                    .expect("task panicked")?;

                tls_acceptor_with_timestamp
                    .insert(TlsAcceptorWithTimestamp {
                        acceptor,
                        refreshed_at: Instant::now(),
                    })
                    .clone()
            }
        };

        let http = http.clone();
        let app = app.clone();
        let connection_succeeded_counter = connection_succeeded_counter.clone();
        let connection_failed_counter = connection_failed_counter.clone();

        tokio::task::Builder::new()
            .name("http conn handler")
            .spawn(async move {
                match tls_acceptor.acceptor.accept(conn).await {
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
            })
            .expect("could not spawn task to handle HTTP connection");
    }

    tracing::info!("carbide-bmc-proxy shutting down");

    Ok(())
}

fn get_tls_acceptor(tls_config: &TlsConfig) -> Result<TlsAcceptor, BmcProxyError> {
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

    tls.alpn_protocols = vec![b"h2".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(tls)))
}

pub fn cert_description_layer<T: Clone>(
    auth_config: &AuthConfig,
) -> Result<CertDescriptionMiddleware<T>, BmcProxyError> {
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
    let (parts, body) = request.into_parts();
    let target_ip = forwarded_host_ip(&parts.headers)
        .ok_or_else(|| {
            error_response(
                (
                    StatusCode::BAD_REQUEST,
                    "missing Forwarded host in request header",
                )
                    .into(),
            )
        })?
        .map_err(|e| error_response((StatusCode::BAD_REQUEST, e.to_string()).into()))?;

    let path_and_query = parts
        .uri
        .into_parts()
        .path_and_query
        .ok_or_else(|| error_response((StatusCode::BAD_REQUEST, "missing path").into()))?;

    let mut bmc_client_info = create_client(
        target_ip,
        state.credential_manager.as_ref(),
        &state.pg_pool,
        &state.config.bmc_proxy,
    )
    .await
    .map_err(|e| error_response((StatusCode::BAD_GATEWAY, e.to_string()).into()))?;

    copy_request_headers(&parts.headers, &mut bmc_client_info.header_map);

    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| error_response((StatusCode::BAD_REQUEST, e.to_string()).into()))?;

    let Credentials::UsernamePassword { username, password } = bmc_client_info.credentials;

    let mut upstream_uri_parts = bmc_client_info.base_upstream_uri.into_parts();
    upstream_uri_parts.path_and_query = Some(path_and_query);
    let upstream_uri = Uri::from_parts(upstream_uri_parts)
        .map_err(|e| error_response((StatusCode::BAD_REQUEST, e.to_string()).into()))?;

    let mut upstream_request = bmc_client_info
        .http_client
        .request(parts.method.clone(), upstream_uri.to_string())
        .basic_auth(username, Some(password))
        .headers(bmc_client_info.header_map);

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

    Ok(build_response(status, &headers, body))
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

    let mut present_principals = auth_context
        .principals
        .iter()
        .map(Principal::as_identifier)
        .collect::<Vec<_>>();
    present_principals.push(Principal::Anonymous.as_identifier());

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

fn forwarded_host_ip(headers: &HeaderMap) -> Option<Result<IpAddr, AddrParseError>> {
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
                if !key.trim().eq_ignore_ascii_case("host") {
                    continue;
                }
                return parse_forwarded_host_value(value.trim());
            }
        }
    }
    None
}

fn parse_forwarded_host_value(value: &str) -> Option<Result<IpAddr, AddrParseError>> {
    let value = value.trim_matches('"');

    if let Ok(ip) = IpAddr::from_str(value) {
        return Some(Ok(ip));
    }

    if let Some(rest) = value.strip_prefix('[')
        && let Some((host, _)) = rest.split_once(']')
    {
        return Some(IpAddr::from_str(host));
    }

    if let Some((host, _port)) = value.rsplit_once(':')
        && let Ok(ip) = IpAddr::from_str(host)
    {
        return Some(Ok(ip));
    }

    None
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
    pub credentials: Credentials,
    pub base_upstream_uri: Uri,
}

async fn create_client(
    ip: IpAddr,
    credential_reader: &dyn CredentialReader,
    pg_pool: &PgPool,
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
    };
    let http_client = {
        let builder = reqwest::Client::builder();
        let builder = builder
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .connect_timeout(std::time::Duration::from_secs(5)) // Limit connections to 5 seconds
            .timeout(std::time::Duration::from_secs(60)); // Limit the overall request to 60 seconds

        match builder.build() {
            Ok(client) => client,
            Err(err) => {
                tracing::error!(%err, "build_http_client");
                return Err(BmcProxyError::InternalProxying(format!(
                    "Http building failed: {err}"
                )));
            }
        }
    };

    let bmc_mac_address = db::machine_interface::find_by_ip(pg_pool, ip)
        .await
        .map_err(|e| BmcProxyError::InternalProxying(format!("Database error: {e}")))?
        .ok_or_else(|| BmcProxyError::UnknownBmcIp(ip))?
        .mac_address;

    let credentials = credential_reader
        .get_credentials(&CredentialKey::BmcCredentials {
            credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
        })
        .await
        .map_err(|e| BmcProxyError::InternalProxying(format!("Error fetching credentials: {e}")))?
        .ok_or_else(|| BmcProxyError::NoCredentials(ip))?;

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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    use super::{forwarded_host_ip, parse_forwarded_host_value};

    #[test]
    fn parses_forwarded_ipv4() {
        assert_eq!(
            parse_forwarded_host_value("10.0.0.5").unwrap().unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[test]
    fn parses_forwarded_ipv6_with_port() {
        assert_eq!(
            parse_forwarded_host_value("\"[2001:db8::1]:443\"")
                .unwrap()
                .unwrap(),
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
            forwarded_host_ip(&headers).unwrap().unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))
        );
    }
}
