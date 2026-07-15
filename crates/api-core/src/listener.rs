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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use ::rpc::forge as rpc;
use carbide_authn::SpiffeContext;
use carbide_authn::middleware::{CertDescriptionMiddleware, ConnectionAttributes};
use hyper::server::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use model::ConfigValidationError;
use opentelemetry::metrics::Meter;
use rustls::server::WebPkiClientVerifier;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_util::sync::CancellationToken;
use tonic_reflection::server::Builder;
use tower_http::add_extension::AddExtensionLayer;
use tower_http::auth::AsyncRequireAuthorizationLayer;
use tower_http::normalize_path::NormalizePath;

use crate::api::Api;
use crate::auth;
use crate::auth::Authorization;
use crate::cfg::file::AuthConfig;
use crate::errors::CarbideError;
use crate::logging::api_logs::LogLayer;

/// Builds the admin web UI, i.e. all the `/admin/...` HTML pages (hosts, instances,
/// IB fabrics, etc.). Given the [`Api`] service, it returns the axum router holding
/// those pages.
///
/// `None` means "don't serve the admin UI at all" -- used by the in-process test
/// servers, which only exercise the gRPC API and never load the web pages.
pub type AdminUiRoutesBuilder =
    Box<dyn FnOnce(Arc<Api>) -> eyre::Result<NormalizePath<axum::Router>> + Send>;

pub enum ApiListenMode {
    Tls(Arc<ApiTlsConfig>),
    PlaintextHttp1,
    PlaintextHttp2,
}

pub struct ApiTlsConfig {
    pub identity_pemfile_path: String,
    pub identity_keyfile_path: String,
    pub root_cafile_path: String,
    pub admin_root_cafile_path: String,
}

/// this function blocks, don't use it in a raw async context
fn get_tls_acceptor(tls_config: &ApiTlsConfig) -> Option<TlsAcceptor> {
    let certs = {
        let fd = match std::fs::File::open(&tls_config.identity_pemfile_path) {
            Ok(fd) => fd,
            Err(_) => return None,
        };
        let mut buf = std::io::BufReader::new(&fd);
        rustls_pemfile::certs(&mut buf)
            .collect::<Result<Vec<_>, _>>()
            .inspect_err(|error| {
                tracing::error!(?error, "Rustls error reading certs");
            })
            .ok()
    }?;

    let key = std::fs::File::open(&tls_config.identity_keyfile_path)
        .inspect_err(|error| tracing::error!(?error, "Error reading key"))
        .ok()
        .and_then(|fd| {
            let mut buf = std::io::BufReader::new(&fd);

            rustls_pemfile::ec_private_keys(&mut buf).next()
        })
        .and_then(|keys| {
            keys.inspect_err(|error| {
                tracing::error!(?error, "Rustls error reading key");
            })
            .ok()
        })
        .or_else(|| {
            tracing::error!("Rustls error: no keys?");
            None
        })?;

    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let roots = {
        let mut roots = RootCertStore::empty();
        match std::fs::read(&tls_config.root_cafile_path) {
            Ok(pem_file) => {
                let mut cert_cursor = std::io::Cursor::new(&pem_file[..]);
                let certs_to_add = rustls_pemfile::certs(&mut cert_cursor)
                    .collect::<Result<Vec<_>, _>>()
                    .inspect_err(|error| {
                        tracing::error!(?error, "error parsing root ca cert file");
                    })
                    .ok()?;
                let (_added, _ignored) = roots.add_parsable_certificates(certs_to_add);
            }
            Err(error) => {
                tracing::error!(?error, "error reading root ca cert file");
                return None;
            }
        }

        if let Ok(pem_file) = std::fs::read(&tls_config.admin_root_cafile_path) {
            let mut cert_cursor = std::io::Cursor::new(&pem_file[..]);
            let certs_to_add = rustls_pemfile::certs(&mut cert_cursor)
                .collect::<Result<Vec<_>, _>>()
                .inspect_err(|error| {
                    tracing::error!(?error, "error parsing admin ca cert file");
                })
                .ok()?;
            let (_added, _ignored) = roots.add_parsable_certificates(certs_to_add);
        }
        Arc::new(roots)
    };

    let client_cert_verifier =
        WebPkiClientVerifier::builder_with_provider(roots, crypto_provider.clone())
            .allow_unauthenticated()
            .allow_unknown_revocation_status()
            .build()
            .inspect_err(|error| {
                tracing::error!(
                    root_cafile_path = %tls_config.root_cafile_path,
                    error = %error,
                    "Could not build client certificate verifier; the root CA file may contain no trust anchors",
                );
            })
            .ok()?;

    match ServerConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(certs, rustls_pki_types::PrivateKeyDer::Sec1(key))
    {
        Ok(mut tls) => {
            tls.alpn_protocols = vec![b"h2".to_vec()];
            Some(TlsAcceptor::from(Arc::new(tls)))
        }
        Err(error) => {
            tracing::error!(?error, "Rustls error building server config");
            None
        }
    }
}

/// The five-minute TLS acceptor refresh, counted instead of logged: the
/// steady tick is a rate, not news, so the per-refresh log line retires.
#[derive(carbide_instrument::Event)]
#[event(
    name = "carbide_api_tls_cert_refreshes_total",
    component = "nico-api",
    log = off,
    metric = counter,
    describe = "Number of TLS acceptor refreshes performed by the API listener"
)]
struct TlsCertsRefreshed;

/// An inbound connection was accepted from the listener, before it is served.
/// Counted, never logged -- the accept rate is a metric, not per-connection
/// news.
#[derive(carbide_instrument::Event)]
#[event(
    name = "carbide_api_tls_connection_attempted_total",
    component = "nico-api",
    log = off,
    metric = counter,
    describe = "Number of inbound TLS connection attempts"
)]
struct TlsConnectionAttempted;

/// A connection was served: the TLS handshake completed, or a plaintext
/// connection was handed to the HTTP stack. Counted, never logged.
#[derive(carbide_instrument::Event)]
#[event(
    name = "carbide_api_tls_connection_success_total",
    component = "nico-api",
    log = off,
    metric = counter,
    describe = "Number of successful TLS connections"
)]
struct TlsConnectionSucceeded;

/// Why an inbound connection failed, as the bounded `reason` label. The
/// rendered strings are the metric's contract: each variant renders to the
/// snake_case value the counter has always reported, byte for byte.
// The shared `ConnectionFailure` postfix is deliberate: the derived snake_case
// is exactly the `reason` label value the counter reports, so the variant
// names are the metric contract rather than a naming slip.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, carbide_instrument::LabelValue)]
enum ConnectionFailReason {
    /// The TCP accept itself errored.
    TcpConnectionFailure,
    /// The TLS handshake errored.
    TlsConnectionFailure,
}

/// An inbound connection failed before it could be served -- the TCP accept or
/// the TLS handshake errored. Metric-only: the `tracing::error!` beside each
/// emit stays the log, byte-for-byte as before; the `reason` label
/// distinguishes which leg failed.
#[derive(carbide_instrument::Event)]
#[event(
    name = "carbide_api_tls_connection_fail_total",
    component = "nico-api",
    log = off,
    metric = counter,
    describe = "Number of failed inbound TLS connection attempts"
)]
struct TlsConnectionFailed {
    #[label]
    reason: ConnectionFailReason,
}

/// Start listening for requests, spawning the listener task into `join_set`.
///
/// This method will return an error if any preconditions fail (could not bind to the port, issues
/// with tls configuration), then moves processing to a background task spawned into `join_set`. The
/// background task does not return unless `cancel_token` is canceled, or if something panics.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all)]
pub async fn start(
    join_set: &mut JoinSet<()>,
    api_service: Arc<Api>,
    listen_mode: ApiListenMode,
    listen_port: SocketAddr,
    auth_config: &Option<AuthConfig>,
    meter: Meter,
    admin_ui_routes_builder: Option<AdminUiRoutesBuilder>,
    cancel_token: CancellationToken,
) -> eyre::Result<()> {
    let api_reflection_service = Builder::configure()
        .register_encoded_file_descriptor_set(::rpc::REFLECTION_API_SERVICE_DESCRIPTOR)
        .build_v1alpha()?;

    let (tls_config, mut tls_acceptor, serve_plaintext_via_http1) = match listen_mode {
        ApiListenMode::Tls(tls_config) => {
            let tls_config_clone = tls_config.clone();
            let tls_acceptor = tokio::task::Builder::new()
                .name("get_tls_acceptor init")
                .spawn_blocking(move || get_tls_acceptor(&tls_config_clone))?
                .await?;
            (Some(tls_config), tls_acceptor, false)
        }
        ApiListenMode::PlaintextHttp1 => (None, None, true),
        ApiListenMode::PlaintextHttp2 => (None, None, false),
    };

    let listener = TcpListener::bind(listen_port).await?;
    let http = http2::Builder::new(TokioExecutor::new());

    let extra_cli_certs = if let Some(auth_config) = auth_config {
        auth_config.cli_certs.clone()
    } else {
        None
    };

    // Get cert trust config from the config file
    let spiffe_context = auth_config
        .as_ref()
        .and_then(|c| c.trust.as_ref())
        .cloned()
        .inspect(|trust_config| tracing::info!(?trust_config, "TrustConfig rendered from config",))
        .map(SpiffeContext::try_from)
        .transpose()?
        .ok_or(CarbideError::InvalidConfiguration(
            ConfigValidationError::InvalidValue(
                "could not parse trust config from auth config in carbide api config toml file"
                    .to_string(),
            ),
        ))?;

    let cert_description_layer: CertDescriptionMiddleware<Authorization> =
        CertDescriptionMiddleware::new(extra_cli_certs, spiffe_context);
    let casbin_layer = if let Some(auth_config) = auth_config {
        if let Some(casbin_policy_file) = &auth_config.casbin_policy_file {
            let casbin_authorizer = Arc::new(
                auth::CasbinAuthorizer::build_casbin(
                    casbin_policy_file,
                    auth_config.permissive_mode,
                )
                .await?,
            );
            let middleware = auth::middleware::CasbinHandler::new(casbin_authorizer);
            Some(AsyncRequireAuthorizationLayer::new(middleware))
        } else {
            None
        }
    } else {
        None
    };
    let internal_rbac_layer = if api_service.runtime_config.bypass_rbac {
        None
    } else {
        Some(AsyncRequireAuthorizationLayer::new(
            auth::middleware::InternalRBACHandler::new(),
        ))
    };

    let router = axum::Router::new()
        .route("/", axum::routing::get(root_url))
        .route_service(
            "/forge.Forge/{*rpc}",
            rpc::forge_server::ForgeServer::from_arc(api_service.clone()),
        )
        .route_service(
            "/grpc.reflection.v1alpha.ServerReflection/{*r}",
            api_reflection_service,
        );

    // Mount the admin web UI under `/admin`, if a builder was injected. The web
    // UI lives in the `carbide-api-web` crate; the builder is supplied by the
    // top-level binary so that this crate doesn't depend on it (see
    // [`AdminUiRoutesBuilder`]).
    let router = match admin_ui_routes_builder {
        Some(build_admin_router) => {
            router.nest_service("/admin", build_admin_router(api_service.clone())?)
        }
        None => router,
    };

    let app = tower::ServiceBuilder::new()
        .layer(LogLayer::new(meter.clone()))
        .layer(cert_description_layer)
        .option_layer(internal_rbac_layer)
        .option_layer(casbin_layer)
        .service(router);

    let mut tls_acceptor_created = Instant::now();
    let mut initialize_tls_acceptor = true;

    join_set
        .build_task()
        .name("listener accept loop")
        .spawn(async move {
            while let Some(incoming_connection) =
                cancel_token.run_until_cancelled(listener.accept()).await
            {
                carbide_instrument::emit(TlsConnectionAttempted);
                let (conn, addr) = match incoming_connection {
                    Ok(incoming) => incoming,
                    Err(e) => {
                        tracing::error!(error = %e, "Error accepting connection");
                        carbide_instrument::emit(TlsConnectionFailed {
                            reason: ConnectionFailReason::TcpConnectionFailure,
                        });
                        continue;
                    }
                };

                // TODO: RT: change the subroutine to return the certificate's parsed expiration from
                // the file on disk and only refresh if it's actually necessary to do so,
                // and emit a metric for the remaining duration on the cert

                // hard refresh our certs every five minutes
                // they may have been rewritten on disk by cert-manager and we want to honor the new cert.
                if let (Some(tls_config), true) = (
                    tls_config.as_ref(),
                    initialize_tls_acceptor
                        || tls_acceptor_created.elapsed()
                            > tokio::time::Duration::from_secs(5 * 60),
                ) {
                    carbide_instrument::emit(TlsCertsRefreshed);
                    initialize_tls_acceptor = false;
                    tls_acceptor_created = Instant::now();

                    tls_acceptor = tokio::task::Builder::new()
                        .name("get_tls_acceptor refresh")
                        .spawn_blocking({
                            let tls_config = tls_config.clone();
                            move || get_tls_acceptor(&tls_config)
                        })
                        // Safety: spawn_blocking only returns Error if run outside the tokio runtime
                        .expect("Failed to spawn blocking task")
                        .await
                        // Safety: Awaiting a JoinHandle only fails if the task panicked, and we want to
                        // propagate panics
                        .expect("task panicked");
                }

                let tls_acceptor = tls_acceptor.clone();
                let http = http.clone();
                let app = app.clone();

                tokio::task::Builder::new()
                    .name("http conn handler")
                    .spawn(async move {
                        if let Some(tls_acceptor) = tls_acceptor {
                            match tls_acceptor.accept(conn).await {
                                Ok(conn) => {
                                    let conn = TokioIo::new(conn);
                                    carbide_instrument::emit(TlsConnectionSucceeded);

                                    let (_, session) = conn.inner().get_ref();
                                    let connection_attributes = {
                                        let peer_address = addr;
                                        let peer_certificates = session
                                            .peer_certificates()
                                            .unwrap_or_default()
                                            .to_vec();
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
                                        .serve_connection(
                                            conn,
                                            TowerToHyperService::new(app_with_ext),
                                        )
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
                                    carbide_instrument::emit(TlsConnectionFailed {
                                        reason: ConnectionFailReason::TlsConnectionFailure,
                                    });
                                }
                            }
                        } else {
                            // servicing without tls -- HTTP only
                            carbide_instrument::emit(TlsConnectionSucceeded);

                            let conn_attrs_extension_layer =
                                AddExtensionLayer::new(Arc::new(ConnectionAttributes {
                                    peer_address: addr,
                                    peer_certificates: vec![],
                                }));

                            let conn = TokioIo::new(conn);

                            let app_with_ext = tower::ServiceBuilder::new()
                                .layer(conn_attrs_extension_layer)
                                .service(app);

                            let result = if serve_plaintext_via_http1 {
                                // Serve the connection as HTTP/1.1 and allow upgrading to HTTP/2
                                http1::Builder::new()
                                    .serve_connection(conn, TowerToHyperService::new(app_with_ext))
                                    .with_upgrades()
                                    .await
                            } else {
                                // Serve the connection as HTTP/2, which will fail if the initial
                                // request is HTTP/1.1 (which is the default behavior for web browsers,
                                // curl, etc.)
                                http.serve_connection(conn, TowerToHyperService::new(app_with_ext))
                                    .await
                            };

                            if let Err(error) = result {
                                tracing::debug!(
                                    error = %error,
                                    error_debug = ?error,
                                    "error servicing plain http connection",
                                );
                            }
                        }
                    })
                    // Safety: This should only fail if called outside a tokio runtime
                    .expect("could not spawn task to handle HTTP connection");
            }

            tracing::info!("carbide-api shutting down");
        })?;

    Ok(())
}

/// Handle the root URL. Health check services often expect a 200 here.
async fn root_url() -> &'static str {
    const ROOT_CONTENTS: &str = if carbide_version::literal!(build_version).is_empty() {
        "Forge development build\n"
    } else {
        concat!("Forge ", carbide_version::literal!(build_version), "\n")
    };
    ROOT_CONTENTS
}

#[cfg(test)]
mod tests {
    use carbide_instrument::LabelValue;
    use carbide_test_support::{Check, check_values};

    use super::ConnectionFailReason;

    /// The `reason` label values are the metric's contract: each variant
    /// renders to the exact snake_case string the fail counter has always
    /// reported. The failure path is never exercised by the metrics
    /// integration test, so this is what locks those bytes.
    #[test]
    fn connection_fail_reason_renders_expected_label_values() {
        check_values(
            [
                Check {
                    scenario: "tcp accept failure",
                    input: ConnectionFailReason::TcpConnectionFailure,
                    expect: "tcp_connection_failure".to_string(),
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
