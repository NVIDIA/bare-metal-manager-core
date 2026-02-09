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
use hyper::server::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use model::ConfigValidationError;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Meter;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::oneshot::{Receiver, Sender};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tonic_reflection::server::Builder;
use tower_http::add_extension::AddExtensionLayer;
use tower_http::auth::AsyncRequireAuthorizationLayer;

use crate::api::Api;
use crate::auth;
use crate::auth::forge_spiffe::ForgeSpiffeContext;
use crate::cfg::file::AuthConfig;
use crate::errors::CarbideError;
use crate::logging::api_logs::LogLayer;

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

    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());

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
                    "Could not build client cert verifier. Does root CA file at {} contain no root trust anchors? {}",
                    tls_config.root_cafile_path,
                    error
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

// This is used as an extension to requests for anything that is an attribute of
// the connection the request came in on, as opposed to the HTTP request itself.
// Note that if you're trying to retrieve it, it's probably inside an Arc in the
// extensions typemap, so .get::<Arc<ConnectionAttributes>>() is what you want.
pub struct ConnectionAttributes {
    peer_address: SocketAddr,
    peer_certificates: Vec<CertificateDer<'static>>,
}

impl ConnectionAttributes {
    pub fn peer_address(&self) -> &SocketAddr {
        &self.peer_address
    }

    pub fn peer_certificates(&self) -> &[CertificateDer<'static>] {
        self.peer_certificates.as_slice()
    }
}

#[tracing::instrument(skip_all)]
pub async fn listen_and_serve(
    api_service: Arc<Api>,
    listen_mode: ApiListenMode,
    listen_port: SocketAddr,
    auth_config: &Option<AuthConfig>,
    meter: Meter,
    mut stop_channel: Receiver<()>,
    ready_channel: Sender<()>,
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
        .inspect(|trust_config| {
            tracing::info!("TrustConfig rendered from config: {trust_config:?}")
        })
        .map(ForgeSpiffeContext::try_from)
        .transpose()?
        .ok_or(CarbideError::InvalidConfiguration(
            ConfigValidationError::InvalidValue(
                "could not parse trust config from auth config in carbide api config toml file"
                    .to_string(),
            ),
        ))?;

    let cert_description_layer =
        auth::middleware::CertDescriptionMiddleware::new(extra_cli_certs, spiffe_context);
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
        )
        .nest_service("/admin", crate::web::routes(api_service.clone())?);

    let app = tower::ServiceBuilder::new()
        .layer(LogLayer::new(meter.clone()))
        .layer(cert_description_layer)
        .option_layer(internal_rbac_layer)
        .option_layer(casbin_layer)
        .service(router.clone());

    let connection_total_counter = meter
        .u64_counter("carbide-api.tls.connection_attempted")
        .with_description("The amount of tls connections that were attempted")
        .build();
    let connection_succeeded_counter = meter
        .u64_counter("carbide-api.tls.connection_success")
        .with_description("The amount of tls connections that were successful")
        .build();
    let connection_failed_counter = meter
        .u64_counter("carbide-api.tls.connection_fail")
        .with_description("The amount of tcp connections that were failures")
        .build();

    let mut tls_acceptor_created = Instant::now();
    let mut initialize_tls_acceptor = true;
    _ = ready_channel.send(()).inspect_err(|_e| {
        // Note: the `_e` here is just sending us back (rejecting) the () that we sent to the ready
        // channel. This will only happen if the other end is closed.
        tracing::warn!("Bug: api server ready_channel is closed, could not notify readiness status")
    });
    loop {
        let incoming_connection = select! {
            incoming_connection = listener.accept() => incoming_connection,
            _ = &mut stop_channel => {
                tracing::info!("carbide-api shutting down");
                return Ok(());
            }
        };
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

        // TODO: RT: change the subroutine to return the certificate's parsed expiration from
        // the file on disk and only refresh if it's actually necessary to do so,
        // and emit a metric for the remaining duration on the cert

        // hard refresh our certs every five minutes
        // they may have been rewritten on disk by cert-manager and we want to honor the new cert.
        if let (Some(tls_config), true) = (
            tls_config.as_ref(),
            initialize_tls_acceptor
                || tls_acceptor_created.elapsed() > tokio::time::Duration::from_secs(5 * 60),
        ) {
            tracing::info!("Refreshing certs");
            initialize_tls_acceptor = false;
            tls_acceptor_created = Instant::now();

            let tls_config_clone = tls_config.clone();
            let fut_tls_acceptor_new_certs = tokio::task::Builder::new()
                .name("get_tls_acceptor refresh")
                .spawn_blocking(move || get_tls_acceptor(&tls_config_clone));
            match fut_tls_acceptor_new_certs {
                Ok(next) => tls_acceptor = next.await?,
                Err(_err) => {
                    tracing::error!("Failed spawning blocking task get_tls_acceptor refresh")
                }
            }
        }

        let tls_acceptor = tls_acceptor.clone();
        let http = http.clone();
        let app = app.clone();
        let connection_succeeded_counter = connection_succeeded_counter.clone();
        let connection_failed_counter = connection_failed_counter.clone();
        tokio::task::Builder::new().name("http conn handler").spawn(async move {
            if let Some(tls_acceptor) = tls_acceptor {
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

                        if let Err(error) = http.serve_connection(conn, TowerToHyperService::new(app_with_ext)).await {
                            tracing::debug!(%error, "error servicing tls http request: {error:?}");
                        }
                    }
                    Err(error) => {
                        tracing::error!(%error, address = %addr, "error accepting tls connection");
                        connection_failed_counter
                            .add(1, &[KeyValue::new("reason", "tls_connection_failure")]);
                    }
                }
            } else {
                // servicing without tls -- HTTP only
                connection_succeeded_counter.add(1, &[]);

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
                    http1::Builder::new().serve_connection(conn, TowerToHyperService::new(app_with_ext)).with_upgrades().await
                } else {
                    // Serve the connection as HTTP/2, which will fail if the initial
                    // request is HTTP/1.1 (which is the default behavior for web browsers,
                    // curl, etc.)
                    http.serve_connection(conn, TowerToHyperService::new(app_with_ext)).await
                };

                if let Err(error) = result {
                    tracing::debug!(%error, "error servicing plain http connection: {error:?}");
                }
            }
        })?;
    }
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
