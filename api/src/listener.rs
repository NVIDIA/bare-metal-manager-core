/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{net::SocketAddr, sync::Arc, time::Instant};

use ::rpc::forge as rpc;
use hyper::server::conn::Http;
use opentelemetry::{metrics::Meter, KeyValue};
use tokio::net::TcpListener;
use tokio_rustls::{
    rustls::{
        server::AllowAnyAnonymousOrAuthenticatedClient, Certificate, PrivateKey, RootCertStore,
        ServerConfig,
    },
    TlsAcceptor,
};
use tonic_reflection::server::Builder;
use tower_http::{add_extension::AddExtensionLayer, auth::AsyncRequireAuthorizationLayer};

use crate::{api::Api, auth, logging::api_logs::LogLayer};

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
        match rustls_pemfile::certs(&mut buf) {
            Ok(certs) => certs.into_iter().map(Certificate).collect(),
            Err(error) => {
                tracing::error!(?error, "Rustls error reading certs");
                return None;
            }
        }
    };

    let key = {
        let fd = match std::fs::File::open(&tls_config.identity_keyfile_path) {
            Ok(fd) => fd,
            Err(_) => return None,
        };
        let mut buf = std::io::BufReader::new(&fd);

        match rustls_pemfile::ec_private_keys(&mut buf) {
            Ok(keys) => keys.into_iter().map(PrivateKey).next(),
            error => {
                tracing::error!(?error, "Rustls error reading key");
                None
            }
        }
    };

    let key = match key {
        Some(key) => key,
        None => {
            tracing::error!("Rustls error: no keys?");
            return None;
        }
    };

    let mut roots = RootCertStore::empty();
    match std::fs::read(&tls_config.root_cafile_path) {
        Ok(pem_file) => {
            let mut cert_cursor = std::io::Cursor::new(&pem_file[..]);
            let certs_to_add = match rustls_pemfile::certs(&mut cert_cursor) {
                Ok(certs) => certs,
                Err(error) => {
                    tracing::error!(?error, "error parsing root ca cert file");
                    return None;
                }
            };
            let (_added, _ignored) = roots.add_parsable_certificates(certs_to_add.as_slice());
        }
        Err(error) => {
            tracing::error!(?error, "error reading root ca cert file");
            return None;
        }
    }

    if let Ok(pem_file) = std::fs::read(&tls_config.admin_root_cafile_path) {
        let mut cert_cursor = std::io::Cursor::new(&pem_file[..]);
        let certs_to_add = match rustls_pemfile::certs(&mut cert_cursor) {
            Ok(certs) => certs,
            Err(error) => {
                tracing::error!(?error, "error parsing admin ca cert file");
                return None;
            }
        };
        let (_added, _ignored) = roots.add_parsable_certificates(certs_to_add.as_slice());
    }

    match ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(AllowAnyAnonymousOrAuthenticatedClient::new(roots).boxed())
        .with_single_cert(certs, key)
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
    peer_certificates: Vec<Certificate>,
}

impl ConnectionAttributes {
    pub fn peer_address(&self) -> &SocketAddr {
        &self.peer_address
    }

    pub fn peer_certificates(&self) -> &[Certificate] {
        self.peer_certificates.as_slice()
    }
}

#[tracing::instrument(skip_all)]
pub async fn listen_and_serve(
    api_service: Arc<Api>,
    tls_config: ApiTlsConfig,
    listen_port: SocketAddr,
    authorizer: auth::Authorizer,
    meter: Meter,
) -> eyre::Result<()> {
    let api_reflection_service = Builder::configure()
        .register_encoded_file_descriptor_set(::rpc::REFLECTION_API_SERVICE_DESCRIPTOR)
        .build()?;

    let tls_config = Arc::new(tls_config);
    let tls_config_clone = tls_config.clone();

    let mut tls_acceptor = tokio::task::Builder::new()
        .name("get_tls_acceptor init")
        .spawn_blocking(move || get_tls_acceptor(&tls_config_clone))?
        .await?;

    let listener = TcpListener::bind(listen_port).await?;
    let mut http = Http::new();
    http.http2_only(true);

    let authn_layer = auth::middleware::AuthenticationMiddleware::default();
    let authz_layer = {
        // TODO: move the initialization of the Authorizer here instead
        let authorizer = Arc::new(authorizer);
        let authz_handler = auth::middleware::AuthzHandler::new(authorizer);
        AsyncRequireAuthorizationLayer::new(authz_handler)
    };

    let router = axum::Router::new()
        .route_service(
            "/forge.Forge/*rpc",
            rpc::forge_server::ForgeServer::from_arc(api_service.clone()),
        )
        .route_service(
            "/grpc.reflection.v1alpha.ServerReflection/*r",
            api_reflection_service,
        )
        .nest_service("/admin", crate::web::routes(api_service.clone()));

    let app = tower::ServiceBuilder::new()
        .layer(LogLayer::new(meter.clone()))
        .layer(authn_layer)
        .layer(authz_layer)
        .service(router.clone());

    let connection_total_counter = meter
        .u64_counter("carbide-api.tls.connection_attempted")
        .with_description("The amount of tls connections that were attempted")
        .init();
    let connection_succeeded_counter = meter
        .u64_counter("carbide-api.tls.connection_success")
        .with_description("The amount of tls connections that were successful")
        .init();
    let connection_failed_counter = meter
        .u64_counter("carbide-api.tls.connection_fail")
        .with_description("The amount of tcp connections that were failures")
        .init();

    let mut tls_acceptor_created = Instant::now();
    let mut initialize_tls_acceptor = true;
    loop {
        let incoming_connection = listener.accept().await;
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
        if initialize_tls_acceptor
            || tls_acceptor_created.elapsed() > tokio::time::Duration::from_secs(5 * 60)
        {
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
                        connection_succeeded_counter.add(1, &[]);

                        let (_, session) = conn.get_ref();
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

                        // TODO: Why does this returns an error Io / UnexpectedEof on every single request?
                        // `h2` already logs the error at DEBUG level
                        let _ = http.serve_connection(conn, app_with_ext).await;
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
                if let Err(error) = http.serve_connection(conn, app).await {
                    tracing::debug!(%error, "error servicing plain http connection");
                }
            }
        })?;
    }
}
