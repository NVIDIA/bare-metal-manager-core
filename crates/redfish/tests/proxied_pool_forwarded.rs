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

// The proxied libredfish pool's wire contract with nico-bmc-proxy: a request
// for BMC X must arrive at the PROXY's authority, over a verified mTLS
// connection, carrying `Forwarded: host=X` so the proxy can route it. This
// is unobservable from libredfish's client type, so a TLS listener stands in
// for the proxy and records what it received.

use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::IntoResponse;
use axum::routing::get;
use axum_server::tls_rustls::RustlsConfig;
use carbide_redfish::libredfish::{RedfishAuth, new_proxied_pool};
use carbide_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialReader, Credentials,
};
use carbide_utils::HostPortPair;
use libredfish::model::service_root::RedfishVendor;

const SERVICE_ROOT: &str = r##"{
  "@odata.id": "/redfish/v1",
  "@odata.type": "#ServiceRoot.v1_5_0.ServiceRoot",
  "RedfishVersion": "1.6.0",
  "Vendor": "Test"
}"##;

/// The routing-relevant headers of one request the fake proxy received.
struct RequestHeaders {
    forwarded: Option<String>,
    host: Option<String>,
}

#[derive(Clone)]
struct Received {
    requests: Arc<Mutex<Vec<RequestHeaders>>>,
}

async fn service_root(State(state): State<Received>, headers: HeaderMap) -> impl IntoResponse {
    let value = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    state.requests.lock().unwrap().push(RequestHeaders {
        forwarded: value("forwarded"),
        host: value("host"),
    });
    ([(header::CONTENT_TYPE, "application/json")], SERVICE_ROOT)
}

struct Pki {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

fn pki() -> Pki {
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.clone().self_signed(&ca_key).expect("ca cert");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let server_params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("server params");
    let server_key = rcgen::KeyPair::generate().expect("server key");
    let server_cert = server_params
        .signed_by(&server_key, &issuer)
        .expect("server cert");

    let client_key = rcgen::KeyPair::generate().expect("client key");
    let client_cert = rcgen::CertificateParams::default()
        .self_signed(&client_key)
        .expect("client cert");

    Pki {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

async fn spawn_fake_proxy(pki: &Pki, received: Received) -> SocketAddr {
    let app = Router::new()
        .route("/redfish/v1", get(service_root))
        .route("/redfish/v1/", get(service_root))
        .with_state(received);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let config = RustlsConfig::from_pem(
        pki.server_cert_pem.clone().into_bytes(),
        pki.server_key_pem.clone().into_bytes(),
    )
    .await
    .expect("server TLS config");
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, config)
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    addr
}

/// The proxied pool never resolves credentials itself; a reader that has
/// none proves it.
struct NoCredentials;

#[async_trait]
impl CredentialReader for NoCredentials {
    async fn get_credentials(
        &self,
        _key: &CredentialKey,
    ) -> Result<Option<Credentials>, carbide_secrets::SecretsError> {
        Ok(None)
    }
}

#[tokio::test]
async fn proxied_pool_reaches_the_proxy_over_mtls_with_a_forwarded_header() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let pki = pki();
    let received = Received {
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let proxy_addr = spawn_fake_proxy(&pki, received.clone()).await;

    // Verified TLS to the proxy (its CA trusted, our identity presented) --
    // the same shape `ProxiedRedfishPool` builds in production.
    let inner = libredfish::RedfishClientPool::builder()
        .identity(pki.client_cert_pem.clone(), pki.client_key_pem.clone())
        .add_root_certificates(pki.ca_pem.clone())
        .build()
        .expect("verified pool builds");
    let pool = new_proxied_pool(
        Arc::new(NoCredentials),
        inner,
        HostPortPair::HostAndPort("127.0.0.1".to_string(), proxy_addr.port()),
    );

    let client = pool
        .create_client(
            "192.0.2.10",
            Some(443),
            RedfishAuth::Key(CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcRoot {
                    bmc_mac_address: mac_address::MacAddress::new([2, 0, 0, 0, 0, 1]),
                },
            }),
            // `Unknown` skips vendor auto-detect, so exactly one request.
            Some(RedfishVendor::Unknown),
        )
        .await
        .expect("client builds without resolving credentials");

    client
        .get_service_root()
        .await
        .expect("the fake proxy serves a service root");

    let requests = received.requests.lock().unwrap();
    assert_eq!(requests.len(), 1, "exactly one request reached the proxy");
    let RequestHeaders { forwarded, host } = &requests[0];
    assert_eq!(
        forwarded.as_deref(),
        Some("host=192.0.2.10"),
        "the Forwarded header must name the BMC for the proxy to route to"
    );
    assert_eq!(
        host.as_deref(),
        Some(format!("127.0.0.1:{}", proxy_addr.port()).as_str()),
        "the request must be addressed to the proxy, not the BMC"
    );
}
