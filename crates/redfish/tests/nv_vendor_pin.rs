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

//! The `nv_redfish` pool reads the operator vendor pin, so its service root
//! cache has to distinguish one pin from another.

use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum_server::tls_rustls::RustlsConfig;
use carbide_redfish::nv_redfish::NvRedfishClientPool;
use carbide_redfish::vendor_override::{BmcVendorOverrideResolver, VendorOverrideError};
use carbide_secrets::credentials::Credentials;
use libredfish::model::service_root::RedfishVendor;

/// A resolver whose answer can be changed, standing in for an operator editing
/// `bmc_vendor_override` while the process is running.
struct SettablePin(Mutex<Option<RedfishVendor>>);

impl SettablePin {
    fn new(pin: Option<RedfishVendor>) -> Arc<Self> {
        Arc::new(Self(Mutex::new(pin)))
    }

    fn set(&self, pin: Option<RedfishVendor>) {
        *self.0.lock().expect("pin mutex poisoned") = pin;
    }
}

#[async_trait::async_trait]
impl BmcVendorOverrideResolver for SettablePin {
    async fn vendor_override(
        &self,
        _host: &str,
    ) -> Result<Option<RedfishVendor>, VendorOverrideError> {
        Ok(*self.0.lock().expect("pin mutex poisoned"))
    }
}

#[derive(Clone)]
struct AppState {
    root_hits: Arc<AtomicUsize>,
}

const SERVICE_ROOT: &str = r##"{
  "@odata.id": "/redfish/v1/",
  "@odata.type": "#ServiceRoot.v1_13_0.ServiceRoot",
  "Id": "RootService",
  "Name": "Root Service",
  "RedfishVersion": "1.15.1",
  "Vendor": "Supermicro",
  "Product": "Supermicro Redfish Server",
  "UUID": "6acb216c-bfde-11d3-02c0-146dd4e0ff10",
  "Chassis": { "@odata.id": "/redfish/v1/Chassis" },
  "Systems": { "@odata.id": "/redfish/v1/Systems" },
  "Managers": { "@odata.id": "/redfish/v1/Managers" },
  "UpdateService": { "@odata.id": "/redfish/v1/UpdateService" },
  "SessionService": { "@odata.id": "/redfish/v1/SessionService" },
  "Links": { "Sessions": { "@odata.id": "/redfish/v1/SessionService/Sessions" } },
  "ProtocolFeaturesSupported": {
    "ExpandQuery": { "ExpandAll": true, "Levels": true, "Links": true, "MaxLevels": 5, "NoLinks": true },
    "FilterQuery": true,
    "SelectQuery": true
  }
}"##;

async fn service_root(State(state): State<AppState>) -> impl IntoResponse {
    state.root_hits.fetch_add(1, Ordering::SeqCst);
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        SERVICE_ROOT,
    )
}

fn spawn_mock_bmc(root_hits: Arc<AtomicUsize>) -> SocketAddr {
    let app = Router::new()
        .route("/redfish/v1", get(service_root))
        .route("/redfish/v1/", get(service_root))
        .with_state(AppState { root_hits });

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();

    let tls = bmc_mock::tls::server_config(None::<&str>).unwrap();
    let config = RustlsConfig::from_config(Arc::new(tls));
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, config)
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    addr
}

/// Without the pin in the cache key, an operator setting or clearing a pin would
/// keep getting a root built under the old one until the cache lifetime elapsed.
#[tokio::test]
async fn changing_the_pin_rebuilds_the_cached_service_root() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let root_hits = Arc::new(AtomicUsize::new(0));
    let addr = spawn_mock_bmc(root_hits.clone());
    let resolver = SettablePin::new(None);
    let pool = NvRedfishClientPool::new(Arc::new(ArcSwap::new(Arc::new(None))), resolver.clone());
    let creds = || Credentials::UsernamePassword {
        username: "root".to_string(),
        password: "placeholder".to_string(),
    };

    pool.service_root(addr, creds()).await.expect("first fetch");
    assert_eq!(root_hits.load(Ordering::SeqCst), 1, "first call fetches");

    pool.service_root(addr, creds()).await.expect("cache hit");
    assert_eq!(
        root_hits.load(Ordering::SeqCst),
        1,
        "an unchanged pin must be served from cache"
    );

    resolver.set(Some(RedfishVendor::Dell));
    pool.service_root(addr, creds()).await.expect("after pin");
    assert_eq!(
        root_hits.load(Ordering::SeqCst),
        2,
        "setting a pin must not serve the root cached without one"
    );

    pool.service_root(addr, creds()).await.expect("cache hit");
    assert_eq!(
        root_hits.load(Ordering::SeqCst),
        2,
        "the new pin caches in its own right"
    );

    // Each pin caches in its own right, so going back to a pin already seen
    // reuses that entry rather than refetching.
    resolver.set(None);
    pool.service_root(addr, creds()).await.expect("after clear");
    assert_eq!(
        root_hits.load(Ordering::SeqCst),
        2,
        "clearing a pin returns to the entry built without one"
    );

    resolver.set(Some(RedfishVendor::Hpe));
    pool.service_root(addr, creds()).await.expect("third pin");
    assert_eq!(
        root_hits.load(Ordering::SeqCst),
        3,
        "a pin never seen before must fetch its own root"
    );
}

/// The pin has to reach what `nv_redfish` parses, not just NICo's own reads, so
/// the root the pool hands back carries the pinned vendor and nothing else.
#[tokio::test]
async fn a_pinned_root_reports_the_pinned_vendor_to_nv_redfish() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let root_hits = Arc::new(AtomicUsize::new(0));
    let addr = spawn_mock_bmc(root_hits.clone());
    let creds = || Credentials::UsernamePassword {
        username: "root".to_string(),
        password: "placeholder".to_string(),
    };

    // The mock reports Supermicro with a product, while the operator says Dell.
    let unpinned = NvRedfishClientPool::new(
        Arc::new(ArcSwap::new(Arc::new(None))),
        SettablePin::new(None),
    );
    let detected = unpinned
        .service_root(addr, creds())
        .await
        .expect("detected");
    assert_eq!(
        detected.vendor(),
        Some(nv_redfish::service_root::Vendor::new("Supermicro")),
        "precondition, the BMC reports its own vendor"
    );
    assert!(
        detected.product().is_some(),
        "precondition, it has a product"
    );
    let detected_product = detected.product().map(|p| p.into_inner().to_string());

    let pinned_pool = NvRedfishClientPool::new(
        Arc::new(ArcSwap::new(Arc::new(None))),
        SettablePin::new(Some(RedfishVendor::Dell)),
    );
    let pinned = pinned_pool
        .service_root(addr, creds())
        .await
        .expect("pinned");

    assert_eq!(
        pinned.vendor(),
        Some(nv_redfish::service_root::Vendor::new("Dell")),
        "the pin must reach the vendor nv_redfish classifies on"
    );
    assert_eq!(
        pinned.product().map(|p| p.into_inner().to_string()),
        detected_product,
        "only the vendor is written, so the product is left as reported"
    );
}

/// A resolver failure is advisory, so the pool must still build a client.
#[tokio::test]
async fn a_resolver_failure_falls_back_to_detection() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    struct AlwaysFails;

    #[async_trait::async_trait]
    impl BmcVendorOverrideResolver for AlwaysFails {
        async fn vendor_override(
            &self,
            host: &str,
        ) -> Result<Option<RedfishVendor>, VendorOverrideError> {
            Err(VendorOverrideError::new(
                host,
                Box::new(std::io::Error::other("database down")),
            ))
        }
    }

    let root_hits = Arc::new(AtomicUsize::new(0));
    let addr = spawn_mock_bmc(root_hits.clone());
    let pool = NvRedfishClientPool::new(
        Arc::new(ArcSwap::new(Arc::new(None))),
        Arc::new(AlwaysFails),
    );

    let root = pool
        .service_root(
            addr,
            Credentials::UsernamePassword {
                username: "root".to_string(),
                password: "placeholder".to_string(),
            },
        )
        .await;

    assert!(root.is_ok(), "a resolver failure must not fail the client");
    assert_eq!(root_hits.load(Ordering::SeqCst), 1);
}
