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

//! Legacy DNS Server Implementation
//!
//! This module provides the original carbide-dns implementation that listens
//! directly on a DNS port (53 or custom) and handles DNS queries using trust-dns-server.
//! This is maintained for backward compatibility during migration to the PowerDNS backend.

use std::collections::HashMap;
use std::iter;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eyre::Report;
use metrics_endpoint::{MetricsEndpointConfig, new_metrics_setup, run_metrics_endpoint};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Meter};
use rpc::forge_tls_client::{ApiConfig, ForgeClientT, ForgeTlsClient};
use rpc::protos::forge;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};
use trust_dns_resolver::proto::op::{Header, ResponseCode};
use trust_dns_resolver::proto::rr::{DNSClass, Name, RData};
use trust_dns_server::ServerFuture;
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::proto::rr::RecordType::{A, AAAA};
use trust_dns_server::proto::rr::{Record, RecordType};
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

use crate::config::Config;

/// Metrics for the legacy DNS server, created from an OpenTelemetry `Meter`.
struct LegacyDnsMetrics {
    negative_cache_hit: Counter<u64>,
    negative_cache_miss: Counter<u64>,
    negative_cache_eviction: Counter<u64>,
}

impl LegacyDnsMetrics {
    fn new(meter: &Meter) -> Self {
        Self {
            negative_cache_hit: meter
                .u64_counter("carbide_dns_negative_cache_hit_count")
                .build(),
            negative_cache_miss: meter
                .u64_counter("carbide_dns_negative_cache_miss_count")
                .build(),
            negative_cache_eviction: meter
                .u64_counter("carbide_dns_negative_cache_eviction_count")
                .build(),
        }
    }
}

// LegacyDnsMetrics contains OpenTelemetry instrument types which don't implement Debug.
impl std::fmt::Debug for LegacyDnsMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyDnsMetrics").finish()
    }
}

#[derive(Debug)]
pub struct LegacyDnsServer {
    forge_client: Arc<Mutex<ForgeClientT>>,
    negative_cache: Arc<RwLock<HashMap<CacheKey, NegativeEntry>>>,
    negative_ttl: Duration,
    metrics: LegacyDnsMetrics,
}

#[derive(Debug)]
struct NegativeEntry {
    reason_code: ResponseCode,
    expires_at: Instant,
}

#[derive(Hash, Debug, Eq, PartialEq)]
struct CacheKey {
    qname: String,
    qtype: RecordType,
}

#[async_trait::async_trait]
impl RequestHandler for LegacyDnsServer {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let request_info = request.request_info();

        let mut response_header = Header::response_from_request(request.header());

        let message = MessageResponseBuilder::from_message_request(request);

        let qtype = request.query().query_type();
        let qname = request_info.query.name().to_string();

        let cache_key = CacheKey {
            qname: qname.clone(),
            qtype,
        };

        match qtype {
            A | AAAA => {
                let q_type_num = match qtype {
                    AAAA => 28,
                    _ => 1,
                };

                let cached = {
                    let cache = self.negative_cache.read().await;
                    cache
                        .get(&cache_key)
                        .filter(|e| e.expires_at > Instant::now())
                        .map(|e| e.reason_code)
                };

                let (response_code, record) = if let Some(code) = cached {
                    self.metrics
                        .negative_cache_hit
                        .add(1, &[KeyValue::new("response_code", format!("{code:?}"))]);
                    tracing::debug!(%qname, %qtype, "negative cache hit");
                    tracing::info!(
                        "Returning {} from negative cache for {:?}",
                        format!("{code:?}"),
                        cache_key
                    );
                    (code, None)
                } else {
                    // Build the legacy DnsQuestion request
                    let carbide_dns_request =
                        tonic::Request::new(forge::dns_message::DnsQuestion {
                            q_name: Some(request_info.query.name().to_string()),
                            q_class: Some(1),
                            q_type: Some(q_type_num),
                        });

                    info!("Sending {} to api server", request_info.query.original());

                    match Self::retrieve_record(self.forge_client.clone(), carbide_dns_request)
                        .await
                    {
                        Ok(ip) => {
                            let (rtype, rdata) = match ip {
                                IpAddr::V4(v4) => (A, RData::A(v4.into())),
                                IpAddr::V6(v6) => (AAAA, RData::AAAA(v6.into())),
                            };
                            let dns_record = Record::new()
                                .set_ttl(30)
                                .set_name(Name::from(request_info.query.name()))
                                .set_record_type(rtype)
                                .set_dns_class(DNSClass::IN)
                                .set_data(Some(rdata))
                                .clone();
                            (ResponseCode::NoError, Some(dns_record))
                        }
                        Err(e) => {
                            warn!(
                                "Unable to find record: {} error was {}",
                                request_info.query.name(),
                                e
                            );
                            let code = match e.code() {
                                tonic::Code::NotFound => ResponseCode::NXDomain,
                                tonic::Code::InvalidArgument => ResponseCode::Refused,
                                _ => ResponseCode::ServFail,
                            };

                            if matches!(code, ResponseCode::NXDomain | ResponseCode::Refused) {
                                tracing::debug!(%qname, %qtype, "negative cache miss");
                                tracing::info!(
                                    "Adding {} for {:?} to negative cache",
                                    format!("{code:?}"),
                                    cache_key
                                );
                                let mut cache = self.negative_cache.write().await;
                                cache.insert(
                                    cache_key,
                                    NegativeEntry {
                                        reason_code: code,
                                        expires_at: Instant::now() + self.negative_ttl,
                                    },
                                );
                                self.metrics
                                    .negative_cache_miss
                                    .add(1, &[KeyValue::new("response_code", format!("{code:?}"))]);
                            }

                            (code, None)
                        }
                    }
                };

                response_header.set_response_code(response_code);

                let message = message.build(
                    response_header,
                    &record,
                    iter::empty(),
                    iter::empty(),
                    iter::empty(),
                );

                response_handle.send_response(message).await.unwrap()
            }
            _ => {
                warn!("Unsupported query type: {}", request.query());
                let response = MessageResponseBuilder::from_message_request(request);
                response_handle
                    .send_response(response.error_msg(request.header(), ResponseCode::NotImp))
                    .await
                    .unwrap()
            }
        }
    }
}

impl LegacyDnsServer {
    pub fn new(
        forge_client: Arc<Mutex<ForgeClientT>>,
        negative_ttl: Duration,
        meter: &Meter,
    ) -> Self {
        Self {
            forge_client,
            negative_cache: Arc::new(RwLock::new(HashMap::new())),
            negative_ttl,
            metrics: LegacyDnsMetrics::new(meter),
        }
    }

    async fn retrieve_record(
        forge_client: Arc<Mutex<ForgeClientT>>,
        request: tonic::Request<forge::dns_message::DnsQuestion>,
    ) -> Result<IpAddr, tonic::Status> {
        let mut client = forge_client.lock().await;
        #[allow(deprecated)]
        let response = client.lookup_record_legacy(request).await?.into_inner();

        info!("Received response from API server");

        let record = response
            .rrs
            .first()
            .ok_or_else(|| tonic::Status::internal("Resource Record list is empty".to_string()))?;
        let rdata = record.rdata.as_deref().unwrap_or("");
        let ip = IpAddr::from_str(rdata).map_err(|_e| {
            tonic::Status::internal(format!("Can not parse record data \"{rdata}\" as IP"))
        })?;

        Ok(ip)
    }

    pub async fn run(config: Config, listen: std::net::SocketAddr) -> Result<(), Report> {
        info!(
            "Starting legacy DNS server mode on {} (this mode is deprecated)",
            listen
        );

        let forge_client_config = config.forge_client_config();
        let api_uri = config.carbide_uri.to_string();
        let api_config = ApiConfig::new(api_uri.as_str(), &forge_client_config);

        info!("Connecting to carbide-api at {}", api_uri);

        let client = Arc::new(Mutex::new(ForgeTlsClient::retry_build(&api_config).await?));

        // TODO: make negative_cache_ttl configurable via Config
        let negative_ttl = Duration::from_secs(120);

        let metrics_setup = new_metrics_setup("carbide-dns", "carbide", true)?;

        // Must keep meter_provider alive for the lifetime of the server,
        // otherwise SdkMeterProvider::drop() shuts down the Prometheus exporter.
        let _metrics_guard = metrics_setup.meter_provider;

        let metrics_config = MetricsEndpointConfig {
            address: SocketAddr::from_str("0.0.0.0:8844").expect("Invalid address socket address"),
            registry: metrics_setup.registry,
            health_controller: Some(metrics_setup.health_controller),
        };

        tokio::spawn(async move {
            tracing::info!("Spawning metrics endpoint on {}", metrics_config.address);
            if let Err(e) = run_metrics_endpoint(&metrics_config).await {
                tracing::error!("Metrics endpoint error: {}", e);
            }
        });

        let api = LegacyDnsServer::new(client, negative_ttl, &metrics_setup.meter);

        let cache = api.negative_cache.clone();

        let cache_eviction_counter = api.metrics.negative_cache_eviction.clone();

        // Spawn thread to remove cache entries that have expired
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(negative_ttl);
            loop {
                interval.tick().await;
                let mut cache = cache.write().await;
                let before = cache.len();
                cache.retain(|_, entry| entry.expires_at > Instant::now());
                let evicted = before - cache.len();
                if evicted > 0 {
                    cache_eviction_counter.add(evicted as u64, &[]);
                }
            }
        });

        let mut server = ServerFuture::new(api);
        let udp_socket = UdpSocket::bind(&listen).await?;
        server.register_socket(udp_socket);

        let tcp_socket = TcpListener::bind(&listen).await?;
        server.register_listener(tcp_socket, Duration::new(5, 0));

        info!(
            "Started legacy DNS server on {} version {}",
            listen,
            carbide_version::version!()
        );

        match server.block_until_done().await {
            Ok(()) => {
                info!("Carbide-dns legacy server is stopping");
            }
            Err(e) => {
                let error_msg = format!("Carbide-dns has encountered an error: {e}");
                error!("{}", error_msg);
                return Err(eyre::eyre!("{}", error_msg));
            }
        }
        Ok(())
    }
}
