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

//! Carbide DNS Server
//!
//! Listens directly on a DNS port (UDP/TCP) and resolves queries by forwarding
//! them to carbide-api via the `lookup_record` RPC.

use std::iter;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dns_record::DnsResourceRecordType;
use eyre::Report;
use metrics_endpoint::{MetricsEndpointConfig, new_metrics_setup, run_metrics_endpoint};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Meter};
use rpc::forge_tls_client::{ApiConfig, ForgeClientT, ForgeTlsClient};
use rpc::protos::dns::DnsResourceRecordLookupRequest;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use trust_dns_resolver::proto::op::{Header, ResponseCode};
use trust_dns_resolver::proto::rr::{DNSClass, Name, RData};
use trust_dns_server::ServerFuture;
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::proto::rr::{Record, RecordType};
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

pub mod config;
mod negative_cache;

use crate::config::Config;
use crate::negative_cache::{CacheKey, NegativeCache};

struct DnsMetrics {
    negative_cache_hit: Counter<u64>,
    negative_cache_miss: Counter<u64>,
    negative_cache_eviction: Counter<u64>,
    negative_cache_drop: Counter<u64>,
}

impl DnsMetrics {
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
            negative_cache_drop: meter
                .u64_counter("carbide_dns_negative_cache_drop_count")
                .build(),
        }
    }
}

// DnsMetrics contains OpenTelemetry instrument types which don't implement Debug.
impl std::fmt::Debug for DnsMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsMetrics").finish()
    }
}

#[derive(Debug)]
pub struct DnsServer {
    forge_client: Mutex<ForgeClientT>,
    negative_cache: Arc<NegativeCache>,
    metrics: DnsMetrics,
}

#[async_trait::async_trait]
impl RequestHandler for DnsServer {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let request_info = request.request_info();
        let qtype = request.query().query_type();
        let qname = request_info.query.name().to_string();

        let span = tracing::info_span!("dns_request", %qname, %qtype);
        let _guard = span.enter();

        let start = Instant::now();

        // Only handle types that DnsResourceRecordType supports and that we can build
        // RData for; return NotImp for everything else. Currently, A and AAAA are
        // supported; add arms here as the API and RData parsing are extended.
        let dns_qtype = match DnsResourceRecordType::try_from(qtype.to_string().as_str()) {
            Ok(t @ (DnsResourceRecordType::A | DnsResourceRecordType::AAAA)) => t,
            _ => {
                warn!(%qname, %qtype, "Unsupported query type");
                let response = MessageResponseBuilder::from_message_request(request);
                return response_handle
                    .send_response(response.error_msg(request.header(), ResponseCode::NotImp))
                    .await
                    .unwrap();
            }
        };

        let cache_key = CacheKey {
            qname: qname.clone(),
            qtype,
        };

        let cached = self.negative_cache.get(&cache_key).await;

        let record_name = Name::from(request_info.query.name());
        let message = MessageResponseBuilder::from_message_request(request);
        let mut response_header = Header::response_from_request(request.header());

        let (response_code, records) = if let Some(code) = cached {
            self.metrics
                .negative_cache_hit
                .add(1, &[KeyValue::new("response_code", format!("{code:?}"))]);
            tracing::debug!("Negative cache hit");
            (code, vec![])
        } else {
            // Clone the client out under the lock, then release it so the
            // upstream RPC runs without serializing other in-flight queries.
            let client = {
                let guard = self.forge_client.lock().await;
                guard.clone()
            };
            match Self::retrieve_records(client, &qname, dns_qtype, &record_name).await {
                Ok(records) => {
                    tracing::info!(record_count = records.len(), "DNS lookup succeeded");
                    (ResponseCode::NoError, records)
                }
                Err(e) => {
                    warn!(error = %e, "DNS lookup failed");
                    let code = match e.code() {
                        tonic::Code::NotFound => ResponseCode::NXDomain,
                        tonic::Code::InvalidArgument => ResponseCode::Refused,
                        _ => ResponseCode::ServFail,
                    };

                    if matches!(code, ResponseCode::NXDomain | ResponseCode::Refused) {
                        // Count the upstream negative regardless of whether it
                        // ends up cached below.
                        self.metrics
                            .negative_cache_miss
                            .add(1, &[KeyValue::new("response_code", format!("{code:?}"))]);

                        if self.negative_cache.record(cache_key, code).await {
                            tracing::debug!(%code, "Caching negative response");
                        } else {
                            self.metrics
                                .negative_cache_drop
                                .add(1, &[KeyValue::new("response_code", format!("{code:?}"))]);
                            warn!(
                                %code,
                                max_entries = self.negative_cache.max_entries(),
                                "Negative cache full; not caching this response"
                            );
                        }
                    }

                    (code, vec![])
                }
            }
        };

        let duration = start.elapsed();
        tracing::info!(
            response_code = ?response_code,
            record_count = records.len(),
            duration_ms = duration.as_millis(),
            "Request completed"
        );

        response_header.set_response_code(response_code);
        let message = message.build(
            response_header,
            records.iter(),
            iter::empty(),
            iter::empty(),
            iter::empty(),
        );

        response_handle.send_response(message).await.unwrap()
    }
}

impl DnsServer {
    pub fn new(forge_client: Mutex<ForgeClientT>, meter: &Meter, config: &Config) -> Self {
        Self {
            forge_client,
            negative_cache: Arc::new(NegativeCache::new(
                Duration::from_secs(config.negative_cache_ttl_secs),
                config.negative_cache_entries_max_count as usize,
            )),
            metrics: DnsMetrics::new(meter),
        }
    }

    /// Queries carbide-api for DNS records matching `qname` and `qtype`, then
    /// converts the results into trust-dns `Record` objects ready for the response.
    async fn retrieve_records(
        mut forge_client: ForgeClientT,
        qname: &str,
        qtype: DnsResourceRecordType,
        record_name: &Name,
    ) -> Result<Vec<Record>, tonic::Status> {
        let span = tracing::debug_span!("retrieve_records", %qname, %qtype);
        let _guard = span.enter();

        let request = tonic::Request::new(DnsResourceRecordLookupRequest {
            qtype: qtype.to_string(),
            qname: qname.to_string(),
            zone_id: "-1".to_string(),
            local: None,
            remote: None,
            real_remote: None,
        });

        let api_start = Instant::now();
        let response = forge_client.lookup_record(request).await?.into_inner();
        let api_duration = api_start.elapsed();

        tracing::debug!(
            record_count = response.records.len(),
            duration_ms = api_duration.as_millis(),
            "API lookup completed"
        );

        let records = response
            .records
            .into_iter()
            // The API returns all record types for the qname; keep only the requested type.
            .filter(|r| DnsResourceRecordType::try_from(r.qtype.as_str()).ok() == Some(qtype))
            .filter_map(|r| {
                let (record_type, rdata) = match qtype {
                    DnsResourceRecordType::A => {
                        let ip = r.content.parse::<std::net::Ipv4Addr>().map_err(|e| {
                            warn!(content = %r.content, error = %e, "Failed to parse IPv4 address");
                            e
                        }).ok()?;
                        (RecordType::A, RData::A(ip.into()))
                    }
                    DnsResourceRecordType::AAAA => {
                        let ip = r.content.parse::<std::net::Ipv6Addr>().map_err(|e| {
                            warn!(content = %r.content, error = %e, "Failed to parse IPv6 address");
                            e
                        }).ok()?;
                        (RecordType::AAAA, RData::AAAA(ip.into()))
                    }
                    // Unreachable: handle_request only dispatches A and AAAA to this function.
                    _ => return None,
                };
                Some(
                    Record::new()
                        .set_ttl(r.ttl)
                        .set_name(record_name.clone())
                        .set_record_type(record_type)
                        .set_dns_class(DNSClass::IN)
                        .set_data(Some(rdata))
                        .clone(),
                )
            })
            .collect::<Vec<_>>();

        tracing::debug!(
            filtered_record_count = records.len(),
            "Records after filtering by qtype"
        );

        if records.is_empty() {
            return Err(tonic::Status::not_found(format!(
                "No {} records found for {}",
                qtype, qname
            )));
        }

        Ok(records)
    }

    pub async fn run(config: Config) -> Result<(), Report> {
        let listen = config.listen_address;

        info!("Starting DNS server on {}", listen);

        let forge_client_config = config.forge_client_config();
        let api_uri = config.api_uri.to_string();
        let api_config = ApiConfig::new(api_uri.as_str(), &forge_client_config);

        info!("Connecting to carbide-api at {}", api_uri);

        let client = Mutex::new(ForgeTlsClient::retry_build(&api_config).await?);

        let negative_ttl = Duration::from_secs(config.negative_cache_ttl_secs);

        let metrics_setup = new_metrics_setup("carbide-dns", "carbide", true)?;

        // Must keep meter_provider alive for the lifetime of the server;
        // dropping it shuts down the Prometheus exporter.
        let _metrics_guard = metrics_setup.meter_provider;

        let metrics_config = MetricsEndpointConfig {
            address: config.metrics_listen_address,
            registry: metrics_setup.registry,
            health_controller: Some(metrics_setup.health_controller),
        };

        tokio::spawn(async move {
            tracing::info!("Spawning metrics endpoint on {}", metrics_config.address);
            if let Err(e) = run_metrics_endpoint(&metrics_config).await {
                tracing::error!("Metrics endpoint error: {}", e);
            }
        });

        let server = DnsServer::new(client, &metrics_setup.meter, &config);

        let cache = server.negative_cache.clone();
        let cache_eviction_counter = server.metrics.negative_cache_eviction.clone();

        // Periodically remove expired negative cache entries.
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(negative_ttl);
            loop {
                interval.tick().await;
                let evicted = cache.evict_expired().await;
                if evicted > 0 {
                    cache_eviction_counter.add(evicted as u64, &[]);
                }
            }
        });

        let mut srv = ServerFuture::new(server);
        let udp_socket = UdpSocket::bind(&listen).await?;
        srv.register_socket(udp_socket);

        let tcp_socket = TcpListener::bind(&listen).await?;
        srv.register_listener(tcp_socket, Duration::new(5, 0));

        info!(
            "Started DNS server on {} version {}",
            listen,
            carbide_version::version!()
        );

        match srv.block_until_done().await {
            Ok(()) => {
                info!("Carbide-dns server is stopping");
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
