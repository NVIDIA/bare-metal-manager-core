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

use std::iter;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use eyre::Report;
use rpc::forge_tls_client::{ApiConfig, ForgeClientT, ForgeTlsClient};
use rpc::protos::forge;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use trust_dns_resolver::proto::op::{Header, ResponseCode};
use trust_dns_resolver::proto::rr::{DNSClass, Name, RData};
use trust_dns_server::ServerFuture;
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::proto::rr::Record;
use trust_dns_server::proto::rr::RecordType::A;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

use crate::config::Config;

#[derive(Debug)]
pub struct LegacyDnsServer {
    forge_client: Arc<Mutex<ForgeClientT>>,
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

        match request.query().query_type() {
            A => {
                // Build the legacy DnsQuestion request
                let carbide_dns_request = tonic::Request::new(forge::dns_message::DnsQuestion {
                    q_name: Some(request_info.query.name().to_string()),
                    q_class: Some(1),
                    q_type: Some(1),
                });

                info!("Sending {} to api server", request_info.query.original());

                let record: Option<Record> =
                    match Self::retrieve_record(self.forge_client.clone(), carbide_dns_request)
                        .await
                    {
                        Ok(value) => {
                            response_header.set_response_code(ResponseCode::NoError);
                            let a_record = Record::new()
                                .set_ttl(30)
                                .set_name(Name::from(request_info.query.name()))
                                .set_record_type(A)
                                .set_dns_class(DNSClass::IN)
                                .set_data(Some(RData::A(value.into())))
                                .clone();
                            Some(a_record)
                        }
                        Err(e) => {
                            warn!(
                                "Unable to find record: {} error was {}",
                                request_info.query.name(),
                                e
                            );
                            response_header.set_response_code(match e.code() {
                                tonic::Code::NotFound => ResponseCode::NXDomain,
                                tonic::Code::InvalidArgument => ResponseCode::Refused,
                                _ => ResponseCode::ServFail, // All kinds of internal errors
                            });

                            None
                        }
                    };

                let message = message.build(
                    response_header,
                    &record,
                    iter::empty(),
                    iter::empty(),
                    iter::empty(),
                );

                let response_info = response_handle.send_response(message).await;
                response_info.unwrap()
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
    pub fn new(forge_client: Arc<Mutex<ForgeClientT>>) -> Self {
        Self { forge_client }
    }

    async fn retrieve_record(
        forge_client: Arc<Mutex<ForgeClientT>>,
        request: tonic::Request<forge::dns_message::DnsQuestion>,
    ) -> Result<Ipv4Addr, tonic::Status> {
        let mut client = forge_client.lock().await;
        #[allow(deprecated)]
        let response = client.lookup_record_legacy(request).await?.into_inner();

        info!("Received response from API server");

        let record = response
            .rrs
            .first()
            .ok_or_else(|| tonic::Status::internal("Resource Record list is empty".to_string()))?;
        let ip =
            Ipv4Addr::from_str(record.rdata.as_ref().unwrap_or(&String::new())).map_err(|_e| {
                tonic::Status::internal(format!(
                    "Can not parse record data \"{}\" as IP",
                    record.rdata.as_ref().unwrap_or(&String::new())
                ))
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

        let api = LegacyDnsServer::new(client);

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
