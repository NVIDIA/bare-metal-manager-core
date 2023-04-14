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
use std::iter;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{self, ForgeClientT};
use eyre::Report;
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::client::op::{Header, ResponseCode};
use trust_dns_server::client::rr::{DNSClass, Name, RData};
use trust_dns_server::proto::op::ResponseCode::{NXDomain, NoError};
use trust_dns_server::proto::rr::Record;
use trust_dns_server::proto::rr::RecordType::A;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use trust_dns_server::ServerFuture;

use crate::cfg;

#[derive(Debug, Default)]
pub struct DnsServer {
    url: String,
    forge_root_ca_path: String,
}

#[async_trait::async_trait]
impl RequestHandler for DnsServer {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let request_info = request.request_info();

        let mut response_header = Header::response_from_request(request.header());

        let message = MessageResponseBuilder::from_message_request(request);

        //TODO: i need to figure out how to inject the root ca path into this pod.  probably the same as the other ones but for now just leave it.
        let client = forge_tls_client::ForgeTlsClient::new(self.forge_root_ca_path.clone())
            .connect(self.url.clone())
            .await
            .unwrap_or_else(|err| {
                panic!(
                    "Unable to connect to carbide-api at: {}, error was: {}",
                    &self.url, err
                )
            });

        match request.query().query_type() {
            A => {
                // TODO After examining what is included as part of request_info.query(), class and type are already
                // included.  We can simplify DnsQuestion to one field "query" which we can deconstruct on the receiving
                // side.
                let carbide_dns_request = tonic::Request::new(rpc::dns_message::DnsQuestion {
                    q_name: Some(request_info.query.name().to_string()),
                    q_class: Some(1),
                    q_type: Some(1),
                });

                log::info!("Sending {} to api server", request_info.query.original());

                let record: Option<Record> =
                    match DnsServer::retrieve_record(client, carbide_dns_request).await {
                        Ok(value) => {
                            response_header.set_response_code(NoError);
                            let a_record = Record::new()
                                .set_ttl(30)
                                .set_name(Name::from(request_info.query.name()))
                                .set_record_type(A)
                                .set_dns_class(DNSClass::IN)
                                .set_data(Some(RData::A(value)))
                                .clone();
                            Some(a_record)
                        }
                        Err(e) => {
                            log::warn!(
                                "Unable to find record: {} error was {}",
                                request_info.query.name(),
                                e
                            );
                            response_header.set_response_code(NXDomain);
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
                log::warn!("Unsupported query type: {}", request.query());
                let response = MessageResponseBuilder::from_message_request(request);
                response_handle
                    .send_response(response.error_msg(request.header(), ResponseCode::NotImp))
                    .await
                    .unwrap()
            }
        }
    }
}

impl DnsServer {
    pub fn new(url: &str, forge_root_ca_path: String) -> Self {
        Self {
            url: url.into(),
            forge_root_ca_path,
        }
    }

    pub async fn retrieve_record(
        mut client: ForgeClientT,
        request: tonic::Request<rpc::dns_message::DnsQuestion>,
    ) -> Result<Ipv4Addr, Report> {
        let response = client.lookup_record(request).await?;

        log::info!("Received response from API server");

        response
            .into_inner()
            .rrs
            .into_iter()
            .map(|r| Ipv4Addr::from_str(r.rdata.unwrap().as_ref()).map_err(Report::from))
            .next()
            .unwrap()
    }

    pub async fn run(daemon_config: &cfg::Daemon) -> Result<(), Report> {
        let carbide_url = daemon_config.carbide_url.clone();
        let forge_root_ca_path = std::env::var("FORGE_ROOT_CA_PATH")
            .unwrap_or_else(|_| "dev/certs/forge_root.pem".to_string());

        let api = DnsServer::new(&carbide_url, forge_root_ca_path);

        log::info!("Connecting to carbide-api at {:?}", &carbide_url);

        let mut server = ServerFuture::new(api);

        let udp_socket = UdpSocket::bind(&daemon_config.listen).await?;
        server.register_socket(udp_socket);

        let tcp_socket = TcpListener::bind(&daemon_config.listen).await?;
        server.register_listener(tcp_socket, Duration::new(5, 0));

        log::info!("Started DNS server on {:?}", &daemon_config.listen);

        match server.block_until_done().await {
            Ok(()) => {
                log::info!("Carbide-dns is stopping");
            }
            Err(e) => {
                let error_msg = format!("Carbide-dns has encountered and error: {}", e);
                log::error!("{}", error_msg);
                panic!("{}", error_msg);
            }
        }
        Ok(())
    }
}
