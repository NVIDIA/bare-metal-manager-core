//extern crate trust_dns_server;

use std::iter;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use color_eyre::Report;
use log::{error, info, warn};
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::client::op::{Header, ResponseCode};
use trust_dns_server::client::rr::{DNSClass, Name, RData};
use trust_dns_server::proto::rr::Record;
use trust_dns_server::proto::rr::RecordType::{A, PTR, SOA};
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use trust_dns_server::ServerFuture;

use rpc::v0 as rpc;

use crate::cfg;

#[derive(Debug)]
pub struct DnsServer;

#[derive(Debug)]
struct DnsRequest;

struct DnsReply(ResponseInfo);

struct Carbide {
    api_endpoint: String,
}

impl Carbide {
    fn new(url: String) -> Self {
        Self { api_endpoint: url }
    }
}

impl DnsReply {
    pub fn serve_failed() -> ResponseInfo {
        let mut header = Header::new();
        header.set_response_code(ResponseCode::ServFail);
        header.into()
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsRequest {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        match request.query().query_type() {
            a => {
                let mut response_header = Header::response_from_request(request.header());

                let mut x = Record::new()
                    .set_ttl(30)
                    .set_record_type(A)
                    .set_name(Name::from_str("foo.bar.com").unwrap())
                    .set_data(Some(RData::A(Ipv4Addr::new(192, 168, 2, 2))))
                    .set_dns_class(DNSClass::IN)
                    .clone();

                let mut message = MessageResponseBuilder::from_message_request(request).build(
                    response_header,
                    iter::once(&x),
                    iter::once(&x),
                    iter::once(&x),
                    iter::empty(),
                );

                let foo = response_handle.send_response(message).await;
                foo.unwrap()
            }
            CNAME => {
                todo!()
            }
            PTR => {
                todo!()
            }
            SOA => {
                todo!()
            }
            _ => {
                error!("Unsupported query type");
                DnsReply::serve_failed()
            } //DnsReply::serve_failed()
        }
    }
}

impl DnsServer {
    pub async fn run(daemon_config: &cfg::Daemon) -> Result<(), Report> {
        let url = daemon_config.carbide_url.to_string();

        info!("Connecting to carbide-api at {:?}", &url);

        match rpc::metal_client::MetalClient::connect(String::from(&url)).await {
            Ok(mut client) => {
                todo!()
            }
            Err(err) => {
                let error_message = format!("Unable to connect to carbide-api at: {}", &url);
                error!("{}", error_message);
                panic!("{}", error_message);
            }
        }

        info!("Starting DNS server on {:?}", daemon_config.listen[0]);

        let mut server = ServerFuture::new(DnsRequest);

        let udp_socket = UdpSocket::bind("127.0.0.1:5356").await?;
        server.register_socket(udp_socket);

        let tcp_socket = TcpListener::bind("127.0.0.1:5356").await?;
        server.register_listener(tcp_socket, Duration::new(5, 0));

        match server.block_until_done().await {
            Ok(()) => {
                info!("Carbide-dns is stopping");
            }
            Err(e) => {
                let error_msg = format!("Carbide-dns has encountered and error: {}", e);
                error!("{}", error_msg);
                panic!("{}", error_msg);
            }
        }
        Ok(())
    }
}
