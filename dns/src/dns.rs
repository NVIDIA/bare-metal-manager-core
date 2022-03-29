extern crate trust_dns_server;

use color_eyre::Report;
use log::info;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

use rpc::v0::metal_client::MetalClient;

use crate::cfg;

#[derive(Debug)]
pub struct DnsServer;

pub struct Carbide;

struct DnsMessage {}

#[async_trait::async_trait]
impl RequestHandler for DnsMessage {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        todo!()
    }
}

/*
impl Metal for Dns {
   async fn lookup(
     &self,
     request: Request<rpc::v0::Lookup>,
   ) -> Result<ResponseInfo, Status>  {
       todo!()
   }

}
*/

impl DnsServer {
    pub async fn run(daemon_config: &cfg::Daemon) -> Result<(), Report> {
        info!("Starting DNS server on {:?}", daemon_config.listen[0]);

        let api_connection = Carbide {
           //carbide_client: MetalClient::connect(daemon_config.carbide_url.to_string()).await?
       };

        Ok(())
    }
}
