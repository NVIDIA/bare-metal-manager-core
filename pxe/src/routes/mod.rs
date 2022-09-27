pub mod cloud_init;
pub mod ipxe;

use ::rpc::forge::v0 as rpc;

pub struct RpcContext;

impl RpcContext {
    async fn get_instance(machine_id: rpc::Uuid, url: String) -> Result<rpc::Instance, String> {
        match rpc::forge_client::ForgeClient::connect(url).await {
            Ok(mut client) => {
                let request = tonic::Request::new(machine_id.clone());

                client
                    .find_instance_by_machine_id(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| {
                        format!(
                            "unable to find instance for machine {} via Carbide: {:?}",
                            machine_id, error
                        )
                    })
            }
            Err(err) => Err(format!("unable to connect to Carbide API: {:?}", err)),
        }
    }
}
