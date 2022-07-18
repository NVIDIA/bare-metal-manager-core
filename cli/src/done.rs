use rpc::forge::v0 as rpc;
use cli::{CarbideClientError, CarbideClientResult};
use tonic::Response;

pub struct Done {}

impl Done {
    pub async fn run(
        listen: String,
        uuid: &str,
    ) -> CarbideClientResult<Response<rpc::Machine>> {
        let rpc_uuid: rpc::Uuid = uuid::Uuid::parse_str(uuid)
            .map(|m| m.into())
            .map_err(|e| CarbideClientError::GenericError(e.to_string()))?;
        let mut client = rpc::forge_client::ForgeClient::connect(listen).await?;
        let request = tonic::Request::new(rpc_uuid);
        Ok(client.done(request).await?)
    }

}


