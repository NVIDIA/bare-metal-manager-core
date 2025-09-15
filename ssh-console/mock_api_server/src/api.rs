use crate::MockApiServer;
use crate::generated::forge::forge_server::Forge;
use crate::generated::forge::{
    BmcMetaDataGetResponse, BuildInfo, InstanceList, InstanceSearchQuery, InstancesByIdsRequest,
    Machine, ValidateTenantPublicKeyRequest, ValidateTenantPublicKeyResponse, VersionRequest,
};
use crate::generated::{common, forge};
use forge_uuid::machine::MachineId;
use forge_version::v;
use tonic::{Request, Response, Status};
use uuid::Uuid;

#[tonic::async_trait]
impl Forge for MockApiServer {
    async fn version(
        &self,
        _request: Request<VersionRequest>,
    ) -> Result<Response<BuildInfo>, Status> {
        Ok(Response::new(BuildInfo {
            build_version: v!(build_version).to_string(),
            build_date: v!(build_date).to_string(),
            git_sha: v!(git_sha).to_string(),
            rust_version: v!(rust_version).to_string(),
            build_user: v!(build_user).to_string(),
            build_hostname: v!(build_hostname).to_string(),
            runtime_config: None,
        }))
    }

    async fn validate_tenant_public_key(
        &self,
        request: Request<ValidateTenantPublicKeyRequest>,
    ) -> Result<Response<ValidateTenantPublicKeyResponse>, Status> {
        let request = request.into_inner();
        let Ok(instance_id) = request.instance_id.parse::<Uuid>() else {
            return Err(Status::invalid_argument("Invalid instance ID"));
        };

        let Some(mock_host) = self
            .mock_hosts
            .iter()
            .find(|host| host.instance_id == instance_id)
        else {
            return Err(Status::not_found(format!(
                "No instance found with ID {instance_id}"
            )));
        };

        let pub_key_split = mock_host
            .tenant_public_key
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        let pub_key_base64 = if pub_key_split.len() == 1 {
            pub_key_split[0]
        } else {
            pub_key_split[1]
        };

        if pub_key_base64 == request.tenant_public_key {
            Ok(Response::new(ValidateTenantPublicKeyResponse {}))
        } else {
            Err(Status::internal("Public key does not match"))
        }
    }

    async fn find_instances_by_ids(
        &self,
        request: Request<InstancesByIdsRequest>,
    ) -> Result<Response<InstanceList>, Status> {
        let request = request.into_inner();
        let mock_instances = request
            .instance_ids
            .iter()
            .filter_map(|instance_id| {
                self.mock_hosts
                    .iter()
                    .find(|h| {
                        h.instance_id.to_string().to_lowercase() == instance_id.value.to_lowercase()
                    })
                    .map(|h| (instance_id, h))
            })
            .collect::<Vec<_>>();

        let instances = mock_instances
            .into_iter()
            .map(|(instance_id, mock_host)| forge::Instance {
                id: Some(instance_id.clone()),
                machine_id: Some(mock_host.machine_id),
                ..Default::default()
            })
            .collect::<Vec<_>>();

        Ok(Response::new(forge::InstanceList { instances }))
    }

    async fn get_machine(&self, request: Request<MachineId>) -> Result<Response<Machine>, Status> {
        let machine_id = request.into_inner();
        let Some(mock_host) = self
            .mock_hosts
            .iter()
            .find(|mock_host| mock_host.machine_id == machine_id)
        else {
            return Err(Status::not_found(format!(
                "No machine found with ID {machine_id}"
            )));
        };

        Ok(Response::new(mock_host.clone().into()))
    }

    async fn get_bmc_meta_data(
        &self,
        request: tonic::Request<forge::BmcMetaDataGetRequest>,
    ) -> std::result::Result<tonic::Response<forge::BmcMetaDataGetResponse>, tonic::Status> {
        let request = request.into_inner();
        let Some(machine_id) = request.machine_id else {
            return Err(Status::invalid_argument("Missing machine ID"));
        };

        let Some(mock_host) = self
            .mock_hosts
            .iter()
            .find(|mock_host| mock_host.machine_id == machine_id)
        else {
            return Err(Status::not_found("No machine with that ID"));
        };

        Ok(Response::new(BmcMetaDataGetResponse {
            ip: mock_host.bmc_ip.to_string(),
            user: mock_host.bmc_user.clone(),
            password: mock_host.bmc_password.clone(),
            ssh_port: mock_host.bmc_ssh_port.map(Into::into),
            ipmi_port: mock_host.ipmi_port.map(Into::into),
            ..Default::default()
        }))
    }

    async fn find_machine_ids(
        &self,
        _request: Request<forge::MachineSearchConfig>,
    ) -> Result<Response<common::MachineIdList>, Status> {
        Ok(Response::new(common::MachineIdList {
            machine_ids: self
                .mock_hosts
                .iter()
                .map(|mock_host| mock_host.machine_id)
                .collect(),
        }))
    }

    async fn find_machines_by_ids(
        &self,
        request: Request<forge::MachinesByIdsRequest>,
    ) -> Result<Response<forge::MachineList>, Status> {
        Ok(Response::new(forge::MachineList {
            machines: request
                .into_inner()
                .machine_ids
                .into_iter()
                .filter_map(|machine_id| {
                    self.mock_hosts
                        .iter()
                        .find(|mock_host| mock_host.machine_id == machine_id)
                        .cloned()
                })
                .map(Into::into)
                .collect(),
        }))
    }

    async fn find_instances(
        &self,
        request: Request<InstanceSearchQuery>,
    ) -> Result<Response<InstanceList>, Status> {
        let Some(instance_id) = request.into_inner().id else {
            return Err(Status::invalid_argument("Missing instance ID"));
        };

        let Some(mock_host) = self.mock_hosts.iter().find(|mock_host| {
            mock_host.instance_id.to_string().to_lowercase() == instance_id.value.to_lowercase()
        }) else {
            return Err(Status::not_found(format!(
                "No instance found with id {}",
                instance_id.value
            )));
        };

        Ok(Response::new(InstanceList {
            instances: vec![mock_host.clone().into()],
        }))
    }
}
