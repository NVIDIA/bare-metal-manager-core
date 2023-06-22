use std::future::Future;

use ::rpc::forge::{self as rpc, MachineType, NetworkSegmentSearchConfig};
use ::rpc::forge_tls_client::{self, ForgeClientT};

use super::{CarbideCliError, CarbideCliResult};
use crate::cfg::carbide_options::ForceDeleteMachineQuery;
use crate::Config;

/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
pub async fn with_forge_client<T, F>(
    api_config: Config,
    callback: impl FnOnce(ForgeClientT) -> F,
) -> CarbideCliResult<T>
where
    F: Future<Output = CarbideCliResult<T>>,
{
    let client = forge_tls_client::ForgeTlsClient::new(api_config.forge_root_ca_path)
        .connect(api_config.carbide_api_url)
        .await
        .map_err(|err| CarbideCliError::ApiConnectFailed(err.to_string()))?;

    callback(client).await
}

pub async fn get_machine(id: String, api_config: Config) -> CarbideCliResult<rpc::Machine> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineId { id });
        let machine_details = client
            .get_machine(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(machine_details)
    })
    .await
}

pub async fn get_host_machine(id: String, api_config: Config) -> CarbideCliResult<rpc::Machine> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineSearchQuery {
            id: Some(rpc::MachineId { id: id.clone() }),
            fqdn: None,
            search_config: Some(rpc::MachineSearchConfig {
                include_dpus: false,
                include_history: false,
                include_predicted_host: true,
            }),
        });

        let machine_details = client
            .find_machines(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        machine_details
            .machines
            .first()
            .ok_or(CarbideCliError::MachineNotFound(rpc::MachineId { id }))
            .cloned()
    })
    .await
}

pub async fn get_dpu_machine(id: String, api_config: Config) -> CarbideCliResult<rpc::Machine> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineSearchQuery {
            id: Some(rpc::MachineId { id: id.clone() }),
            fqdn: None,
            search_config: Some(rpc::MachineSearchConfig {
                include_dpus: true,
                include_history: false,
                include_predicted_host: false,
            }),
        });

        let machine_details = client
            .find_machines(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        let machine = machine_details
            .machines
            .into_iter()
            .next()
            .ok_or(CarbideCliError::MachineNotFound(rpc::MachineId { id }))?;

        if machine.machine_type() == MachineType::Dpu {
            Ok(machine)
        } else {
            Err(CarbideCliError::UnexpectedMachineType(
                rpc::MachineType::Dpu,
                machine.machine_type(),
            ))
        }
    })
    .await
}

pub async fn get_all_machines(api_config: Config) -> CarbideCliResult<rpc::MachineList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineSearchQuery {
            id: None,
            fqdn: None,
            search_config: Some(rpc::MachineSearchConfig {
                include_dpus: true,
                include_history: true,
                include_predicted_host: true,
            }),
        });
        let machine_details = client
            .find_machines(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(machine_details)
    })
    .await
}

pub async fn get_instances(
    api_config: Config,
    id: Option<String>,
) -> CarbideCliResult<rpc::InstanceList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::InstanceSearchQuery {
            id: id.map(|x| rpc::Uuid { value: x }),
        });
        let instance_details = client
            .find_instances(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(instance_details)
    })
    .await
}

pub async fn get_instances_by_machine_id(
    api_config: Config,
    id: String,
) -> CarbideCliResult<rpc::InstanceList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineId { id });
        let instance_details = client
            .find_instance_by_machine_id(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(instance_details)
    })
    .await
}

pub async fn get_segments(
    id: Option<rpc::Uuid>,
    api_config: Config,
) -> CarbideCliResult<rpc::NetworkSegmentList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::NetworkSegmentQuery {
            id,
            search_config: Some(NetworkSegmentSearchConfig {
                include_history: true,
            }),
        });
        let networks = client
            .find_network_segments(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(networks)
    })
    .await
}

pub async fn get_domains(
    id: Option<rpc::Uuid>,
    api_config: Config,
) -> CarbideCliResult<rpc::DomainList> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::DomainSearchQuery { id, name: None });
        let networks = client
            .find_domain(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(networks)
    })
    .await
}

pub async fn get_dpu_ssh_credential(
    query: String,
    api_config: Config,
) -> CarbideCliResult<rpc::CredentialResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::CredentialRequest { host_id: query });
        let cred = client
            .get_dpu_ssh_credential(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(cred)
    })
    .await
}

pub async fn get_all_managed_host_network_status(
    api_config: Config,
) -> CarbideCliResult<rpc::ManagedHostNetworkStatusResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::ManagedHostNetworkStatusRequest {});
        let all = client
            .get_all_managed_host_network_status(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(all)
    })
    .await
}

pub async fn get_managed_host_network_config(
    id: String,
    api_config: Config,
) -> CarbideCliResult<rpc::ManagedHostNetworkConfigResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(rpc::ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(rpc::MachineId { id }),
        });
        let all = client
            .get_managed_host_network_config(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(all)
    })
    .await
}

pub async fn machine_admin_force_delete(
    query: ForceDeleteMachineQuery,
    api_config: Config,
) -> CarbideCliResult<::rpc::forge::AdminForceDeleteMachineResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(::rpc::forge::AdminForceDeleteMachineRequest {
            host_query: query.machine,
        });
        let response = client
            .admin_force_delete_machine(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;

        Ok(response)
    })
    .await
}

// How will we find the BMC credentials to perform the reboot?
pub enum RebootAuth {
    // User provided them directly on command line
    Direct { user: String, password: String },
    // Carbide should look them up in Vault
    Indirect { machine_id: String },
}

pub async fn reboot(
    api_config: Config,
    ip: String,
    port: Option<u32>,
    auth: RebootAuth,
) -> CarbideCliResult<rpc::AdminRebootResponse> {
    with_forge_client(api_config, |mut client| async move {
        let (user, password, machine_id) = match auth {
            RebootAuth::Direct { user, password } => (Some(user), Some(password), None),
            RebootAuth::Indirect { machine_id } => (None, None, Some(machine_id)),
        };
        let request = tonic::Request::new(rpc::AdminRebootRequest {
            ip,
            port,
            user,
            password,
            machine_id,
        });
        let out = client
            .admin_reboot(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn define_resource_pool(
    req: rpc::DefineResourcePoolRequest,
    api_config: Config,
) -> CarbideCliResult<rpc::DefineResourcePoolResponse> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(req);
        let out = client
            .admin_define_resource_pool(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn list_resource_pools(
    req: rpc::ListResourcePoolsRequest,
    api_config: Config,
) -> CarbideCliResult<rpc::ResourcePools> {
    with_forge_client(api_config, |mut client| async move {
        let request = tonic::Request::new(req);
        let out = client
            .admin_list_resource_pools(request)
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}

pub async fn version(api_config: &Config) -> CarbideCliResult<rpc::VersionResult> {
    with_forge_client(api_config.clone(), |mut client| async move {
        let out = client
            .version(tonic::Request::new(()))
            .await
            .map(|response| response.into_inner())
            .map_err(CarbideCliError::ApiInvocationError)?;
        Ok(out)
    })
    .await
}
