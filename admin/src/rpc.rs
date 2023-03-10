use std::future::Future;

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
use ::rpc::forge as rpc;
use tonic::transport::Channel;

use super::{CarbideCliError, CarbideCliResult};
use crate::cfg::carbide_options::ForceDeleteMachineQuery;

pub async fn with_forge_client<T, F>(
    server: String,
    callback: impl FnOnce(rpc::forge_client::ForgeClient<Channel>) -> F,
) -> CarbideCliResult<T>
where
    F: Future<Output = CarbideCliResult<T>>,
{
    let client = rpc::forge_client::ForgeClient::connect(server)
        .await
        .map_err(CarbideCliError::ApiConnectFailed)?;

    callback(client).await
}

pub async fn get_machine(id: String, server: String) -> CarbideCliResult<rpc::Machine> {
    with_forge_client(server, |mut client| async move {
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

pub async fn get_all_machines(server: String) -> CarbideCliResult<rpc::MachineList> {
    with_forge_client(server, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineSearchQuery {
            id: None,
            fqdn: None,
            search_config: None,
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
    server: String,
    id: Option<String>,
) -> CarbideCliResult<rpc::InstanceList> {
    with_forge_client(server, |mut client| async move {
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
    server: String,
    id: String,
) -> CarbideCliResult<rpc::InstanceList> {
    with_forge_client(server, |mut client| async move {
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
    server: String,
) -> CarbideCliResult<rpc::NetworkSegmentList> {
    with_forge_client(server, |mut client| async move {
        let request = tonic::Request::new(rpc::NetworkSegmentQuery { id });
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
    server: String,
) -> CarbideCliResult<rpc::DomainList> {
    with_forge_client(server, |mut client| async move {
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
    server: String,
) -> CarbideCliResult<rpc::CredentialResponse> {
    with_forge_client(server, |mut client| async move {
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

pub async fn machine_admin_force_delete(
    query: ForceDeleteMachineQuery,
    server: String,
) -> CarbideCliResult<::rpc::forge::AdminForceDeleteMachineResponse> {
    with_forge_client(server, |mut client| async move {
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
    server: String,
    ip: String,
    port: Option<u32>,
    auth: RebootAuth,
) -> CarbideCliResult<rpc::AdminRebootResponse> {
    with_forge_client(server, |mut client| async move {
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
