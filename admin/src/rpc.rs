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

pub async fn with_forge_client<T, F>(
    server: String,
    callback: impl FnOnce(rpc::forge_client::ForgeClient<Channel>) -> F,
) -> CarbideCliResult<T>
where
    F: Future<Output = CarbideCliResult<T>>,
{
    let client = rpc::forge_client::ForgeClient::connect(server)
        .await
        .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

    callback(client)
        .await
        .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))
}

pub async fn get_machine(id: String, server: String) -> CarbideCliResult<rpc::Machine> {
    with_forge_client(server, |mut client| async move {
        let request = tonic::Request::new(rpc::Uuid { value: id });
        let machine_details = client
            .get_machine(request)
            .await
            .map(|response| response.into_inner())
            .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

        Ok(machine_details)
    })
    .await
}

pub async fn get_all_machines(server: String) -> CarbideCliResult<rpc::MachineList> {
    with_forge_client(server, |mut client| async move {
        let request = tonic::Request::new(rpc::MachineSearchQuery {
            id: None,
            fqdn: None,
        });
        let machine_details = client
            .find_machines(request)
            .await
            .map(|response| response.into_inner())
            .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

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
            .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

        Ok(instance_details)
    })
    .await
}

pub async fn get_instances_by_machine_id(
    server: String,
    id: String,
) -> CarbideCliResult<rpc::InstanceList> {
    with_forge_client(server, |mut client| async move {
        let request = tonic::Request::new(rpc::Uuid { value: id });
        let instance_details = client
            .find_instance_by_machine_id(request)
            .await
            .map(|response| response.into_inner())
            .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

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
            .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

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
            .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

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
            .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

        Ok(cred)
    })
    .await
}
