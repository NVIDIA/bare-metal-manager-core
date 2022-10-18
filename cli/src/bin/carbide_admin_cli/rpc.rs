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

use super::{CarbideCliError, CarbideCliResult};

pub async fn get_machine(id: String, server: String) -> CarbideCliResult<rpc::Machine> {
    let mut client = rpc::forge_client::ForgeClient::connect(server)
        .await
        .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

    let request = tonic::Request::new(rpc::Uuid { value: id });
    let machine_details = client
        .get_machine(request)
        .await
        .map(|response| response.into_inner())
        .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

    Ok(machine_details)
}

pub async fn get_all_machines(server: String) -> CarbideCliResult<rpc::MachineList> {
    let mut client = rpc::forge_client::ForgeClient::connect(server)
        .await
        .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

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
}

pub async fn get_instances(
    server: String,
    id: Option<String>,
) -> CarbideCliResult<rpc::InstanceList> {
    let mut client = rpc::forge_client::ForgeClient::connect(server)
        .await
        .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

    let request = tonic::Request::new(rpc::InstanceSearchQuery {
        id: id.map(|x| rpc::Uuid { value: x }),
    });
    let instance_details = client
        .find_instances(request)
        .await
        .map(|response| response.into_inner())
        .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

    Ok(instance_details)
}

pub async fn get_instances_by_machine_id(
    server: String,
    id: String,
) -> CarbideCliResult<rpc::InstanceList> {
    let mut client = rpc::forge_client::ForgeClient::connect(server)
        .await
        .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

    let request = tonic::Request::new(rpc::Uuid { value: id });
    let instance_details = client
        .find_instance_by_machine_id(request)
        .await
        .map(|response| response.into_inner())
        .map_err(|x| CarbideCliError::ApiConnectFailed(x.to_string()))?;

    Ok(instance_details)
}
