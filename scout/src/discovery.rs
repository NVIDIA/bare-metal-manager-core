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

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client;

use crate::CarbideClientError;

pub async fn run(forge_api: &str, machine_id: &str) -> Result<(), CarbideClientError> {
    let mut client = forge_tls_client::ForgeTlsClient::new(None)
        .connect(forge_api)
        .await
        .map_err(|err| CarbideClientError::GenericError(err.to_string()))?;
    if let Err(err) = crate::users::create_users(&mut client, machine_id).await {
        log::error!("Error while setting up users. {}", err.to_string());
    }
    crate::ipmi::update_ipmi_creds(&mut client, machine_id)
        .await
        .map_err(|err| {
            log::error!("Error while setting up IPMI. {}", err.to_string());
            err
        })?;
    Ok(())
}

pub async fn completed(forge_api: &str, machine_id: &str) -> Result<(), CarbideClientError> {
    let mut client = forge_tls_client::ForgeTlsClient::new(None)
        .connect(forge_api)
        .await
        .map_err(|err| CarbideClientError::GenericError(err.to_string()))?;
    let request = tonic::Request::new(rpc::MachineDiscoveryCompletedRequest {
        machine_id: Some(machine_id.to_string().into()),
    });
    client.discovery_completed(request).await?;
    Ok(())
}
