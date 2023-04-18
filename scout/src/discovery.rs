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

use crate::{cfg::Options, client::create_forge_client, CarbideClientError};

pub(crate) async fn run(config: &Options, machine_id: &str) -> Result<(), CarbideClientError> {
    let mut client = create_forge_client(config).await?;
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

pub(crate) async fn completed(
    config: &Options,
    machine_id: &str,
) -> Result<(), CarbideClientError> {
    let mut client = create_forge_client(config).await?;
    let request = tonic::Request::new(rpc::MachineDiscoveryCompletedRequest {
        machine_id: Some(machine_id.to_string().into()),
    });
    client.discovery_completed(request).await?;
    Ok(())
}
