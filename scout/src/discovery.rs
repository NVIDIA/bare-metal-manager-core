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

pub(crate) async fn run(_config: &Options, _machine_id: &str) -> Result<(), CarbideClientError> {
    Ok(())
}

pub(crate) async fn completed(
    config: &Options,
    machine_id: &str,
    discovery_error: Option<String>,
) -> Result<(), CarbideClientError> {
    let mut client = create_forge_client(config).await?;
    let request = tonic::Request::new(rpc::MachineDiscoveryCompletedRequest {
        machine_id: Some(machine_id.to_string().into()),
        discovery_error,
    });
    client.discovery_completed(request).await?;
    Ok(())
}
pub(crate) async fn rebooted(config: &Options, machine_id: &str) -> Result<(), CarbideClientError> {
    let mut client = create_forge_client(config).await?;
    let request = tonic::Request::new(rpc::MachineRebootCompletedRequest {
        machine_id: Some(machine_id.to_string().into()),
    });
    client.reboot_completed(request).await?;
    Ok(())
}
