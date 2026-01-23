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
use carbide_uuid::machine::MachineId;

use crate::CarbideClientError;
use crate::cfg::Options;
use crate::client::create_forge_client;

pub(crate) async fn completed(
    config: &Options,
    machine_id: &MachineId,
) -> Result<(), CarbideClientError> {
    let mut client = create_forge_client(config).await?;
    let request = tonic::Request::new(rpc::MachineDiscoveryCompletedRequest {
        machine_id: Some(*machine_id),
    });
    client.discovery_completed(request).await?;
    Ok(())
}
pub(crate) async fn rebooted(
    config: &Options,
    machine_id: &MachineId,
) -> Result<(), CarbideClientError> {
    let mut client = create_forge_client(config).await?;
    let request = tonic::Request::new(rpc::MachineRebootCompletedRequest {
        machine_id: Some(*machine_id),
    });
    client.reboot_completed(request).await?;
    Ok(())
}
