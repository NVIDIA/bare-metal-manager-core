/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use forge_host_support::hardware_enumeration::{CpuArchitecture, HardwareEnumerationError};
// wrapper for libc::uname()
use uname::uname;

use crate::CarbideClientError;

pub async fn run(forge_api: &str, machine_id: uuid::Uuid) -> Result<(), CarbideClientError> {
    if let Err(err) = crate::users::create_users(forge_api.to_string(), machine_id).await {
        log::error!("Error while setting up users. {}", err.to_string());
    }
    // Note: We're intentionally not doing this for Aarch64 (DPUs) because losing the root password for
    // those is ... not fun. And because we're not using IPMI on them, so it's a risk not worth taking
    // right now.  Maybe revisit later.
    let info = uname().map_err(|e| HardwareEnumerationError::GenericError(e.to_string()))?;
    let architecture: CpuArchitecture = info.machine.parse()?;
    if architecture == CpuArchitecture::X86_64 {
        if let Err(err) = crate::ipmi::update_ipmi_creds(forge_api.to_string(), machine_id).await {
            log::error!("Error while setting up IPMI. {}", err.to_string());
        }
    }
    Ok(())
}

pub async fn completed(forge_api: &str, machine_id: uuid::Uuid) -> Result<(), CarbideClientError> {
    let mut client = rpc::forge_client::ForgeClient::connect(forge_api.to_string()).await?;
    let request = tonic::Request::new(rpc::MachineDiscoveryCompletedRequest {
        machine_id: Some(machine_id.into()),
    });
    client.discovery_completed(request).await?;
    Ok(())
}
