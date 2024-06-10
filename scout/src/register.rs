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

use crate::attestation::get_tpm_description;
use forge_host_support::{
    hardware_enumeration::enumerate_hardware,
    registration::{register_machine, DiscoveryRetry},
};
use tracing::info;

use crate::CarbideClientError;

pub async fn run(
    forge_api: &str,
    root_ca: String,
    machine_interface_id: uuid::Uuid,
    discovery_retry_secs: u64,
    discovery_retries_max: u32,
    tpm_path: &str,
) -> Result<String, CarbideClientError> {
    let mut hardware_info = enumerate_hardware()?;
    info!("Successfully enumerated hardware");

    hardware_info.tpm_description = get_tpm_description(tpm_path);

    let retry = DiscoveryRetry {
        secs: discovery_retry_secs,
        max: discovery_retries_max,
    };
    let registration_data = register_machine(
        forge_api,
        root_ca,
        Some(machine_interface_id),
        hardware_info,
        false,
        retry,
        true,
    )
    .await?;
    let machine_id = registration_data.machine_id;
    info!("successfully discovered machine {machine_id} for interface {machine_interface_id}");

    Ok(machine_id)
}
