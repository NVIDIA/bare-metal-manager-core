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

use forge_host_support::{
    hardware_enumeration::enumerate_hardware, registration::register_machine,
};

use crate::CarbideClientError;

pub async fn run(
    forge_api: &str,
    machine_interface_id: uuid::Uuid,
) -> Result<String, CarbideClientError> {
    let hardware_info = enumerate_hardware()?;
    log::info!("Successfully enumerated hardware");

    let registration_data =
        register_machine(forge_api, machine_interface_id, hardware_info).await?;
    let machine_id = registration_data.machine_id;
    log::info!("successfully discovered machine {machine_id} for interface {machine_interface_id}");

    Ok(machine_id)
}
