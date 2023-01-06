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

use cli::CarbideClientError;

use forge_host_support::{
    hardware_enumeration::{enumerate_hardware, CpuArchitecture},
    registration::register_machine,
};

pub struct Discovery {}

impl Discovery {
    pub async fn run(
        forge_api: &str,
        machine_interface_id: uuid::Uuid,
    ) -> Result<(), CarbideClientError> {
        let (hardware_info, architecture) = enumerate_hardware()?;
        log::info!("Successfully enumerated hardware");

        let registration_data =
            register_machine(forge_api, machine_interface_id, hardware_info).await?;
        let machine_id = registration_data.machine_id;

        if let Err(err) = crate::users::create_users(forge_api.to_string(), machine_id).await {
            log::error!("Error while setting up users. {}", err.to_string());
        }
        //Note: We're intentionally not doing this for Aarch64 (DPUs) because losing the root password for those is ... not fun.
        //And because we're not using IPMI on them, so it's a risk not worth taking right now.  Maybe revisit later.
        if architecture == CpuArchitecture::X86_64 {
            if let Err(err) =
                crate::ipmi::update_ipmi_creds(forge_api.to_string(), machine_id).await
            {
                log::error!("Error while setting up IPMI. {}", err.to_string());
            }
        }

        log::info!("successfully discovered machine with ID {machine_id} for interface {machine_interface_id}");

        Ok(())
    }
}
