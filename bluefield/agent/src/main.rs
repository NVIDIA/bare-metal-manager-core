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

mod command_line;

use forge_host_support::{agent_config::AgentConfig, hardware_enumeration::enumerate_hardware};
use std::time::Duration;

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let config = command_line::Options::load();

    pretty_env_logger::formatted_timed_builder().init();

    match AgentConfig::load_from(&config.config_path) {
        Ok(config) => {
            log::info!("Successfully loaded agent configuration {:?}", config);
        }
        Err(e) => {
            log::error!("Error loading agent configuration: {:?}", e);
        }
    }

    let _hardware_info = enumerate_hardware()?;

    log::info!("Successfully enumerated DPU hardware");

    // TODO: Use forge_host_support::registration to make an initial call to
    // the forge site controller API and retrieve the machine ID and later an
    // mTLS cert for further interactions.
    // However we first need to get the machine_interface_id and API server URL
    // into the service for doing this.

    let mut log_debug = true;
    loop {
        if log_debug {
            log::debug!("Forge DPU agent is running");
        } else {
            log::info!("Forge DPU agent is running");
        }
        log_debug = !log_debug;

        std::thread::sleep(Duration::from_secs(30));
    }
}
