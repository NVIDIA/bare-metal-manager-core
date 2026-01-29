/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::fmt::Write;

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};
use ::rpc::forge::NetworkTopologyRequest;

use super::args::ShowNetworkDevice;
use crate::rpc::ApiClient;

pub async fn handle_show(
    output_format: OutputFormat,
    query: ShowNetworkDevice,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let id: Option<String> = if query.all || query.id.is_empty() {
        None
    } else {
        Some(query.id)
    };

    let devices = api_client
        .0
        .get_network_topology(NetworkTopologyRequest { id })
        .await?;

    match output_format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&devices)?),
        OutputFormat::AsciiTable => show_network_devices_info(devices)?,
        OutputFormat::Csv => println!("CSV not yet supported."),
        OutputFormat::Yaml => println!("YAML not yet supported."),
    }

    Ok(())
}

fn show_network_devices_info(data: rpc::forge::NetworkTopologyData) -> CarbideCliResult<()> {
    let mut lines = String::new();

    writeln!(&mut lines, "{}", "-".repeat(95))?;
    for network_device in data.network_devices {
        writeln!(
            &mut lines,
            "Network Device: {}/{}",
            network_device.name, network_device.id
        )?;
        writeln!(
            &mut lines,
            "Description:    {}",
            network_device.description.unwrap_or_default()
        )?;
        writeln!(
            &mut lines,
            "Mgmt IP:        {}",
            network_device.mgmt_ip.join(",")
        )?;
        writeln!(
            &mut lines,
            "Discovered Via: {}",
            network_device.discovered_via
        )?;
        writeln!(&mut lines, "Device Type:    {}", network_device.device_type)?;
        writeln!(&mut lines)?;
        writeln!(&mut lines, "Connected DPU(s):")?;
        for device in &network_device.devices {
            writeln!(
                &mut lines,
                "\t\t{} | {:8} | {}",
                device.id.unwrap_or_default(),
                device.local_port,
                device
                    .remote_port
                    .split('=')
                    .next_back()
                    .unwrap_or_default()
            )?;
        }
        writeln!(&mut lines, "{}", "-".repeat(95))?;
    }
    writeln!(&mut lines)?;

    println!("{lines}");

    Ok(())
}
