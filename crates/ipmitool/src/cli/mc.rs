/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! CLI subcommands for management controller (MC) operations.

use eyre::Context;

use crate::transport::IpmiTransport;
use crate::types::{IpmiRequest, NetFn};

/// Management controller subcommands.
#[derive(clap::Subcommand)]
pub enum McCommand {
    /// Get Device ID — query MC firmware and device info.
    Info,
    /// Reset the management controller.
    Reset {
        /// Reset type: "cold" or "warm".
        #[arg(default_value = "cold")]
        reset_type: String,
    },
    /// Get Device GUID.
    Guid,
    /// Watchdog timer operations.
    Watchdog {
        #[command(subcommand)]
        action: WatchdogAction,
    },
    /// Run built-in self test.
    Selftest,
}

/// Watchdog timer subcommands.
#[derive(clap::Subcommand)]
pub enum WatchdogAction {
    /// Get current watchdog timer state.
    Get,
    /// Reset the watchdog timer countdown.
    Reset,
    /// Turn off the watchdog timer.
    Off,
}

/// Dispatch an MC subcommand to the appropriate IPMI request.
///
/// # Errors
///
/// Returns an error if the IPMI transport fails or the BMC returns an error
/// completion code.
pub async fn run(
    transport: &mut impl IpmiTransport,
    cmd: McCommand,
) -> eyre::Result<()> {
    match cmd {
        McCommand::Info => {
            // Get Device ID: NetFn=App (0x06), Cmd=0x01.
            let req = IpmiRequest::new(NetFn::App, 0x01);
            let resp = transport
                .send_recv(&req)
                .await
                .context("send Get Device ID")?;
            resp.check_completion().context("Get Device ID")?;

            if resp.data.len() < 11 {
                eyre::bail!(
                    "Get Device ID response too short: {} bytes",
                    resp.data.len()
                );
            }

            let device_id = resp.data[0];
            let device_revision = resp.data[1] & 0x0F;
            let provides_sdrs = resp.data[1] & 0x80 != 0;
            let fw_major = resp.data[2] & 0x7F;
            let fw_minor = resp.data[3];
            let ipmi_version_major = resp.data[4] & 0x0F;
            let ipmi_version_minor = (resp.data[4] >> 4) & 0x0F;
            let manufacturer_id = u32::from(resp.data[6])
                | (u32::from(resp.data[7]) << 8)
                | (u32::from(resp.data[8]) << 16);
            let product_id =
                u16::from(resp.data[9]) | (u16::from(resp.data[10]) << 8);

            println!("Device ID                 : {device_id}");
            println!("Device Revision           : {device_revision}");
            println!("Provides Device SDRs      : {}", if provides_sdrs { "yes" } else { "no" });
            println!(
                "Firmware Revision         : {fw_major}.{fw_minor:02}"
            );
            println!(
                "IPMI Version              : {ipmi_version_major}.{ipmi_version_minor}"
            );
            println!("Manufacturer ID           : {manufacturer_id}");
            println!("Product ID                : {product_id} (0x{product_id:04X})");

            Ok(())
        }
        McCommand::Reset { reset_type } => {
            // MC Reset: NetFn=App (0x06), Cmd=0x02 (Cold) or 0x03 (Warm).
            let (cmd_byte, label) = match reset_type.as_str() {
                "cold" => (0x02, "cold"),
                "warm" => (0x03, "warm"),
                other => eyre::bail!("unknown reset type: {other} (expected 'cold' or 'warm')"),
            };

            let req = IpmiRequest::new(NetFn::App, cmd_byte);
            // The BMC may not respond before resetting, so we tolerate
            // a timeout here.
            match transport.send_recv(&req).await {
                Ok(resp) => {
                    resp.check_completion().context("MC Reset")?;
                }
                Err(crate::error::IpmitoolError::Timeout { .. }) => {
                    // Expected — the BMC reset before it could reply.
                }
                Err(e) => return Err(e).context("send MC Reset"),
            }
            println!("Sent MC {label} reset command");
            Ok(())
        }
        McCommand::Guid => {
            // Get Device GUID: NetFn=App (0x06), Cmd=0x08.
            let req = IpmiRequest::new(NetFn::App, 0x08);
            let resp = transport
                .send_recv(&req)
                .await
                .context("send Get Device GUID")?;
            resp.check_completion().context("Get Device GUID")?;

            if resp.data.len() < 16 {
                eyre::bail!(
                    "Get Device GUID response too short: {} bytes",
                    resp.data.len()
                );
            }

            // The GUID is 16 bytes in mixed-endian format per SMBIOS/RFC 4122.
            // Print as a standard UUID string.
            let d = &resp.data;
            println!(
                "System GUID  : {:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                d[3], d[2], d[1], d[0],
                d[5], d[4],
                d[7], d[6],
                d[8], d[9],
                d[10], d[11], d[12], d[13], d[14], d[15]
            );
            Ok(())
        }
        McCommand::Watchdog { action } => {
            match action {
                WatchdogAction::Get => {
                    // Get Watchdog Timer: NetFn=App (0x06), Cmd=0x25.
                    let req = IpmiRequest::new(NetFn::App, 0x25);
                    let resp = transport
                        .send_recv(&req)
                        .await
                        .context("send Get Watchdog Timer")?;
                    resp.check_completion()
                        .context("Get Watchdog Timer")?;

                    if resp.data.len() < 6 {
                        eyre::bail!(
                            "Get Watchdog Timer response too short: {} bytes",
                            resp.data.len()
                        );
                    }

                    let timer_use = resp.data[0] & 0x07;
                    let timer_use_str = match timer_use {
                        1 => "BIOS FRB2",
                        2 => "BIOS/POST",
                        3 => "OS Load",
                        4 => "SMS/OS",
                        5 => "OEM",
                        _ => "reserved",
                    };
                    let running = resp.data[0] & 0x40 != 0;
                    let timeout_action = resp.data[1] & 0x07;
                    let timeout_action_str = match timeout_action {
                        0 => "No action",
                        1 => "Hard Reset",
                        2 => "Power Down",
                        3 => "Power Cycle",
                        _ => "reserved",
                    };

                    let countdown_ms = u16::from(resp.data[4])
                        | (u16::from(resp.data[5]) << 8);

                    println!("Watchdog Timer Use   : {timer_use_str}");
                    println!("Watchdog Timer Is    : {}", if running { "Started/Running" } else { "Stopped" });
                    println!("Timeout Action       : {timeout_action_str}");
                    println!(
                        "Countdown            : {:.1}s",
                        f64::from(countdown_ms) / 10.0
                    );
                    Ok(())
                }
                WatchdogAction::Reset => {
                    // Reset Watchdog Timer: NetFn=App (0x06), Cmd=0x22.
                    let req = IpmiRequest::new(NetFn::App, 0x22);
                    let resp = transport
                        .send_recv(&req)
                        .await
                        .context("send Reset Watchdog Timer")?;
                    resp.check_completion()
                        .context("Reset Watchdog Timer")?;
                    println!("Watchdog Timer Reset");
                    Ok(())
                }
                WatchdogAction::Off => {
                    // To turn off the watchdog, we need to set the watchdog
                    // timer with "don't log" + "timer use = 0" + "no action".
                    // Set Watchdog Timer: NetFn=App (0x06), Cmd=0x24.
                    let data = vec![
                        0x00, // timer use = 0, don't start
                        0x00, // timeout action = none
                        0x00, // pre-timeout interval = 0
                        0x00, // timer use expiration flags clear
                        0x00, 0x00, // countdown LSB, MSB
                    ];
                    let req = IpmiRequest::with_data(NetFn::App, 0x24, data);
                    let resp = transport
                        .send_recv(&req)
                        .await
                        .context("send Set Watchdog Timer")?;
                    resp.check_completion()
                        .context("Set Watchdog Timer")?;
                    println!("Watchdog Timer Off");
                    Ok(())
                }
            }
        }
        McCommand::Selftest => {
            // Get Self Test Results: NetFn=App (0x06), Cmd=0x04.
            let req = IpmiRequest::new(NetFn::App, 0x04);
            let resp = transport
                .send_recv(&req)
                .await
                .context("send Get Self Test Results")?;
            resp.check_completion()
                .context("Get Self Test Results")?;

            if resp.data.len() < 2 {
                eyre::bail!(
                    "Get Self Test Results response too short: {} bytes",
                    resp.data.len()
                );
            }

            let result1 = resp.data[0];
            let result2 = resp.data[1];

            match result1 {
                0x55 => println!("Self Test: passed"),
                0x56 => println!("Self Test: not implemented"),
                0x57 => {
                    println!("Self Test: corrupted or inaccessible device");
                    println!("  Failure detail: 0x{result2:02X}");
                }
                0x58 => {
                    println!("Self Test: fatal hardware error");
                    println!("  Failure detail: 0x{result2:02X}");
                }
                other => {
                    println!(
                        "Self Test: device-specific result 0x{other:02X} 0x{result2:02X}"
                    );
                }
            }

            Ok(())
        }
    }
}
