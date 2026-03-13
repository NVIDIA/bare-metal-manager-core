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

//! CLI subcommands for chassis operations (power, status, identify, bootdev).

use eyre::Context;

use crate::transport::IpmiTransport;
use crate::types::{IpmiRequest, NetFn};

/// Chassis subcommands.
#[derive(clap::Subcommand)]
pub enum ChassisCommand {
    /// Get chassis power status and other state.
    Status,
    /// Chassis power control.
    Power {
        #[command(subcommand)]
        action: PowerAction,
    },
    /// Chassis identify (blink LED).
    Identify {
        /// Duration in seconds (0 = turn off).
        #[arg(default_value = "15")]
        interval: u8,
        /// Force identify on indefinitely.
        #[arg(long)]
        force: bool,
    },
    /// Set boot device for next boot.
    Bootdev {
        /// Boot device: pxe, disk, safe, diag, cdrom, bios, floppy.
        device: String,
        /// Make the boot device setting persistent across reboots.
        #[arg(long)]
        persistent: bool,
    },
}

/// Power control actions.
#[derive(clap::Subcommand)]
pub enum PowerAction {
    /// Power on.
    On,
    /// Power off (hard).
    Off,
    /// Power cycle (off then on).
    Cycle,
    /// Hard reset.
    Reset,
    /// Soft shutdown (ACPI).
    Soft,
    /// Query power status.
    Status,
}

/// Dispatch a chassis subcommand to the appropriate IPMI request.
///
/// # Errors
///
/// Returns an error if the IPMI transport fails or the BMC returns an error
/// completion code.
pub async fn run(
    transport: &mut impl IpmiTransport,
    cmd: ChassisCommand,
) -> eyre::Result<()> {
    match cmd {
        ChassisCommand::Status => {
            // Get Chassis Status: NetFn=Chassis (0x00), Cmd=0x01.
            let req = IpmiRequest::new(NetFn::Chassis, 0x01);
            let resp = transport
                .send_recv(&req)
                .await
                .context("send Get Chassis Status")?;
            resp.check_completion().context("Get Chassis Status")?;

            // Parse the response per IPMI v2.0 spec section 28.2.
            // Byte 0: current power state.
            if resp.data.is_empty() {
                eyre::bail!("empty chassis status response");
            }

            let power_on = resp.data[0] & 0x01 != 0;
            println!(
                "System Power         : {}",
                if power_on { "on" } else { "off" }
            );

            // Additional state bits from byte 0.
            let power_overload = resp.data[0] & 0x02 != 0;
            let interlock = resp.data[0] & 0x04 != 0;
            let power_fault = resp.data[0] & 0x08 != 0;
            let power_control_fault = resp.data[0] & 0x10 != 0;
            let power_restore_policy = (resp.data[0] >> 5) & 0x03;

            let policy_str = match power_restore_policy {
                0 => "always-off",
                1 => "previous",
                2 => "always-on",
                _ => "unknown",
            };
            println!("Power Overload       : {power_overload}");
            println!("Power Interlock      : {interlock}");
            println!("Main Power Fault     : {power_fault}");
            println!("Power Control Fault  : {power_control_fault}");
            println!("Power Restore Policy : {policy_str}");

            Ok(())
        }
        ChassisCommand::Power { action } => {
            // Chassis Control: NetFn=Chassis (0x00), Cmd=0x02.
            // Data byte = control value.
            let (control_byte, label) = match action {
                PowerAction::Status => {
                    // Power status is just a Get Chassis Status query.
                    let req = IpmiRequest::new(NetFn::Chassis, 0x01);
                    let resp = transport
                        .send_recv(&req)
                        .await
                        .context("send Get Chassis Status")?;
                    resp.check_completion().context("Get Chassis Status")?;

                    if resp.data.is_empty() {
                        eyre::bail!("empty chassis status response");
                    }
                    let power_on = resp.data[0] & 0x01 != 0;
                    println!(
                        "Chassis Power is {}",
                        if power_on { "on" } else { "off" }
                    );
                    return Ok(());
                }
                PowerAction::Off => (0x00, "Down/Off"),
                PowerAction::On => (0x01, "Up/On"),
                PowerAction::Cycle => (0x02, "Cycle"),
                PowerAction::Reset => (0x03, "Reset"),
                PowerAction::Soft => (0x05, "Soft"),
            };

            let req = IpmiRequest::with_data(
                NetFn::Chassis,
                0x02,
                vec![control_byte],
            );
            let resp = transport
                .send_recv(&req)
                .await
                .context("send Chassis Control")?;
            resp.check_completion().context("Chassis Control")?;
            println!("Chassis Power Control: {label}");
            Ok(())
        }
        ChassisCommand::Identify { interval, force } => {
            // Chassis Identify: NetFn=Chassis (0x00), Cmd=0x04.
            let mut data = vec![interval];
            if force {
                // Byte 1 bit 0 = force identify on.
                data.push(0x01);
            }
            let req = IpmiRequest::with_data(NetFn::Chassis, 0x04, data);
            let resp = transport
                .send_recv(&req)
                .await
                .context("send Chassis Identify")?;
            resp.check_completion().context("Chassis Identify")?;
            if force {
                println!("Chassis identify forced on indefinitely");
            } else if interval == 0 {
                println!("Chassis identify off");
            } else {
                println!("Chassis identify interval: {interval}s");
            }
            Ok(())
        }
        ChassisCommand::Bootdev { device, persistent } => {
            // Set System Boot Options: NetFn=Chassis (0x00), Cmd=0x08.
            // Parameter selector 5 = boot flags.
            let device_code = match device.as_str() {
                "pxe" => 0x04,
                "disk" | "hd" => 0x08,
                "safe" => 0x0C,
                "diag" => 0x10,
                "cdrom" => 0x14,
                "bios" | "setup" => 0x18,
                "floppy" => 0x3C,
                other => eyre::bail!("unknown boot device: {other}"),
            };

            // Boot flag parameter data:
            // Byte 0: parameter valid + selector (0x05)
            // Byte 1: 0x80 = boot flags valid, 0x40 = persistent if requested
            // Byte 2: device bits
            // Bytes 3-4: reserved zeros
            let persist_bit = if persistent { 0x40 } else { 0x00 };
            let data = vec![
                0x05,                    // parameter selector = boot flags
                0x80 | persist_bit,      // set valid + optional persistent
                device_code,             // boot device
                0x00,                    // reserved
                0x00,                    // reserved
            ];

            let req = IpmiRequest::with_data(NetFn::Chassis, 0x08, data);
            let resp = transport
                .send_recv(&req)
                .await
                .context("send Set System Boot Options")?;
            resp.check_completion()
                .context("Set System Boot Options")?;
            println!("Set boot device to {device}");
            if persistent {
                println!("Boot device setting is persistent");
            }
            Ok(())
        }
    }
}
