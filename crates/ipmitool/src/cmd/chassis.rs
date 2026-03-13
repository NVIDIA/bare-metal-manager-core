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

//! Chassis commands: power control, boot device, status, identify.
//!
//! All commands in this module use [`NetFn::Chassis`] (0x00).

use crate::error::{IpmitoolError, Result};
use crate::transport::IpmiTransport;
use crate::types::{IpmiRequest, NetFn};

// ==============================================================================
// Types
// ==============================================================================

/// Chassis power control actions (IPMI v2.0 Table 28-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerCommand {
    /// Immediate power off (hard shutdown).
    Off,
    /// Power on.
    On,
    /// Power cycle (off then on, with ~1 second interval).
    Cycle,
    /// Hard reset.
    Reset,
    /// Initiate a soft shutdown via ACPI (pulse power button).
    SoftShutdown,
}

impl PowerCommand {
    /// Returns the IPMI data byte encoding for this power command.
    fn as_byte(self) -> u8 {
        match self {
            Self::Off => 0x00,
            Self::On => 0x01,
            Self::Cycle => 0x02,
            Self::Reset => 0x03,
            Self::SoftShutdown => 0x05,
        }
    }
}

/// Boot device selections for Set/Get System Boot Options (parameter 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootDevice {
    /// No override — use BIOS default boot order.
    None,
    /// PXE network boot.
    Pxe,
    /// Boot from default hard disk.
    Disk,
    /// Boot into safe mode (diagnostic partition).
    Safe,
    /// Boot into diagnostics.
    Diag,
    /// Boot from CD/DVD.
    CdDvd,
    /// Boot into BIOS setup.
    BiosSetup,
    /// Boot from remote floppy/primary removable media.
    RemoteFloppy,
    /// Boot from remote CD/DVD.
    RemoteCd,
    /// Boot from primary remote media.
    RemotePrimary,
}

impl BootDevice {
    /// Encode as the 4-bit device field in boot flags bits [5:2] of byte 2.
    fn to_flags_byte(self) -> u8 {
        let nibble = match self {
            Self::None => 0x00,
            Self::Pxe => 0x01,
            Self::Disk => 0x02,
            Self::Safe => 0x03,
            Self::Diag => 0x04,
            Self::CdDvd => 0x05,
            Self::BiosSetup => 0x06,
            Self::RemoteFloppy => 0x07,
            Self::RemoteCd => 0x08,
            Self::RemotePrimary => 0x09,
        };
        nibble << 2
    }

    /// Decode from the 4-bit device field in boot flags bits [5:2] of byte 2.
    fn from_flags_byte(byte: u8) -> Self {
        match (byte >> 2) & 0x0F {
            0x00 => Self::None,
            0x01 => Self::Pxe,
            0x02 => Self::Disk,
            0x03 => Self::Safe,
            0x04 => Self::Diag,
            0x05 => Self::CdDvd,
            0x06 => Self::BiosSetup,
            0x07 => Self::RemoteFloppy,
            0x08 => Self::RemoteCd,
            0x09 => Self::RemotePrimary,
            _ => Self::None,
        }
    }
}

/// Parsed response from Get Chassis Status (cmd 0x01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChassisStatus {
    /// Whether the system power is currently on.
    pub power_on: bool,
    /// Last power event byte (see IPMI spec Table 28-3).
    pub last_power_event: u8,
    /// Miscellaneous chassis state byte.
    pub misc_state: u8,
    /// Front panel button capabilities and disable bits (optional 4th byte).
    pub front_panel_capabilities: u8,
}

// ==============================================================================
// Commands
// ==============================================================================

/// Get Chassis Status (NetFn=Chassis, Cmd=0x01).
///
/// Returns the current power state, last power event, and miscellaneous state.
///
/// # Errors
///
/// Returns an error if the transport fails or the BMC returns a non-success
/// completion code, or if the response is too short.
pub async fn get_chassis_status(
    transport: &mut impl IpmiTransport,
) -> Result<ChassisStatus> {
    let req = IpmiRequest::new(NetFn::Chassis, 0x01);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    if resp.data.len() < 3 {
        return Err(IpmitoolError::InvalidResponse(format!(
            "Get Chassis Status response too short: expected >= 3 bytes, got {}",
            resp.data.len()
        )));
    }

    Ok(ChassisStatus {
        power_on: (resp.data[0] & 0x01) != 0,
        last_power_event: resp.data[1],
        misc_state: resp.data[2],
        // The fourth byte is optional per the spec.
        front_panel_capabilities: resp.data.get(3).copied().unwrap_or(0),
    })
}

/// Chassis Control (NetFn=Chassis, Cmd=0x02).
///
/// Sends a power command (on, off, cycle, reset, soft shutdown) to the chassis.
///
/// # Errors
///
/// Returns an error if the transport fails or the BMC returns a non-success
/// completion code.
pub async fn chassis_control(
    transport: &mut impl IpmiTransport,
    cmd: PowerCommand,
) -> Result<()> {
    let req = IpmiRequest::with_data(NetFn::Chassis, 0x02, vec![cmd.as_byte()]);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()
}

/// Chassis Identify (NetFn=Chassis, Cmd=0x04).
///
/// Turns on the chassis identify LED for the given interval. If `force` is set,
/// the BMC ignores the interval and keeps the LED on indefinitely.
///
/// # Errors
///
/// Returns an error if the transport fails or the BMC returns a non-success
/// completion code.
pub async fn chassis_identify(
    transport: &mut impl IpmiTransport,
    interval: Option<u8>,
    force: bool,
) -> Result<()> {
    let mut data = vec![interval.unwrap_or(15)];
    if force {
        data.push(0x01);
    }
    let req = IpmiRequest::with_data(NetFn::Chassis, 0x04, data);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()
}

/// Set System Boot Options — boot device (NetFn=Chassis, Cmd=0x08).
///
/// Sets the boot device override. If `persistent` is false, the override
/// applies only to the next boot.
///
/// We write parameter selector 5 (boot flags) with the appropriate device
/// and persistence bits.
///
/// # Errors
///
/// Returns an error if the transport fails or the BMC returns a non-success
/// completion code.
pub async fn set_boot_device(
    transport: &mut impl IpmiTransport,
    device: BootDevice,
    persistent: bool,
) -> Result<()> {
    // Parameter selector 5 = boot flags.
    // Byte 1: 0x80 = boot flag valid bit set, 0xC0 = valid + persistent.
    let byte1 = if persistent { 0xC0 } else { 0x80 };
    let byte2 = device.to_flags_byte();

    let data = vec![
        0x05, // parameter selector = boot flags
        byte1, // boot flag valid + persistence
        byte2, // boot device
        0x00,  // BIOS verbosity / console redirection (default)
        0x00,  // BIOS shared mode (default)
        0x00,  // BIOS mux control (default)
    ];

    let req = IpmiRequest::with_data(NetFn::Chassis, 0x08, data);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()
}

/// Get System Boot Options — boot device (NetFn=Chassis, Cmd=0x09).
///
/// Reads parameter 5 (boot flags) and returns the currently configured
/// boot device.
///
/// # Errors
///
/// Returns an error if the transport fails, the BMC returns a non-success
/// completion code, or the response is too short to contain boot flags.
pub async fn get_boot_device(
    transport: &mut impl IpmiTransport,
) -> Result<BootDevice> {
    // Request parameter 5 (boot flags), set selector 0, block selector 0.
    let data = vec![0x05, 0x00, 0x00];
    let req = IpmiRequest::with_data(NetFn::Chassis, 0x09, data);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    // Response: byte 0 = parameter version, byte 1 = parameter selector,
    // byte 2 = parameter data byte 1 (valid/persistent), byte 3 = boot device.
    if resp.data.len() < 4 {
        return Err(IpmitoolError::InvalidResponse(format!(
            "Get Boot Options response too short: expected >= 4 bytes, got {}",
            resp.data.len()
        )));
    }

    Ok(BootDevice::from_flags_byte(resp.data[3]))
}

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    #[tokio::test]
    async fn get_chassis_status_parses_power_on() {
        let mut transport = MockTransport::new();
        // Completion code 0x00, power state byte with bit 0 set (power on),
        // last power event, misc state, front panel capabilities.
        transport.add_response(0x00, 0x01, vec![0x00, 0x61, 0x00, 0x00, 0x00]);

        let status = get_chassis_status(&mut transport)
            .await
            .expect("should parse chassis status");

        assert!(status.power_on);
        assert_eq!(status.last_power_event, 0x00);
        assert_eq!(status.misc_state, 0x00);
    }

    #[tokio::test]
    async fn get_chassis_status_parses_power_off() {
        let mut transport = MockTransport::new();
        // Power state byte with bit 0 clear (power off).
        transport.add_response(0x00, 0x01, vec![0x00, 0x60, 0x10, 0x20, 0x00]);

        let status = get_chassis_status(&mut transport)
            .await
            .expect("should parse chassis status");

        assert!(!status.power_on);
        assert_eq!(status.last_power_event, 0x10);
        assert_eq!(status.misc_state, 0x20);
    }

    #[tokio::test]
    async fn get_chassis_status_short_response_errors() {
        let mut transport = MockTransport::new();
        // Only 2 data bytes after completion code — too short.
        transport.add_response(0x00, 0x01, vec![0x00, 0x01, 0x02]);

        let result = get_chassis_status(&mut transport).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn chassis_control_power_on() {
        let mut transport = MockTransport::new();
        // Success response (just completion code).
        transport.add_response(0x00, 0x02, vec![0x00]);

        chassis_control(&mut transport, PowerCommand::On)
            .await
            .expect("power on should succeed");
    }

    #[tokio::test]
    async fn chassis_control_power_off() {
        let mut transport = MockTransport::new();
        transport.add_response(0x00, 0x02, vec![0x00]);

        chassis_control(&mut transport, PowerCommand::Off)
            .await
            .expect("power off should succeed");
    }

    #[tokio::test]
    async fn chassis_identify_default() {
        let mut transport = MockTransport::new();
        transport.add_response(0x00, 0x04, vec![0x00]);

        chassis_identify(&mut transport, None, false)
            .await
            .expect("identify should succeed");
    }

    #[tokio::test]
    async fn set_and_get_boot_device_pxe() {
        let mut transport = MockTransport::new();

        // Set boot device success response.
        transport.add_response(0x00, 0x08, vec![0x00]);

        // Get boot device response: param version, param selector, valid byte,
        // boot device byte with PXE (0x01 << 2 = 0x04).
        transport.add_response(0x00, 0x09, vec![0x00, 0x01, 0x05, 0x80, 0x04]);

        set_boot_device(&mut transport, BootDevice::Pxe, false)
            .await
            .expect("set boot device should succeed");

        let device = get_boot_device(&mut transport)
            .await
            .expect("get boot device should succeed");

        assert_eq!(device, BootDevice::Pxe);
    }

    #[tokio::test]
    async fn boot_device_roundtrip() {
        let devices = [
            BootDevice::None,
            BootDevice::Pxe,
            BootDevice::Disk,
            BootDevice::Safe,
            BootDevice::Diag,
            BootDevice::CdDvd,
            BootDevice::BiosSetup,
            BootDevice::RemoteFloppy,
            BootDevice::RemoteCd,
            BootDevice::RemotePrimary,
        ];
        for device in devices {
            let byte = device.to_flags_byte();
            let back = BootDevice::from_flags_byte(byte);
            assert_eq!(device, back, "roundtrip failed for {device:?}");
        }
    }
}
