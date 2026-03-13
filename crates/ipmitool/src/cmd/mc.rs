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

//! Management Controller (MC) commands: device info, reset, self-test,
//! GUID, watchdog timer.
//!
//! All commands in this module use [`NetFn::App`] (0x06).

use crate::error::{IpmitoolError, Result};
use crate::transport::IpmiTransport;
use crate::types::{IpmiRequest, NetFn};

// ==============================================================================
// Types
// ==============================================================================

/// Parsed response from Get Device ID (cmd 0x01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceId {
    /// Device ID byte (usually 0x20 for BMC).
    pub device_id: u8,
    /// Device revision (bits [3:0]).
    pub device_revision: u8,
    /// Major firmware revision (bits [6:0] of the firmware rev 1 byte).
    pub firmware_major: u8,
    /// Minor firmware revision in BCD.
    pub firmware_minor: u8,
    /// IPMI specification version (BCD, e.g. 0x20 = IPMI 2.0).
    pub ipmi_version: u8,
    /// Additional device support flags.
    pub additional_device_support: u8,
    /// Manufacturer ID (3 bytes LE, stored as u32 with high byte zero).
    pub manufacturer_id: u32,
    /// Product ID (2 bytes LE).
    pub product_id: u16,
    /// Auxiliary firmware revision info (4 bytes, present only if response
    /// is 15 bytes long).
    pub aux_firmware_revision: Option<[u8; 4]>,
}

/// Parsed response from Get Self Test Results (cmd 0x04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTestResult {
    /// First result byte: 0x55 = no error, 0x56 = self test not implemented,
    /// 0x57 = corrupted/inaccessible device, 0x58 = fatal hardware error.
    pub result_byte1: u8,
    /// Second result byte: device-specific failure details (bit mask).
    pub result_byte2: u8,
}

/// Parsed response from Get Watchdog Timer (cmd 0x25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchdogTimer {
    /// Timer use byte (bits indicate BIOS FRB2, BIOS POST, OS load, etc.).
    pub timer_use: u8,
    /// Timer actions byte (timeout action + pre-timeout interrupt).
    pub timer_actions: u8,
    /// Pre-timeout interval in seconds.
    pub pre_timeout_interval: u8,
    /// Timer use expiration flags.
    pub timer_use_expiration: u8,
    /// Initial countdown value in 100ms increments (LE).
    pub initial_countdown: u16,
    /// Present (current) countdown value in 100ms increments (LE).
    pub present_countdown: u16,
}

// ==============================================================================
// Commands
// ==============================================================================

/// Get Device ID (NetFn=App, Cmd=0x01).
///
/// Returns the BMC's device ID, firmware revision, IPMI version,
/// manufacturer, and product IDs.
///
/// # Errors
///
/// Returns an error if the transport fails, the BMC returns a non-success
/// completion code, or the response is too short.
pub async fn get_device_id(
    transport: &mut impl IpmiTransport,
) -> Result<DeviceId> {
    let req = IpmiRequest::new(NetFn::App, 0x01);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    // Minimum response: 11 bytes (device ID through product ID).
    // Optional: 4 more bytes of auxiliary firmware revision (total 15).
    if resp.data.len() < 11 {
        return Err(IpmitoolError::InvalidResponse(format!(
            "Get Device ID response too short: expected >= 11 bytes, got {}",
            resp.data.len()
        )));
    }

    let d = &resp.data;

    let manufacturer_id =
        u32::from(d[6]) | (u32::from(d[7]) << 8) | (u32::from(d[8]) << 16);

    let product_id = u16::from(d[9]) | (u16::from(d[10]) << 8);

    let aux_firmware_revision = if d.len() >= 15 {
        Some([d[11], d[12], d[13], d[14]])
    } else {
        None
    };

    Ok(DeviceId {
        device_id: d[0],
        device_revision: d[1] & 0x0F,
        firmware_major: d[2] & 0x7F,
        firmware_minor: d[3],
        ipmi_version: d[4],
        additional_device_support: d[5],
        manufacturer_id,
        product_id,
        aux_firmware_revision,
    })
}

/// Cold Reset (NetFn=App, Cmd=0x02).
///
/// Performs a cold reset of the BMC. The BMC may not send a response
/// before resetting.
///
/// # Errors
///
/// Returns an error if the transport fails or the BMC returns a non-success
/// completion code.
pub async fn cold_reset(transport: &mut impl IpmiTransport) -> Result<()> {
    let req = IpmiRequest::new(NetFn::App, 0x02);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()
}

/// Warm Reset (NetFn=App, Cmd=0x03).
///
/// Performs a warm reset of the BMC.
///
/// # Errors
///
/// Returns an error if the transport fails or the BMC returns a non-success
/// completion code.
pub async fn warm_reset(transport: &mut impl IpmiTransport) -> Result<()> {
    let req = IpmiRequest::new(NetFn::App, 0x03);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()
}

/// Get Self Test Results (NetFn=App, Cmd=0x04).
///
/// Returns the BMC self-test result bytes.
///
/// # Errors
///
/// Returns an error if the transport fails, the BMC returns a non-success
/// completion code, or the response is too short.
pub async fn get_self_test_results(
    transport: &mut impl IpmiTransport,
) -> Result<SelfTestResult> {
    let req = IpmiRequest::new(NetFn::App, 0x04);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    if resp.data.len() < 2 {
        return Err(IpmitoolError::InvalidResponse(format!(
            "Get Self Test Results response too short: expected >= 2 bytes, got {}",
            resp.data.len()
        )));
    }

    Ok(SelfTestResult {
        result_byte1: resp.data[0],
        result_byte2: resp.data[1],
    })
}

/// Get Device GUID (NetFn=App, Cmd=0x37).
///
/// Returns the 16-byte GUID of the management controller.
///
/// # Errors
///
/// Returns an error if the transport fails, the BMC returns a non-success
/// completion code, or the response is not exactly 16 bytes.
pub async fn get_device_guid(
    transport: &mut impl IpmiTransport,
) -> Result<[u8; 16]> {
    let req = IpmiRequest::new(NetFn::App, 0x37);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    if resp.data.len() < 16 {
        return Err(IpmitoolError::InvalidResponse(format!(
            "Get Device GUID response too short: expected 16 bytes, got {}",
            resp.data.len()
        )));
    }

    let mut guid = [0u8; 16];
    guid.copy_from_slice(&resp.data[..16]);
    Ok(guid)
}

/// Get Watchdog Timer (NetFn=App, Cmd=0x25).
///
/// Returns the current watchdog timer configuration and countdown.
///
/// # Errors
///
/// Returns an error if the transport fails, the BMC returns a non-success
/// completion code, or the response is too short.
pub async fn get_watchdog_timer(
    transport: &mut impl IpmiTransport,
) -> Result<WatchdogTimer> {
    let req = IpmiRequest::new(NetFn::App, 0x25);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()?;

    if resp.data.len() < 8 {
        return Err(IpmitoolError::InvalidResponse(format!(
            "Get Watchdog Timer response too short: expected >= 8 bytes, got {}",
            resp.data.len()
        )));
    }

    let d = &resp.data;
    Ok(WatchdogTimer {
        timer_use: d[0],
        timer_actions: d[1],
        pre_timeout_interval: d[2],
        timer_use_expiration: d[3],
        initial_countdown: u16::from(d[4]) | (u16::from(d[5]) << 8),
        present_countdown: u16::from(d[6]) | (u16::from(d[7]) << 8),
    })
}

/// Reset Watchdog Timer (NetFn=App, Cmd=0x22).
///
/// Resets the watchdog timer countdown to its initial value.
///
/// # Errors
///
/// Returns an error if the transport fails or the BMC returns a non-success
/// completion code.
pub async fn reset_watchdog_timer(
    transport: &mut impl IpmiTransport,
) -> Result<()> {
    let req = IpmiRequest::new(NetFn::App, 0x22);
    let resp = transport.send_recv(&req).await?;
    resp.check_completion()
}

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    /// Build a realistic Get Device ID response (15 bytes with aux revision).
    fn device_id_response() -> Vec<u8> {
        vec![
            0x00, // completion code = success
            0x20, // device ID
            0x01, // device revision
            0x02, // firmware major (bit 7 = device available)
            0x35, // firmware minor (BCD)
            0x20, // IPMI version 2.0
            0xBF, // additional device support
            0x57, 0x01, 0x00, // manufacturer ID = 0x000157 (LE)
            0x90, 0x00, // product ID = 0x0090 (LE)
            0x01, 0x02, 0x03, 0x04, // aux firmware revision
        ]
    }

    #[tokio::test]
    async fn get_device_id_parses_all_fields() {
        let mut transport = MockTransport::new();
        transport.add_response(0x06, 0x01, device_id_response());

        let id = get_device_id(&mut transport)
            .await
            .expect("should parse device ID");

        assert_eq!(id.device_id, 0x20);
        assert_eq!(id.device_revision, 0x01);
        assert_eq!(id.firmware_major, 0x02);
        assert_eq!(id.firmware_minor, 0x35);
        assert_eq!(id.ipmi_version, 0x20);
        assert_eq!(id.additional_device_support, 0xBF);
        assert_eq!(id.manufacturer_id, 0x000157);
        assert_eq!(id.product_id, 0x0090);
        assert_eq!(id.aux_firmware_revision, Some([0x01, 0x02, 0x03, 0x04]));
    }

    #[tokio::test]
    async fn get_device_id_without_aux_revision() {
        let mut transport = MockTransport::new();
        // Truncated response: 11 data bytes, no aux firmware revision.
        let resp = vec![
            0x00, // completion code
            0x20, 0x01, 0x02, 0x35, 0x20, 0xBF, // device info
            0x57, 0x01, 0x00, // manufacturer ID
            0x90, 0x00, // product ID
        ];
        transport.add_response(0x06, 0x01, resp);

        let id = get_device_id(&mut transport)
            .await
            .expect("should parse device ID without aux");

        assert_eq!(id.device_id, 0x20);
        assert!(id.aux_firmware_revision.is_none());
    }

    #[tokio::test]
    async fn get_device_id_short_response_errors() {
        let mut transport = MockTransport::new();
        // Only 5 data bytes — too short.
        transport.add_response(0x06, 0x01, vec![0x00, 0x20, 0x01, 0x02, 0x35, 0x20]);

        let result = get_device_id(&mut transport).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cold_reset_succeeds() {
        let mut transport = MockTransport::new();
        transport.add_response(0x06, 0x02, vec![0x00]);

        cold_reset(&mut transport)
            .await
            .expect("cold reset should succeed");
    }

    #[tokio::test]
    async fn warm_reset_succeeds() {
        let mut transport = MockTransport::new();
        transport.add_response(0x06, 0x03, vec![0x00]);

        warm_reset(&mut transport)
            .await
            .expect("warm reset should succeed");
    }

    #[tokio::test]
    async fn get_self_test_results_parses() {
        let mut transport = MockTransport::new();
        // 0x55 = no error, 0x00 = no failures.
        transport.add_response(0x06, 0x04, vec![0x00, 0x55, 0x00]);

        let result = get_self_test_results(&mut transport)
            .await
            .expect("should parse self test results");

        assert_eq!(result.result_byte1, 0x55);
        assert_eq!(result.result_byte2, 0x00);
    }

    #[tokio::test]
    async fn get_device_guid_parses() {
        let mut transport = MockTransport::new();
        let mut resp = vec![0x00]; // completion code
        let guid_bytes: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        resp.extend_from_slice(&guid_bytes);
        transport.add_response(0x06, 0x37, resp);

        let guid = get_device_guid(&mut transport)
            .await
            .expect("should parse device GUID");

        assert_eq!(guid, guid_bytes);
    }

    #[tokio::test]
    async fn get_watchdog_timer_parses() {
        let mut transport = MockTransport::new();
        // 8 data bytes for watchdog timer.
        transport.add_response(
            0x06,
            0x25,
            vec![
                0x00, // completion code
                0x42, // timer use
                0x01, // timer actions
                0x00, // pre-timeout interval
                0x08, // timer use expiration
                0xE8, 0x03, // initial countdown = 1000 (0x03E8 LE)
                0xD0, 0x02, // present countdown = 720 (0x02D0 LE)
            ],
        );

        let wdt = get_watchdog_timer(&mut transport)
            .await
            .expect("should parse watchdog timer");

        assert_eq!(wdt.timer_use, 0x42);
        assert_eq!(wdt.timer_actions, 0x01);
        assert_eq!(wdt.pre_timeout_interval, 0x00);
        assert_eq!(wdt.timer_use_expiration, 0x08);
        assert_eq!(wdt.initial_countdown, 1000);
        assert_eq!(wdt.present_countdown, 720);
    }

    #[tokio::test]
    async fn reset_watchdog_timer_succeeds() {
        let mut transport = MockTransport::new();
        transport.add_response(0x06, 0x22, vec![0x00]);

        reset_watchdog_timer(&mut transport)
            .await
            .expect("reset watchdog timer should succeed");
    }
}
