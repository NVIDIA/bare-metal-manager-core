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

//! SEL (System Event Log) record types and timestamp handling.

use byteorder::{ByteOrder, LittleEndian};

// ==============================================================================
// SEL Record Types
// ==============================================================================

/// SEL record type identifiers. See IPMI v2.0 spec Table 32-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelRecordType {
    /// Standard system event (type 0x02).
    SystemEvent,
    /// OEM timestamped event (types 0xC0-0xDF).
    OemTimestamped(u8),
    /// OEM non-timestamped event (types 0xE0-0xFF).
    OemNonTimestamped(u8),
    /// Unknown record type.
    Unknown(u8),
}

impl From<u8> for SelRecordType {
    fn from(byte: u8) -> Self {
        match byte {
            0x02 => Self::SystemEvent,
            0xC0..=0xDF => Self::OemTimestamped(byte),
            0xE0..=0xFF => Self::OemNonTimestamped(byte),
            other => Self::Unknown(other),
        }
    }
}

/// A parsed SEL record.
#[derive(Debug, Clone)]
pub struct SelRecord {
    /// Record ID (used for iteration, not necessarily sequential).
    pub record_id: u16,
    /// Record type.
    pub record_type: SelRecordType,
    /// Timestamp (seconds since 1970-01-01 00:00:00, or special values).
    /// For non-timestamped OEM records, this is 0.
    pub timestamp: u32,
    /// Generator ID (typically the slave address and LUN of the sensor owner).
    pub generator_id: u16,
    /// Event message format version (0x04 for IPMI v2.0).
    pub evm_rev: u8,
    /// Sensor type code.
    pub sensor_type: u8,
    /// Sensor number.
    pub sensor_number: u8,
    /// Event direction (0 = assertion, 1 = deassertion) and event type.
    pub event_dir_type: u8,
    /// Event data bytes (3 bytes for system events).
    pub event_data: [u8; 3],
}

impl SelRecord {
    /// Parse a 16-byte SEL record from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is too short.
    pub fn from_bytes(data: &[u8]) -> crate::error::Result<Self> {
        if data.len() < 16 {
            return Err(crate::error::IpmitoolError::SelParse(format!(
                "SEL record too short: {} bytes, need 16",
                data.len()
            )));
        }

        let record_id = LittleEndian::read_u16(&data[0..2]);
        let record_type = SelRecordType::from(data[2]);

        // System event record layout (type 0x02):
        //   [0..2]  record ID
        //   [2]     record type
        //   [3..7]  timestamp (LE u32)
        //   [7..9]  generator ID
        //   [9]     EvM rev
        //   [10]    sensor type
        //   [11]    sensor number
        //   [12]    event dir/type
        //   [13..16] event data
        let timestamp = LittleEndian::read_u32(&data[3..7]);
        let generator_id = LittleEndian::read_u16(&data[7..9]);

        Ok(Self {
            record_id,
            record_type,
            timestamp,
            generator_id,
            evm_rev: data[9],
            sensor_type: data[10],
            sensor_number: data[11],
            event_dir_type: data[12],
            event_data: [data[13], data[14], data[15]],
        })
    }

    /// Returns `true` if the event was an assertion (vs deassertion).
    #[must_use]
    pub fn is_assertion(&self) -> bool {
        (self.event_dir_type & 0x80) == 0
    }

    /// Returns the event type code (lower 7 bits of event_dir_type).
    #[must_use]
    pub fn event_type(&self) -> u8 {
        self.event_dir_type & 0x7F
    }
}

// ==============================================================================
// SEL Timestamps
// ==============================================================================

/// Interpret a SEL timestamp.
///
/// IPMI timestamps are seconds since 1970-01-01 00:00:00 UTC, with special
/// handling for values below 0x20000000 (which indicate "pre-init" time —
/// seconds since BMC boot rather than wall-clock time).
#[must_use]
pub fn format_sel_timestamp(timestamp: u32) -> String {
    if timestamp == 0xFFFF_FFFF {
        return "Invalid".to_owned();
    }
    if timestamp < 0x2000_0000 {
        return format!("Pre-Init +{timestamp}s");
    }

    // Convert to a human-readable date. We use a simple manual conversion
    // since we don't want to pull in chrono just for this.
    // Format: YYYY-MM-DD HH:MM:SS
    format_unix_timestamp(timestamp)
}

/// Format a Unix timestamp as "YYYY-MM-DD HH:MM:SS".
/// Simple implementation without external date library dependencies.
fn format_unix_timestamp(ts: u32) -> String {
    let ts = ts as u64;
    let secs_per_day = 86400u64;
    let days = ts / secs_per_day;
    let remaining_secs = ts % secs_per_day;

    let hours = remaining_secs / 3600;
    let minutes = (remaining_secs % 3600) / 60;
    let seconds = remaining_secs % 60;

    // Convert days since epoch to Y-M-D using the civil_from_days algorithm.
    let (year, month, day) = civil_from_days(days as i64);

    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02}")
}

/// Convert days since Unix epoch to (year, month, day).
/// Algorithm from Howard Hinnant's `chrono`-compatible date library.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sel_record_parse() {
        // Construct a minimal 16-byte system event record.
        let mut data = [0u8; 16];
        // Record ID = 0x0001
        data[0] = 0x01;
        data[1] = 0x00;
        // Record type = system event
        data[2] = 0x02;
        // Timestamp = 0x60000000 (~2021)
        data[3] = 0x00;
        data[4] = 0x00;
        data[5] = 0x00;
        data[6] = 0x60;
        // Generator ID = 0x0020
        data[7] = 0x20;
        data[8] = 0x00;
        // EvM rev
        data[9] = 0x04;
        // Sensor type = Temperature (0x01)
        data[10] = 0x01;
        // Sensor number = 42
        data[11] = 42;
        // Event dir/type = assertion, threshold (0x01)
        data[12] = 0x01;
        // Event data
        data[13] = 0x51;
        data[14] = 0x80;
        data[15] = 0x25;

        let record = SelRecord::from_bytes(&data).expect("valid record");
        assert_eq!(record.record_id, 1);
        assert_eq!(record.record_type, SelRecordType::SystemEvent);
        assert_eq!(record.timestamp, 0x6000_0000);
        assert_eq!(record.sensor_number, 42);
        assert!(record.is_assertion());
        assert_eq!(record.event_type(), 0x01);
    }

    #[test]
    fn sel_record_too_short() {
        let data = [0u8; 10];
        assert!(SelRecord::from_bytes(&data).is_err());
    }

    #[test]
    fn timestamp_pre_init() {
        assert_eq!(format_sel_timestamp(100), "Pre-Init +100s");
    }

    #[test]
    fn timestamp_invalid() {
        assert_eq!(format_sel_timestamp(0xFFFF_FFFF), "Invalid");
    }

    #[test]
    fn timestamp_known_date() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let formatted = format_sel_timestamp(1_704_067_200);
        assert_eq!(formatted, "2024-01-01 00:00:00");
    }

    #[test]
    fn timestamp_epoch() {
        // Epoch itself is below 0x20000000 so it's pre-init.
        assert_eq!(format_sel_timestamp(0), "Pre-Init +0s");
    }

    #[test]
    fn sel_record_type_from_byte() {
        assert_eq!(SelRecordType::from(0x02), SelRecordType::SystemEvent);
        assert_eq!(
            SelRecordType::from(0xC5),
            SelRecordType::OemTimestamped(0xC5)
        );
        assert_eq!(
            SelRecordType::from(0xF0),
            SelRecordType::OemNonTimestamped(0xF0)
        );
        assert_eq!(SelRecordType::from(0x01), SelRecordType::Unknown(0x01));
    }

    #[test]
    fn deassertion_event() {
        let mut data = [0u8; 16];
        data[2] = 0x02; // system event
        data[12] = 0x81; // bit 7 set = deassertion
        let record = SelRecord::from_bytes(&data).expect("valid record");
        assert!(!record.is_assertion());
        assert_eq!(record.event_type(), 0x01);
    }
}
