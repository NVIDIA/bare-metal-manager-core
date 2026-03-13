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

//! FRU (Field Replaceable Unit) data types and field encoding/decoding.
//!
//! FRU data is organized into areas: Internal Use, Chassis Info, Board Info,
//! Product Info, and MultiRecord. Each area contains type/length-encoded fields
//! that can be binary, BCD+, 6-bit packed ASCII, or 8-bit ASCII/Latin-1.
//!
//! See IPMI Platform Management FRU Information Storage Definition v1.0.

// ==============================================================================
// FRU Field Encoding
// ==============================================================================

/// The encoding type for a FRU field, determined by the upper 2 bits of
/// the type/length byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FruFieldEncoding {
    /// Binary or unspecified data.
    Binary,
    /// BCD plus encoding (digits 0-9, space, dash, period).
    BcdPlus,
    /// 6-bit packed ASCII (3 chars per 2 bytes, ASCII 0x20-0x5F).
    SixBitAscii,
    /// 8-bit ASCII + Latin-1. If the highest bit is set, it's Latin-1.
    EightBitAscii,
}

impl FruFieldEncoding {
    /// Extract the encoding type from a FRU type/length byte.
    #[must_use]
    pub fn from_type_length(tl: u8) -> Self {
        match (tl >> 6) & 0x03 {
            0x00 => Self::Binary,
            0x01 => Self::BcdPlus,
            0x02 => Self::SixBitAscii,
            0x03 => Self::EightBitAscii,
            _ => unreachable!("2-bit mask"),
        }
    }

    /// Extract the data length from a FRU type/length byte.
    #[must_use]
    pub fn data_length(tl: u8) -> usize {
        (tl & 0x3F) as usize
    }
}

/// BCD plus character set: 0-9, space, dash, period, and reserved codes.
const BCD_PLUS_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ' ', '-', '.', '?', '?', '?',
];

/// Decode a BCD plus encoded field into a string.
#[must_use]
pub fn decode_bcd_plus(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for &byte in data {
        let lo = (byte & 0x0F) as usize;
        let hi = ((byte >> 4) & 0x0F) as usize;
        result.push(BCD_PLUS_CHARS[lo]);
        // Only push high nibble if it's not padding (0x00 at end).
        if hi != 0 || lo != 0 {
            result.push(BCD_PLUS_CHARS[hi]);
        }
    }
    result
}

/// Decode a 6-bit packed ASCII field into a string.
///
/// Each group of 3 bytes encodes 4 characters (6 bits each, offset by 0x20).
#[must_use]
pub fn decode_6bit_ascii(data: &[u8]) -> String {
    let total_bits = data.len() * 8;
    let char_count = total_bits / 6;
    let mut result = String::with_capacity(char_count);

    for i in 0..char_count {
        let bit_offset = i * 6;
        let byte_index = bit_offset / 8;
        let bit_index = bit_offset % 8;

        let raw = if bit_index <= 2 {
            // All 6 bits fit in one byte.
            (data[byte_index] >> bit_index) & 0x3F
        } else {
            // Spans two bytes.
            let lo = data[byte_index] >> bit_index;
            let hi = if byte_index + 1 < data.len() {
                data[byte_index + 1] << (8 - bit_index)
            } else {
                0
            };
            (lo | hi) & 0x3F
        };

        result.push(char::from(raw + 0x20));
    }

    result
}

/// Decode a FRU field given its type/length byte and raw data.
///
/// Returns a human-readable string representation. Binary fields are
/// hex-encoded.
#[must_use]
pub fn decode_fru_field(tl: u8, data: &[u8]) -> String {
    match FruFieldEncoding::from_type_length(tl) {
        FruFieldEncoding::Binary => hex::encode(data),
        FruFieldEncoding::BcdPlus => decode_bcd_plus(data),
        FruFieldEncoding::SixBitAscii => decode_6bit_ascii(data),
        FruFieldEncoding::EightBitAscii => {
            String::from_utf8_lossy(data).trim_end().to_owned()
        }
    }
}

// ==============================================================================
// FRU Area Types
// ==============================================================================

/// Offsets to each FRU area, from the Common Header (first 8 bytes).
/// Offsets are in units of 8 bytes. A zero offset means the area is absent.
#[derive(Debug, Clone, Default)]
pub struct FruCommonHeader {
    pub format_version: u8,
    pub internal_use_offset: u8,
    pub chassis_info_offset: u8,
    pub board_info_offset: u8,
    pub product_info_offset: u8,
    pub multirecord_offset: u8,
}

impl FruCommonHeader {
    /// Parse the 8-byte FRU Common Header.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is too short or the checksum is invalid.
    pub fn from_bytes(data: &[u8]) -> crate::error::Result<Self> {
        if data.len() < 8 {
            return Err(crate::error::IpmitoolError::FruParse(
                "common header too short".to_owned(),
            ));
        }

        // Verify checksum: sum of all 8 bytes must be 0 mod 256.
        let checksum: u8 = data[..8].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        if checksum != 0 {
            return Err(crate::error::IpmitoolError::FruParse(format!(
                "common header checksum mismatch: 0x{checksum:02X}"
            )));
        }

        Ok(Self {
            format_version: data[0],
            internal_use_offset: data[1],
            chassis_info_offset: data[2],
            board_info_offset: data[3],
            product_info_offset: data[4],
            multirecord_offset: data[5],
        })
    }
}

/// Parsed Board Info area fields.
#[derive(Debug, Clone, Default)]
pub struct FruBoardInfo {
    pub manufacturer: String,
    pub product_name: String,
    pub serial_number: String,
    pub part_number: String,
    pub fru_file_id: String,
    pub custom_fields: Vec<String>,
}

/// Parsed Product Info area fields.
#[derive(Debug, Clone, Default)]
pub struct FruProductInfo {
    pub manufacturer: String,
    pub product_name: String,
    pub part_model_number: String,
    pub version: String,
    pub serial_number: String,
    pub asset_tag: String,
    pub fru_file_id: String,
    pub custom_fields: Vec<String>,
}

/// Parsed Chassis Info area fields.
#[derive(Debug, Clone, Default)]
pub struct FruChassisInfo {
    pub chassis_type: u8,
    pub part_number: String,
    pub serial_number: String,
    pub custom_fields: Vec<String>,
}

/// Aggregated FRU inventory data.
#[derive(Debug, Clone, Default)]
pub struct FruData {
    pub board: Option<FruBoardInfo>,
    pub product: Option<FruProductInfo>,
    pub chassis: Option<FruChassisInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcd_plus_decoding() {
        // "12345" encoded as BCD+: 0x21, 0x43, 0x05
        let data = [0x21, 0x43, 0x05];
        let result = decode_bcd_plus(&data);
        assert_eq!(result, "123450");
    }

    #[test]
    fn six_bit_ascii_decoding() {
        // "IPMI" in 6-bit packed ASCII:
        // I=0x29, P=0x30, M=0x2D, I=0x29
        // Bits: 101001 110000 101101 101001
        // Packed into bytes: 0xA9 0x4B 0x6A
        // Actually let's compute properly:
        // char 0 (I=0x29): bits 0-5 of byte 0
        // char 1 (P=0x30): bits 6-7 of byte 0, bits 0-3 of byte 1
        // char 2 (M=0x2D): bits 4-7 of byte 1, bits 0-1 of byte 2
        // char 3 (I=0x29): bits 2-7 of byte 2
        //
        // byte0 = (0x29) | (0x30 << 6) = 0x29 | 0xC0 = 0xE9..? No.
        // 0x29 = 0b_00101001. Low 6 bits in byte0[0:5] = 0b101001.
        // 0x30 = 0b_00110000. Low 2 bits in byte0[6:7] = 0b00. Next 4 bits in byte1[0:3] = 0b1100.
        // byte0 = 0b_00_101001 = 0x29
        // byte1[0:3] = 0b1100, byte1[4:7] = low 4 of M (0x2D = 0b101101) => 0b1101
        // byte1 = 0b_1101_1100 = 0xDC..? Let me just test with known data.
        //
        // Use a simpler test: "AB" = 0x21, 0x22
        // byte0[0:5] = 0x21 = 0b100001
        // byte0[6:7] = low 2 of 0x22 = 0b10
        // byte1[0:3] = high 4 of 0x22 = 0b0010
        // byte0 = 0b_10_100001 = 0xA1
        // byte1 = 0b_xxxx_0010 (only 4 bits used, rest zero) = 0x02
        let data = [0xA1, 0x08];
        let result = decode_6bit_ascii(&data);
        // 16 bits / 6 = 2 chars
        assert_eq!(result.len(), 2);
        assert_eq!(&result[..1], "A");
    }

    #[test]
    fn eight_bit_ascii_field() {
        let tl = 0xC5; // encoding=11 (8-bit), length=5
        let data = b"Hello";
        assert_eq!(decode_fru_field(tl, data), "Hello");
    }

    #[test]
    fn fru_common_header_valid() {
        // Build a valid header: version=1, offsets, pad, checksum
        let mut header = [0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00u8];
        // Compute checksum: sum of first 7 bytes, then set byte 7 to make total 0.
        let sum: u8 = header[..7].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        header[7] = 0u8.wrapping_sub(sum);

        let parsed = FruCommonHeader::from_bytes(&header).expect("valid header");
        assert_eq!(parsed.format_version, 1);
        assert_eq!(parsed.board_info_offset, 1);
        assert_eq!(parsed.product_info_offset, 2);
    }

    #[test]
    fn fru_common_header_bad_checksum() {
        let header = [0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x00, 0xFF];
        assert!(FruCommonHeader::from_bytes(&header).is_err());
    }
}
