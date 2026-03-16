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

//! IPMI v1.5 wire format packet building and parsing.
//!
//! An IPMI v1.5 LAN packet has the following structure:
//!
//! ```text
//! [RMCP Header 4B]          — RmcpHeader::IPMI (class = 0x07, no RMCP+ bit)
//! [Auth Type 1B]             — 0x00=None, 0x02=MD5
//! [Session Seq 4B LE]        — sequence number
//! [Session ID 4B LE]         — from Activate Session response
//! [Auth Code 0|16B]          — absent for AuthType::None, 16 bytes for MD5
//! [Payload Length 1B]        — single byte (u8, NOT u16 like v2.0)
//! [IPMI Message]             — inner IPMI message bytes
//! ```

use byteorder::{ByteOrder, LittleEndian};

use crate::error::{IpmitoolError, Result};
use crate::transport::lanplus::header::RmcpHeader;

use super::auth::AuthType;

// ==============================================================================
// Parsed Packet
// ==============================================================================

/// A parsed IPMI v1.5 packet, borrowing the payload from the input buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct V15ParsedPacket<'a> {
    pub auth_type: AuthType,
    pub session_seq: u32,
    pub session_id: u32,
    pub auth_code: Option<[u8; 16]>,
    pub payload: &'a [u8],
}

// ==============================================================================
// Packet Building
// ==============================================================================

/// Build a complete IPMI v1.5 LAN packet.
///
/// The packet includes the RMCP header, session fields, optional MD5 auth code,
/// and the inner IPMI message as payload.
///
/// # Panics
///
/// Panics if `ipmi_msg` is longer than 255 bytes (the v1.5 payload length field
/// is a single `u8`).
pub fn build_v15_packet(
    auth_type: AuthType,
    session_seq: u32,
    session_id: u32,
    auth_code: Option<&[u8; 16]>,
    ipmi_msg: &[u8],
) -> Vec<u8> {
    assert!(
        ipmi_msg.len() <= u8::MAX as usize,
        "IPMI v1.5 payload must fit in a u8 length field"
    );

    // Pre-calculate total size: 4 (RMCP) + 1 (auth type) + 4 (seq) + 4 (id)
    // + 0|16 (auth code) + 1 (length) + payload.
    let auth_code_len = if auth_code.is_some() { 16 } else { 0 };
    let total = 4 + 1 + 4 + 4 + auth_code_len + 1 + ipmi_msg.len();
    let mut buf = Vec::with_capacity(total);

    // RMCP header — plain IPMI class (no RMCP+ bit).
    buf.extend_from_slice(&RmcpHeader::IPMI.as_bytes());

    // Authentication type.
    buf.push(auth_type as u8);

    // Session sequence number (little-endian).
    let mut tmp = [0u8; 4];
    LittleEndian::write_u32(&mut tmp, session_seq);
    buf.extend_from_slice(&tmp);

    // Session ID (little-endian).
    LittleEndian::write_u32(&mut tmp, session_id);
    buf.extend_from_slice(&tmp);

    // Auth code (present only for authenticated sessions).
    if let Some(code) = auth_code {
        buf.extend_from_slice(code);
    }

    // Payload length (single byte, unlike v2.0's u16).
    buf.push(ipmi_msg.len() as u8);

    // Inner IPMI message.
    buf.extend_from_slice(ipmi_msg);

    buf
}

// ==============================================================================
// Packet Parsing
// ==============================================================================

/// Parse an IPMI v1.5 LAN packet from a raw byte buffer.
///
/// # Errors
///
/// Returns an error if the packet is too short, contains an unsupported auth
/// type, or if the payload length field does not match the remaining data.
pub fn parse_v15_packet(data: &[u8]) -> Result<V15ParsedPacket<'_>> {
    // Minimum packet: 4 (RMCP) + 1 (auth) + 4 (seq) + 4 (id) + 1 (len) = 14 bytes
    // (with AuthType::None and zero-length payload).
    if data.len() < 14 {
        return Err(IpmitoolError::InvalidResponse(format!(
            "IPMI v1.5 packet too short: {} bytes, need at least 14",
            data.len()
        )));
    }

    // Parse and validate the RMCP header (first 4 bytes).
    let _rmcp = RmcpHeader::from_bytes(&data[..4])?;

    // Auth type at offset 4.
    let auth_type = AuthType::try_from(data[4])?;

    // Session sequence and ID are always at fixed offsets.
    let session_seq = LittleEndian::read_u32(&data[5..9]);
    let session_id = LittleEndian::read_u32(&data[9..13]);

    // The rest depends on whether an auth code is present.
    let (auth_code, payload_offset) = match auth_type {
        AuthType::None => (None, 13),
        AuthType::Md5 => {
            // Auth code is 16 bytes starting at offset 13.
            if data.len() < 30 {
                return Err(IpmitoolError::InvalidResponse(format!(
                    "IPMI v1.5 MD5 packet too short: {} bytes, need at least 30",
                    data.len()
                )));
            }
            let mut code = [0u8; 16];
            code.copy_from_slice(&data[13..29]);
            (Some(code), 29)
        }
    };

    let payload_length = data[payload_offset] as usize;
    let payload_start = payload_offset + 1;

    // Validate that the declared payload length matches the remaining bytes.
    let remaining = data.len() - payload_start;
    if remaining < payload_length {
        return Err(IpmitoolError::InvalidResponse(format!(
            "IPMI v1.5 payload length mismatch: header says {payload_length}, \
             but only {remaining} bytes remain"
        )));
    }

    let payload = &data[payload_start..payload_start + payload_length];

    Ok(V15ParsedPacket {
        auth_type,
        session_seq,
        session_id,
        auth_code,
        payload,
    })
}

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_auth_none() {
        let ipmi_msg = vec![0x20, 0x18, 0xC8, 0x81, 0x00, 0x38, 0x8E];
        let packet = build_v15_packet(AuthType::None, 1, 0xDEAD_BEEF, None, &ipmi_msg);

        let parsed = parse_v15_packet(&packet).expect("valid packet");
        assert_eq!(parsed.auth_type, AuthType::None);
        assert_eq!(parsed.session_seq, 1);
        assert_eq!(parsed.session_id, 0xDEAD_BEEF);
        assert_eq!(parsed.auth_code, None);
        assert_eq!(parsed.payload, &ipmi_msg);
    }

    #[test]
    fn roundtrip_auth_md5() {
        let ipmi_msg = vec![0x20, 0x18, 0xC8, 0x81, 0x04, 0x01, 0xAA, 0xBB, 0x17];
        let auth_code = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let packet = build_v15_packet(
            AuthType::Md5,
            42,
            0x1234_5678,
            Some(&auth_code),
            &ipmi_msg,
        );

        let parsed = parse_v15_packet(&packet).expect("valid packet");
        assert_eq!(parsed.auth_type, AuthType::Md5);
        assert_eq!(parsed.session_seq, 42);
        assert_eq!(parsed.session_id, 0x1234_5678);
        assert_eq!(parsed.auth_code, Some(auth_code));
        assert_eq!(parsed.payload, &ipmi_msg);
    }

    #[test]
    fn parse_too_short() {
        // Only 10 bytes — well below the 14-byte minimum.
        let short = [0x06, 0x00, 0xFF, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let err = parse_v15_packet(&short).unwrap_err();
        assert!(
            err.to_string().contains("too short"),
            "expected 'too short' error, got: {err}"
        );
    }

    #[test]
    fn parse_invalid_auth_type() {
        // Build a minimal packet then overwrite the auth type byte with an
        // unsupported value (0xFF).
        let mut packet = build_v15_packet(AuthType::None, 0, 0, None, &[0x00]);
        packet[4] = 0xFF;

        let err = parse_v15_packet(&packet).unwrap_err();
        assert!(
            err.to_string().contains("auth type") || err.to_string().contains("0xff"),
            "expected auth type error, got: {err}"
        );
    }
}
