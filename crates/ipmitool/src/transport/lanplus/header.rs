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

//! RMCP and IPMI session header types.
//!
//! An RMCP+ message has the following structure:
//!
//! ```text
//! [RMCP Header (4 bytes)]
//! [IPMI Session Header (variable)]
//! [IPMI Message / Payload]
//! [Session Trailer (integrity pad + auth code, if authenticated)]
//! ```

use byteorder::{ByteOrder, LittleEndian};

use crate::error::{IpmitoolError, Result};

// ==============================================================================
// RMCP Header
// ==============================================================================
//
// The RMCP (Remote Management and Control Protocol) header is 4 bytes:
//   [0] Version (0x06 for RMCP 1.0)
//   [1] Reserved (0x00)
//   [2] Sequence number (0xFF for IPMI-over-RMCP)
//   [3] Class of message (0x07 = IPMI, with bit 7 for RMCP+ if set)

/// RMCP protocol version.
pub const RMCP_VERSION: u8 = 0x06;

/// RMCP message class: IPMI.
pub const RMCP_CLASS_IPMI: u8 = 0x07;

/// RMCP+ message class bit (ASF 2.0 format, set in class byte).
pub const RMCP_CLASS_RMCPPLUS_BIT: u8 = 0x80;

/// RMCP header (4 bytes at the start of every RMCP message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RmcpHeader {
    pub version: u8,
    pub reserved: u8,
    pub sequence: u8,
    pub class: u8,
}

impl RmcpHeader {
    /// Standard RMCP header for IPMI messages (non-RMCP+).
    pub const IPMI: Self = Self {
        version: RMCP_VERSION,
        reserved: 0x00,
        sequence: 0xFF,
        class: RMCP_CLASS_IPMI,
    };

    /// RMCP header for RMCP+ (IPMI v2.0) messages.
    pub const RMCPPLUS: Self = Self {
        version: RMCP_VERSION,
        reserved: 0x00,
        sequence: 0xFF,
        class: RMCP_CLASS_IPMI | RMCP_CLASS_RMCPPLUS_BIT,
    };

    /// Serialize to 4 bytes.
    #[must_use]
    pub fn as_bytes(self) -> [u8; 4] {
        [self.version, self.reserved, self.sequence, self.class]
    }

    /// Parse from a 4-byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is too short or the version is wrong.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(IpmitoolError::InvalidResponse(
                "RMCP header too short".to_owned(),
            ));
        }
        if data[0] != RMCP_VERSION {
            return Err(IpmitoolError::InvalidResponse(format!(
                "unexpected RMCP version: 0x{:02X}",
                data[0]
            )));
        }
        Ok(Self {
            version: data[0],
            reserved: data[1],
            sequence: data[2],
            class: data[3],
        })
    }

    /// Returns `true` if this is an RMCP+ format message.
    #[must_use]
    pub fn is_rmcpplus(&self) -> bool {
        (self.class & RMCP_CLASS_RMCPPLUS_BIT) != 0
    }
}

// ==============================================================================
// IPMI v2.0 Session Header
// ==============================================================================
//
// For RMCP+ authenticated sessions, the session header is:
//   [0]     Authentication type (0x06 = RMCP+)
//   [1]     Payload type (with encryption/authentication bits)
//   [2..6]  Session ID (LE u32)
//   [6..10] Session sequence number (LE u32)
//   [10..12] Payload length (LE u16)
//
// For unauthenticated / pre-session messages:
//   [0]     Authentication type (0x06)
//   [1]     Payload type
//   [2..6]  Session ID = 0
//   [6..10] Session sequence = 0
//   [10..12] Payload length

/// Authentication type value for RMCP+ (IPMI v2.0).
pub const AUTH_TYPE_RMCPPLUS: u8 = 0x06;

/// Payload type values for RMCP+ messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadType {
    /// Standard IPMI message.
    Ipmi = 0x00,
    /// SOL (Serial-over-LAN) data.
    Sol = 0x01,
    /// Open Session Request (RMCP+).
    OpenSessionRequest = 0x10,
    /// Open Session Response.
    OpenSessionResponse = 0x11,
    /// RAKP Message 1.
    Rakp1 = 0x12,
    /// RAKP Message 2.
    Rakp2 = 0x13,
    /// RAKP Message 3.
    Rakp3 = 0x14,
    /// RAKP Message 4.
    Rakp4 = 0x15,
}

impl TryFrom<u8> for PayloadType {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, u8> {
        match value & 0x3F {
            0x00 => Ok(Self::Ipmi),
            0x01 => Ok(Self::Sol),
            0x10 => Ok(Self::OpenSessionRequest),
            0x11 => Ok(Self::OpenSessionResponse),
            0x12 => Ok(Self::Rakp1),
            0x13 => Ok(Self::Rakp2),
            0x14 => Ok(Self::Rakp3),
            0x15 => Ok(Self::Rakp4),
            other => Err(other),
        }
    }
}

impl From<PayloadType> for u8 {
    fn from(pt: PayloadType) -> u8 {
        pt as u8
    }
}

/// IPMI v2.0 / RMCP+ session header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHeader {
    pub auth_type: u8,
    /// Payload type (lower 6 bits) with encryption (bit 7) and
    /// authentication (bit 6) flags.
    pub payload_type_raw: u8,
    /// Remote console session ID (for requests) or managed system session ID
    /// (for responses).
    pub session_id: u32,
    /// Session sequence number.
    pub session_seq: u32,
    /// Length of the payload that follows this header.
    pub payload_length: u16,
}

impl SessionHeader {
    /// Size of the session header in bytes.
    pub const SIZE: usize = 12;

    /// Returns the payload type (lower 6 bits).
    pub fn payload_type(&self) -> std::result::Result<PayloadType, u8> {
        PayloadType::try_from(self.payload_type_raw)
    }

    /// Returns `true` if the payload is encrypted.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        (self.payload_type_raw & 0x80) != 0
    }

    /// Returns `true` if the payload is authenticated (has integrity trailer).
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        (self.payload_type_raw & 0x40) != 0
    }

    /// Create a pre-session header (session ID and sequence both zero).
    #[must_use]
    pub fn pre_session(payload_type: PayloadType) -> Self {
        Self {
            auth_type: AUTH_TYPE_RMCPPLUS,
            payload_type_raw: payload_type as u8,
            session_id: 0,
            session_seq: 0,
            payload_length: 0, // Caller sets this after building the payload.
        }
    }

    /// Create an authenticated session header with encryption and integrity.
    #[must_use]
    pub fn authenticated(
        payload_type: PayloadType,
        session_id: u32,
        session_seq: u32,
    ) -> Self {
        Self {
            auth_type: AUTH_TYPE_RMCPPLUS,
            // Set bit 7 (encrypted) and bit 6 (authenticated).
            payload_type_raw: (payload_type as u8) | 0xC0,
            session_id,
            session_seq,
            payload_length: 0,
        }
    }

    /// Serialize to bytes (appended to the given buffer).
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.push(self.auth_type);
        buf.push(self.payload_type_raw);

        let mut tmp = [0u8; 4];
        LittleEndian::write_u32(&mut tmp, self.session_id);
        buf.extend_from_slice(&tmp);

        LittleEndian::write_u32(&mut tmp, self.session_seq);
        buf.extend_from_slice(&tmp);

        let mut len_buf = [0u8; 2];
        LittleEndian::write_u16(&mut len_buf, self.payload_length);
        buf.extend_from_slice(&len_buf);
    }

    /// Parse from a byte slice at the given offset.
    ///
    /// # Errors
    ///
    /// Returns an error if there aren't enough bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(IpmitoolError::InvalidResponse(format!(
                "session header too short: {} bytes, need {}",
                data.len(),
                Self::SIZE,
            )));
        }

        Ok(Self {
            auth_type: data[0],
            payload_type_raw: data[1],
            session_id: LittleEndian::read_u32(&data[2..6]),
            session_seq: LittleEndian::read_u32(&data[6..10]),
            payload_length: LittleEndian::read_u16(&data[10..12]),
        })
    }
}

// ==============================================================================
// IPMI Message Header (inside the payload)
// ==============================================================================
//
// The IPMI message (inside the RMCP+ payload, after decryption) has:
//   [0]     Responder address (0x20 for BMC)
//   [1]     NetFn (upper 6 bits) / Responder LUN (lower 2 bits)
//   [2]     Header checksum
//   [3]     Requester address (0x81 for remote console via LAN)
//   [4]     Requester sequence (upper 6 bits) / Requester LUN (lower 2 bits)
//   [5]     Command code
//   [6..]   Command data
//   [last]  Data checksum (over bytes [3..last])

/// Standard BMC slave address.
pub const BMC_SLAVE_ADDR: u8 = 0x20;

/// Remote console address for LAN interface.
pub const REMOTE_CONSOLE_ADDR: u8 = 0x81;

/// IPMI message header fields (for building/parsing the inner IPMI message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpmiMsgHeader {
    pub rs_addr: u8,
    pub netfn_rs_lun: u8,
    pub rq_addr: u8,
    pub rq_seq_rq_lun: u8,
    pub cmd: u8,
}

impl IpmiMsgHeader {
    /// Build a request message header.
    ///
    /// `rq_seq` is the 6-bit sequence number (0-63).
    #[must_use]
    pub fn request(netfn: u8, cmd: u8, rq_seq: u8) -> Self {
        Self {
            rs_addr: BMC_SLAVE_ADDR,
            netfn_rs_lun: netfn << 2,
            rq_addr: REMOTE_CONSOLE_ADDR,
            rq_seq_rq_lun: rq_seq << 2,
            cmd,
        }
    }

    /// Extract the NetFn from the header.
    #[must_use]
    pub fn netfn(&self) -> u8 {
        self.netfn_rs_lun >> 2
    }

    /// Compute the header checksum (two's complement of sum of rs_addr + netfn_rs_lun).
    #[must_use]
    pub fn header_checksum(&self) -> u8 {
        let sum = self.rs_addr.wrapping_add(self.netfn_rs_lun);
        0u8.wrapping_sub(sum)
    }

    /// Serialize the full IPMI message (header + data + checksums) to bytes.
    pub fn build_message(&self, data: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(7 + data.len());
        msg.push(self.rs_addr);
        msg.push(self.netfn_rs_lun);
        msg.push(self.header_checksum());
        msg.push(self.rq_addr);
        msg.push(self.rq_seq_rq_lun);
        msg.push(self.cmd);
        msg.extend_from_slice(data);

        // Data checksum: two's complement of sum of bytes from rq_addr onward.
        let data_sum: u8 = msg[3..].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        msg.push(0u8.wrapping_sub(data_sum));

        msg
    }

    /// Parse an IPMI message header and validate checksums.
    ///
    /// Returns (header, data_slice) where data_slice is the command data
    /// (excluding the data checksum byte).
    ///
    /// # Errors
    ///
    /// Returns an error if the message is too short or checksums are invalid.
    pub fn parse_message(msg: &[u8]) -> Result<(Self, &[u8])> {
        // Minimum: 6 header bytes + 1 checksum = 7
        if msg.len() < 7 {
            return Err(IpmitoolError::InvalidResponse(format!(
                "IPMI message too short: {} bytes",
                msg.len()
            )));
        }

        // Validate header checksum.
        let hdr_sum = msg[0].wrapping_add(msg[1]).wrapping_add(msg[2]);
        if hdr_sum != 0 {
            return Err(IpmitoolError::InvalidResponse(format!(
                "IPMI header checksum failed: 0x{hdr_sum:02X}"
            )));
        }

        // Validate data checksum.
        let data_sum: u8 = msg[3..].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        if data_sum != 0 {
            return Err(IpmitoolError::InvalidResponse(format!(
                "IPMI data checksum failed: 0x{data_sum:02X}"
            )));
        }

        let header = Self {
            rs_addr: msg[0],
            netfn_rs_lun: msg[1],
            rq_addr: msg[3],
            rq_seq_rq_lun: msg[4],
            cmd: msg[5],
        };

        // Data is everything between cmd and the final checksum byte.
        let data = &msg[6..msg.len() - 1];

        Ok((header, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // RMCP Header Tests
    // =========================================================================

    #[test]
    fn rmcp_header_roundtrip() {
        let header = RmcpHeader::RMCPPLUS;
        let bytes = header.as_bytes();
        let parsed = RmcpHeader::from_bytes(&bytes).expect("valid header");
        assert_eq!(header, parsed);
        assert!(parsed.is_rmcpplus());
    }

    #[test]
    fn rmcp_header_ipmi_not_rmcpplus() {
        let header = RmcpHeader::IPMI;
        assert!(!header.is_rmcpplus());
    }

    #[test]
    fn rmcp_header_too_short() {
        assert!(RmcpHeader::from_bytes(&[0x06, 0x00]).is_err());
    }

    #[test]
    fn rmcp_header_bad_version() {
        assert!(RmcpHeader::from_bytes(&[0x05, 0x00, 0xFF, 0x07]).is_err());
    }

    // =========================================================================
    // Session Header Tests
    // =========================================================================

    #[test]
    fn session_header_roundtrip() {
        let header = SessionHeader {
            auth_type: AUTH_TYPE_RMCPPLUS,
            payload_type_raw: PayloadType::Ipmi as u8 | 0xC0,
            session_id: 0x12345678,
            session_seq: 0x00000001,
            payload_length: 42,
        };

        let mut buf = Vec::new();
        header.write_to(&mut buf);
        assert_eq!(buf.len(), SessionHeader::SIZE);

        let parsed = SessionHeader::from_bytes(&buf).expect("valid header");
        assert_eq!(header, parsed);
        assert!(parsed.is_encrypted());
        assert!(parsed.is_authenticated());
    }

    #[test]
    fn session_header_pre_session() {
        let header = SessionHeader::pre_session(PayloadType::OpenSessionRequest);
        assert_eq!(header.session_id, 0);
        assert_eq!(header.session_seq, 0);
        assert!(!header.is_encrypted());
        assert!(!header.is_authenticated());
        assert_eq!(
            header.payload_type(),
            Ok(PayloadType::OpenSessionRequest)
        );
    }

    #[test]
    fn session_header_authenticated() {
        let header = SessionHeader::authenticated(PayloadType::Ipmi, 0xABCD, 5);
        assert!(header.is_encrypted());
        assert!(header.is_authenticated());
        assert_eq!(header.session_id, 0xABCD);
        assert_eq!(header.session_seq, 5);
    }

    // =========================================================================
    // IPMI Message Tests
    // =========================================================================

    #[test]
    fn ipmi_message_build_parse_roundtrip() {
        let header = IpmiMsgHeader::request(0x06, 0x01, 7); // App, Get Device ID, seq=7
        let data = vec![0xAA, 0xBB];
        let msg = header.build_message(&data);

        // Verify structure.
        assert_eq!(msg[0], BMC_SLAVE_ADDR); // rs_addr
        assert_eq!(msg[5], 0x01); // cmd

        let (parsed_hdr, parsed_data) =
            IpmiMsgHeader::parse_message(&msg).expect("valid message");
        assert_eq!(parsed_hdr.netfn(), 0x06);
        assert_eq!(parsed_hdr.cmd, 0x01);
        assert_eq!(parsed_data, &[0xAA, 0xBB]);
    }

    #[test]
    fn ipmi_message_empty_data() {
        let header = IpmiMsgHeader::request(0x00, 0x01, 0); // Chassis, Get Status
        let msg = header.build_message(&[]);

        let (parsed_hdr, parsed_data) =
            IpmiMsgHeader::parse_message(&msg).expect("valid message");
        assert_eq!(parsed_hdr.netfn(), 0x00);
        assert_eq!(parsed_hdr.cmd, 0x01);
        assert!(parsed_data.is_empty());
    }

    #[test]
    fn ipmi_header_checksum() {
        // rs_addr=0x20, netfn_rs_lun=0x18 (App<<2) → sum=0x38 → checksum=0xC8
        let header = IpmiMsgHeader::request(0x06, 0x01, 0);
        assert_eq!(header.netfn_rs_lun, 0x18);
        let expected = 0u8.wrapping_sub(0x20u8.wrapping_add(0x18));
        assert_eq!(header.header_checksum(), expected);
    }

    #[test]
    fn ipmi_message_bad_header_checksum() {
        let mut msg = IpmiMsgHeader::request(0x06, 0x01, 0).build_message(&[]);
        msg[2] = 0xFF; // Corrupt header checksum.
        assert!(IpmiMsgHeader::parse_message(&msg).is_err());
    }

    #[test]
    fn ipmi_message_bad_data_checksum() {
        let mut msg = IpmiMsgHeader::request(0x06, 0x01, 0).build_message(&[0xAA]);
        let last = msg.len() - 1;
        msg[last] = 0xFF; // Corrupt data checksum.
        assert!(IpmiMsgHeader::parse_message(&msg).is_err());
    }

    #[test]
    fn ipmi_message_too_short() {
        assert!(IpmiMsgHeader::parse_message(&[0x20, 0x18, 0xC8]).is_err());
    }
}
