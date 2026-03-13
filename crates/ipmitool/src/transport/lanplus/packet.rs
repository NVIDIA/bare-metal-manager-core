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

//! RMCP+ packet construction and parsing.
//!
//! An RMCP+ packet has the following wire format:
//!
//! ```text
//! [RMCP Header (4 bytes)]
//! [Session Header (12 bytes)]
//! [Payload (variable, encrypted if session is authenticated)]
//! [Integrity Pad (0-3 bytes, to align to 4 bytes)]
//! [Pad Length (1 byte)]
//! [Next Header (1 byte, always 0x07)]
//! [Auth Code / ICV (variable, depends on integrity algorithm)]
//! ```
//!
//! The integrity data (pad through auth code) is only present when the session
//! header indicates authentication (bit 6 of payload type).

use super::header::{PayloadType, RmcpHeader, SessionHeader};
use crate::error::{IpmitoolError, Result};

/// The "next header" value in the integrity trailer (always 0x07 per spec).
const INTEGRITY_NEXT_HEADER: u8 = 0x07;

// ==============================================================================
// Packet Building
// ==============================================================================

/// Build a complete RMCP+ packet for a pre-session (unauthenticated) message.
///
/// Used for Open Session Request, RAKP messages, and other messages sent
/// before the session is fully established.
#[must_use]
pub fn build_pre_session_packet(payload_type: PayloadType, payload: &[u8]) -> Vec<u8> {
    let rmcp = RmcpHeader::RMCPPLUS;
    let mut session = SessionHeader::pre_session(payload_type);
    session.payload_length = payload.len() as u16;

    let mut packet = Vec::with_capacity(4 + SessionHeader::SIZE + payload.len());
    packet.extend_from_slice(&rmcp.as_bytes());
    session.write_to(&mut packet);
    packet.extend_from_slice(payload);

    packet
}

/// Build a complete RMCP+ packet for an authenticated session message.
///
/// This constructs the packet with:
/// 1. RMCP header
/// 2. Session header (with encryption + authentication flags)
/// 3. Encrypted payload (IV + AES-CBC ciphertext)
/// 4. Integrity trailer (pad + auth code)
///
/// The `encrypt_fn` encrypts the plaintext payload and returns IV + ciphertext.
/// The `integrity_fn` computes the auth code over the session header through
/// the next_header byte.
///
/// # Errors
///
/// Returns an error if encryption or integrity computation fails.
pub fn build_authenticated_packet(
    session_id: u32,
    session_seq: u32,
    payload: &[u8],
    encrypt_fn: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
    integrity_fn: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    let rmcp = RmcpHeader::RMCPPLUS;

    // Encrypt the payload.
    let encrypted_payload = encrypt_fn(payload)?;

    let mut session =
        SessionHeader::authenticated(PayloadType::Ipmi, session_id, session_seq);
    session.payload_length = encrypted_payload.len() as u16;

    // Build the packet up through the payload.
    let mut packet = Vec::with_capacity(
        4 + SessionHeader::SIZE + encrypted_payload.len() + 20, // room for trailer
    );
    packet.extend_from_slice(&rmcp.as_bytes());
    session.write_to(&mut packet);
    packet.extend_from_slice(&encrypted_payload);

    // Integrity trailer: pad to 4-byte boundary, then pad_length + next_header.
    // The integrity pad starts after the encrypted payload.
    // The data that gets integrity-protected starts at the session header
    // (offset 4, after the RMCP header).
    let integrity_start = 4; // start of session header

    // Compute integrity padding: the total from session header through
    // next_header byte must be such that the auth code starts at a
    // consistent offset. The pad aligns the data before the auth code.
    let data_len = packet.len() - integrity_start;
    let pad_length = (4 - (data_len % 4)) % 4;
    packet.extend(std::iter::repeat_n(0xFF, pad_length));
    packet.push(pad_length as u8);
    packet.push(INTEGRITY_NEXT_HEADER);

    // Compute integrity check value over session header through next_header.
    let integrity_data = &packet[integrity_start..];
    let auth_code = integrity_fn(integrity_data)?;
    packet.extend_from_slice(&auth_code);

    Ok(packet)
}

// ==============================================================================
// Packet Parsing
// ==============================================================================

/// Parsed RMCP+ packet — the raw components before decryption.
#[derive(Debug)]
pub struct ParsedPacket<'a> {
    pub rmcp: RmcpHeader,
    pub session: SessionHeader,
    /// The payload bytes (encrypted if session is authenticated).
    pub payload: &'a [u8],
    /// The integrity auth code, if present.
    pub auth_code: Option<&'a [u8]>,
}

/// Parse an RMCP+ packet from raw bytes.
///
/// This splits the packet into its constituent parts but does NOT decrypt
/// the payload or verify the integrity check value — that's the caller's
/// responsibility.
///
/// `expected_auth_code_len` is the length of the integrity auth code for
/// the negotiated integrity algorithm (e.g., 12 for HMAC-SHA1-96, 16 for
/// HMAC-SHA256-128). Pass 0 for unauthenticated messages.
///
/// # Errors
///
/// Returns an error if the packet is malformed (too short, bad headers).
pub fn parse_packet(data: &[u8], expected_auth_code_len: usize) -> Result<ParsedPacket<'_>> {
    // Minimum: RMCP (4) + Session Header (12) = 16 bytes.
    if data.len() < 16 {
        return Err(IpmitoolError::InvalidResponse(format!(
            "packet too short: {} bytes",
            data.len()
        )));
    }

    let rmcp = RmcpHeader::from_bytes(&data[0..4])?;
    let session = SessionHeader::from_bytes(&data[4..16])?;

    let payload_start = 16;
    let payload_len = session.payload_length as usize;

    if payload_start + payload_len > data.len() {
        return Err(IpmitoolError::InvalidResponse(format!(
            "payload length {} exceeds packet size {}",
            payload_len,
            data.len()
        )));
    }

    let payload = &data[payload_start..payload_start + payload_len];

    // If authenticated, extract the auth code from the trailer.
    let auth_code = if session.is_authenticated() && expected_auth_code_len > 0 {
        let trailer_start = payload_start + payload_len;
        let _remaining = &data[trailer_start..];

        // The trailer is: [pad bytes] [pad_length] [next_header=0x07] [auth_code]
        // We know the auth code length, so work backwards from the end.
        if data.len() < trailer_start + 2 + expected_auth_code_len {
            return Err(IpmitoolError::InvalidResponse(
                "packet too short for integrity trailer".to_owned(),
            ));
        }

        let auth_code_start = data.len() - expected_auth_code_len;
        Some(&data[auth_code_start..])
    } else {
        None
    };

    Ok(ParsedPacket {
        rmcp,
        session,
        payload,
        auth_code,
    })
}

/// Verify the integrity check value of a parsed packet.
///
/// `integrity_fn` should compute the expected auth code over the given data.
/// The integrity-protected data runs from the session header (offset 4)
/// through the next_header byte (just before the auth code).
///
/// # Errors
///
/// Returns an error if the auth code doesn't match.
pub fn verify_integrity(
    packet_bytes: &[u8],
    auth_code_len: usize,
    integrity_fn: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
) -> Result<()> {
    if auth_code_len == 0 {
        return Ok(());
    }

    let integrity_start = 4; // After RMCP header
    let auth_code_start = packet_bytes.len() - auth_code_len;
    let integrity_data = &packet_bytes[integrity_start..auth_code_start];
    let received_auth_code = &packet_bytes[auth_code_start..];

    let expected_auth_code = integrity_fn(integrity_data)?;

    if received_auth_code != expected_auth_code.as_slice() {
        return Err(IpmitoolError::Crypto(
            "integrity check value mismatch".to_owned(),
        ));
    }

    Ok(())
}

/// Extract the session header bytes from a raw packet for integrity computation.
///
/// Returns the slice from session header start through end of payload
/// (before any integrity trailer).
#[must_use]
pub fn integrity_protected_data(packet: &[u8], payload_len: usize) -> &[u8] {
    let session_header_start = 4;
    let payload_end = 16 + payload_len;
    &packet[session_header_start..payload_end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_pre_session_packet_structure() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let packet = build_pre_session_packet(PayloadType::OpenSessionRequest, &payload);

        // RMCP header (4) + session header (12) + payload (4) = 20
        assert_eq!(packet.len(), 20);

        // Verify RMCP header.
        let rmcp = RmcpHeader::from_bytes(&packet[0..4]).expect("valid rmcp");
        assert!(rmcp.is_rmcpplus());

        // Verify session header.
        let session = SessionHeader::from_bytes(&packet[4..16]).expect("valid session");
        assert_eq!(
            session.payload_type(),
            Ok(PayloadType::OpenSessionRequest)
        );
        assert_eq!(session.session_id, 0);
        assert_eq!(session.session_seq, 0);
        assert_eq!(session.payload_length, 4);

        // Verify payload.
        assert_eq!(&packet[16..20], &payload);
    }

    #[test]
    fn parse_pre_session_packet_roundtrip() {
        let payload = vec![0xAA, 0xBB, 0xCC];
        let packet = build_pre_session_packet(PayloadType::Rakp1, &payload);

        let parsed = parse_packet(&packet, 0).expect("valid packet");
        assert!(parsed.rmcp.is_rmcpplus());
        assert_eq!(parsed.session.payload_type(), Ok(PayloadType::Rakp1));
        assert_eq!(parsed.payload, &payload);
        assert!(parsed.auth_code.is_none());
    }

    #[test]
    fn build_authenticated_packet_structure() {
        // Use identity "encryption" and fixed "integrity" for testing.
        let payload = vec![0x01, 0x02, 0x03];
        let packet = build_authenticated_packet(
            0xDEADBEEF,
            1,
            &payload,
            |p| Ok(p.to_vec()),          // No-op "encryption"
            |_data| Ok(vec![0xAA; 12]),   // Fixed 12-byte auth code
        )
        .expect("build packet");

        // Verify RMCP header.
        let rmcp = RmcpHeader::from_bytes(&packet[0..4]).expect("valid rmcp");
        assert!(rmcp.is_rmcpplus());

        // Verify session header.
        let session = SessionHeader::from_bytes(&packet[4..16]).expect("valid session");
        assert!(session.is_encrypted());
        assert!(session.is_authenticated());
        assert_eq!(session.session_id, 0xDEADBEEF);
        assert_eq!(session.session_seq, 1);
        assert_eq!(session.payload_length, 3);

        // Verify the packet ends with the auth code.
        assert_eq!(&packet[packet.len() - 12..], &[0xAA; 12]);
    }

    #[test]
    fn parse_authenticated_packet() {
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let auth_code_len = 16;
        let packet = build_authenticated_packet(
            0x12345678,
            42,
            &payload,
            |p| Ok(p.to_vec()),
            |_| Ok(vec![0xBB; auth_code_len]),
        )
        .expect("build packet");

        let parsed = parse_packet(&packet, auth_code_len).expect("parse packet");
        assert_eq!(parsed.session.session_id, 0x12345678);
        assert_eq!(parsed.session.session_seq, 42);
        assert_eq!(parsed.payload, &payload);
        assert_eq!(parsed.auth_code, Some(&[0xBB; 16][..]));
    }

    #[test]
    fn parse_packet_too_short() {
        assert!(parse_packet(&[0u8; 10], 0).is_err());
    }

    #[test]
    fn verify_integrity_valid() {
        let payload = vec![0x01, 0x02];
        let auth_code_len = 12;
        let packet = build_authenticated_packet(
            1,
            1,
            &payload,
            |p| Ok(p.to_vec()),
            |data| {
                // Simple "integrity": XOR all bytes, repeated 12 times.
                let xor = data.iter().fold(0u8, |acc, &b| acc ^ b);
                Ok(vec![xor; 12])
            },
        )
        .expect("build packet");

        // Verification with the same function should succeed.
        verify_integrity(&packet, auth_code_len, |data| {
            let xor = data.iter().fold(0u8, |acc, &b| acc ^ b);
            Ok(vec![xor; 12])
        })
        .expect("integrity valid");
    }

    #[test]
    fn verify_integrity_mismatch() {
        let payload = vec![0x01, 0x02];
        let auth_code_len = 12;
        let packet = build_authenticated_packet(
            1,
            1,
            &payload,
            |p| Ok(p.to_vec()),
            |_| Ok(vec![0xAA; 12]),
        )
        .expect("build packet");

        // Verification with a different function should fail.
        let result = verify_integrity(&packet, auth_code_len, |_| Ok(vec![0xBB; 12]));
        assert!(result.is_err());
    }

    #[test]
    fn payload_type_flags() {
        // Encrypted + authenticated.
        let raw = 0xC0 | PayloadType::Ipmi as u8;
        let session = SessionHeader {
            auth_type: 0x06,
            payload_type_raw: raw,
            session_id: 1,
            session_seq: 1,
            payload_length: 0,
        };
        assert!(session.is_encrypted());
        assert!(session.is_authenticated());
        assert_eq!(session.payload_type(), Ok(PayloadType::Ipmi));
    }

    #[test]
    fn build_pre_session_rakp_messages() {
        // Verify all RAKP payload types can be built.
        for pt in [
            PayloadType::Rakp1,
            PayloadType::Rakp2,
            PayloadType::Rakp3,
            PayloadType::Rakp4,
        ] {
            let packet = build_pre_session_packet(pt, &[0x42]);
            let parsed = parse_packet(&packet, 0).expect("valid packet");
            assert_eq!(parsed.session.payload_type(), Ok(pt));
        }
    }
}
