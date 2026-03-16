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

//! IPMI v1.5 authentication types and auth code computation.
//!
//! IPMI v1.5 (LAN interface, not RMCP+) uses a simpler authentication model
//! than v2.0. The session header carries an `AuthType` field and, for MD5
//! authentication, a 16-byte auth code computed as:
//!
//! ```text
//! MD5(password_pad16 || session_id_LE || message || session_seq_LE || password_pad16)
//! ```
//!
//! This module provides the auth type enum, password padding, and the MD5 auth
//! code computation used during IPMI v1.5 session establishment and messaging.

use byteorder::{ByteOrder, LittleEndian};
use digest::Digest;
use md5::Md5;

use crate::error::{IpmitoolError, Result};

// ==============================================================================
// Authentication Type
// ==============================================================================

/// IPMI v1.5 authentication type, carried in every session header.
///
/// Only `None` and `Md5` are implemented. The specification also defines:
/// - MD2 (`0x01`) -- not implemented; MD2 is obsolete and rarely supported.
/// - Straight password (`0x04`) -- not implemented; sends password in cleartext.
///
/// TODO: Add MD2 and Password variants if needed for legacy BMC compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthType {
    /// No authentication. Session header carries a zeroed auth code field.
    None = 0x00,

    /// MD5-based authentication. The auth code is an MD5 hash over the password,
    /// session ID, message body, and session sequence number.
    Md5 = 0x02,
}

impl TryFrom<u8> for AuthType {
    type Error = IpmitoolError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(AuthType::None),
            0x02 => Ok(AuthType::Md5),
            other => Err(IpmitoolError::InvalidResponse(format!(
                "unsupported IPMI v1.5 auth type: 0x{other:02x}"
            ))),
        }
    }
}

impl From<AuthType> for u8 {
    fn from(auth: AuthType) -> u8 {
        auth as u8
    }
}

// ==============================================================================
// Password Padding
// ==============================================================================

/// Null-pad or truncate a password to exactly 16 bytes.
///
/// IPMI v1.5 requires the password field to be exactly 16 bytes. Shorter
/// passwords are right-padded with null bytes; longer passwords are silently
/// truncated. This matches the behavior of the C `ipmitool` implementation.
pub fn pad_password(password: &[u8]) -> [u8; 16] {
    let mut padded = [0u8; 16];
    let len = password.len().min(16);
    padded[..len].copy_from_slice(&password[..len]);
    padded
}

// ==============================================================================
// MD5 Auth Code Computation
// ==============================================================================

/// Compute the IPMI v1.5 MD5 authentication code.
///
/// The hash input is:
///
/// ```text
/// password_pad16 || session_id (LE, 4B) || data || session_seq (LE, 4B) || password_pad16
/// ```
///
/// The `data` parameter is the raw IPMI message bytes. The payload length
/// byte from the session header is **not** included — this was empirically
/// confirmed by comparing auth codes against the C `ipmitool` 1.8.19 wire
/// traffic on a Supermicro IPMI v1.5 BMC (see `examples/auth_code_check.rs`).
///
/// The password bookends prevent length-extension attacks, and the session ID
/// and sequence number bind the auth code to a specific session and position
/// within it.
pub fn compute_md5_auth_code(
    password: &[u8],
    session_id: u32,
    data: &[u8],
    session_seq: u32,
) -> [u8; 16] {
    let pw = pad_password(password);

    let mut hasher = Md5::new();

    // password_pad16
    hasher.update(pw);

    // session_id as little-endian 4 bytes
    let mut sid_buf = [0u8; 4];
    LittleEndian::write_u32(&mut sid_buf, session_id);
    hasher.update(sid_buf);

    // Data field — caller is responsible for including the payload length
    // byte when required (in-session messages) or omitting it (Activate
    // Session).
    hasher.update(data);

    // session_seq as little-endian 4 bytes
    let mut seq_buf = [0u8; 4];
    LittleEndian::write_u32(&mut seq_buf, session_seq);
    hasher.update(seq_buf);

    // password_pad16 (again)
    hasher.update(pw);

    hasher.finalize().into()
}

// ==============================================================================
// Raw MD5 Helper
// ==============================================================================

/// Compute a plain MD5 hash of arbitrary data.
///
/// This is a thin wrapper around the `md5` crate for use in contexts that need
/// a simple hash (e.g., challenge–response derivation) rather than the full
/// IPMI auth code construction.
pub fn raw_md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // AuthType conversion
    // =========================================================================

    #[test]
    fn auth_type_round_trip() {
        assert_eq!(AuthType::try_from(0x00).expect("None"), AuthType::None);
        assert_eq!(AuthType::try_from(0x02).expect("Md5"), AuthType::Md5);
        assert_eq!(u8::from(AuthType::None), 0x00);
        assert_eq!(u8::from(AuthType::Md5), 0x02);
    }

    #[test]
    fn auth_type_unsupported_value() {
        assert!(AuthType::try_from(0x01).is_err(), "MD2 not supported");
        assert!(AuthType::try_from(0x04).is_err(), "Password not supported");
        assert!(AuthType::try_from(0xFF).is_err(), "unknown type");
    }

    // =========================================================================
    // Password padding
    // =========================================================================

    #[test]
    fn pad_password_empty() {
        let padded = pad_password(b"");
        assert_eq!(padded, [0u8; 16]);
    }

    #[test]
    fn pad_password_exact_16_bytes() {
        let input = b"0123456789abcdef";
        assert_eq!(input.len(), 16);
        let padded = pad_password(input);
        assert_eq!(&padded, input);
    }

    #[test]
    fn pad_password_short() {
        let padded = pad_password(b"test");
        let mut expected = [0u8; 16];
        expected[..4].copy_from_slice(b"test");
        assert_eq!(padded, expected);
    }

    #[test]
    fn pad_password_longer_than_16_bytes() {
        let input = b"this-is-a-very-long-password-that-exceeds-16";
        let padded = pad_password(input);
        // Only the first 16 bytes are kept.
        assert_eq!(&padded, &input[..16]);
    }

    // =========================================================================
    // Raw MD5
    // =========================================================================

    #[test]
    fn raw_md5_empty_string() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let hash = raw_md5(b"");
        assert_eq!(
            hex::encode(hash),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn raw_md5_known_value() {
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        let hash = raw_md5(b"abc");
        assert_eq!(
            hex::encode(hash),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    // =========================================================================
    // MD5 Auth Code — known-answer test
    // =========================================================================
    //
    // We manually construct the expected hash input and verify that
    // `compute_md5_auth_code` produces the same digest.

    /// The function now takes raw `data` — the caller decides whether to
    /// include the payload length byte. This test passes data directly.
    #[test]
    fn compute_md5_auth_code_known_answer() {
        let password = b"secret";
        let session_id: u32 = 0xAABBCCDD;
        let data = b"hello";
        let session_seq: u32 = 0x00000007;

        // Build the expected preimage by hand.
        let pw = pad_password(password);

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&pw);

        let mut sid = [0u8; 4];
        LittleEndian::write_u32(&mut sid, session_id);
        preimage.extend_from_slice(&sid);

        preimage.extend_from_slice(data);

        let mut seq = [0u8; 4];
        LittleEndian::write_u32(&mut seq, session_seq);
        preimage.extend_from_slice(&seq);

        preimage.extend_from_slice(&pw);

        let expected = raw_md5(&preimage);
        let actual = compute_md5_auth_code(password, session_id, data, session_seq);

        assert_eq!(actual, expected);
    }

    #[test]
    fn compute_md5_auth_code_empty_data() {
        let result = compute_md5_auth_code(b"", 0, b"", 0);
        assert_eq!(result.len(), 16);

        // Verify against manual computation.
        let pw = [0u8; 16];
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&pw);
        preimage.extend_from_slice(&[0u8; 4]); // session_id = 0
        // empty data
        preimage.extend_from_slice(&[0u8; 4]); // session_seq = 0
        preimage.extend_from_slice(&pw);

        assert_eq!(result, raw_md5(&preimage));
    }
}
