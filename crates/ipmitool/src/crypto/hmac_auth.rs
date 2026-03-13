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

//! HMAC-based authentication and integrity algorithms for RMCP+.
//!
//! IPMI v2.0 uses HMAC for two purposes:
//! 1. **Authentication** (RAKP handshake): HMAC over session establishment data
//!    to prove knowledge of the password.
//! 2. **Integrity** (per-message): HMAC over the session header + payload to
//!    detect tampering. The integrity HMAC is truncated to a fixed length.

use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;

use crate::error::{IpmitoolError, Result};

// ==============================================================================
// HMAC Computation Functions
// ==============================================================================

/// Compute HMAC-SHA1 over the given data with the given key.
///
/// Returns the full 20-byte HMAC.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac =
        Hmac::<Sha1>::new_from_slice(key).map_err(|e| IpmitoolError::Crypto(e.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Compute HMAC-SHA256 over the given data with the given key.
///
/// Returns the full 32-byte HMAC.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|e| IpmitoolError::Crypto(e.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Compute HMAC-MD5 over the given data with the given key.
///
/// Returns the full 16-byte HMAC.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac =
        Hmac::<Md5>::new_from_slice(key).map_err(|e| IpmitoolError::Crypto(e.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

// ==============================================================================
// Integrity Check Value (ICV) Functions
// ==============================================================================
//
// Per-message integrity uses a truncated HMAC computed with K1 (derived from
// the Session Integrity Key). The truncation length depends on the algorithm:
//
// - HMAC-SHA1-96:    20-byte HMAC truncated to 12 bytes
// - HMAC-MD5-128:    16-byte HMAC (no truncation)
// - HMAC-SHA256-128: 32-byte HMAC truncated to 16 bytes

/// Compute the integrity check value (ICV) using HMAC-SHA1-96.
///
/// Uses K1 as the key. Returns 12 bytes (96 bits).
pub fn integrity_hmac_sha1_96(k1: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let full = hmac_sha1(k1, data)?;
    Ok(full[..12].to_vec())
}

/// Compute the integrity check value using HMAC-MD5-128.
///
/// Uses K1 as the key. Returns the full 16 bytes.
pub fn integrity_hmac_md5_128(k1: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_md5(k1, data)
}

/// Compute the integrity check value using HMAC-SHA256-128.
///
/// Uses K1 as the key. Returns 16 bytes (128 bits, truncated from 256).
pub fn integrity_hmac_sha256_128(k1: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let full = hmac_sha256(k1, data)?;
    Ok(full[..16].to_vec())
}

// ==============================================================================
// RAKP Authentication HMAC
// ==============================================================================
//
// During RAKP message exchange, the BMC and client each compute an HMAC over
// the session establishment data to prove they know the password. The specific
// data concatenation varies by RAKP message (1 through 4).

/// Compute the RAKP auth code using HMAC-SHA1.
///
/// This is the same as `hmac_sha1` but named for clarity in the RAKP context.
pub fn rakp_hmac_sha1(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_sha1(key, data)
}

/// Compute the RAKP auth code using HMAC-SHA256.
pub fn rakp_hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_sha256(key, data)
}

/// Compute the RAKP auth code using HMAC-MD5.
pub fn rakp_hmac_md5(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_md5(key, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Known-Answer Tests (KATs) for HMAC
    // =========================================================================
    //
    // Test vectors from RFC 2202 (HMAC-SHA1, HMAC-MD5) and RFC 4231 (HMAC-SHA256).

    #[test]
    fn hmac_sha1_rfc2202_test_case_1() {
        // Key = 0x0b repeated 20 times, Data = "Hi There"
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let result = hmac_sha1(&key, data).expect("hmac computation");
        assert_eq!(
            hex::encode(&result),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
    }

    #[test]
    fn hmac_sha1_rfc2202_test_case_2() {
        // Key = "Jefe", Data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let result = hmac_sha1(key, data).expect("hmac computation");
        assert_eq!(
            hex::encode(&result),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_1() {
        // Key = 0x0b repeated 20 times, Data = "Hi There"
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let result = hmac_sha256(&key, data).expect("hmac computation");
        assert_eq!(
            hex::encode(&result),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_2() {
        // Key = "Jefe", Data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let result = hmac_sha256(key, data).expect("hmac computation");
        assert_eq!(
            hex::encode(&result),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_md5_rfc2202_test_case_1() {
        // Key = 0x0b repeated 16 times, Data = "Hi There"
        let key = vec![0x0b; 16];
        let data = b"Hi There";
        let result = hmac_md5(&key, data).expect("hmac computation");
        assert_eq!(hex::encode(&result), "9294727a3638bb1c13f48ef8158bfc9d");
    }

    #[test]
    fn hmac_md5_rfc2202_test_case_2() {
        // Key = "Jefe", Data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let result = hmac_md5(key, data).expect("hmac computation");
        assert_eq!(hex::encode(&result), "750c783e6ab0b503eaa86e310a5db738");
    }

    // =========================================================================
    // Integrity truncation tests
    // =========================================================================

    #[test]
    fn integrity_sha1_96_truncation() {
        let key = vec![0xAA; 20];
        let data = b"test data for integrity";
        let icv = integrity_hmac_sha1_96(&key, data).expect("integrity computation");
        assert_eq!(icv.len(), 12, "HMAC-SHA1-96 should be 12 bytes");

        // Verify it's a prefix of the full HMAC.
        let full = hmac_sha1(&key, data).expect("full hmac");
        assert_eq!(&full[..12], &icv[..]);
    }

    #[test]
    fn integrity_sha256_128_truncation() {
        let key = vec![0xBB; 32];
        let data = b"test data for integrity";
        let icv = integrity_hmac_sha256_128(&key, data).expect("integrity computation");
        assert_eq!(icv.len(), 16, "HMAC-SHA256-128 should be 16 bytes");

        let full = hmac_sha256(&key, data).expect("full hmac");
        assert_eq!(&full[..16], &icv[..]);
    }

    #[test]
    fn integrity_md5_128_no_truncation() {
        let key = vec![0xCC; 16];
        let data = b"test data for integrity";
        let icv = integrity_hmac_md5_128(&key, data).expect("integrity computation");
        assert_eq!(icv.len(), 16, "HMAC-MD5-128 should be 16 bytes");

        let full = hmac_md5(&key, data).expect("full hmac");
        assert_eq!(full, icv);
    }
}
