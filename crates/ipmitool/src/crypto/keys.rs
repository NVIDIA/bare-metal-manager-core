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

//! RMCP+ session key derivation: SIK, K1, K2.
//!
//! After RAKP handshake completes, both sides derive a Session Integrity Key
//! (SIK) from the RAKP exchange data. From SIK, two additional keys are
//! derived:
//!
//! - **K1** = HMAC_SIK(0x01 repeated 20 bytes) — used for integrity (per-message HMAC)
//! - **K2** = HMAC_SIK(0x02 repeated 20 bytes) — used for confidentiality (AES key)
//!
//! The HMAC algorithm used for key derivation matches the authentication
//! algorithm negotiated during session open.

use crate::error::Result;
use crate::types::AuthAlgorithm;

use super::hmac_auth;

/// The constant byte repeated to form the K1 derivation input.
const K1_CONSTANT: u8 = 0x01;
/// The constant byte repeated to form the K2 derivation input.
const K2_CONSTANT: u8 = 0x02;

/// Length of the HMAC input constant (20 bytes per IPMI spec).
const KEY_DERIVATION_INPUT_LEN: usize = 20;

// ==============================================================================
// Session Integrity Key (SIK) Derivation
// ==============================================================================

/// Derive the Session Integrity Key (SIK) from the RAKP exchange data.
///
/// SIK = HMAC_Kg(Rm || Rc || Role || ULength || UName)
///
/// Where:
/// - Kg is the BMC key (or password if Kg is all zeros)
/// - Rm is the managed system's random number (from RAKP Message 2)
/// - Rc is the remote console's random number (from RAKP Message 1)
/// - Role is the requested privilege level
/// - ULength is the username length
/// - UName is the username
///
/// # Errors
///
/// Returns an error if the HMAC computation fails.
pub fn derive_sik(
    auth_alg: AuthAlgorithm,
    kg: &[u8],
    rm: &[u8],
    rc: &[u8],
    role: u8,
    username: &[u8],
) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(rm.len() + rc.len() + 2 + username.len());
    data.extend_from_slice(rm);
    data.extend_from_slice(rc);
    data.push(role);
    data.push(username.len() as u8);
    data.extend_from_slice(username);

    hmac_for_auth(auth_alg, kg, &data)
}

// ==============================================================================
// K1 and K2 Derivation
// ==============================================================================

/// Derive K1 from the Session Integrity Key.
///
/// K1 = HMAC_SIK(0x01 * 20) — used as the integrity key for per-message HMACs.
pub fn derive_k1(auth_alg: AuthAlgorithm, sik: &[u8]) -> Result<Vec<u8>> {
    let input = vec![K1_CONSTANT; KEY_DERIVATION_INPUT_LEN];
    hmac_for_auth(auth_alg, sik, &input)
}

/// Derive K2 from the Session Integrity Key.
///
/// K2 = HMAC_SIK(0x02 * 20) — used as the AES encryption key.
/// For AES-CBC-128, only the first 16 bytes of K2 are used.
pub fn derive_k2(auth_alg: AuthAlgorithm, sik: &[u8]) -> Result<Vec<u8>> {
    let input = vec![K2_CONSTANT; KEY_DERIVATION_INPUT_LEN];
    hmac_for_auth(auth_alg, sik, &input)
}

/// Dispatch to the appropriate HMAC function based on the auth algorithm.
fn hmac_for_auth(alg: AuthAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match alg {
        AuthAlgorithm::HmacSha1 => hmac_auth::hmac_sha1(key, data),
        AuthAlgorithm::HmacSha256 => hmac_auth::hmac_sha256(key, data),
        AuthAlgorithm::HmacMd5 => hmac_auth::hmac_md5(key, data),
        AuthAlgorithm::None => {
            // RAKP-none: no authentication, return empty key.
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k1_k2_are_different() {
        let sik = vec![0xAA; 20];
        let k1 = derive_k1(AuthAlgorithm::HmacSha256, &sik).expect("k1");
        let k2 = derive_k2(AuthAlgorithm::HmacSha256, &sik).expect("k2");
        assert_ne!(k1, k2, "K1 and K2 must differ");
    }

    #[test]
    fn k1_is_deterministic() {
        let sik = vec![0xBB; 20];
        let k1a = derive_k1(AuthAlgorithm::HmacSha1, &sik).expect("k1");
        let k1b = derive_k1(AuthAlgorithm::HmacSha1, &sik).expect("k1");
        assert_eq!(k1a, k1b);
    }

    #[test]
    fn sik_derivation_sha256() {
        // Verify SIK derivation produces a 32-byte key for SHA256.
        let kg = b"password";
        let rm = [0x11; 16];
        let rc = [0x22; 16];
        let role = 0x04; // Administrator
        let username = b"admin";

        let sik =
            derive_sik(AuthAlgorithm::HmacSha256, kg, &rm, &rc, role, username).expect("sik");
        assert_eq!(sik.len(), 32, "SHA256 SIK should be 32 bytes");
    }

    #[test]
    fn sik_derivation_sha1() {
        let kg = b"password";
        let rm = [0x11; 16];
        let rc = [0x22; 16];
        let role = 0x04;
        let username = b"admin";

        let sik =
            derive_sik(AuthAlgorithm::HmacSha1, kg, &rm, &rc, role, username).expect("sik");
        assert_eq!(sik.len(), 20, "SHA1 SIK should be 20 bytes");
    }

    #[test]
    fn k2_first_16_bytes_for_aes() {
        // In practice, only the first 16 bytes of K2 are used as the AES key.
        let sik = vec![0xCC; 20];
        let k2 = derive_k2(AuthAlgorithm::HmacSha256, &sik).expect("k2");
        assert!(k2.len() >= 16, "K2 must be at least 16 bytes for AES-128");
    }

    #[test]
    fn auth_none_returns_empty() {
        let sik = derive_sik(
            AuthAlgorithm::None,
            b"ignored",
            &[0; 16],
            &[0; 16],
            0x04,
            b"admin",
        )
        .expect("sik");
        assert!(sik.is_empty());
    }
}
