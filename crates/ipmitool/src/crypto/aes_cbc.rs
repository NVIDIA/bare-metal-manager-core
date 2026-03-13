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

//! AES-CBC-128 encryption/decryption with IPMI custom padding.
//!
//! IPMI v2.0 does NOT use standard PKCS#7 padding. Instead, it uses a custom
//! scheme where pad bytes are sequential (1, 2, 3, ..., N) followed by the
//! pad length byte. The total padded message (including the pad length byte)
//! must be a multiple of the AES block size (16 bytes).
//!
//! # Padding Format
//!
//! Given plaintext of length L, the padding is:
//! 1. Compute pad_length = number of bytes needed so that
//!    (L + pad_length + 1) is a multiple of 16. The +1 is for the pad_length
//!    byte itself.
//! 2. Append bytes: 0x01, 0x02, ..., pad_length
//! 3. Append one byte: pad_length
//!
//! So the last byte of the padded block is always the pad length, and the
//! preceding pad bytes count up from 1.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use rand::Rng;

use crate::error::{IpmitoolError, Result};

/// AES block size in bytes.
const AES_BLOCK_SIZE: usize = 16;

// ==============================================================================
// IPMI Custom Padding
// ==============================================================================

/// Apply IPMI custom padding to plaintext.
///
/// Returns the padded plaintext. The result length (excluding IV) will be
/// a multiple of 16 bytes.
#[must_use]
pub fn ipmi_pad(plaintext: &[u8]) -> Vec<u8> {
    // We need: (plaintext.len() + pad_count + 1) % 16 == 0
    // Where the +1 is for the pad_length byte.
    let total_without_pad = plaintext.len() + 1; // +1 for pad_length byte
    let pad_count = match total_without_pad % AES_BLOCK_SIZE {
        0 => 0,
        remainder => AES_BLOCK_SIZE - remainder,
    };

    let mut padded = Vec::with_capacity(plaintext.len() + pad_count + 1);
    padded.extend_from_slice(plaintext);

    // Pad bytes count up from 1.
    for i in 1..=pad_count {
        padded.push(i as u8);
    }

    // Final byte is the pad count.
    padded.push(pad_count as u8);

    padded
}

/// Remove IPMI custom padding from decrypted data.
///
/// # Errors
///
/// Returns an error if the padding is invalid (pad_length too large, or
/// pad bytes don't match the expected sequence).
pub fn ipmi_unpad(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.is_empty() {
        return Err(IpmitoolError::Crypto("empty padded data".to_owned()));
    }

    let pad_length = *padded.last().expect("checked non-empty") as usize;

    // The pad_length byte is always present, so the total overhead is
    // pad_length + 1. Validate it fits.
    if pad_length + 1 > padded.len() {
        return Err(IpmitoolError::Crypto(format!(
            "pad length {pad_length} exceeds data length {}",
            padded.len()
        )));
    }

    // Verify the pad bytes are the expected sequence 1, 2, ..., pad_length.
    let data_end = padded.len() - 1 - pad_length;
    for (i, &byte) in padded[data_end..padded.len() - 1].iter().enumerate() {
        let expected = (i + 1) as u8;
        if byte != expected {
            return Err(IpmitoolError::Crypto(format!(
                "invalid pad byte at position {i}: expected 0x{expected:02X}, got 0x{byte:02X}"
            )));
        }
    }

    Ok(padded[..data_end].to_vec())
}

// ==============================================================================
// AES-CBC-128 Encrypt / Decrypt
// ==============================================================================

/// Encrypt plaintext using AES-CBC-128 with IPMI custom padding.
///
/// A random IV is generated and prepended to the ciphertext. The returned
/// bytes are: `[IV (16 bytes)] [encrypted padded data]`.
///
/// # Errors
///
/// Returns an error if the key is not exactly 16 bytes.
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != AES_BLOCK_SIZE {
        return Err(IpmitoolError::Crypto(format!(
            "AES-128 key must be 16 bytes, got {}",
            key.len()
        )));
    }

    // Generate random IV.
    let mut iv = [0u8; AES_BLOCK_SIZE];
    rand::rng().fill(&mut iv);

    encrypt_with_iv(key, &iv, plaintext)
}

/// Encrypt plaintext using AES-CBC-128 with a specified IV (for testing).
///
/// Returns `[IV (16 bytes)] [encrypted padded data]`.
pub fn encrypt_with_iv(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != AES_BLOCK_SIZE {
        return Err(IpmitoolError::Crypto(format!(
            "AES-128 key must be 16 bytes, got {}",
            key.len()
        )));
    }

    let padded = ipmi_pad(plaintext);
    debug_assert_eq!(padded.len() % AES_BLOCK_SIZE, 0, "padding bug");

    let encryptor = Encryptor::<Aes128>::new_from_slices(key, iv)
        .map_err(|e| IpmitoolError::Crypto(e.to_string()))?;

    // Encrypt in-place using NoPadding — we handle padding ourselves.
    let padded_len = padded.len();
    let mut buf = padded;
    let ciphertext = encryptor
        .encrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf, padded_len)
        .map_err(|e| IpmitoolError::Crypto(e.to_string()))?;

    // Prepend IV to ciphertext.
    let mut result = Vec::with_capacity(AES_BLOCK_SIZE + ciphertext.len());
    result.extend_from_slice(iv);
    result.extend_from_slice(ciphertext);

    Ok(result)
}

/// Decrypt ciphertext that was encrypted with AES-CBC-128 + IPMI custom padding.
///
/// The input must start with a 16-byte IV followed by the encrypted data.
///
/// # Errors
///
/// Returns an error if the key is wrong size, the data is too short,
/// the data isn't block-aligned, or the padding is invalid.
pub fn decrypt(key: &[u8], iv_and_ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != AES_BLOCK_SIZE {
        return Err(IpmitoolError::Crypto(format!(
            "AES-128 key must be 16 bytes, got {}",
            key.len()
        )));
    }

    if iv_and_ciphertext.len() < AES_BLOCK_SIZE * 2 {
        return Err(IpmitoolError::Crypto(format!(
            "ciphertext too short: {} bytes (need at least {} for IV + 1 block)",
            iv_and_ciphertext.len(),
            AES_BLOCK_SIZE * 2
        )));
    }

    let (iv, ciphertext) = iv_and_ciphertext.split_at(AES_BLOCK_SIZE);

    if ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return Err(IpmitoolError::Crypto(format!(
            "ciphertext length {} is not a multiple of block size {}",
            ciphertext.len(),
            AES_BLOCK_SIZE
        )));
    }

    let decryptor = Decryptor::<Aes128>::new_from_slices(key, iv)
        .map_err(|e| IpmitoolError::Crypto(e.to_string()))?;

    // Decrypt in-place using NoPadding — we handle IPMI custom padding ourselves.
    let mut buf = ciphertext.to_vec();
    let padded = decryptor
        .decrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|e| IpmitoolError::Crypto(e.to_string()))?;

    ipmi_unpad(padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Padding Tests
    // =========================================================================

    #[test]
    fn pad_empty() {
        // Empty + 1 (pad_length byte) = 1, need 15 pad bytes to reach 16.
        let padded = ipmi_pad(&[]);
        assert_eq!(padded.len(), 16);
        // Pad bytes: 1,2,...,15 then pad_length=15
        assert_eq!(padded[14], 15);
        assert_eq!(padded[15], 15);
    }

    #[test]
    fn pad_fifteen_bytes() {
        // 15 bytes + 1 (pad_length byte) = 16, already aligned. Pad count = 0.
        let data = vec![0xAA; 15];
        let padded = ipmi_pad(&data);
        assert_eq!(padded.len(), 16);
        // Last byte is pad_length = 0.
        assert_eq!(padded[15], 0);
        assert_eq!(&padded[..15], &data[..]);
    }

    #[test]
    fn pad_one_byte() {
        // 1 byte + 1 = 2, need 14 pad bytes.
        let padded = ipmi_pad(&[0x42]);
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[0], 0x42);
        for i in 1..=14 {
            assert_eq!(padded[i], i as u8, "pad byte {i}");
        }
        assert_eq!(padded[15], 14); // pad_length
    }

    #[test]
    fn pad_sixteen_bytes() {
        // 16 bytes + 1 = 17, need 15 pad bytes to reach 32.
        let data = vec![0xBB; 16];
        let padded = ipmi_pad(&data);
        assert_eq!(padded.len(), 32);
        assert_eq!(padded[31], 15); // pad_length
    }

    #[test]
    fn unpad_roundtrip() {
        for len in 0..=64 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let padded = ipmi_pad(&data);
            assert_eq!(padded.len() % AES_BLOCK_SIZE, 0);
            let unpadded = ipmi_unpad(&padded).expect("valid padding");
            assert_eq!(unpadded, data, "roundtrip failed for length {len}");
        }
    }

    #[test]
    fn unpad_invalid_pad_length() {
        // Pad length byte says 20, but data is only 16 bytes.
        let mut data = vec![0u8; 16];
        data[15] = 20;
        assert!(ipmi_unpad(&data).is_err());
    }

    #[test]
    fn unpad_invalid_pad_sequence() {
        // Correct length but wrong pad byte values.
        let mut data = vec![0u8; 16];
        data[15] = 2; // pad_length = 2
        data[13] = 0xFF; // should be 1
        data[14] = 2; // correct
        assert!(ipmi_unpad(&data).is_err());
    }

    // =========================================================================
    // AES-CBC Encrypt/Decrypt Tests
    // =========================================================================

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 16];
        let plaintext = b"Hello, IPMI world! This is a test of AES-CBC encryption.";

        let encrypted = encrypt(&key, plaintext).expect("encrypt");
        assert!(encrypted.len() >= 32); // at least IV + 1 block

        let decrypted = decrypt(&key, &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty() {
        let key = [0x00u8; 16];
        let plaintext = b"";

        let encrypted = encrypt(&key, plaintext).expect("encrypt");
        let decrypted = decrypt(&key, &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn encrypt_decrypt_exact_block() {
        // 15 bytes of plaintext = exactly 1 block after pad (15 + 1 pad_len byte = 16).
        let key = [0x11u8; 16];
        let plaintext = vec![0xAA; 15];

        let encrypted = encrypt(&key, &plaintext).expect("encrypt");
        // IV (16) + 1 block (16) = 32 bytes
        assert_eq!(encrypted.len(), 32);

        let decrypted = decrypt(&key, &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key = [0x42u8; 16];
        let wrong_key = [0x43u8; 16];
        let plaintext = b"secret data";

        let encrypted = encrypt(&key, plaintext).expect("encrypt");
        // Decryption with wrong key should fail (bad padding).
        assert!(decrypt(&wrong_key, &encrypted).is_err());
    }

    #[test]
    fn encrypt_with_known_iv() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = vec![0u8; 15]; // Will have pad_length=0

        let result = encrypt_with_iv(&key, &iv, &plaintext).expect("encrypt");
        // First 16 bytes should be the IV (all zeros).
        assert_eq!(&result[..16], &[0u8; 16]);
        // The rest is the encrypted block.
        assert_eq!(result.len(), 32);

        // Verify roundtrip.
        let decrypted = decrypt(&key, &result).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn reject_short_ciphertext() {
        let key = [0u8; 16];
        // Only 16 bytes = just IV, no ciphertext blocks.
        assert!(decrypt(&key, &[0u8; 16]).is_err());
    }

    #[test]
    fn reject_wrong_key_length() {
        assert!(encrypt(&[0u8; 15], b"test").is_err());
        assert!(encrypt(&[0u8; 17], b"test").is_err());
    }

    #[test]
    fn various_plaintext_lengths() {
        let key = [0x55u8; 16];
        for len in 0..=100 {
            let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let encrypted = encrypt(&key, &plaintext).expect("encrypt");
            let decrypted = decrypt(&key, &encrypted).expect("decrypt");
            assert_eq!(decrypted, plaintext, "failed for length {len}");
        }
    }
}
