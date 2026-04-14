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

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use sha2::{Digest, Sha256};

use crate::KmsError;

/// NONCE_LEN is the byte length of an AES-256-GCM
/// nonce.
const NONCE_LEN: usize = 12;

/// encrypt encrypts plaintext using AES-256-GCM
/// with a random 12-byte nonce. Returns
/// (ciphertext, nonce) on success.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KmsError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| KmsError::EncryptionFailed("AES-256-GCM encryption failed".to_string()))?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

/// decrypt decrypts AES-256-GCM ciphertext using
/// the provided key and nonce.
pub fn decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, KmsError> {
    if nonce.len() != NONCE_LEN {
        return Err(KmsError::DecryptionFailed(format!(
            "invalid nonce length: expected {NONCE_LEN} bytes, got {}",
            nonce.len()
        )));
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| KmsError::DecryptionFailed("AES-256-GCM decryption failed".to_string()))
}

/// derive_key_id produces a deterministic identifier
/// from key material. Returns the first 16 hex
/// characters of the SHA-256 hash of the key.
pub fn derive_key_id(key: &[u8; 32]) -> String {
    let hash = Sha256::digest(key);
    hex::encode(&hash[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        key
    }

    fn other_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(100);
        }
        key
    }

    // Verifies that encrypt then decrypt produces
    // the original plaintext.
    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = test_key();
        let plaintext = b"hello, secrets!";

        let (ciphertext, nonce) = encrypt(&key, plaintext).expect("encrypt");
        let decrypted = decrypt(&key, &nonce, &ciphertext).expect("decrypt");

        assert_eq!(decrypted, plaintext);
    }

    // Verifies that decrypting with the wrong key fails.
    #[test]
    fn wrong_key_fails_decryption() {
        let key = test_key();
        let wrong_key = other_key();
        let plaintext = b"sensitive data";

        let (ciphertext, nonce) = encrypt(&key, plaintext).expect("encrypt");
        let result = decrypt(&wrong_key, &nonce, &ciphertext);

        assert!(result.is_err());
    }

    // Verifies that encrypting the same plaintext
    // twice produces different ciphertext.
    #[test]
    fn different_nonces_produce_different_ciphertext() {
        let key = test_key();
        let plaintext = b"same plaintext";

        let (ct1, nonce1) = encrypt(&key, plaintext).expect("encrypt 1");
        let (ct2, nonce2) = encrypt(&key, plaintext).expect("encrypt 2");

        assert_ne!(nonce1, nonce2);
        assert_ne!(ct1, ct2);
    }

    // Verifies that an invalid nonce length returns
    // an error.
    #[test]
    fn invalid_nonce_length_errors() {
        let key = test_key();
        let result = decrypt(&key, &[0u8; 11], &[]);
        assert!(result.is_err());
    }

    // Verifies that derive_key_id is deterministic.
    #[test]
    fn derive_key_id_is_deterministic() {
        let key = test_key();
        assert_eq!(derive_key_id(&key), derive_key_id(&key));
    }

    // Verifies that different keys produce different
    // key_ids.
    #[test]
    fn derive_key_id_differs_for_different_keys() {
        assert_ne!(derive_key_id(&test_key()), derive_key_id(&other_key()));
    }

    // Verifies that derive_key_id produces 16 hex
    // characters.
    #[test]
    fn derive_key_id_is_16_hex_chars() {
        let id = derive_key_id(&test_key());
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
