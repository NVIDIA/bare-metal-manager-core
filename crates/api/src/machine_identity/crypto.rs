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

//! Machine-identity encryption: Vault-backed AES keys for `tenant_identity_config` ciphertext
//! (signing private key + token delegation auth JSON), and parsing of stored delegation
//! `client_secret_basic` JSON for outbound token exchange.

use ::rpc::forge::ClientSecretBasic;
use forge_secrets::credentials::{CredentialKey, CredentialReader, Credentials};
use forge_secrets::key_encryption;
use model::tenant::{
    EncryptedTokenDelegationAuthConfig, EncryptionKeyId, TokenDelegationAuthMethod,
};
use tonic::Status;

use crate::CarbideError;

pub(crate) async fn machine_identity_encryption_secret(
    credentials: &dyn CredentialReader,
    encryption_key_id: &EncryptionKeyId,
) -> Result<key_encryption::Aes256Key, Status> {
    let cred_key = CredentialKey::MachineIdentityEncryptionKey {
        key_id: encryption_key_id.as_str().to_string(),
    };
    let creds = credentials
        .get_credentials(&cred_key)
        .await
        .map_err(|e| CarbideError::InvalidArgument(e.to_string()))?
        .ok_or_else(|| {
            CarbideError::InvalidArgument(format!(
                "encryption key '{}' not found in secrets (machine_identity.encryption_keys)",
                encryption_key_id.as_str()
            ))
        })?;
    let stored = match &creds {
        Credentials::UsernamePassword { password, .. } => password.as_str(),
    };
    key_encryption::aes256_key_from_stored_secret(stored)
        .map_err(|e| CarbideError::InvalidArgument(e.to_string()).into())
}

/// Decrypts `encrypted_auth_method_config` when set, otherwise `None`.
pub(crate) async fn decrypt_token_delegation_encrypted_blob(
    credentials: &dyn CredentialReader,
    encryption_key_id: &EncryptionKeyId,
    encrypted_auth_method_config: Option<&EncryptedTokenDelegationAuthConfig>,
) -> Result<Option<String>, Status> {
    let Some(enc) = encrypted_auth_method_config else {
        return Ok(None);
    };
    if enc.as_str().is_empty() {
        return Ok(None);
    }
    let aes = machine_identity_encryption_secret(credentials, encryption_key_id).await?;
    let plain = key_encryption::decrypt(enc.as_str(), &aes).map_err(|e| {
        CarbideError::internal(format!(
            "stored token delegation configuration could not be decrypted: {e}"
        ))
    })?;
    let utf8 = String::from_utf8(plain).map_err(|e| {
        CarbideError::internal(format!(
            "stored token delegation configuration plaintext was not valid UTF-8: {e}"
        ))
    })?;
    Ok(Some(utf8))
}

pub(crate) fn token_delegation_credentials(
    auth_method: TokenDelegationAuthMethod,
    plaintext_json: Option<&str>,
) -> Result<Option<(String, String)>, Status> {
    match auth_method {
        TokenDelegationAuthMethod::None => Ok(None),
        TokenDelegationAuthMethod::ClientSecretBasic => {
            let s = plaintext_json.ok_or_else(|| {
                CarbideError::internal(
                    "token delegation client credentials are missing".to_string(),
                )
            })?;
            let c: ClientSecretBasic = serde_json::from_str(s).map_err(|e| {
                CarbideError::internal(format!(
                    "stored token delegation client credentials are invalid: {e}"
                ))
            })?;
            if c.client_id.is_empty() || c.client_secret.is_empty() {
                return Err(CarbideError::internal(
                    "stored token delegation client credentials are incomplete".to_string(),
                )
                .into());
            }
            Ok(Some((c.client_id, c.client_secret)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_delegation_credentials_none_and_client_secret_basic() {
        assert!(
            token_delegation_credentials(TokenDelegationAuthMethod::None, None)
                .unwrap()
                .is_none()
        );
        let j = r#"{"client_id":"cid","client_secret":"csec"}"#;
        let got =
            token_delegation_credentials(TokenDelegationAuthMethod::ClientSecretBasic, Some(j))
                .unwrap()
                .unwrap();
        assert_eq!(got.0, "cid");
        assert_eq!(got.1, "csec");
        assert!(
            token_delegation_credentials(TokenDelegationAuthMethod::ClientSecretBasic, None)
                .is_err()
        );
    }
}
