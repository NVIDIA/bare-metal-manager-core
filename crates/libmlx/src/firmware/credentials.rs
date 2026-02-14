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

use serde::{Deserialize, Serialize};

use crate::firmware::error::{FirmwareError, FirmwareResult};

// Credentials represents authentication for firmware downloads and
// transfers. A single type is used for both HTTP and SSH sources;
// validation that the credential type matches the source type
// happens at resolve time.
//
// When used in TOML configuration, the "type" field determines
// which variant is deserialized:
//
//   [firmware_credentials]
//   type = "bearer_token"
//   token = "asjdhkasdlkj..."
//
//   [firmware_credentials]
//   type = "basic_auth"
//   username = "deploy"
//   password = "s3cret"
//
//   [firmware_credentials]
//   type = "ssh_agent"
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Credentials {
    // BearerToken uses an Authorization: Bearer <token> header.
    BearerToken {
        token: String,
    },
    // BasicAuth uses HTTP Basic authentication.
    BasicAuth {
        username: String,
        password: String,
    },
    // Header uses a custom header name and value for authentication.
    Header {
        name: String,
        value: String,
    },
    // SshKey uses a private key file for SSH authentication, with
    // an optional passphrase.
    SshKey {
        path: String,
        #[serde(default)]
        passphrase: Option<String>,
    },
    // SshAgent uses the running SSH agent for authentication. The
    // agent is reached via the SSH_AUTH_SOCK environment variable.
    SshAgent,
}

impl Credentials {
    // bearer_token creates a BearerToken credential.
    pub fn bearer_token(token: impl Into<String>) -> Self {
        Self::BearerToken {
            token: token.into(),
        }
    }

    // basic_auth creates a BasicAuth credential.
    pub fn basic_auth(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::BasicAuth {
            username: username.into(),
            password: password.into(),
        }
    }

    // header creates a custom Header credential.
    pub fn header(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Header {
            name: name.into(),
            value: value.into(),
        }
    }

    // ssh_key creates an SshKey credential from a private key path.
    pub fn ssh_key(path: impl Into<String>) -> Self {
        Self::SshKey {
            path: path.into(),
            passphrase: None,
        }
    }

    // ssh_key_with_passphrase creates an SshKey credential from a
    // private key path and passphrase.
    pub fn ssh_key_with_passphrase(path: impl Into<String>, passphrase: impl Into<String>) -> Self {
        Self::SshKey {
            path: path.into(),
            passphrase: Some(passphrase.into()),
        }
    }

    // ssh_agent creates an SshAgent credential.
    pub fn ssh_agent() -> Self {
        Self::SshAgent
    }

    // validate_http returns an error if this credential type is not
    // compatible with HTTP sources.
    pub fn validate_http(&self) -> FirmwareResult<()> {
        match self {
            Credentials::BearerToken { .. }
            | Credentials::BasicAuth { .. }
            | Credentials::Header { .. } => Ok(()),
            Credentials::SshKey { .. } | Credentials::SshAgent => Err(FirmwareError::ConfigError(
                "SSH credentials cannot be used with HTTP sources".to_string(),
            )),
        }
    }

    // validate_ssh returns an error if this credential type is not
    // compatible with SSH sources.
    pub fn validate_ssh(&self) -> FirmwareResult<()> {
        match self {
            Credentials::SshKey { .. } | Credentials::SshAgent => Ok(()),
            Credentials::BearerToken { .. }
            | Credentials::BasicAuth { .. }
            | Credentials::Header { .. } => Err(FirmwareError::ConfigError(
                "HTTP credentials cannot be used with SSH sources".to_string(),
            )),
        }
    }
}
