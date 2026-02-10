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

use mlxconfig_firmware::credentials::Credentials;

// -- validate_http --

#[test]
fn test_bearer_token_valid_for_http() {
    let cred = Credentials::bearer_token("my-token");
    assert!(cred.validate_http().is_ok());
}

#[test]
fn test_basic_auth_valid_for_http() {
    let cred = Credentials::basic_auth("user", "pass");
    assert!(cred.validate_http().is_ok());
}

#[test]
fn test_header_valid_for_http() {
    let cred = Credentials::header("X-API-Key", "abc123");
    assert!(cred.validate_http().is_ok());
}

#[test]
fn test_ssh_key_invalid_for_http() {
    let cred = Credentials::ssh_key("/home/user/.ssh/id_rsa");
    assert!(cred.validate_http().is_err());
}

#[test]
fn test_ssh_agent_invalid_for_http() {
    let cred = Credentials::ssh_agent();
    assert!(cred.validate_http().is_err());
}

// -- validate_ssh --

#[test]
fn test_ssh_key_valid_for_ssh() {
    let cred = Credentials::ssh_key("/home/user/.ssh/id_rsa");
    assert!(cred.validate_ssh().is_ok());
}

#[test]
fn test_ssh_key_with_passphrase_valid_for_ssh() {
    let cred = Credentials::ssh_key_with_passphrase("/home/user/.ssh/id_rsa", "my-passphrase");
    assert!(cred.validate_ssh().is_ok());
}

#[test]
fn test_ssh_agent_valid_for_ssh() {
    let cred = Credentials::ssh_agent();
    assert!(cred.validate_ssh().is_ok());
}

#[test]
fn test_bearer_token_invalid_for_ssh() {
    let cred = Credentials::bearer_token("my-token");
    assert!(cred.validate_ssh().is_err());
}

#[test]
fn test_basic_auth_invalid_for_ssh() {
    let cred = Credentials::basic_auth("user", "pass");
    assert!(cred.validate_ssh().is_err());
}

// -- serde roundtrip --

#[test]
fn test_bearer_token_serde_roundtrip() {
    let cred = Credentials::bearer_token("my-secret-token");
    let toml = toml::to_string(&cred).unwrap();
    let deserialized: Credentials = toml::from_str(&toml).unwrap();

    match deserialized {
        Credentials::BearerToken { token } => assert_eq!(token, "my-secret-token"),
        other => panic!("Expected BearerToken, got {other:?}"),
    }
}

#[test]
fn test_basic_auth_serde_roundtrip() {
    let cred = Credentials::basic_auth("deploy", "s3cret");
    let toml = toml::to_string(&cred).unwrap();
    let deserialized: Credentials = toml::from_str(&toml).unwrap();

    match deserialized {
        Credentials::BasicAuth { username, password } => {
            assert_eq!(username, "deploy");
            assert_eq!(password, "s3cret");
        }
        other => panic!("Expected BasicAuth, got {other:?}"),
    }
}

#[test]
fn test_ssh_agent_serde_roundtrip() {
    let cred = Credentials::ssh_agent();
    let toml = toml::to_string(&cred).unwrap();
    let deserialized: Credentials = toml::from_str(&toml).unwrap();

    assert!(matches!(deserialized, Credentials::SshAgent));
}

#[test]
fn test_ssh_key_serde_roundtrip() {
    let cred = Credentials::ssh_key("/home/deploy/.ssh/id_ed25519");
    let toml = toml::to_string(&cred).unwrap();
    let deserialized: Credentials = toml::from_str(&toml).unwrap();

    match deserialized {
        Credentials::SshKey { path, passphrase } => {
            assert_eq!(path, "/home/deploy/.ssh/id_ed25519");
            assert!(passphrase.is_none());
        }
        other => panic!("Expected SshKey, got {other:?}"),
    }
}
