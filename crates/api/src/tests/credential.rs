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

use forge_secrets::credentials::{CredentialKey, CredentialReader, CredentialType, Credentials};
use rpc::forge::forge_server::Forge;
use rpc::forge::{CredentialCreationRequest, CredentialType as RpcCredentialType};
use tonic::Code;

use crate::tests::common::api_fixtures::create_test_env;

#[crate::sqlx_test]
async fn test_create_host_uefi_credential_when_missing(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let response = env
        .api
        .create_credential(tonic::Request::new(CredentialCreationRequest {
            credential_type: RpcCredentialType::HostUefi.into(),
            username: None,
            password: "test-host-uefi-password".to_string(),
            vendor: None,
            mac_address: None,
        }))
        .await;
    assert!(response.is_ok());

    let stored = env
        .test_credential_manager
        .get_credentials(&CredentialKey::HostUefi {
            credential_type: CredentialType::SiteDefault,
        })
        .await
        .unwrap();
    assert_eq!(
        stored,
        Some(Credentials::UsernamePassword {
            username: "".to_string(),
            password: "test-host-uefi-password".to_string(),
        })
    );

    // A second create should fail because the credential now exists.
    let second = env
        .api
        .create_credential(tonic::Request::new(CredentialCreationRequest {
            credential_type: RpcCredentialType::HostUefi.into(),
            username: None,
            password: "another-password".to_string(),
            vendor: None,
            mac_address: None,
        }))
        .await;
    assert!(second.is_err());
    assert_eq!(second.unwrap_err().code(), Code::AlreadyExists);
}

#[crate::sqlx_test]
async fn test_create_dpu_uefi_credential_when_missing(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let response = env
        .api
        .create_credential(tonic::Request::new(CredentialCreationRequest {
            credential_type: RpcCredentialType::DpuUefi.into(),
            username: None,
            password: "test-dpu-uefi-password".to_string(),
            vendor: None,
            mac_address: None,
        }))
        .await;
    assert!(response.is_ok());

    let stored = env
        .test_credential_manager
        .get_credentials(&CredentialKey::DpuUefi {
            credential_type: CredentialType::SiteDefault,
        })
        .await
        .unwrap();
    assert_eq!(
        stored,
        Some(Credentials::UsernamePassword {
            username: "".to_string(),
            password: "test-dpu-uefi-password".to_string(),
        })
    );

    // A second create should fail because the credential now exists.
    let second = env
        .api
        .create_credential(tonic::Request::new(CredentialCreationRequest {
            credential_type: RpcCredentialType::DpuUefi.into(),
            username: None,
            password: "another-password".to_string(),
            vendor: None,
            mac_address: None,
        }))
        .await;
    assert!(second.is_err());
    assert_eq!(second.unwrap_err().code(), Code::AlreadyExists);
}
