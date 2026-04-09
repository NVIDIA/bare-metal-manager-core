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

use forge_secrets::credentials::{
    BgpCredentialType, CredentialKey, CredentialReader, CredentialType, Credentials,
};
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    CredentialCreationRequest, CredentialDeletionRequest, CredentialType as RpcCredentialType,
};
use tonic::Code;

use crate::handlers::credential::MAX_BGP_PASSWORD_LENGTH;
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

#[crate::sqlx_test]
async fn test_create_and_delete_bgp_credential(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // Create the site-wide DPU BGP credential.
    let response = env
        .api
        .create_credential(tonic::Request::new(CredentialCreationRequest {
            credential_type: RpcCredentialType::BgpSiteWideLeafPassword.into(),
            username: None,
            password: "test-dpu-bgp-password".to_string(),
            vendor: None,
            mac_address: None,
        }))
        .await;
    assert!(response.is_ok());

    // Verify the credential was stored in the credential manager.
    let stored = env
        .test_credential_manager
        .get_credentials(&CredentialKey::Bgp {
            credential_type: BgpCredentialType::SiteWideLeafPassword,
        })
        .await
        .unwrap();
    assert_eq!(
        stored,
        Some(Credentials::UsernamePassword {
            username: "".to_string(),
            password: "test-dpu-bgp-password".to_string(),
        })
    );

    // Delete the site-wide DPU BGP credential.
    let delete_response = env
        .api
        .delete_credential(tonic::Request::new(CredentialDeletionRequest {
            credential_type: RpcCredentialType::BgpSiteWideLeafPassword.into(),
            username: None,
            mac_address: None,
        }))
        .await;
    assert!(delete_response.is_ok());

    // Verify the credential was removed from the credential manager.
    let deleted = env
        .test_credential_manager
        .get_credentials(&CredentialKey::Bgp {
            credential_type: BgpCredentialType::SiteWideLeafPassword,
        })
        .await
        .unwrap();
    assert_eq!(deleted, None);
}

#[crate::sqlx_test]
async fn test_create_bgp_credential_validates_max_password_length(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // Create a site-wide DPU BGP credential using the maximum supported length.
    let max_password = "a".repeat(MAX_BGP_PASSWORD_LENGTH);
    let ok_response = env
        .api
        .create_credential(tonic::Request::new(CredentialCreationRequest {
            credential_type: RpcCredentialType::BgpSiteWideLeafPassword.into(),
            username: None,
            password: max_password.clone(),
            vendor: None,
            mac_address: None,
        }))
        .await;
    assert!(ok_response.is_ok());

    // Verify the credential was stored unchanged.
    let stored = env
        .test_credential_manager
        .get_credentials(&CredentialKey::Bgp {
            credential_type: BgpCredentialType::SiteWideLeafPassword,
        })
        .await
        .unwrap();
    assert_eq!(
        stored,
        Some(Credentials::UsernamePassword {
            username: "".to_string(),
            password: max_password,
        })
    );

    // Try to create a site-wide DPU BGP credential longer than the supported maximum.
    let response = env
        .api
        .create_credential(tonic::Request::new(CredentialCreationRequest {
            credential_type: RpcCredentialType::BgpSiteWideLeafPassword.into(),
            username: None,
            password: "a".repeat(MAX_BGP_PASSWORD_LENGTH + 1),
            vendor: None,
            mac_address: None,
        }))
        .await;
    let err = response.expect_err("passwords longer than the max should be rejected");

    // Verify the handler returns a validation error.
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains(&format!(
        "BGP password length exceeds {MAX_BGP_PASSWORD_LENGTH} characters"
    )));

    // Verify the previously stored credential was left unchanged.
    let stored = env
        .test_credential_manager
        .get_credentials(&CredentialKey::Bgp {
            credential_type: BgpCredentialType::SiteWideLeafPassword,
        })
        .await
        .unwrap();
    assert_eq!(
        stored,
        Some(Credentials::UsernamePassword {
            username: "".to_string(),
            password: "a".repeat(MAX_BGP_PASSWORD_LENGTH),
        })
    );
}
