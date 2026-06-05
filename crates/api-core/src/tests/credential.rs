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
    BgpCredentialType, CredentialKey, CredentialReader, CredentialType, CredentialWriter,
    Credentials,
};
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    CredentialCreationRequest, CredentialDeletionRequest, CredentialType as RpcCredentialType,
    GetBmcCredentialsRequest,
};
use tonic::Code;

use crate::handlers::credential::MAX_BGP_PASSWORD_LENGTH;
use crate::tests::common::api_fixtures::create_test_env;
use crate::tests::common::api_fixtures::site_explorer::new_switch;

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
async fn test_get_bmc_credentials_rejects_caller_without_spiffe_service_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // No `AuthContext` extension attached -> no SPIFFE service identity ->
    // PermissionDenied. We do not need a real BMC, machine record, or
    // populated credentials for this assertion because the SPIFFE check
    // happens before any of those lookups.
    let mut request = tonic::Request::new(GetBmcCredentialsRequest {
        mac_addr: "11:22:33:44:55:66".to_string(),
    });
    request
        .extensions_mut()
        .insert(crate::auth::AuthContext::default());

    let err = env
        .api
        .get_bmc_credentials(request)
        .await
        .expect_err("caller without SPIFFE service id should be rejected");
    assert_eq!(err.code(), Code::PermissionDenied);
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

#[crate::sqlx_test]
async fn test_get_switch_nvos_credentials(pool: sqlx::PgPool) -> eyre::Result<()> {
    let env = create_test_env(pool).await;
    let switch_id = new_switch(&env, Some("Switch1".to_string()), None).await?;
    let bmc_mac_address = db::switch::find_switch_endpoints_by_ids(&env.pool, &[switch_id])
        .await?
        .first()
        .expect("switch endpoint row")
        .bmc_mac;

    env.test_credential_manager
        .set_credentials(
            &CredentialKey::SwitchNvosAdmin { bmc_mac_address },
            &Credentials::UsernamePassword {
                username: "nvos-admin".to_string(),
                password: "nvos-secret".to_string(),
            },
        )
        .await?;

    let response = env
        .api
        .get_switch_nvos_credentials(tonic::Request::new(
            rpc::forge::GetSwitchNvosCredentialsRequest {
                switch_id: Some(switch_id),
            },
        ))
        .await?
        .into_inner();

    let credentials = response.credentials.expect("credentials");
    let Some(rpc::forge::bmc_credentials::Type::UsernamePassword(username_password)) =
        credentials.r#type
    else {
        panic!("expected username/password credentials");
    };

    assert_eq!(username_password.username, "nvos-admin");
    assert_eq!(username_password.password, "nvos-secret");

    Ok(())
}
