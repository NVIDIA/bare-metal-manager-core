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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::{CredentialType, forge as forgerpc};
use forge_secrets::credentials::Credentials;

use super::args::{
    AddBMCredential, AddDpuFactoryDefaultCredential, AddHostFactoryDefaultCredential,
    AddNmxMCredential, AddUFMCredential, AddUefiCredential, DeleteBMCredential,
    DeleteNmxMCredential, DeleteUFMCredential, GenerateUFMCertCredential,
};
use crate::rpc::ApiClient;

pub(crate) fn url_validator(url: String) -> Result<String, CarbideCliError> {
    let addr = tonic::transport::Uri::try_from(&url)
        .map_err(|_| CarbideCliError::GenericError("invalid url".to_string()))?;
    Ok(addr.to_string())
}

pub(crate) fn password_validator(s: String) -> Result<String, CarbideCliError> {
    // TODO: check password according BMC pwd rule.
    if s.is_empty() {
        return Err(CarbideCliError::GenericError("invalid input".to_string()));
    }
    Ok(s)
}

pub async fn add_ufm(c: AddUFMCredential, api_client: &ApiClient) -> CarbideCliResult<()> {
    let username = url_validator(c.url)?;
    let password = c.token;
    let req = forgerpc::CredentialCreationRequest {
        credential_type: CredentialType::Ufm.into(),
        username: Some(username),
        password,
        mac_address: None,
        vendor: None,
    };
    api_client.0.create_credential(req).await?;
    Ok(())
}

pub async fn delete_ufm(c: DeleteUFMCredential, api_client: &ApiClient) -> CarbideCliResult<()> {
    let username = url_validator(c.url)?;
    let req = forgerpc::CredentialDeletionRequest {
        credential_type: CredentialType::Ufm.into(),
        username: Some(username),
        mac_address: None,
    };
    api_client.0.delete_credential(req).await?;
    Ok(())
}

pub async fn generate_ufm_cert(
    c: GenerateUFMCertCredential,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let req = forgerpc::CredentialCreationRequest {
        credential_type: CredentialType::Ufm.into(),
        username: None,
        password: "".to_string(),
        mac_address: None,
        vendor: Some(c.fabric),
    };
    api_client.0.create_credential(req).await?;
    Ok(())
}

pub async fn add_bmc(c: AddBMCredential, api_client: &ApiClient) -> CarbideCliResult<()> {
    let password = password_validator(c.password)?;
    let req = forgerpc::CredentialCreationRequest {
        credential_type: CredentialType::from(c.kind).into(),
        username: c.username,
        password,
        mac_address: c.mac_address.map(|mac| mac.to_string()),
        vendor: None,
    };
    api_client.0.create_credential(req).await?;
    Ok(())
}

pub async fn delete_bmc(c: DeleteBMCredential, api_client: &ApiClient) -> CarbideCliResult<()> {
    let req = forgerpc::CredentialDeletionRequest {
        credential_type: CredentialType::from(c.kind).into(),
        username: None,
        mac_address: c.mac_address.map(|mac| mac.to_string()),
    };
    api_client.0.delete_credential(req).await?;
    Ok(())
}

pub async fn add_uefi(c: AddUefiCredential, api_client: &ApiClient) -> CarbideCliResult<()> {
    let mut password = password_validator(c.password)?;
    if password.is_empty() {
        password = Credentials::generate_password_no_special_char();
    }

    let req = forgerpc::CredentialCreationRequest {
        credential_type: CredentialType::from(c.kind).into(),
        username: None,
        password,
        mac_address: None,
        vendor: None,
    };
    api_client.0.create_credential(req).await?;
    Ok(())
}

pub async fn add_host_factory_default(
    c: AddHostFactoryDefaultCredential,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let req = forgerpc::CredentialCreationRequest {
        credential_type: CredentialType::HostBmcFactoryDefault.into(),
        username: Some(c.username),
        password: c.password,
        mac_address: None,
        vendor: Some(c.vendor.to_string()),
    };
    api_client.0.create_credential(req).await?;
    Ok(())
}

pub async fn add_dpu_factory_default(
    c: AddDpuFactoryDefaultCredential,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let req = forgerpc::CredentialCreationRequest {
        credential_type: CredentialType::DpuBmcFactoryDefault.into(),
        username: Some(c.username),
        password: c.password,
        mac_address: None,
        vendor: None,
    };
    api_client.0.create_credential(req).await?;
    Ok(())
}

pub async fn add_nmxm(c: AddNmxMCredential, api_client: &ApiClient) -> CarbideCliResult<()> {
    let req = forgerpc::CredentialCreationRequest {
        credential_type: CredentialType::NmxM.into(),
        username: Some(c.username),
        password: c.password,
        mac_address: None,
        vendor: None,
    };
    api_client.0.create_credential(req).await?;
    Ok(())
}

pub async fn delete_nmxm(c: DeleteNmxMCredential, api_client: &ApiClient) -> CarbideCliResult<()> {
    let req = forgerpc::CredentialDeletionRequest {
        credential_type: CredentialType::NmxM.into(),
        username: Some(c.username),
        mac_address: None,
    };
    api_client.0.delete_credential(req).await?;
    Ok(())
}
