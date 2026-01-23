/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge::MachineCredentialsUpdateResponse;
use ::rpc::forge::machine_credentials_update_request::{CredentialPurpose, Credentials};
use carbide_uuid::machine::MachineId;
use forge_secrets::credentials::{BmcCredentialType, CredentialKey, CredentialProvider};
use mac_address::MacAddress;

use crate::{CarbideError, CarbideResult};

pub struct UpdateCredentials {
    pub machine_id: MachineId,
    pub mac_address: Option<MacAddress>,
    pub credentials: Vec<Credentials>,
}

impl UpdateCredentials {
    pub async fn execute(
        &self,
        credential_provider: &dyn CredentialProvider,
    ) -> CarbideResult<MachineCredentialsUpdateResponse> {
        for credential in self.credentials.iter() {
            let credential_purpose = CredentialPurpose::try_from(credential.credential_purpose)
                .map_err(|error| {
                    CarbideError::internal(format!(
                        "invalid discriminant {error:?} for Credential Purpose from grpc?"
                    ))
                })?;

            let key = match credential_purpose {
                CredentialPurpose::Hbn => CredentialKey::DpuHbn {
                    machine_id: self.machine_id,
                },
                CredentialPurpose::LoginUser => CredentialKey::DpuSsh {
                    machine_id: self.machine_id,
                },
                CredentialPurpose::Bmc => CredentialKey::BmcCredentials {
                    credential_type: BmcCredentialType::BmcRoot {
                        bmc_mac_address: self
                            .mac_address
                            .ok_or_else(|| CarbideError::MissingArgument("MAC Address"))?,
                    },
                },
            };

            credential_provider
                .set_credentials(
                    &key,
                    &forge_secrets::credentials::Credentials::UsernamePassword {
                        username: credential.user.clone(),
                        password: credential.password.clone(),
                    },
                )
                .await
                .map_err(|err| CarbideError::internal(format!("{err}")))?;
        }

        Ok(MachineCredentialsUpdateResponse {})
    }
}
