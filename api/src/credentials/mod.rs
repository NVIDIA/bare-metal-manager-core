use ::rpc::forge::{
    machine_credentials_update_request::CredentialPurpose,
    machine_credentials_update_request::Credentials, MachineCredentialsUpdateRequest,
    MachineCredentialsUpdateResponse,
};
use forge_secrets::credentials::{BmcCredentialType, CredentialKey, CredentialProvider};
use mac_address::MacAddress;

use crate::{
    model::{
        machine::machine_id::{try_parse_machine_id, MachineId},
        RpcDataConversionError,
    },
    CarbideError, CarbideResult,
};

pub struct UpdateCredentials {
    pub machine_id: MachineId,
    pub mac_address: Option<MacAddress>,
    pub credentials: Vec<Credentials>,
}

impl TryFrom<MachineCredentialsUpdateRequest> for UpdateCredentials {
    type Error = RpcDataConversionError;

    fn try_from(
        user_credentials: MachineCredentialsUpdateRequest,
    ) -> Result<Self, RpcDataConversionError> {
        let machine_id = try_parse_machine_id(
            &user_credentials
                .machine_id
                .ok_or(RpcDataConversionError::MissingArgument("machine_id"))?,
        )?;

        let mac_address = match user_credentials.mac_address {
            Some(v) => Some(
                v.parse()
                    .map_err(|_| RpcDataConversionError::InvalidMacAddress("mac_address".into()))?,
            ),
            None => None,
        };

        Ok(Self {
            machine_id,
            mac_address,
            credentials: user_credentials.credentials,
        })
    }
}

impl UpdateCredentials {
    pub async fn update(
        &self,
        credential_provider: &dyn CredentialProvider,
    ) -> CarbideResult<MachineCredentialsUpdateResponse> {
        for credential in self.credentials.iter() {
            let credential_purpose = CredentialPurpose::try_from(credential.credential_purpose)
                .map_err(|error| {
                    CarbideError::GenericError(format!(
                        "invalid discriminant {error:?} for Credential Purpose from grpc?"
                    ))
                })?;

            let key = match credential_purpose {
                CredentialPurpose::Hbn => CredentialKey::DpuHbn {
                    machine_id: self.machine_id.to_string(),
                },
                CredentialPurpose::LoginUser => CredentialKey::DpuSsh {
                    machine_id: self.machine_id.to_string(),
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
                    key,
                    forge_secrets::credentials::Credentials::UsernamePassword {
                        username: credential.user.clone(),
                        password: credential.password.clone(),
                    },
                )
                .await
                .map_err(|err| CarbideError::GenericError(format!("{err}")))?;
        }
        Ok(MachineCredentialsUpdateResponse {})
    }
}
