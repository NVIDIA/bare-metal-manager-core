use ::rpc::forge::{
    machine_credentials_update_request::CredentialPurpose,
    machine_credentials_update_request::Credentials, MachineCredentialsUpdateRequest,
    MachineCredentialsUpdateResponse,
};
use forge_credentials::{CredentialKey, CredentialProvider};

use crate::{CarbideError, CarbideResult};

pub struct UpdateCredentials {
    machine_id: ::rpc::MachineId,
    credentials: Vec<Credentials>,
}

impl TryFrom<MachineCredentialsUpdateRequest> for UpdateCredentials {
    type Error = CarbideError;

    fn try_from(user_credentials: MachineCredentialsUpdateRequest) -> CarbideResult<Self> {
        Ok(Self {
            machine_id: user_credentials.machine_id.ok_or_else(|| {
                CarbideError::GenericError("missing or invalid machine_id".to_string())
            })?,
            credentials: user_credentials.credentials,
        })
    }
}

impl UpdateCredentials {
    pub async fn update<C>(
        &self,
        credential_provider: &C,
    ) -> CarbideResult<MachineCredentialsUpdateResponse>
    where
        C: CredentialProvider,
    {
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
            };

            credential_provider
                .set_credentials(
                    key,
                    forge_credentials::Credentials::UsernamePassword {
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
