use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use vaultrs::client::VaultClient;
use vaultrs::kv2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Credentials {
    UsernamePassword { username: String, password: String },
    //TODO: maybe add cert here?
}

#[async_trait]
///
/// Abstract over a credentials provider that functions as a kv map between "key" -> "cred"
pub trait CredentialProvider: Send + Sync {
    async fn get_credentials(&self, key: CredentialKey) -> Result<Credentials, eyre::Report>;
    async fn set_credentials(
        &self,
        key: CredentialKey,
        credentials: Credentials,
    ) -> Result<(), eyre::Report>;
}

pub struct ForgeVaultClient {
    vault_client: VaultClient,
    vault_mount_location: String,
}

impl ForgeVaultClient {
    pub fn new(vault_client: VaultClient, vault_mount_location: String) -> Self {
        Self {
            vault_client,
            vault_mount_location,
        }
    }
}

#[async_trait]
impl CredentialProvider for ForgeVaultClient {
    async fn get_credentials(&self, key: CredentialKey) -> Result<Credentials, eyre::Report> {
        let credentials = kv2::read(
            &self.vault_client,
            &self.vault_mount_location,
            key.to_key_str().as_str(),
        )
        .await
        .map_err(|err| {
            log::error!("Error getting credentials. Error: {err:?}");
            err
        })?;

        Ok(credentials)
    }

    async fn set_credentials(
        &self,
        key: CredentialKey,
        credentials: Credentials,
    ) -> Result<(), eyre::Report> {
        let _secret_version_metadata = kv2::set(
            &self.vault_client,
            &self.vault_mount_location,
            key.to_key_str().as_str(),
            &credentials,
        )
        .await
        .map_err(|err| {
            log::error!("Error setting credentials. Error: {err:?}");
            err
        })?;

        Ok(())
    }
}

pub enum CredentialKey {
    Bmc {
        user_role: String,
        machine_id: String,
    },
    DpuSsh {
        machine_id: String,
    },
    DpuHbn {
        machine_id: String,
    },
}

impl CredentialKey {
    pub fn to_key_str(&self) -> String {
        match self {
            CredentialKey::Bmc {
                user_role,
                machine_id,
            } => {
                format!("machines/{machine_id}/bmc-metadata-items/{user_role}")
            }
            CredentialKey::DpuSsh { machine_id } => {
                format!("machines/{machine_id}/dpu-ssh")
            }
            CredentialKey::DpuHbn { machine_id } => {
                format!("machines/{machine_id}/dpu-hbn")
            }
        }
    }
}
