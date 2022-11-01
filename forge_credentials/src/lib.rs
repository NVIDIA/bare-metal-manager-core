use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use vaultrs::client::VaultClient;
use vaultrs::kv2;

const VAULT_MOUNT: &str = "secret";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Credentials {
    UsernamePassword { username: String, password: String },
    //TODO: maybe add cert here?
}

#[async_trait]
///
/// Abstract over a credentials provider that functions as a kv map between "key" -> "cred"
pub trait CredentialProvider: Send + Sync {
    async fn get_credentials(&self, key: CredentialKey) -> Result<Credentials, anyhow::Error>;
    async fn set_credentials(
        &self,
        key: CredentialKey,
        credentials: Credentials,
    ) -> Result<(), anyhow::Error>;
}

#[async_trait]
impl CredentialProvider for VaultClient {
    async fn get_credentials(&self, key: CredentialKey) -> Result<Credentials, anyhow::Error> {
        let credentials = kv2::read(self, VAULT_MOUNT, key.to_key_str().as_str()).await?;

        Ok(credentials)
    }

    async fn set_credentials(
        &self,
        key: CredentialKey,
        credentials: Credentials,
    ) -> Result<(), anyhow::Error> {
        let _secret_version_metadata =
            kv2::set(self, VAULT_MOUNT, key.to_key_str().as_str(), &credentials).await?;

        Ok(())
    }
}

#[async_trait]
impl CredentialProvider for &rocket::State<VaultClient> {
    async fn get_credentials(&self, key: CredentialKey) -> Result<Credentials, anyhow::Error> {
        let credentials = kv2::read(self.inner(), VAULT_MOUNT, key.to_key_str().as_str()).await?;

        Ok(credentials)
    }

    async fn set_credentials(
        &self,
        key: CredentialKey,
        credentials: Credentials,
    ) -> Result<(), anyhow::Error> {
        let _secret_version_metadata = kv2::set(
            self.inner(),
            VAULT_MOUNT,
            key.to_key_str().as_str(),
            &credentials,
        )
        .await?;

        Ok(())
    }
}

pub enum CredentialKey {
    Bmc {
        user_role: String,
        machine_id: String,
    },
    DpuSsh {
        interface_id: String,
    },
    DpuHbn {
        interface_id: String,
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
            CredentialKey::DpuSsh { interface_id } => {
                format!("machines/{interface_id}/dpu-ssh")
            }
            CredentialKey::DpuHbn { interface_id } => {
                format!("machines/{interface_id}/dpu-hbn")
            }
        }
    }
}
