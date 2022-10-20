use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vaultrs::client::VaultClient;
use vaultrs::kv2;

use crate::db::ipmi::UserRoles;

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

pub enum CredentialKey {
    Bmc { role: UserRoles, machine_id: Uuid },
}

impl CredentialKey {
    pub fn to_key_str(&self) -> String {
        match self {
            CredentialKey::Bmc { role, machine_id } => {
                format!("machines/{machine_id}/bmc-metadata-items/{}", role)
            }
        }
    }
}
