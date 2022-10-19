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
    async fn get_credentials(&self, key: &str) -> Result<Credentials, anyhow::Error>;
    async fn set_credentials(
        &self,
        key: &str,
        credentials: Credentials,
    ) -> Result<(), anyhow::Error>;
}

#[async_trait]
impl CredentialProvider for VaultClient {
    async fn get_credentials(&self, key: &str) -> Result<Credentials, anyhow::Error> {
        let credentials = kv2::read(self, VAULT_MOUNT, key).await?;

        Ok(credentials)
    }

    async fn set_credentials(
        &self,
        key: &str,
        credentials: Credentials,
    ) -> Result<(), anyhow::Error> {
        let _secret_version_metadata = kv2::set(self, VAULT_MOUNT, key, &credentials).await?;

        Ok(())
    }
}

pub fn get_bmc_credentials_path(uuid: &Uuid, role: UserRoles) -> String {
    format!("machines/{uuid}/bmc-metadata-items/{}", role)
}
