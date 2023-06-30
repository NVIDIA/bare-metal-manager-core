use async_trait::async_trait;
use vaultrs::client::VaultClient;
use vaultrs::kv2;

use crate::credentials::{CredentialKey, CredentialProvider, Credentials};

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
            tracing::error!("Error getting credentials. Error: {err:?}");
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
            tracing::error!("Error setting credentials. Error: {err:?}");
            err
        })?;

        Ok(())
    }
}
