use async_trait::async_trait;
use vaultrs::api::pki::requests::GenerateCertificateRequest;
use vaultrs::client::VaultClient;
use vaultrs::{kv2, pki};

use crate::certificates::{Certificate, CertificateProvider};
use crate::credentials::{CredentialKey, CredentialProvider, Credentials};

pub struct ForgeVaultClient {
    vault_client: VaultClient,
    kv_mount_location: String,
    pki_mount_location: String,
    pki_role_name: String,
}

impl ForgeVaultClient {
    pub fn new(
        vault_client: VaultClient,
        kv_mount_location: String,
        pki_mount_location: String,
        pki_role_name: String,
    ) -> Self {
        Self {
            vault_client,
            kv_mount_location,
            pki_mount_location,
            pki_role_name,
        }
    }
}

#[async_trait]
impl CredentialProvider for ForgeVaultClient {
    async fn get_credentials(&self, key: CredentialKey) -> Result<Credentials, eyre::Report> {
        let credentials = kv2::read(
            &self.vault_client,
            &self.kv_mount_location,
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
            &self.kv_mount_location,
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

#[async_trait]
impl CertificateProvider for ForgeVaultClient {
    async fn get_certificate<S>(&self, unique_identifier: S) -> Result<Certificate, eyre::Report>
    where
        S: AsRef<str> + Send,
    {
        // let mount_path = "forgeca";
        // let role_name = "forge-cluster";
        let trust_domain = "forge.local";
        let namespace = "forge-system";

        // spiffe://<trust_domain>/<namespace>/machine/<stable_machine_id>
        let spiffe_id = format!(
            "spiffe://{}/{}/machine/{}",
            trust_domain,
            namespace,
            unique_identifier.as_ref()
        );

        // TODO: skew the TTL so that whoever is renewing these will just inherit the skew.
        let mut certificate_request_builder = GenerateCertificateRequest::builder();
        certificate_request_builder
            .mount(self.pki_mount_location.clone())
            .role(self.pki_role_name.clone())
            .uri_sans(spiffe_id)
            .ttl("86400s"); // 24 hours

        let response = pki::cert::generate(
            &self.vault_client,
            self.pki_mount_location.as_str(),
            self.pki_role_name.as_str(),
            Some(&mut certificate_request_builder),
        )
        .await?;

        Ok(Certificate {
            issuing_ca: response.issuing_ca.into_bytes(),
            public_key: response.certificate.into_bytes(),
            private_key: response.private_key.into_bytes(),
        })
    }
}
