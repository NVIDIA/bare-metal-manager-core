use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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

#[allow(clippy::enum_variant_names)]
pub enum CredentialType {
    HardwareDefault,
    SiteDefault,
    BmcMachine { bmc_machine_id: String },
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
    DpuRedfish {
        credential_type: CredentialType,
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
            CredentialKey::DpuRedfish { credential_type } => match credential_type {
                CredentialType::HardwareDefault => {
                    "machines/all_factory_default/bmc-metadata-items/root".to_string()
                }
                CredentialType::SiteDefault => {
                    "machines/all_site_default/bmc-metadata-items/root".to_string()
                }
                CredentialType::BmcMachine { bmc_machine_id } => {
                    format!("bmc_machines/{bmc_machine_id}/redfish-admin")
                }
            },
        }
    }
}
