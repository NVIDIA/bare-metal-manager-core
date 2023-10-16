use async_trait::async_trait;
use rand::{seq::SliceRandom, thread_rng, Rng};
use serde::{Deserialize, Serialize};

const PASSWORD_LEN: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Credentials {
    UsernamePassword { username: String, password: String },
    //TODO: maybe add cert here?
}

impl Credentials {
    pub fn generate_password() -> String {
        const UPPERCHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const LOWERCHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        const NUMCHARS: &[u8] = b"0123456789";
        const EXTRACHARS: &[u8] = b"^%$@!~_";
        const CHARSET: [&[u8]; 4] = [UPPERCHARS, LOWERCHARS, NUMCHARS, EXTRACHARS];

        let mut rng = rand::thread_rng();

        let mut password: Vec<char> = (0..PASSWORD_LEN)
            .map(|_| {
                let chid = rng.gen_range(0..CHARSET.len());
                let idx = rng.gen_range(0..CHARSET[chid].len());
                CHARSET[chid][idx] as char
            })
            .collect();

        // Enforce 1 Uppercase, 1 lowercase, 1 symbol and 1 numeric value rule.
        let mut positions_to_overlap = (0..PASSWORD_LEN).collect::<Vec<_>>();
        positions_to_overlap.shuffle(&mut thread_rng());
        let positions_to_overlap = positions_to_overlap.into_iter().take(CHARSET.len());

        for (index, pos) in positions_to_overlap.enumerate() {
            let char_index = rng.gen_range(0..CHARSET[index].len());
            password[pos] = CHARSET[index][char_index] as char;
        }

        password.into_iter().collect()
    }
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
    HostRedfish {
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
                    "machines/all_dpus/factory_default/bmc-metadata-items/root".to_string()
                }
                CredentialType::SiteDefault => {
                    "machines/all_dpus/site_default/bmc-metadata-items/root".to_string()
                }
                CredentialType::BmcMachine { bmc_machine_id } => {
                    format!("machines/bmc_machines/{bmc_machine_id}/redfish-admin")
                }
            },
            CredentialKey::HostRedfish { credential_type } => match credential_type {
                CredentialType::HardwareDefault => {
                    "machines/all_hosts/factory_default/bmc-metadata-items/root".to_string()
                }
                CredentialType::SiteDefault => {
                    "machines/all_hosts/site_default/bmc-metadata-items/root".to_string()
                }
                CredentialType::BmcMachine { .. } => {
                    panic!("BmcMachine is only used for DPUs");
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generated_password() {
        // According to Bmc password policy:
        // Minimum length: 13
        // Maximum length: 20
        // Minimum number of upper-case characters: 1
        // Minimum number of lower-case characters: 1
        // Minimum number of digits: 1
        // Minimum number of special characters: 1
        let password = Credentials::generate_password();
        assert!(password.len() >= 13 && password.len() <= 20);
        assert!(password.chars().any(|c| c.is_uppercase()));
        assert!(password.chars().any(|c| c.is_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().any(|c| c.is_ascii_punctuation()));
    }
}
