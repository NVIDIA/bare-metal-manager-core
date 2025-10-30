/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use core::fmt;
use std::collections::HashMap;

use async_trait::async_trait;
use mac_address::MacAddress;
use rand::Rng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::SecretsError;

const PASSWORD_LEN: usize = 16;

#[derive(Clone, Serialize, Deserialize)]
pub enum Credentials {
    UsernamePassword { username: String, password: String },
    //TODO: maybe add cert here?
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Credentials::UsernamePassword {
                username,
                password: _,
            } => f
                .debug_struct("UsernamePassword")
                .field("username", username)
                .field("password", &"REDACTED")
                .finish(),
        }
    }
}

impl fmt::Display for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Credentials {
    pub fn generate_password() -> String {
        const UPPERCHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const LOWERCHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        const NUMCHARS: &[u8] = b"0123456789";
        const EXTRACHARS: &[u8] = b"^%$@!~_";
        const CHARSET: [&[u8]; 4] = [UPPERCHARS, LOWERCHARS, NUMCHARS, EXTRACHARS];

        let mut rng = rand::rng();

        let mut password: Vec<char> = (0..PASSWORD_LEN)
            .map(|_| {
                let chid = rng.random_range(0..CHARSET.len());
                let idx = rng.random_range(0..CHARSET[chid].len());
                CHARSET[chid][idx] as char
            })
            .collect();

        // Enforce 1 Uppercase, 1 lowercase, 1 symbol and 1 numeric value rule.
        let mut positions_to_overlap = (0..PASSWORD_LEN).collect::<Vec<_>>();
        positions_to_overlap.shuffle(&mut rand::rng());
        let positions_to_overlap = positions_to_overlap.into_iter().take(CHARSET.len());

        for (index, pos) in positions_to_overlap.enumerate() {
            let char_index = rng.random_range(0..CHARSET[index].len());
            password[pos] = CHARSET[index][char_index] as char;
        }

        password.into_iter().collect()
    }

    pub fn generate_password_no_special_char() -> String {
        const UPPERCHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const LOWERCHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        const NUMCHARS: &[u8] = b"0123456789";
        const CHARSET: [&[u8]; 3] = [UPPERCHARS, LOWERCHARS, NUMCHARS];

        let mut rng = rand::rng();

        let mut password: Vec<char> = (0..PASSWORD_LEN)
            .map(|_| {
                let chid = rng.random_range(0..CHARSET.len());
                let idx = rng.random_range(0..CHARSET[chid].len());
                CHARSET[chid][idx] as char
            })
            .collect();

        // Enforce 1 Uppercase, 1 lowercase, 1 symbol and 1 numeric value rule.
        let mut positions_to_overlap = (0..PASSWORD_LEN).collect::<Vec<_>>();
        positions_to_overlap.shuffle(&mut rand::rng());
        let positions_to_overlap = positions_to_overlap.into_iter().take(CHARSET.len());

        for (index, pos) in positions_to_overlap.enumerate() {
            let char_index = rng.random_range(0..CHARSET[index].len());
            password[pos] = CHARSET[index][char_index] as char;
        }

        password.into_iter().collect()
    }
}

#[async_trait]
/// Abstract over a credentials provider that functions as a kv map between "key" -> "cred"
pub trait CredentialProvider: Send + Sync {
    // TODO: Should this take CredentialKey by ref? It's not Copy
    async fn get_credentials(
        &self,
        key: CredentialKey,
    ) -> Result<Option<Credentials>, SecretsError>;
    async fn set_credentials(
        &self,
        key: CredentialKey,
        credentials: Credentials,
    ) -> Result<(), SecretsError>;

    async fn delete_credentials(&self, key: CredentialKey) -> Result<(), SecretsError>;
}

#[derive(Default)]
pub struct TestCredentialProvider {
    credentials: Mutex<HashMap<String, Credentials>>,
    fallback_credentials: Option<Credentials>,
}

impl TestCredentialProvider {
    /// Construct a TestCredentialProvider which falls back on a default set of credentials if we
    /// can't find matching ones set via set_credentials()
    pub fn new(fallback_credentials: Credentials) -> Self {
        Self {
            credentials: Mutex::new(HashMap::new()),
            fallback_credentials: Some(fallback_credentials),
        }
    }
}

#[async_trait]
impl CredentialProvider for TestCredentialProvider {
    async fn get_credentials(
        &self,
        key: CredentialKey,
    ) -> Result<Option<Credentials>, SecretsError> {
        let credentials = self.credentials.lock().await;
        let cred = credentials
            .get(key.to_key_str().as_str())
            .or(self.fallback_credentials.as_ref());

        Ok(cred.cloned())
    }

    async fn set_credentials(
        &self,
        key: CredentialKey,
        credentials: Credentials,
    ) -> Result<(), SecretsError> {
        let mut data = self.credentials.lock().await;
        let _ = data.insert(key.to_key_str(), credentials);

        Ok(())
    }

    async fn delete_credentials(&self, key: CredentialKey) -> Result<(), SecretsError> {
        let mut data = self.credentials.lock().await;
        let _ = data.remove(&key.to_key_str());

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialType {
    DpuHardwareDefault,
    HostHardwareDefault { vendor: bmc_vendor::BMCVendor },
    SiteDefault,
    Machine { machine_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BmcCredentialType {
    // Site Wide Root Credentials
    SiteWideRoot,
    // BMC Specific Root Credentials
    BmcRoot { bmc_mac_address: MacAddress },
    // BMC Specific Forge-Admin Credentials
    BmcForgeAdmin { bmc_mac_address: MacAddress },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialKey {
    DpuSsh { machine_id: String },
    DpuHbn { machine_id: String },
    DpuRedfish { credential_type: CredentialType },
    HostRedfish { credential_type: CredentialType },
    UfmAuth { fabric: String },
    DpuUefi { credential_type: CredentialType },
    HostUefi { credential_type: CredentialType },
    BmcCredentials { credential_type: BmcCredentialType },
}

impl CredentialKey {
    pub fn to_key_str(&self) -> String {
        match self {
            CredentialKey::DpuSsh { machine_id } => {
                format!("machines/{machine_id}/dpu-ssh")
            }
            CredentialKey::DpuHbn { machine_id } => {
                format!("machines/{machine_id}/dpu-hbn")
            }
            CredentialKey::DpuRedfish { credential_type } => match credential_type {
                CredentialType::DpuHardwareDefault => {
                    "machines/all_dpus/factory_default/bmc-metadata-items/root".to_string()
                }
                CredentialType::SiteDefault => {
                    "machines/all_dpus/site_default/bmc-metadata-items/root".to_string()
                }
                CredentialType::Machine { machine_id } => {
                    format!("machines/{machine_id}/bmc-metadata-items/administrator")
                }
                CredentialType::HostHardwareDefault { .. } => {
                    unreachable!(
                        "DpuRedfish / HostHardwareDefault is an invalid credential combination"
                    );
                }
            },
            CredentialKey::HostRedfish { credential_type } => match credential_type {
                CredentialType::HostHardwareDefault { vendor } => {
                    format!("machines/all_hosts/factory_default/bmc-metadata-items/{vendor}")
                }
                CredentialType::SiteDefault => {
                    "machines/all_hosts/site_default/bmc-metadata-items/root".to_string()
                }
                CredentialType::Machine { machine_id } => {
                    format!("machines/{machine_id}/host-redfish-admin")
                }
                CredentialType::DpuHardwareDefault => {
                    unreachable!(
                        "HostRedfish / DpuHardwareDefault is an invalid credential combination"
                    );
                }
            },
            CredentialKey::UfmAuth { fabric } => {
                format!("ufm/{fabric}/auth")
            }
            CredentialKey::DpuUefi { credential_type } => match credential_type {
                CredentialType::DpuHardwareDefault => {
                    "machines/all_dpus/factory_default/uefi-metadata-items/auth".to_string()
                }
                CredentialType::SiteDefault => {
                    "machines/all_dpus/site_default/uefi-metadata-items/auth".to_string()
                }
                _ => {
                    panic!("Not supported credential key");
                }
            },
            CredentialKey::HostUefi { credential_type } => match credential_type {
                CredentialType::SiteDefault => {
                    "machines/all_hosts/site_default/uefi-metadata-items/auth".to_string()
                }
                _ => {
                    panic!("Not supported credential key");
                }
            },
            CredentialKey::BmcCredentials { credential_type } => {
                let base: String = "machines/bmc".to_string();
                match credential_type {
                    BmcCredentialType::SiteWideRoot => {
                        format!("{base}/site/root")
                    }
                    BmcCredentialType::BmcRoot { bmc_mac_address } => {
                        format!("{base}/{bmc_mac_address}/root")
                    }
                    BmcCredentialType::BmcForgeAdmin { bmc_mac_address } => {
                        format!("{base}/{bmc_mac_address}/forge-admin-account")
                    }
                }
            }
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
