/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use core::fmt;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic;
use std::sync::atomic::AtomicU32;

use async_trait::async_trait;
use carbide_uuid::machine::MachineId;
use mac_address::MacAddress;
use rand::Rng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::SecretsError;

const PASSWORD_LEN: usize = 16;

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
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
    async fn get_credentials(
        &self,
        key: &CredentialKey,
    ) -> Result<Option<Credentials>, SecretsError>;

    async fn set_credentials(
        &self,
        key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), SecretsError>;

    async fn create_credentials(
        &self,
        key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), SecretsError>;

    async fn delete_credentials(&self, key: &CredentialKey) -> Result<(), SecretsError>;
}

#[derive(Default)]
pub struct TestCredentialProvider {
    credentials: Mutex<HashMap<String, Credentials>>,
    fallback_credentials: Option<Credentials>,
    pub set_credentials_sleep_time_ms: AtomicU32,
}

impl TestCredentialProvider {
    /// Construct a TestCredentialProvider which falls back on a default set of credentials if we
    /// can't find matching ones set via set_credentials()
    pub fn new(fallback_credentials: Credentials) -> Self {
        Self {
            credentials: Mutex::new(HashMap::new()),
            fallback_credentials: Some(fallback_credentials),
            set_credentials_sleep_time_ms: Default::default(),
        }
    }
}

#[async_trait]
impl CredentialProvider for TestCredentialProvider {
    async fn get_credentials(
        &self,
        key: &CredentialKey,
    ) -> Result<Option<Credentials>, SecretsError> {
        let credentials = self.credentials.lock().await;
        let cred = credentials
            .get(key.to_key_str().as_ref())
            .or(self.fallback_credentials.as_ref());

        Ok(cred.cloned())
    }

    async fn set_credentials(
        &self,
        key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), SecretsError> {
        let sleep_ms = self
            .set_credentials_sleep_time_ms
            .load(atomic::Ordering::Acquire);
        if sleep_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(sleep_ms as _)).await;
        }
        let mut data = self.credentials.lock().await;
        data.insert(key.to_key_str().to_string(), credentials.clone());
        Ok(())
    }

    async fn create_credentials(
        &self,
        key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), SecretsError> {
        let sleep_ms = self
            .set_credentials_sleep_time_ms
            .load(atomic::Ordering::Acquire);
        if sleep_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(sleep_ms as _)).await;
        }
        let mut data = self.credentials.lock().await;
        let key_str = key.to_key_str();
        if data.contains_key(key_str.as_ref()) {
            return Err(SecretsError::GenericError(eyre::eyre!(
                "Secret already exists with key {key_str}"
            )));
        }

        data.insert(key_str.to_string(), credentials.clone());
        Ok(())
    }

    async fn delete_credentials(&self, key: &CredentialKey) -> Result<(), SecretsError> {
        let mut data = self.credentials.lock().await;
        let _ = data.remove(key.to_key_str().as_ref());

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[allow(clippy::enum_variant_names)]
pub enum CredentialType {
    DpuHardwareDefault,
    HostHardwareDefault { vendor: bmc_vendor::BMCVendor },
    SiteDefault,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
    DpuSsh { machine_id: MachineId },
    DpuHbn { machine_id: MachineId },
    DpuRedfish { credential_type: CredentialType },
    HostRedfish { credential_type: CredentialType },
    UfmAuth { fabric: String },
    DpuUefi { credential_type: CredentialType },
    HostUefi { credential_type: CredentialType },
    BmcCredentials { credential_type: BmcCredentialType },
    ExtensionService { service_id: String, version: String },
    NmxM { nmxm_id: String },
    RackFirmware { firmware_id: String },
    SwitchNvosAdmin { bmc_mac_address: MacAddress },
}

impl CredentialKey {
    pub fn to_key_str(&self) -> Cow<'_, str> {
        match self {
            CredentialKey::DpuSsh { machine_id } => {
                Cow::from(format!("machines/{machine_id}/dpu-ssh"))
            }
            CredentialKey::DpuHbn { machine_id } => {
                Cow::from(format!("machines/{machine_id}/dpu-hbn"))
            }
            CredentialKey::DpuRedfish { credential_type } => match credential_type {
                CredentialType::DpuHardwareDefault => {
                    Cow::from("machines/all_dpus/factory_default/bmc-metadata-items/root")
                }
                CredentialType::SiteDefault => {
                    Cow::from("machines/all_dpus/site_default/bmc-metadata-items/root")
                }
                CredentialType::HostHardwareDefault { .. } => {
                    unreachable!(
                        "DpuRedfish / HostHardwareDefault is an invalid credential combination"
                    );
                }
            },
            CredentialKey::HostRedfish { credential_type } => match credential_type {
                CredentialType::HostHardwareDefault { vendor } => Cow::from(format!(
                    "machines/all_hosts/factory_default/bmc-metadata-items/{vendor}"
                )),
                CredentialType::SiteDefault => {
                    Cow::from("machines/all_hosts/site_default/bmc-metadata-items/root")
                }
                CredentialType::DpuHardwareDefault => {
                    unreachable!(
                        "HostRedfish / DpuHardwareDefault is an invalid credential combination"
                    );
                }
            },
            CredentialKey::UfmAuth { fabric } => Cow::from(format!("ufm/{fabric}/auth")),
            CredentialKey::DpuUefi { credential_type } => match credential_type {
                CredentialType::DpuHardwareDefault => {
                    Cow::from("machines/all_dpus/factory_default/uefi-metadata-items/auth")
                }
                CredentialType::SiteDefault => {
                    Cow::from("machines/all_dpus/site_default/uefi-metadata-items/auth")
                }
                _ => {
                    panic!("Not supported credential key");
                }
            },
            CredentialKey::HostUefi { credential_type } => match credential_type {
                CredentialType::SiteDefault => {
                    Cow::from("machines/all_hosts/site_default/uefi-metadata-items/auth")
                }
                _ => {
                    panic!("Not supported credential key");
                }
            },
            CredentialKey::BmcCredentials { credential_type } => match credential_type {
                BmcCredentialType::SiteWideRoot => Cow::from("machines/bmc/site/root"),
                BmcCredentialType::BmcRoot { bmc_mac_address } => {
                    Cow::from(format!("machines/bmc/{bmc_mac_address}/root"))
                }
                BmcCredentialType::BmcForgeAdmin { bmc_mac_address } => Cow::from(format!(
                    "machines/bmc/{bmc_mac_address}/forge-admin-account"
                )),
            },
            CredentialKey::ExtensionService {
                service_id,
                version,
            } => Cow::from(format!(
                "machines/extension-services/{service_id}/versions/{version}/credential"
            )),
            CredentialKey::NmxM { nmxm_id } => Cow::from(format!("nmxm/{nmxm_id}/auth")),
            CredentialKey::RackFirmware { firmware_id } => {
                Cow::from(format!("rack_firmware/{firmware_id}/token"))
            }
            CredentialKey::SwitchNvosAdmin { bmc_mac_address } => {
                Cow::from(format!("switch_nvos/{bmc_mac_address}/admin"))
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
