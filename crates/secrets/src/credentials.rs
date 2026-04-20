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
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, atomic};

use async_trait::async_trait;
use carbide_uuid::machine::MachineId;
use mac_address::MacAddress;
use rand::Rng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::SecretsError;

const PASSWORD_LEN: usize = 16;
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
/// Abstract over a credentials reader that functions as a kv map between "key" -> "cred"
pub trait CredentialReader: Send + Sync {
    async fn get_credentials(
        &self,
        key: &CredentialKey,
    ) -> Result<Option<Credentials>, SecretsError>;
}

#[async_trait]
impl<T: CredentialReader + ?Sized> CredentialReader for Arc<T> {
    async fn get_credentials(
        &self,
        key: &CredentialKey,
    ) -> Result<Option<Credentials>, SecretsError> {
        (**self).get_credentials(key).await
    }
}

#[async_trait]
pub trait CredentialWriter: Send + Sync {
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

#[async_trait]
impl<T: CredentialWriter + ?Sized> CredentialWriter for Arc<T> {
    async fn set_credentials(
        &self,
        key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), SecretsError> {
        (**self).set_credentials(key, credentials).await
    }

    async fn create_credentials(
        &self,
        key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), SecretsError> {
        (**self).create_credentials(key, credentials).await
    }

    async fn delete_credentials(&self, key: &CredentialKey) -> Result<(), SecretsError> {
        (**self).delete_credentials(key).await
    }
}

pub trait CredentialManager: CredentialReader + CredentialWriter {}

pub struct CompositeCredentialManager<R, W> {
    reader: R,
    writer: W,
}

impl<R: CredentialReader, W: CredentialWriter> CompositeCredentialManager<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

#[async_trait]
impl<R: CredentialReader, W: CredentialWriter> CredentialReader
    for CompositeCredentialManager<R, W>
{
    async fn get_credentials(
        &self,
        key: &CredentialKey,
    ) -> Result<Option<Credentials>, SecretsError> {
        self.reader.get_credentials(key).await
    }
}

#[async_trait]
impl<R: CredentialReader, W: CredentialWriter> CredentialWriter
    for CompositeCredentialManager<R, W>
{
    async fn set_credentials(
        &self,
        key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), SecretsError> {
        self.writer.set_credentials(key, credentials).await
    }

    async fn create_credentials(
        &self,
        key: &CredentialKey,
        credentials: &Credentials,
    ) -> Result<(), SecretsError> {
        self.writer.create_credentials(key, credentials).await
    }

    async fn delete_credentials(&self, key: &CredentialKey) -> Result<(), SecretsError> {
        self.writer.delete_credentials(key).await
    }
}

impl<R: CredentialReader, W: CredentialWriter> CredentialManager
    for CompositeCredentialManager<R, W>
{
}

#[derive(Default)]
pub struct TestCredentialManager {
    credentials: Mutex<HashMap<String, Credentials>>,
    fallback_credentials: Option<Credentials>,
    pub set_credentials_sleep_time_ms: AtomicU32,
}

impl TestCredentialManager {
    /// Construct a TestCredentialManager which falls back on a default set of credentials if we
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
impl CredentialReader for TestCredentialManager {
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
}

#[async_trait]
impl CredentialWriter for TestCredentialManager {
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

impl CredentialManager for TestCredentialManager {}

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BgpCredentialType {
    // Site Wide Credentials
    SiteWideLeafPassword,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MqttCredentialType {
    Dpa,
    DsxExchangeEventBus,
    DsxExchangeConsumer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialKey {
    DpuSsh {
        machine_id: MachineId,
    },
    DpuHbn {
        machine_id: MachineId,
    },
    DpuRedfish {
        credential_type: CredentialType,
    },
    Bgp {
        credential_type: BgpCredentialType,
    },
    HostRedfish {
        credential_type: CredentialType,
    },
    UfmAuth {
        fabric: String,
    },
    DpuUefi {
        credential_type: CredentialType,
    },
    HostUefi {
        credential_type: CredentialType,
    },
    BmcCredentials {
        credential_type: BmcCredentialType,
    },
    ExtensionService {
        service_id: String,
        version: String,
    },
    NmxM {
        nmxm_id: String,
    },
    RackFirmware {
        firmware_id: String,
    },
    SwitchNvosAdmin {
        bmc_mac_address: MacAddress,
    },
    MqttAuth {
        credential_type: MqttCredentialType,
    },
    /// Machine identity encryption key by key-id (from credential file `machine_identity.encryption_keys`).
    /// Returns `UsernamePassword { username: key_id, password: secret }`.
    MachineIdentityEncryptionKey {
        key_id: String,
    },
}

/// CredentialPrefix identifies a category of
/// credentials by their shared path prefix.
/// Useful for listing or querying all secrets
/// within a category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialPrefix {
    DpuSsh,
    DpuHbn,
    DpuRedfish,
    Bgp,
    HostRedfish,
    UfmAuth,
    DpuUefi,
    HostUefi,
    BmcCredentials,
    ExtensionService,
    NmxM,
    RackFirmware,
    SwitchNvosAdmin,
    MqttAuth,
    MachineIdentityEncryptionKey,
}

impl CredentialPrefix {
    /// as_str returns the Vault-style path prefix
    /// for this credential category.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DpuSsh => "machines/",
            Self::DpuHbn => "machines/",
            Self::DpuRedfish => "machines/all_dpus/",
            Self::Bgp => "bgp/",
            Self::HostRedfish => "machines/all_hosts/",
            Self::UfmAuth => "ufm/",
            Self::DpuUefi => "machines/all_dpus/",
            Self::HostUefi => "machines/all_hosts/",
            Self::BmcCredentials => "machines/bmc/",
            Self::ExtensionService => "machines/extension-services/",
            Self::NmxM => "nmxm/",
            Self::RackFirmware => "rack_firmware/",
            Self::SwitchNvosAdmin => "switch_nvos/",
            Self::MqttAuth => "mqtt/",
            Self::MachineIdentityEncryptionKey => "machine_identity/",
        }
    }

    /// all returns every credential prefix variant.
    pub fn all() -> &'static [CredentialPrefix] {
        &[
            Self::DpuSsh,
            Self::DpuHbn,
            Self::DpuRedfish,
            Self::Bgp,
            Self::HostRedfish,
            Self::UfmAuth,
            Self::DpuUefi,
            Self::HostUefi,
            Self::BmcCredentials,
            Self::ExtensionService,
            Self::NmxM,
            Self::RackFirmware,
            Self::SwitchNvosAdmin,
            Self::MqttAuth,
            Self::MachineIdentityEncryptionKey,
        ]
    }
}

impl CredentialKey {
    /// prefix returns the CredentialPrefix category
    /// this key belongs to.
    pub fn prefix(&self) -> CredentialPrefix {
        match self {
            Self::DpuSsh { .. } => CredentialPrefix::DpuSsh,
            Self::DpuHbn { .. } => CredentialPrefix::DpuHbn,
            Self::DpuRedfish { .. } => CredentialPrefix::DpuRedfish,
            Self::Bgp { .. } => CredentialPrefix::Bgp,
            Self::HostRedfish { .. } => CredentialPrefix::HostRedfish,
            Self::UfmAuth { .. } => CredentialPrefix::UfmAuth,
            Self::DpuUefi { .. } => CredentialPrefix::DpuUefi,
            Self::HostUefi { .. } => CredentialPrefix::HostUefi,
            Self::BmcCredentials { .. } => CredentialPrefix::BmcCredentials,
            Self::ExtensionService { .. } => CredentialPrefix::ExtensionService,
            Self::NmxM { .. } => CredentialPrefix::NmxM,
            Self::RackFirmware { .. } => CredentialPrefix::RackFirmware,
            Self::SwitchNvosAdmin { .. } => CredentialPrefix::SwitchNvosAdmin,
            Self::MqttAuth { .. } => CredentialPrefix::MqttAuth,
            Self::MachineIdentityEncryptionKey { .. } => {
                CredentialPrefix::MachineIdentityEncryptionKey
            }
        }
    }

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
            CredentialKey::MqttAuth { credential_type } => match credential_type {
                MqttCredentialType::Dpa => Cow::from("mqtt/dpa/auth"),
                MqttCredentialType::DsxExchangeEventBus => {
                    Cow::from("mqtt/dsx-exchange-event-bus/auth")
                }
                MqttCredentialType::DsxExchangeConsumer => {
                    Cow::from("mqtt/dsx-exchange-consumer/auth")
                }
            },
            CredentialKey::MachineIdentityEncryptionKey { key_id } => {
                Cow::from(format!("machine_identity/encryption_keys/{key_id}"))
            }
            CredentialKey::Bgp { credential_type } => match credential_type {
                BgpCredentialType::SiteWideLeafPassword => Cow::from("bgp/leaf/site/auth"),
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

    #[test]
    fn test_generated_password_no_special_char() {
        let password = Credentials::generate_password_no_special_char();
        assert_eq!(password.len(), PASSWORD_LEN);
        assert!(password.chars().any(|c| c.is_uppercase()));
        assert!(password.chars().any(|c| c.is_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[tokio::test]
    async fn composite_manager_delegates_reads_and_writes() {
        let reader = TestCredentialManager::new(Credentials::UsernamePassword {
            username: "read-user".to_string(),
            password: "read-pass".to_string(),
        });
        let writer = TestCredentialManager::default();
        let composite = CompositeCredentialManager::new(reader, writer);

        let key = CredentialKey::UfmAuth {
            fabric: "test-fabric".to_string(),
        };

        let read_result = composite.get_credentials(&key).await.expect("read");
        assert_eq!(
            read_result,
            Some(Credentials::UsernamePassword {
                username: "read-user".to_string(),
                password: "read-pass".to_string(),
            })
        );

        let write_cred = Credentials::UsernamePassword {
            username: "written".to_string(),
            password: "written-pass".to_string(),
        };
        composite
            .set_credentials(&key, &write_cred)
            .await
            .expect("write");

        // Reads still return the reader's fallback, not the written value
        let after_write = composite
            .get_credentials(&key)
            .await
            .expect("read after write");
        assert_eq!(
            after_write,
            Some(Credentials::UsernamePassword {
                username: "read-user".to_string(),
                password: "read-pass".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn create_credentials_rejects_duplicate() {
        let mgr = TestCredentialManager::default();
        let key = CredentialKey::UfmAuth {
            fabric: "dup-test".to_string(),
        };
        let cred = Credentials::UsernamePassword {
            username: "u".to_string(),
            password: "p".to_string(),
        };

        mgr.create_credentials(&key, &cred)
            .await
            .expect("first create");
        let result = mgr.create_credentials(&key, &cred).await;
        assert!(result.is_err());
    }

    // Verifies that every CredentialKey variant produces a non-empty path that starts
    // with a known prefix and contains no leading or trailing slashes. These paths are
    // stored as-is in the Postgres secrets table and must match what Vault uses.
    #[test]
    fn to_key_str_produces_valid_paths() {
        #[allow(deprecated)]
        let machine_id = MachineId::default();
        let mac: MacAddress = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let cases: Vec<(CredentialKey, &str)> = vec![
            (CredentialKey::DpuHbn { machine_id }, "machines/"),
            (
                CredentialKey::DpuRedfish {
                    credential_type: CredentialType::DpuHardwareDefault,
                },
                "machines/all_dpus/",
            ),
            (
                CredentialKey::DpuRedfish {
                    credential_type: CredentialType::SiteDefault,
                },
                "machines/all_dpus/",
            ),
            (
                CredentialKey::HostRedfish {
                    credential_type: CredentialType::HostHardwareDefault {
                        vendor: bmc_vendor::BMCVendor::Nvidia,
                    },
                },
                "machines/all_hosts/",
            ),
            (
                CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                },
                "machines/all_hosts/",
            ),
            (
                CredentialKey::UfmAuth {
                    fabric: "test-fabric".to_string(),
                },
                "ufm/",
            ),
            (
                CredentialKey::DpuUefi {
                    credential_type: CredentialType::DpuHardwareDefault,
                },
                "machines/all_dpus/",
            ),
            (
                CredentialKey::DpuUefi {
                    credential_type: CredentialType::SiteDefault,
                },
                "machines/all_dpus/",
            ),
            (
                CredentialKey::HostUefi {
                    credential_type: CredentialType::SiteDefault,
                },
                "machines/all_hosts/",
            ),
            (
                CredentialKey::BmcCredentials {
                    credential_type: BmcCredentialType::SiteWideRoot,
                },
                "machines/bmc/",
            ),
            (
                CredentialKey::BmcCredentials {
                    credential_type: BmcCredentialType::BmcRoot {
                        bmc_mac_address: mac,
                    },
                },
                "machines/bmc/",
            ),
            (
                CredentialKey::BmcCredentials {
                    credential_type: BmcCredentialType::BmcForgeAdmin {
                        bmc_mac_address: mac,
                    },
                },
                "machines/bmc/",
            ),
            (
                CredentialKey::ExtensionService {
                    service_id: "svc1".to_string(),
                    version: "v1".to_string(),
                },
                "machines/extension-services/",
            ),
            (
                CredentialKey::NmxM {
                    nmxm_id: "nmxm1".to_string(),
                },
                "nmxm/",
            ),
            (
                CredentialKey::RackFirmware {
                    firmware_id: "fw1".to_string(),
                },
                "rack_firmware/",
            ),
            (
                CredentialKey::SwitchNvosAdmin {
                    bmc_mac_address: mac,
                },
                "switch_nvos/",
            ),
            (
                CredentialKey::MqttAuth {
                    credential_type: MqttCredentialType::Dpa,
                },
                "mqtt/",
            ),
            (
                CredentialKey::MqttAuth {
                    credential_type: MqttCredentialType::DsxExchangeEventBus,
                },
                "mqtt/",
            ),
            (
                CredentialKey::MqttAuth {
                    credential_type: MqttCredentialType::DsxExchangeConsumer,
                },
                "mqtt/",
            ),
        ];

        for (key, expected_prefix) in &cases {
            let path = key.to_key_str();
            assert!(!path.is_empty(), "{key:?} produced an empty path");
            assert!(
                !path.starts_with('/'),
                "{key:?} path {path:?} should not start with /"
            );
            assert!(
                !path.ends_with('/'),
                "{key:?} path {path:?} should not end with /"
            );
            assert!(
                path.starts_with(expected_prefix),
                "{key:?} path {path:?} should start with {expected_prefix:?}"
            );
        }
    }

    // Verifies that every CredentialKey's to_key_str()
    // starts with its prefix().as_str().
    #[test]
    fn to_key_str_matches_prefix() {
        #[allow(deprecated)]
        let machine_id = MachineId::default();
        let mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let keys: Vec<CredentialKey> = vec![
            CredentialKey::DpuSsh { machine_id },
            CredentialKey::DpuHbn { machine_id },
            CredentialKey::DpuRedfish {
                credential_type: CredentialType::SiteDefault,
            },
            CredentialKey::Bgp {
                credential_type: BgpCredentialType::SiteWideLeafPassword,
            },
            CredentialKey::HostRedfish {
                credential_type: CredentialType::SiteDefault,
            },
            CredentialKey::UfmAuth {
                fabric: "f".to_string(),
            },
            CredentialKey::DpuUefi {
                credential_type: CredentialType::SiteDefault,
            },
            CredentialKey::HostUefi {
                credential_type: CredentialType::SiteDefault,
            },
            CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::SiteWideRoot,
            },
            CredentialKey::ExtensionService {
                service_id: "s".to_string(),
                version: "v".to_string(),
            },
            CredentialKey::NmxM {
                nmxm_id: "n".to_string(),
            },
            CredentialKey::RackFirmware {
                firmware_id: "f".to_string(),
            },
            CredentialKey::SwitchNvosAdmin {
                bmc_mac_address: mac,
            },
            CredentialKey::MqttAuth {
                credential_type: MqttCredentialType::Dpa,
            },
            CredentialKey::MachineIdentityEncryptionKey {
                key_id: "k".to_string(),
            },
        ];

        for key in &keys {
            let path = key.to_key_str();
            let prefix = key.prefix();
            assert!(
                path.starts_with(prefix.as_str()),
                "{key:?}: path {path:?} should start \
                 with prefix {:?}",
                prefix.as_str()
            );
        }
    }

    // Verifies that CredentialPrefix::all() contains
    // every variant.
    #[test]
    fn prefix_all_is_complete() {
        let all = CredentialPrefix::all();
        assert_eq!(all.len(), 15);
    }
}
