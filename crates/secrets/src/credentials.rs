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
use std::sync::Arc;

use async_trait::async_trait;
use carbide_uuid::machine::MachineId;
use carbide_uuid::rack::RackId;
use mac_address::MacAddress;
use rand::RngExt;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

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
    /// Versioned site-wide BMC root "rotate-TO" target written by a rotation
    /// (`machines/bmc/site/root/v{N}`). The unversioned [`SiteWideRoot`]
    /// (`machines/bmc/site/root`) stays as the "current site target" alias used
    /// at ingestion / set-from-factory; this variant addresses a specific
    /// rotation target version.
    SiteWideRootVersioned {
        version: u32,
    },
    // BMC Specific Root Credentials
    BmcRoot {
        bmc_mac_address: MacAddress,
    },
    // BMC Specific Forge-Admin Credentials
    BmcForgeAdmin {
        bmc_mac_address: MacAddress,
    },
}

/// Versioned site-wide UEFI "rotate-TO" target a rotation writes and controllers
/// read before copying into a device's per-device UEFI secret. Host and DPU UEFI
/// each get their own target (under the shared `machines/uefi/` prefix); the MAC
/// in the per-device path distinguishes the two, but the site targets are
/// disambiguated by this `host`/`dpu` segment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum UefiSiteTarget {
    /// `machines/uefi/host/site/root/v{N}`
    Host { version: u32 },
    /// `machines/uefi/dpu/site/root/v{N}`
    Dpu { version: u32 },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NicLockdownIkm {
    /// Site-wide SuperNIC lockdown IKM (input key material), versioned for
    /// rotation. This is the secret the per-NIC lock keys are derived from, not
    /// a lock key itself. Derived keys are never stored; only this IKM lives in
    /// Vault.
    SiteWide { version: u32 },
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
    NicLockdownIkm {
        credential_type: NicLockdownIkm,
    },
    /// Versioned site-wide UEFI "rotate-TO" target (`machines/uefi/...`).
    /// Admin/rotation-written only; not a loginable per-device credential.
    UefiSiteTarget {
        target: UefiSiteTarget,
    },
    ExtensionService {
        service_id: String,
        version: String,
    },
    NmxM {
        nmxm_id: String,
    },
    SwitchNvosAdmin {
        bmc_mac_address: MacAddress,
    },
    /// Versioned site-wide NVOS "rotate-TO" target (`switch_nvos/site/admin/v{N}`).
    /// Admin/rotation-written only; not a loginable per-device credential.
    SwitchNvosSiteAdmin {
        version: u32,
    },
    MqttAuth {
        credential_type: MqttCredentialType,
    },
    /// Machine identity encryption key by key-id (from credential file `machine_identity.encryption_keys`).
    /// Returns `UsernamePassword { username: key_id, password: secret }`.
    MachineIdentityEncryptionKey {
        key_id: String,
    },
    RackMaintenanceAccessToken {
        rack_id: RackId,
    },
}

/// The site-wide default credentials endpoint exploration requires before it
/// can run (validated by `SiteExplorer::check_preconditions`).
///
/// Single source of truth: the explorer's precondition check and the admin UI's
/// "default credentials not set" warning both iterate this list so the two
/// cannot drift apart. Order matches the explorer's original check order.
pub const REQUIRED_SITE_DEFAULT_CREDENTIAL_KEYS: [CredentialKey; 3] = [
    CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::SiteWideRoot,
    },
    CredentialKey::DpuUefi {
        credential_type: CredentialType::SiteDefault,
    },
    CredentialKey::HostUefi {
        credential_type: CredentialType::SiteDefault,
    },
];

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
    /// Per-device and versioned site-wide UEFI secrets (`machines/uefi/`).
    Uefi,
    BmcCredentials,
    NicLockdownIkm,
    ExtensionService,
    NmxM,
    SwitchNvosAdmin,
    MqttAuth,
    MachineIdentityEncryptionKey,
    RackMaintenanceAccessToken,
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
            Self::Uefi => "machines/uefi/",
            Self::BmcCredentials => "machines/bmc/",
            Self::NicLockdownIkm => "machines/nic_lockdown_ikm/",
            Self::ExtensionService => "machines/extension-services/",
            Self::NmxM => "nmxm/",
            Self::SwitchNvosAdmin => "switch_nvos/",
            Self::MqttAuth => "mqtt/",
            Self::MachineIdentityEncryptionKey => "machine_identity/",
            Self::RackMaintenanceAccessToken => "racks/",
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
            Self::Uefi,
            Self::BmcCredentials,
            Self::NicLockdownIkm,
            Self::ExtensionService,
            Self::NmxM,
            Self::SwitchNvosAdmin,
            Self::MqttAuth,
            Self::MachineIdentityEncryptionKey,
            Self::RackMaintenanceAccessToken,
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
            Self::NicLockdownIkm { .. } => CredentialPrefix::NicLockdownIkm,
            Self::UefiSiteTarget { .. } => CredentialPrefix::Uefi,
            Self::ExtensionService { .. } => CredentialPrefix::ExtensionService,
            Self::NmxM { .. } => CredentialPrefix::NmxM,
            Self::SwitchNvosAdmin { .. } => CredentialPrefix::SwitchNvosAdmin,
            Self::SwitchNvosSiteAdmin { .. } => CredentialPrefix::SwitchNvosAdmin,
            Self::MqttAuth { .. } => CredentialPrefix::MqttAuth,
            Self::MachineIdentityEncryptionKey { .. } => {
                CredentialPrefix::MachineIdentityEncryptionKey
            }
            Self::RackMaintenanceAccessToken { .. } => CredentialPrefix::RackMaintenanceAccessToken,
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
                BmcCredentialType::SiteWideRootVersioned { version } => {
                    Cow::from(format!("machines/bmc/site/root/v{version}"))
                }
                BmcCredentialType::BmcRoot { bmc_mac_address } => {
                    Cow::from(format!("machines/bmc/{bmc_mac_address}/root"))
                }
                BmcCredentialType::BmcForgeAdmin { bmc_mac_address } => Cow::from(format!(
                    "machines/bmc/{bmc_mac_address}/forge-admin-account"
                )),
            },
            CredentialKey::NicLockdownIkm { credential_type } => match credential_type {
                NicLockdownIkm::SiteWide { version } => {
                    Cow::from(format!("machines/nic_lockdown_ikm/site/root/v{version}"))
                }
            },
            CredentialKey::UefiSiteTarget { target } => match target {
                UefiSiteTarget::Host { version } => {
                    Cow::from(format!("machines/uefi/host/site/root/v{version}"))
                }
                UefiSiteTarget::Dpu { version } => {
                    Cow::from(format!("machines/uefi/dpu/site/root/v{version}"))
                }
            },
            CredentialKey::ExtensionService {
                service_id,
                version,
            } => Cow::from(format!(
                "machines/extension-services/{service_id}/versions/{version}/credential"
            )),
            CredentialKey::NmxM { nmxm_id } => Cow::from(format!("nmxm/{nmxm_id}/auth")),
            CredentialKey::SwitchNvosAdmin { bmc_mac_address } => {
                Cow::from(format!("switch_nvos/{bmc_mac_address}/admin"))
            }
            CredentialKey::SwitchNvosSiteAdmin { version } => {
                Cow::from(format!("switch_nvos/site/admin/v{version}"))
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
            CredentialKey::RackMaintenanceAccessToken { rack_id } => {
                Cow::from(format!("racks/{rack_id}/maintenance/access-token"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::{Check, check_values};

    use super::*;
    use crate::test_support::credentials::TestCredentialManager;

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

    // Pins the exact Vault path for the versioned lockdown IKM, including
    // how the version is rendered (v{N}), since other components and the
    // seed migration depend on this layout.
    #[test]
    fn lockdown_site_wide_path_is_versioned() {
        let key = CredentialKey::NicLockdownIkm {
            credential_type: NicLockdownIkm::SiteWide { version: 0 },
        };
        assert_eq!(key.to_key_str(), "machines/nic_lockdown_ikm/site/root/v0");
        assert_eq!(key.prefix(), CredentialPrefix::NicLockdownIkm);

        let key_v12 = CredentialKey::NicLockdownIkm {
            credential_type: NicLockdownIkm::SiteWide { version: 12 },
        };
        assert_eq!(
            key_v12.to_key_str(),
            "machines/nic_lockdown_ikm/site/root/v12"
        );
    }

    // Pins the exact versioned site-wide "rotate-TO" target paths per credential
    // family. The rotation handler writes these and the controllers read them, so
    // the `v{N}` layout (and the unversioned BMC alias staying put) must not drift.
    #[test]
    fn site_wide_rotation_target_paths_are_versioned() {
        let bmc = CredentialKey::BmcCredentials {
            credential_type: BmcCredentialType::SiteWideRootVersioned { version: 3 },
        };
        assert_eq!(bmc.to_key_str(), "machines/bmc/site/root/v3");
        assert_eq!(bmc.prefix(), CredentialPrefix::BmcCredentials);

        // The unversioned alias is unchanged and still distinct.
        let bmc_alias = CredentialKey::BmcCredentials {
            credential_type: BmcCredentialType::SiteWideRoot,
        };
        assert_eq!(bmc_alias.to_key_str(), "machines/bmc/site/root");

        let host_uefi = CredentialKey::UefiSiteTarget {
            target: UefiSiteTarget::Host { version: 0 },
        };
        assert_eq!(host_uefi.to_key_str(), "machines/uefi/host/site/root/v0");
        assert_eq!(host_uefi.prefix(), CredentialPrefix::Uefi);

        let dpu_uefi = CredentialKey::UefiSiteTarget {
            target: UefiSiteTarget::Dpu { version: 7 },
        };
        assert_eq!(dpu_uefi.to_key_str(), "machines/uefi/dpu/site/root/v7");
        assert_eq!(dpu_uefi.prefix(), CredentialPrefix::Uefi);

        let nvos = CredentialKey::SwitchNvosSiteAdmin { version: 2 };
        assert_eq!(nvos.to_key_str(), "switch_nvos/site/admin/v2");
        assert_eq!(nvos.prefix(), CredentialPrefix::SwitchNvosAdmin);
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
        let rack_id = RackId::new("rack-01");
        let mac: MacAddress = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        // Each row is a key and the path prefix its `to_key_str()` must carry. A
        // path is well-formed when it is non-empty, has no leading or trailing
        // slash, and starts with that prefix.
        struct Row {
            key: CredentialKey,
            expected_prefix: &'static str,
        }

        // The four invariants of a well-formed key path, checked as named fields
        // rather than folded into one bool so a failing row names the invariant
        // it broke. A well-formed path holds all four.
        #[derive(Debug, PartialEq)]
        struct PathChecks {
            non_empty: bool,
            no_leading_slash: bool,
            no_trailing_slash: bool,
            has_expected_prefix: bool,
        }

        impl PathChecks {
            const fn all_hold() -> Self {
                Self {
                    non_empty: true,
                    no_leading_slash: true,
                    no_trailing_slash: true,
                    has_expected_prefix: true,
                }
            }
        }

        check_values(
            [
                Check {
                    scenario: "dpu hbn",
                    input: Row {
                        key: CredentialKey::DpuHbn { machine_id },
                        expected_prefix: "machines/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "dpu redfish hardware default",
                    input: Row {
                        key: CredentialKey::DpuRedfish {
                            credential_type: CredentialType::DpuHardwareDefault,
                        },
                        expected_prefix: "machines/all_dpus/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "dpu redfish site default",
                    input: Row {
                        key: CredentialKey::DpuRedfish {
                            credential_type: CredentialType::SiteDefault,
                        },
                        expected_prefix: "machines/all_dpus/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "host redfish hardware default",
                    input: Row {
                        key: CredentialKey::HostRedfish {
                            credential_type: CredentialType::HostHardwareDefault {
                                vendor: bmc_vendor::BMCVendor::Nvidia,
                            },
                        },
                        expected_prefix: "machines/all_hosts/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "host redfish site default",
                    input: Row {
                        key: CredentialKey::HostRedfish {
                            credential_type: CredentialType::SiteDefault,
                        },
                        expected_prefix: "machines/all_hosts/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "ufm auth",
                    input: Row {
                        key: CredentialKey::UfmAuth {
                            fabric: "test-fabric".to_string(),
                        },
                        expected_prefix: "ufm/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "dpu uefi hardware default",
                    input: Row {
                        key: CredentialKey::DpuUefi {
                            credential_type: CredentialType::DpuHardwareDefault,
                        },
                        expected_prefix: "machines/all_dpus/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "dpu uefi site default",
                    input: Row {
                        key: CredentialKey::DpuUefi {
                            credential_type: CredentialType::SiteDefault,
                        },
                        expected_prefix: "machines/all_dpus/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "host uefi site default",
                    input: Row {
                        key: CredentialKey::HostUefi {
                            credential_type: CredentialType::SiteDefault,
                        },
                        expected_prefix: "machines/all_hosts/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "bmc site wide root",
                    input: Row {
                        key: CredentialKey::BmcCredentials {
                            credential_type: BmcCredentialType::SiteWideRoot,
                        },
                        expected_prefix: "machines/bmc/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "bmc root",
                    input: Row {
                        key: CredentialKey::BmcCredentials {
                            credential_type: BmcCredentialType::BmcRoot {
                                bmc_mac_address: mac,
                            },
                        },
                        expected_prefix: "machines/bmc/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "bmc forge admin",
                    input: Row {
                        key: CredentialKey::BmcCredentials {
                            credential_type: BmcCredentialType::BmcForgeAdmin {
                                bmc_mac_address: mac,
                            },
                        },
                        expected_prefix: "machines/bmc/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "nic lockdown ikm",
                    input: Row {
                        key: CredentialKey::NicLockdownIkm {
                            credential_type: NicLockdownIkm::SiteWide { version: 0 },
                        },
                        expected_prefix: "machines/nic_lockdown_ikm/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "bmc site wide root versioned",
                    input: Row {
                        key: CredentialKey::BmcCredentials {
                            credential_type: BmcCredentialType::SiteWideRootVersioned {
                                version: 0,
                            },
                        },
                        expected_prefix: "machines/bmc/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "host uefi site target",
                    input: Row {
                        key: CredentialKey::UefiSiteTarget {
                            target: UefiSiteTarget::Host { version: 0 },
                        },
                        expected_prefix: "machines/uefi/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "dpu uefi site target",
                    input: Row {
                        key: CredentialKey::UefiSiteTarget {
                            target: UefiSiteTarget::Dpu { version: 0 },
                        },
                        expected_prefix: "machines/uefi/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "switch nvos site admin",
                    input: Row {
                        key: CredentialKey::SwitchNvosSiteAdmin { version: 0 },
                        expected_prefix: "switch_nvos/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "extension service",
                    input: Row {
                        key: CredentialKey::ExtensionService {
                            service_id: "svc1".to_string(),
                            version: "v1".to_string(),
                        },
                        expected_prefix: "machines/extension-services/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "nmxm",
                    input: Row {
                        key: CredentialKey::NmxM {
                            nmxm_id: "nmxm1".to_string(),
                        },
                        expected_prefix: "nmxm/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "switch nvos admin",
                    input: Row {
                        key: CredentialKey::SwitchNvosAdmin {
                            bmc_mac_address: mac,
                        },
                        expected_prefix: "switch_nvos/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "mqtt dpa",
                    input: Row {
                        key: CredentialKey::MqttAuth {
                            credential_type: MqttCredentialType::Dpa,
                        },
                        expected_prefix: "mqtt/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "mqtt dsx exchange event bus",
                    input: Row {
                        key: CredentialKey::MqttAuth {
                            credential_type: MqttCredentialType::DsxExchangeEventBus,
                        },
                        expected_prefix: "mqtt/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "mqtt dsx exchange consumer",
                    input: Row {
                        key: CredentialKey::MqttAuth {
                            credential_type: MqttCredentialType::DsxExchangeConsumer,
                        },
                        expected_prefix: "mqtt/",
                    },
                    expect: PathChecks::all_hold(),
                },
                Check {
                    scenario: "rack maintenance access token",
                    input: Row {
                        key: CredentialKey::RackMaintenanceAccessToken { rack_id },
                        expected_prefix: "racks/",
                    },
                    expect: PathChecks::all_hold(),
                },
            ],
            |Row {
                 key,
                 expected_prefix,
             }| {
                let path = key.to_key_str();
                PathChecks {
                    non_empty: !path.is_empty(),
                    no_leading_slash: !path.starts_with('/'),
                    no_trailing_slash: !path.ends_with('/'),
                    has_expected_prefix: path.starts_with(expected_prefix),
                }
            },
        );
    }

    // Verifies that every CredentialKey's to_key_str()
    // starts with its prefix().as_str().
    #[test]
    fn to_key_str_matches_prefix() {
        #[allow(deprecated)]
        let machine_id = MachineId::default();
        let rack_id = RackId::new("rack-01");
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
            CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::SiteWideRootVersioned { version: 0 },
            },
            CredentialKey::NicLockdownIkm {
                credential_type: NicLockdownIkm::SiteWide { version: 0 },
            },
            CredentialKey::UefiSiteTarget {
                target: UefiSiteTarget::Host { version: 0 },
            },
            CredentialKey::UefiSiteTarget {
                target: UefiSiteTarget::Dpu { version: 0 },
            },
            CredentialKey::ExtensionService {
                service_id: "s".to_string(),
                version: "v".to_string(),
            },
            CredentialKey::NmxM {
                nmxm_id: "n".to_string(),
            },
            CredentialKey::SwitchNvosAdmin {
                bmc_mac_address: mac,
            },
            CredentialKey::SwitchNvosSiteAdmin { version: 0 },
            CredentialKey::MqttAuth {
                credential_type: MqttCredentialType::Dpa,
            },
            CredentialKey::MachineIdentityEncryptionKey {
                key_id: "k".to_string(),
            },
            CredentialKey::RackMaintenanceAccessToken { rack_id },
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
        assert_eq!(all.len(), 17);
    }
}
