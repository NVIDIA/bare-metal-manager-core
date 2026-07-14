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

mod implementation;
mod instrumented;

pub mod auth;
pub mod conv;
pub mod dpu_bios;
pub mod error;
#[cfg(feature = "test-support")]
pub mod test_support;

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
pub use auth::RedfishAuth;
use carbide_secrets::credentials::{CredentialKey, CredentialReader, CredentialType, Credentials};
use carbide_utils::HostPortPair;
use carbide_utils::redfish::BmcAccessInfo;
pub use error::RedfishClientCreationError;
use libredfish::Redfish;
use libredfish::model::service_root::RedfishVendor;

pub fn new_pool(
    credential_reader: Arc<dyn CredentialReader>,
    pool: libredfish::RedfishClientPool,
    proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
) -> Arc<dyn RedfishClientPool> {
    Arc::new(implementation::RedfishClientPoolImpl::new(
        credential_reader,
        pool,
        proxy_address,
    ))
}

/// Create Redfish clients for a certain Redfish BMC endpoint
#[async_trait]
pub trait RedfishClientPool: Send + Sync + 'static {
    // MARK: - Required methods

    /// Creates a new Redfish client for a Machines BMC.
    /// `host` is the IP address or hostname of the BMC.
    /// `vendor` allows you to pre-assign the underlying
    /// RedfishVendor to use for the client, saving the
    /// service root call to auto-detect the vendor.
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        auth: RedfishAuth,
        vendor: Option<RedfishVendor>,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError>;

    /// Returns a CredentialReader for use in setting credentials in the UEFI/BMC.
    fn credential_reader(&self) -> &dyn CredentialReader;

    // MARK: - Default (helper) methods

    async fn probe_redfish_endpoint(
        &self,
        bmc_ip_address: SocketAddr,
    ) -> Result<(), RedfishClientCreationError> {
        let client = self
            .create_client(
                &bmc_ip_address.ip().to_string(),
                Some(bmc_ip_address.port()),
                RedfishAuth::Anonymous,
                Some(RedfishVendor::Unknown),
            )
            .await?;

        client
            .get_service_root()
            .await
            .map_err(RedfishClientCreationError::RedfishError)?;

        Ok(())
    }

    async fn client_by_info(
        &self,
        access: &BmcAccessInfo,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.create_client(
            &access.host,
            access.port,
            RedfishAuth::for_bmc_mac(access.mac_address),
            None,
        )
        .await
    }

    // clear_host_uefi_password updates the UEFI password from Forge's sitewide password to an empty string
    // The assumption is that this function will only be called on a machine that already updated the UEFI password to match the Forge sitewide password.
    //
    // `current_device_credentials` is the credential the device currently
    // carries (the host UEFI password to authenticate the clear with). The
    // caller resolves it -- this low-level crate intentionally knows nothing
    // about credential versions or the rotation table; it just applies the
    // password it is handed.
    async fn clear_host_uefi_password(
        &self,
        client: &dyn Redfish,
        current_device_credentials: Credentials,
    ) -> Result<Option<String>, RedfishClientCreationError> {
        let Credentials::UsernamePassword {
            password: current_password,
            ..
        } = current_device_credentials;

        client
            .clear_uefi_password(current_password.as_str())
            .await
            .map_err(|err| redact_password(err, current_password.as_str()))
            .map_err(RedfishClientCreationError::RedfishError)
    }

    // `sitewide_uefi_credentials` is the site-wide UEFI credential to set on the
    // device (host_uefi when `dpu` is false, dpu_uefi when true). The caller
    // resolves it -- this crate knows nothing about credential versions or the
    // rotation table. The DPU's factory-default password (the credential the
    // device still carries before this runs) is a hardware constant, so it is
    // still read here.
    async fn uefi_setup(
        &self,
        client: &dyn Redfish,
        dpu: bool,
        sitewide_uefi_credentials: Credentials,
    ) -> Result<Option<String>, RedfishClientCreationError> {
        let Credentials::UsernamePassword {
            password: new_password,
            ..
        } = sitewide_uefi_credentials;
        let mut current_password = String::new();
        if dpu {
            let bios_attrs = client
                .bios()
                .await
                .map_err(RedfishClientCreationError::RedfishError)?;

            //
            // This should be changed to be an actual failure once we make it this far since we don't
            // want to leave machines lying around in the datacenter without UEFI credentials.
            //
            // But adding logs here so that we know when it happens
            //
            match bios_attrs.get("Attributes") {
                None => {
                    tracing::warn!(
                        "BIOS Attributes are missing in the Redfish System BIOS endpoint, skipping UEFI password setting"
                    );
                    return Ok(None);
                }
                Some(attrs) => match attrs.as_object() {
                    None => {
                        tracing::warn!(
                            "BIOS attributes are not an object in the Redfish System BIOS endpoint, skipping UEFI password setting"
                        );
                        return Ok(None);
                    }
                    Some(attrs) if !attrs.contains_key("CurrentUefiPassword") => {
                        tracing::warn!(
                            "BIOS Attributes exist, but is missing CurrentUefiPassword key, skipping UEFI password setting"
                        );
                        return Ok(None);
                    }
                    _ => {
                        tracing::info!(
                            "BIOS Attributes found, and contains CurrentUefiPassword, continuing with UEFI password setting"
                        );
                    }
                },
            }

            // Replace the DPU UEFI default password with the site default.
            // The current (factory) password is taken from the DpuUefi factory
            // default key -- a hardware constant, not a versioned/site credential
            // -- so it is read here; the new (site) password was handed in.
            let credentials = self
                .credential_reader()
                .get_credentials(&CredentialKey::DpuUefi {
                    credential_type: CredentialType::DpuHardwareDefault,
                })
                .await?
                .unwrap_or(Credentials::UsernamePassword {
                    username: "".to_string(),
                    password: "bluefield".to_string(),
                });

            (_, current_password) = match credentials {
                Credentials::UsernamePassword { username, password } => (username, password),
            };
        } else {
            // For hosts, first try with empty current password (assuming no
            // password is set), using the site default handed in by the caller.
            match client
                .change_uefi_password(current_password.as_str(), new_password.as_str())
                .await
            {
                Ok(jid) => return Ok(jid),
                Err(e) => {
                    // If the first attempt fails (likely because a password is already set),
                    // retry using the site default password as the current password.
                    // This handles the case where a host was force-deleted without clearing
                    // its UEFI password.
                    let redacted_error = redact_password(e, new_password.as_str());
                    tracing::warn!(
                        error = %redacted_error,
                        "Failed to set UEFI password with empty current password, retrying with site default password"
                    );
                    current_password = new_password.clone();
                }
            }
        }

        client
            .change_uefi_password(current_password.as_str(), new_password.as_str())
            .await
            .map_err(|err| redact_password(err, new_password.as_str()))
            .map_err(|err| redact_password(err, current_password.as_str()))
            .map_err(RedfishClientCreationError::RedfishError)
    }

    /// Rotate a BMC's root password in place, then apply the vendor-specific
    /// password policy.
    ///
    /// `current_bmc_root_credentials` is the credential the BMC currently
    /// carries (used to authenticate the change); `new_password` is the value
    /// to rotate to. The caller resolves both -- this crate knows nothing
    /// about credential versions or the rotation table, it just applies what
    /// it is handed.
    ///
    /// The rotation `PATCH` to `/AccountService` goes through an uninitialized
    /// `Unknown` client on purpose, so libredfish does not eagerly fetch
    /// `/Systems`, `/Managers`, `/Chassis` up front. Those fetches are
    /// unnecessary just to change the password, and they actively break
    /// rotation on factory BMCs that refuse reads until the password has been
    /// changed. Notably, NVIDIA GBx00 in factory state authenticates the
    /// supplied creds just fine but returns HTTP 403
    /// `Base.1.18.1.PasswordChangeRequired` on `/Systems` -- so letting
    /// libredfish initialize first never reaches the `PATCH` that would unblock
    /// it. Only the follow-up policy client (created after the rotation
    /// succeeds) is vendor-specific, so `set_machine_password_policy` gets the
    /// right impl (e.g. Lite-On's, which omits `AccountLockoutCounterResetAfter`).
    async fn set_bmc_root_password(
        &self,
        host: &str,
        port: Option<u16>,
        vendor: RedfishVendor,
        current_bmc_root_credentials: Credentials,
        new_password: String,
    ) -> Result<(), RedfishClientCreationError> {
        let (curr_user, curr_password) = match &current_bmc_root_credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        let client = self
            .create_client(
                host,
                port,
                RedfishAuth::Direct(curr_user.clone(), curr_password.clone()),
                Some(RedfishVendor::Unknown),
            )
            .await?;

        match vendor {
            RedfishVendor::Lenovo => {
                // Change (factory_user, factory_pass) to (factory_user, site_pass)
                client
                    .change_password_by_id("1", new_password.as_str())
                    .await
                    .map_err(|err| redact_password(err, new_password.as_str()))
                    .map_err(|err| redact_password(err, curr_password.as_str()))
                    .map_err(RedfishClientCreationError::RedfishError)?;
            }
            RedfishVendor::NvidiaDpu
            | RedfishVendor::NvidiaGH200
            | RedfishVendor::NvidiaGBSwitch
            | RedfishVendor::P3809
            | RedfishVendor::LiteOnPowerShelf
            | RedfishVendor::DeltaPowerShelf
            | RedfishVendor::NvidiaGBx00
            | RedfishVendor::VeraRubin => {
                // change_password does things that require a password and DPUs need a first
                // password use to be change, so just change it directly
                //
                // GH200 doesn't require change-on-first-use, but it's good practice. GB200
                // probably will.
                client
                    .change_password_by_id(curr_user.as_str(), new_password.as_str())
                    .await
                    .map_err(|err| redact_password(err, new_password.as_str()))
                    .map_err(|err| redact_password(err, curr_password.as_str()))
                    .map_err(RedfishClientCreationError::RedfishError)?;
            }
            // Vikings and Lenovo GB300s (both still detected as AMI here).
            // Resolve the admin account by username, and fall back to the conventional
            // id "2" only when reads are blocked by `PasswordChangeRequired` (Viking factory state).
            // Any other error propagates.
            //
            // https://docs.nvidia.com/dgx/dgxh100-user-guide/redfish-api-supp.html
            RedfishVendor::AMI | RedfishVendor::LenovoGB300 => {
                match client
                    .change_password(curr_user.as_str(), new_password.as_str())
                    .await
                {
                    Ok(()) => {}
                    Err(libredfish::RedfishError::PasswordChangeRequired) => {
                        client
                            .change_password_by_id("2", new_password.as_str())
                            .await
                            .map_err(|err| redact_password(err, new_password.as_str()))
                            .map_err(|err| redact_password(err, curr_password.as_str()))
                            .map_err(RedfishClientCreationError::RedfishError)?;
                    }
                    Err(err) => {
                        return Err(RedfishClientCreationError::RedfishError(redact_password(
                            redact_password(err, new_password.as_str()),
                            curr_password.as_str(),
                        )));
                    }
                }
            }
            RedfishVendor::LenovoAMI
            | RedfishVendor::Supermicro
            | RedfishVendor::Dell
            | RedfishVendor::Hpe => {
                client
                    .change_password(curr_user.as_str(), new_password.as_str())
                    .await
                    .map_err(|err| redact_password(err, new_password.as_str()))
                    .map_err(|err| redact_password(err, curr_password.as_str()))
                    .map_err(RedfishClientCreationError::RedfishError)?;
            }
            RedfishVendor::Unknown => {
                // Defensive guard: callers resolve the vendor via
                // `probe_bmc_vendor` (or site-explorer's `get_redfish_vendor`),
                // both of which reject `Unknown` before we ever get here, so
                // this arm is not reachable from the live path.
                return Err(RedfishClientCreationError::RedfishError(
                    libredfish::RedfishError::MissingVendor,
                ));
            }
        };

        // Log in using the new credentials and set the vendor-specific password policy.
        let vendored_client = self
            .create_client(
                host,
                port,
                RedfishAuth::Direct(curr_user.to_string(), new_password),
                Some(vendor),
            )
            .await?;

        vendored_client
            .set_machine_password_policy()
            .await
            .map_err(RedfishClientCreationError::RedfishError)?;

        Ok(())
    }

    /// Resolve the precise `RedfishVendor` of a BMC, for callers (e.g.
    /// credential rotation) that need the exact dispatch vendor
    /// `set_bmc_root_password` branches on but have nowhere to read it from.
    ///
    /// First tries the anonymous service-root probe, consulting the `Oem` key
    /// as a fallback (some BMCs leave `ServiceRoot.Vendor` null but still
    /// identify via `Oem`). If that does not yield a recognized vendor, falls
    /// back to reading the `Manufacturer` across `Chassis` entries with the
    /// supplied credentials -- the workaround Lite-On/Delta power-shelf BMCs
    /// need, since they don't populate the service-root vendor. Returns
    /// `RedfishError::MissingVendor` when neither path recognizes the vendor.
    async fn probe_bmc_vendor(
        &self,
        host: &str,
        port: Option<u16>,
        credentials: Credentials,
    ) -> Result<RedfishVendor, RedfishClientCreationError> {
        // Anonymous service-root probe. An uninitialized `Unknown` client is
        // enough to read `/redfish/v1`, and works on factory BMCs that would
        // otherwise block reads until the password is rotated.
        let anon_client = self
            .create_client(
                host,
                port,
                RedfishAuth::Anonymous,
                Some(RedfishVendor::Unknown),
            )
            .await?;

        if let Ok(service_root) = anon_client.get_service_root().await
            && let Some(vendor) = service_root.vendor()
            && vendor != RedfishVendor::Unknown
        {
            return Ok(vendor);
        }

        // Chassis `Manufacturer` fallback for BMCs (Lite-On / Delta power
        // shelves) that don't expose a recognized vendor in the service root.
        let Credentials::UsernamePassword { username, password } = credentials;
        let client = self
            .create_client(host, port, RedfishAuth::Direct(username, password), None)
            .await?;

        let chassis_ids = client
            .get_chassis_all()
            .await
            .map_err(RedfishClientCreationError::RedfishError)?;
        for chassis_id in &chassis_ids {
            let chassis = client
                .get_chassis(chassis_id)
                .await
                .map_err(RedfishClientCreationError::RedfishError)?;
            if let Some(manufacturer) = chassis.manufacturer {
                let manufacturer_lc = manufacturer.to_lowercase();
                if manufacturer_lc.contains("lite-on") {
                    return Ok(RedfishVendor::LiteOnPowerShelf);
                } else if manufacturer_lc.contains("delta") {
                    return Ok(RedfishVendor::DeltaPowerShelf);
                }
            }
        }

        Err(RedfishClientCreationError::RedfishError(
            libredfish::RedfishError::MissingVendor,
        ))
    }
}

// Some BMC implementation may return passwords in response body and
// we can display them to user. This function is helper to remove
// password leak for password-related refish functions.
pub fn redact_password(err: libredfish::RedfishError, password: &str) -> libredfish::RedfishError {
    redact_passwords(err, &[password])
}

/// Replaces every occurrence of every non-empty needle with `REDACTED`,
/// masking the union of all matches: where two needles' matches touch or
/// overlap in the text (one password containing the other, or sharing a
/// boundary), the merged span redacts as one, so no fragment of either
/// survives.
fn mask_all(text: &str, needles: &[&str]) -> String {
    const REDACTED: &str = "REDACTED";
    let mut ranges: Vec<(usize, usize)> = needles
        .iter()
        .filter(|needle| !needle.is_empty())
        .flat_map(|needle| {
            // A manual scan over every starting position, not
            // `match_indices`: that skips overlapping matches of the same
            // needle, and a self-repetitive password (`aa` in `xaaay`) would
            // leave a fragment beside the mask. Byte-wise matching of one
            // valid UTF-8 string inside another can only land on character
            // boundaries, so the collected ranges slice cleanly.
            let needle = needle.as_bytes();
            (0..=text.len().saturating_sub(needle.len()))
                .filter(move |&start| text.as_bytes()[start..].starts_with(needle))
                .map(move |start| (start, start + needle.len()))
        })
        .collect();
    ranges.sort_unstable();

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut i = 0;
    while i < ranges.len() {
        let (start, mut end) = ranges[i];
        i += 1;
        while i < ranges.len() && ranges[i].0 <= end {
            end = end.max(ranges[i].1);
            i += 1;
        }
        out.push_str(&text[cursor..start]);
        out.push_str(REDACTED);
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// [`redact_password`] over several passwords at once, with union masking
/// (see [`mask_all`]) so overlapping matches cannot leave fragments of one
/// password behind after another is replaced.
pub fn redact_passwords(
    err: libredfish::RedfishError,
    passwords: &[&str],
) -> libredfish::RedfishError {
    type RfError = libredfish::RedfishError;
    let redact = |v: String| mask_all(&v, passwords);
    match err {
        RfError::HTTPErrorCode {
            url,
            status_code,
            response_body,
        } => RfError::HTTPErrorCode {
            url,
            status_code,
            response_body: redact(response_body),
        },
        RfError::JsonDeserializeError { url, body, source } => RfError::JsonDeserializeError {
            url,
            body: redact(body),
            source,
        },
        RfError::JsonSerializeError {
            url,
            object_debug,
            source,
        } => RfError::JsonSerializeError {
            url,
            object_debug: redact(object_debug),
            source,
        },
        RfError::InvalidValue {
            url,
            field,
            err: libredfish::model::InvalidValueError(v),
        } => RfError::InvalidValue {
            url,
            field,
            err: libredfish::model::InvalidValueError(redact(v)),
        },
        RfError::GenericError { error } => RfError::GenericError {
            error: redact(error),
        },
        // All errors are enumerated here instead of default to get
        // compile error on any new error in libredfish added. This
        // gives you chance to think if password may leak to the new
        // error or not.
        RfError::NetworkError { .. }
        | RfError::NoContent
        | RfError::NoHeader
        | RfError::Lockdown
        | RfError::MissingVendor
        | RfError::PasswordChangeRequired
        | RfError::FileError(_)
        | RfError::UserNotFound(_)
        | RfError::NotSupported(_)
        | RfError::UnnecessaryOperation
        | RfError::MissingKey { .. }
        | RfError::InvalidKeyType { .. }
        | RfError::TooManyUsers
        | RfError::NoDpu
        | RfError::ReqwestError(_)
        | RfError::TypeMismatch { .. }
        | RfError::MissingBootOption(_) => err,
    }
}

#[cfg(test)]
mod tests {
    use libredfish::PowerState;

    use super::*;
    use crate::libredfish::test_support::*;

    /// The mask covers the union of ALL matches, including a needle's
    /// self-overlapping matches (`aa` occurs at both offsets in `xaaay`) and
    /// matches of different needles sharing a boundary -- so no fragment of
    /// any needle is left unmasked.
    #[test]
    fn mask_all_covers_overlapping_and_repeated_matches() {
        struct Case {
            name: &'static str,
            text: &'static str,
            needles: &'static [&'static str],
            expected: &'static str,
        }
        let cases = [
            Case {
                name: "self-overlapping needle",
                text: "xaaay",
                needles: &["aa"],
                expected: "xREDACTEDy",
            },
            Case {
                name: "boundary overlap between two needles",
                text: "rejected abcdefghi",
                needles: &["abcdef", "defghi"],
                expected: "rejected REDACTED",
            },
            Case {
                name: "containment",
                text: "rejected foobar, and foo separately",
                needles: &["foo", "foobar"],
                expected: "rejected REDACTED, and REDACTED separately",
            },
            Case {
                name: "disjoint matches and empty needles ignored",
                text: "a secret and a token",
                needles: &["secret", "token", ""],
                expected: "a REDACTED and a REDACTED",
            },
        ];
        for case in cases {
            assert_eq!(
                mask_all(case.text, case.needles),
                case.expected,
                "case: {}",
                case.name,
            );
        }
    }

    #[tokio::test]
    async fn test_power_state() {
        let sim = RedfishSim::default();
        let client = sim
            .create_client(
                "localhost",
                None,
                RedfishAuth::Key(CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                }),
                None,
            )
            .await
            .unwrap();

        assert_eq!(PowerState::On, client.get_power_state().await.unwrap());
        client
            .power(libredfish::SystemPowerControl::ForceOff)
            .await
            .unwrap();

        assert_eq!(PowerState::Off, client.get_power_state().await.unwrap());
        let client = sim
            .create_client(
                "localhost",
                None,
                RedfishAuth::Key(CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(PowerState::Off, client.get_power_state().await.unwrap());
    }

    #[test]
    fn password_redact_from_error() {
        const PASSWORD: &str = "1234";
        let err = libredfish::RedfishError::HTTPErrorCode {
            url: "https://example.com/redfish/v1/Systems/1/Bios/Actions/Bios.ChangePassword".into(),
            status_code: http::StatusCode::BAD_REQUEST,
            response_body: format!(r#""MessageArgs":["{PASSWORD}"]"#),
        };
        assert!(err.to_string().contains(PASSWORD));
        assert!(
            !redact_password(err, PASSWORD)
                .to_string()
                .contains(PASSWORD)
        );
    }

    /// Rotate a BMC root password against the sim and report the vendor each
    /// `create_client` call was made with, in order. The contract:
    /// the FIRST client (which makes the `/AccountService` PATCH) must be
    /// uninitialized (`Unknown`), and only the SECOND client (which sets the
    /// password policy afterward) should carry the real vendor.
    async fn rotate_and_collect_client_vendors(
        vendor: RedfishVendor,
    ) -> Vec<Option<RedfishVendor>> {
        let sim = RedfishSim::default();
        sim.seed_user("root", "factory_pass");
        sim.set_bmc_root_password(
            "127.0.0.1",
            Some(443),
            vendor,
            Credentials::new("root", "factory_pass"),
            "site_pass".to_string(),
        )
        .await
        .unwrap();

        sim.create_client_calls()
            .into_iter()
            .map(|call| call.vendor)
            .collect()
    }

    #[tokio::test]
    async fn set_bmc_root_password_rotates_with_unknown_then_real_vendor() {
        // Vendors whose root account is the seeded `root` user, so both the
        // by-username and by-id (curr_user) dispatch paths succeed against the
        // sim. Each must produce exactly two `create_client` calls: `Unknown`
        // for the rotation PATCH, then the real vendor for the policy client.
        for vendor in [
            RedfishVendor::LiteOnPowerShelf,
            RedfishVendor::DeltaPowerShelf,
            RedfishVendor::NvidiaDpu,
            RedfishVendor::NvidiaGBx00,
            RedfishVendor::Dell,
            RedfishVendor::Hpe,
            RedfishVendor::AMI,
        ] {
            assert_eq!(
                rotate_and_collect_client_vendors(vendor).await,
                vec![Some(RedfishVendor::Unknown), Some(vendor)],
                "vendor {vendor} must rotate via an Unknown client then a vendor-specific policy client",
            );
        }
    }

    #[tokio::test]
    async fn set_bmc_root_password_lenovo_changes_account_id_one() {
        // Lenovo dispatches to account id "1"; seed it so the rotation succeeds.
        let sim = RedfishSim::default();
        sim.seed_user("1", "factory_pass");
        sim.set_bmc_root_password(
            "127.0.0.1",
            Some(443),
            RedfishVendor::Lenovo,
            Credentials::new("root", "factory_pass"),
            "site_pass".to_string(),
        )
        .await
        .expect("Lenovo rotation against account id 1 should succeed");
    }

    #[tokio::test]
    async fn set_bmc_root_password_ami_falls_back_to_account_id_two() {
        // Factory Viking (AMI) refuses the by-username change with
        // `PasswordChangeRequired`; the rotation must then retry against
        // account id "2".
        let sim = RedfishSim::default();
        sim.seed_user("root", "factory_pass");
        sim.seed_user("2", "factory_pass");
        sim.set_password_change_required(true);

        sim.set_bmc_root_password(
            "127.0.0.1",
            Some(443),
            RedfishVendor::AMI,
            Credentials::new("root", "factory_pass"),
            "site_pass".to_string(),
        )
        .await
        .expect("AMI rotation should fall back to account id 2");
    }

    #[tokio::test]
    async fn set_bmc_root_password_ami_dispatches_to_id_two_after_password_change_required() {
        // Same factory state, but account id "2" is absent: the fallback's
        // `change_password_by_id("2")` fails with `UserNotFound("2")`, proving
        // the AMI path dispatches to id "2" after `PasswordChangeRequired`
        // (rather than swallowing the error or dispatching elsewhere).
        let sim = RedfishSim::default();
        sim.seed_user("root", "factory_pass");
        sim.set_password_change_required(true);

        let err = sim
            .set_bmc_root_password(
                "127.0.0.1",
                Some(443),
                RedfishVendor::AMI,
                Credentials::new("root", "factory_pass"),
                "site_pass".to_string(),
            )
            .await
            .expect_err("missing account id 2 must surface the fallback error");

        assert!(
            matches!(
                &err,
                RedfishClientCreationError::RedfishError(libredfish::RedfishError::UserNotFound(id))
                    if id == "2"
            ),
            "expected UserNotFound(\"2\"), got {err:?}",
        );
    }

    #[tokio::test]
    async fn set_bmc_root_password_rejects_unknown_vendor() {
        let sim = RedfishSim::default();
        sim.seed_user("root", "factory_pass");

        let err = sim
            .set_bmc_root_password(
                "127.0.0.1",
                Some(443),
                RedfishVendor::Unknown,
                Credentials::new("root", "factory_pass"),
                "site_pass".to_string(),
            )
            .await
            .expect_err("Unknown vendor must be rejected");

        assert!(
            matches!(
                err,
                RedfishClientCreationError::RedfishError(libredfish::RedfishError::MissingVendor)
            ),
            "expected MissingVendor, got {err:?}",
        );
    }

    #[tokio::test]
    async fn probe_bmc_vendor_resolves_from_service_root() {
        let sim = RedfishSim::default();
        let vendor = sim
            .probe_bmc_vendor("127.0.0.1", Some(443), Credentials::new("root", "pw"))
            .await
            .unwrap();
        // The sim's service root reports Nvidia / "GB200 NVL".
        assert_eq!(vendor, RedfishVendor::NvidiaGBx00);
    }

    #[tokio::test]
    async fn probe_bmc_vendor_falls_back_to_chassis_manufacturer() {
        for (manufacturer, expected) in [
            ("Lite-On Technology Corp.", RedfishVendor::LiteOnPowerShelf),
            ("Delta Electronics", RedfishVendor::DeltaPowerShelf),
        ] {
            let sim = RedfishSim::default();
            // Force the anonymous service-root probe to yield an unrecognized
            // vendor so probing falls through to the Chassis Manufacturer.
            sim.set_service_root_vendor(Some("Contoso".to_string()));
            sim.set_chassis_manufacturer(Some(manufacturer.to_string()));

            let vendor = sim
                .probe_bmc_vendor("127.0.0.1", Some(443), Credentials::new("root", "pw"))
                .await
                .unwrap();
            assert_eq!(
                vendor, expected,
                "chassis manufacturer {manufacturer} should resolve to {expected}",
            );
        }
    }

    #[tokio::test]
    async fn probe_bmc_vendor_errors_when_vendor_unresolvable() {
        let sim = RedfishSim::default();
        sim.set_service_root_vendor(Some("Contoso".to_string()));
        sim.set_chassis_manufacturer(Some("Acme".to_string()));

        let err = sim
            .probe_bmc_vendor("127.0.0.1", Some(443), Credentials::new("root", "pw"))
            .await
            .expect_err("an unrecognized vendor and chassis must error");

        assert!(
            matches!(
                err,
                RedfishClientCreationError::RedfishError(libredfish::RedfishError::MissingVendor)
            ),
            "expected MissingVendor, got {err:?}",
        );
    }
}
