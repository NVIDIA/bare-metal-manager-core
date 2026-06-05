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
use std::collections::HashMap;
use std::net::IpAddr;

use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use carbide_uuid::rack::RackId;
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use uuid::Uuid;

use crate::metadata::Metadata;

/// Per-host DPU operating mode declared by a site operator on an
/// `ExpectedMachine`. Per-host values win over the site-wide
/// `[site_explorer] dpu_mode` setting; if neither is set the host
/// falls back to `DpuMode::DpuMode`.
///
/// Backed by the Postgres enum `dpu_mode_t`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "dpu_mode_t", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum DpuMode {
    /// DPUs are managed by NICo as normal -- upgrades, overlay networking,
    /// DPA agents, etc. The default.
    #[default]
    DpuMode,
    /// DPU hardware is physically present but configured as a plain NIC;
    /// NICo skips DPU ingest / management and treats the host as zero-DPU.
    NicMode,
    /// No DPU hardware at all -- a plain host NIC on the underlay.
    NoDpu,
}

impl DpuMode {
    /// Returns `true` when the host is not being managed as a host with DPUs
    /// (`NicMode` or `NoDpu`). Used by site-explorer and the state
    /// controller to skip DPU-specific work.
    pub fn is_dpu_managed(&self) -> bool {
        matches!(self, DpuMode::DpuMode)
    }

    /// Resolve a host's effective DPU mode from the (optional) per-host
    /// `ExpectedMachine.dpu_mode` value and the (optional) site-wide
    /// `[site_explorer] dpu_mode` setting. Notes:
    ///
    /// - An explicit per-host `NicMode` or `NoDpu` always wins.
    /// - Per-host `DpuMode` (the default variant) or no `ExpectedMachine`
    ///   at all == defer to the site-wide setting.
    /// - Site-wide `NicMode` or `NoDpu` then wins.
    /// - Site-wide `DpuMode` or missing == fall back to the absolute
    ///   default of `DpuMode::DpuMode`.
    pub fn resolve(expected_mode: Option<DpuMode>, site_dpu_mode: Option<DpuMode>) -> DpuMode {
        match expected_mode {
            Some(DpuMode::NicMode) => DpuMode::NicMode,
            Some(DpuMode::NoDpu) => DpuMode::NoDpu,
            // `DpuMode` (default) or missing == defer to site-wide setting.
            _ => match site_dpu_mode {
                Some(DpuMode::NicMode) => DpuMode::NicMode,
                Some(DpuMode::NoDpu) => DpuMode::NoDpu,
                // Site-wide `DpuMode` or missing == absolute default.
                _ => DpuMode::DpuMode,
            },
        }
    }
}

/// A request to identify an ExpectedMachine by either ID or MAC address.
#[derive(Debug, Clone)]
pub struct ExpectedMachineRequest {
    pub id: Option<Uuid>,
    pub bmc_mac_address: Option<MacAddress>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ExpectedHostNic {
    pub mac_address: MacAddress,
    // something to help the dhcp code select the right ip subnet, eg: bf3, onboard, cx8, oob, etc.
    pub nic_type: Option<String>,
    pub fixed_ip: Option<String>,
    pub fixed_mask: Option<String>,
    pub fixed_gateway: Option<String>,
    /// When true, `primary` flags this NIC as the host's boot (primary)
    /// interface. At most one NIC per ExpectedMachine may be marked primary
    /// (which is enforced in the API). This ultimately propagates into the
    /// machine_interfaces table, but, in today's world, only really applies
    /// to zero-DPU. A machine *with* a DPU will end up taking over when
    /// site-explorer finds a DPU for the machine (and update the primary
    /// interface accordingly).
    #[serde(default)]
    pub primary: Option<bool>,
}

// Important : new fields for expected machine should be Optional _and_ #[serde(default)],
// unless you want to go update all the files in each production deployment that autoload
// the expected machines on api startup
#[derive(Clone, Deserialize)]
pub struct ExpectedMachine {
    #[serde(default)]
    pub id: Option<Uuid>,
    pub bmc_mac_address: MacAddress,
    #[serde(flatten)]
    pub data: ExpectedMachineData,
}

#[derive(Clone, Default, Deserialize)] // Do not add Debug here, it contains password
pub struct ExpectedMachineData {
    pub bmc_username: String,
    pub bmc_password: String,
    pub serial_number: String,
    #[serde(default)]
    pub fallback_dpu_serial_numbers: Vec<String>,
    #[serde(default)]
    pub sku_id: Option<String>,
    #[serde(default)]
    pub metadata: Metadata,
    #[serde(default)]
    pub host_nics: Vec<ExpectedHostNic>,
    pub rack_id: Option<RackId>,
    pub default_pause_ingestion_and_poweron: Option<bool>,
    pub dpf_enabled: Option<bool>,
    /// When set, the API pre-allocates a `machine_interface` for this BMC MAC at this address
    /// (same pattern as expected switches / power shelves) so Site Explorer can reach the BMC
    /// without DHCP. IPs outside Carbide-managed prefixes land on the `static-assignments` segment.
    #[serde(default)]
    pub bmc_ip_address: Option<IpAddr>,
    /// When true, site-explorer skips BMC password rotation and stores the
    /// factory-default credentials in Vault as-is.
    #[serde(default)]
    pub bmc_retain_credentials: Option<bool>,
    /// Per-host DPU operating mode (default `DpuMode::DpuMode` for
    /// backward compat). See `DpuMode` for semantics. Operators set
    /// this to `NicMode` when a physically-present DPU should be treated
    /// as a plain NIC, or to `NoDpu` when there's no DPU hardware at all.
    #[serde(default)]
    pub dpu_mode: DpuMode,
    /// Per-host profile for settings that affect state-machine progression.
    /// Stored as a JSONB column on `expected_machines`; future state-machine
    /// knobs should be added here rather than as new flat columns.
    #[serde(default)]
    pub host_lifecycle_profile: HostLifecycleProfile,
}
// Important : new fields for expected machine (and data) should be optional _and_ serde(default),
// unless you want to go update all the files in each production deployment that autoload
// the expected machines on api startup

/// Per-host lifecycle profile for settings that affect state-machine progression.
/// `Option<bool>` fields support CLI patch semantics (`None` = not specified,
/// keep existing DB value via `COALESCE`). Converts to the runtime `HostProfile`
/// (plain `bool` fields) at machine discovery time.
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostLifecycleProfile {
    /// If true, do not lock down the server as part of lifecycle management within the state machine.
    /// If unset or false, preserve the default behavior of locking down the server after configuring the BIOS.
    #[serde(default)]
    pub disable_lockdown: Option<bool>,
}

impl HostLifecycleProfile {
    /// Returns `true` when every field is `None`, meaning the caller did not
    /// specify any profile value. Used by the UPDATE path to send SQL `NULL`
    /// so that `COALESCE` preserves the existing DB row.
    pub fn is_empty(&self) -> bool {
        self.disable_lockdown.is_none()
    }
}

impl<'r> FromRow<'r, PgRow> for ExpectedMachine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("metadata_labels")?;
        let metadata = Metadata {
            name: row.try_get("metadata_name")?,
            description: row.try_get("metadata_description")?,
            labels: labels.0,
        };

        let json: sqlx::types::Json<Vec<ExpectedHostNic>> = row.try_get("host_nics")?;
        let host_nics: Vec<ExpectedHostNic> = json.0;

        Ok(ExpectedMachine {
            id: row.try_get("id")?,
            bmc_mac_address: row.try_get("bmc_mac_address")?,
            data: ExpectedMachineData {
                bmc_username: row.try_get("bmc_username")?,
                serial_number: row.try_get("serial_number")?,
                bmc_password: row.try_get("bmc_password")?,
                fallback_dpu_serial_numbers: row.try_get("fallback_dpu_serial_numbers")?,
                metadata,
                sku_id: row.try_get("sku_id")?,
                rack_id: row.try_get("rack_id")?,
                host_nics,
                default_pause_ingestion_and_poweron: row
                    .try_get("default_pause_ingestion_and_poweron")?,
                dpf_enabled: row.try_get("dpf_enabled")?,
                bmc_ip_address: row.try_get("bmc_ip_address")?,
                bmc_retain_credentials: row.try_get("bmc_retain_credentials")?,
                dpu_mode: row.try_get("dpu_mode")?,
                host_lifecycle_profile: row
                    .try_get::<sqlx::types::Json<HostLifecycleProfile>, _>("host_lifecycle_profile")
                    .map(|j| j.0)?,
            },
        })
    }
}

#[derive(FromRow)]
pub struct LinkedExpectedMachine {
    pub serial_number: String,
    pub bmc_mac_address: MacAddress, // from expected_machines table
    pub interface_id: Option<MachineInterfaceId>, // from machine_interfaces table
    pub address: Option<String>,     // The explored endpoint
    pub machine_id: Option<MachineId>, // The machine
    pub expected_machine_id: Option<Uuid>, // The expected machine ID
}

/// A host BMC endpoint that was explored by Site Explorer but is not listed
/// in any of the `expected_machines`, `expected_power_shelf`, or
/// `expected_switch` tables. DPUs, power shelves, and switches are filtered
/// out of this list; it only contains host BMCs.
pub struct UnexpectedMachine {
    pub address: IpAddr,
    pub bmc_mac_address: MacAddress,
    pub machine_id: Option<MachineId>,
}

// default_uuid removed; ids are optional to support legacy rows with NULL ids

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing set anywhere -- the host falls back to the absolute
    /// default, `DpuMode::DpuMode`.
    #[test]
    fn resolve_no_expected_mode_no_site_setting_returns_dpu_mode() {
        assert_eq!(DpuMode::resolve(None, None), DpuMode::DpuMode);
    }

    /// Explicit per-host `DpuMode` is indistinguishable from "not set"
    /// in the storage type (the default variant), so it also defers to
    /// the site-wide setting.
    #[test]
    fn resolve_explicit_per_host_dpu_mode_defers_to_site_setting() {
        assert_eq!(
            DpuMode::resolve(Some(DpuMode::DpuMode), None),
            DpuMode::DpuMode
        );
        assert_eq!(
            DpuMode::resolve(Some(DpuMode::DpuMode), Some(DpuMode::NicMode)),
            DpuMode::NicMode
        );
    }

    /// An explicit per-host `NicMode` always wins, regardless of the
    /// site-wide setting. This is the "I want this specific host in
    /// NIC mode" override.
    #[test]
    fn resolve_per_host_nic_mode_always_wins() {
        for site_dpu_mode in [None, Some(DpuMode::DpuMode), Some(DpuMode::NoDpu)] {
            assert_eq!(
                DpuMode::resolve(Some(DpuMode::NicMode), site_dpu_mode),
                DpuMode::NicMode,
                "site_dpu_mode={site_dpu_mode:?}"
            );
        }
    }

    /// An explicit per-host `NoDpu` always wins. Useful for hosts where
    /// the operator knows there's genuinely no DPU hardware (as opposed
    /// to "DPU present but used as NIC", which is `NicMode`).
    #[test]
    fn resolve_per_host_no_dpu_always_wins() {
        for site_dpu_mode in [None, Some(DpuMode::DpuMode), Some(DpuMode::NicMode)] {
            assert_eq!(
                DpuMode::resolve(Some(DpuMode::NoDpu), site_dpu_mode),
                DpuMode::NoDpu,
                "site_dpu_mode={site_dpu_mode:?}"
            );
        }
    }

    /// Site-wide `NicMode` applies to hosts that don't declare a
    /// per-host mode -- this is the whole point of the site-wide
    /// setting (flip an entire site without per-host edits).
    #[test]
    fn resolve_site_wide_nic_mode_applies_when_per_host_is_unset() {
        assert_eq!(
            DpuMode::resolve(None, Some(DpuMode::NicMode)),
            DpuMode::NicMode
        );
        assert_eq!(
            DpuMode::resolve(Some(DpuMode::DpuMode), Some(DpuMode::NicMode)),
            DpuMode::NicMode
        );
    }

    /// Same as above for `NoDpu`: site-wide setting applies when the
    /// per-host value is unset (or the default `DpuMode` placeholder).
    #[test]
    fn resolve_site_wide_no_dpu_applies_when_per_host_is_unset() {
        assert_eq!(DpuMode::resolve(None, Some(DpuMode::NoDpu)), DpuMode::NoDpu);
        assert_eq!(
            DpuMode::resolve(Some(DpuMode::DpuMode), Some(DpuMode::NoDpu)),
            DpuMode::NoDpu
        );
    }

    /// Site-wide `DpuMode` is indistinguishable from "not set" -- both
    /// fall back to the absolute `DpuMode` default. Symmetric with the
    /// per-host `DpuMode` behavior.
    #[test]
    fn resolve_site_wide_dpu_mode_resolves_to_dpu_mode() {
        assert_eq!(
            DpuMode::resolve(None, Some(DpuMode::DpuMode)),
            DpuMode::DpuMode
        );
    }

    /// `is_dpu_managed()` returns true only for the default `DpuMode`
    /// variant -- the two "not managed by NICo as DPU" cases both return
    /// false, which is what site-explorer and state handlers use to skip
    /// DPU-specific work.
    #[test]
    fn is_dpu_managed_covers_both_skip_cases() {
        assert!(DpuMode::DpuMode.is_dpu_managed());
        assert!(!DpuMode::NicMode.is_dpu_managed());
        assert!(!DpuMode::NoDpu.is_dpu_managed());
    }

    #[test]
    fn host_lifecycle_profile_defaults_when_missing_from_json() {
        let json = r#"{
            "bmc_mac_address": "AA:BB:CC:DD:EE:FF",
            "bmc_username": "root",
            "bmc_password": "pass",
            "serial_number": "SN-1"
        }"#;
        let em: ExpectedMachine = serde_json::from_str(json).unwrap();
        assert_eq!(
            em.data.host_lifecycle_profile,
            HostLifecycleProfile::default()
        );
        assert_eq!(em.data.host_lifecycle_profile.disable_lockdown, None);
    }

    #[test]
    fn host_lifecycle_profile_parses_from_json_when_present() {
        let json = r#"{
            "bmc_mac_address": "AA:BB:CC:DD:EE:FF",
            "bmc_username": "root",
            "bmc_password": "pass",
            "serial_number": "SN-1",
            "host_lifecycle_profile": {"disable_lockdown": true}
        }"#;
        let em: ExpectedMachine = serde_json::from_str(json).unwrap();
        assert_eq!(em.data.host_lifecycle_profile.disable_lockdown, Some(true));
    }

    #[test]
    fn host_lifecycle_profile_is_empty_when_all_fields_none() {
        let hlp = HostLifecycleProfile::default();
        assert!(hlp.is_empty());

        let hlp = HostLifecycleProfile {
            disable_lockdown: Some(true),
        };
        assert!(!hlp.is_empty());

        let hlp = HostLifecycleProfile {
            disable_lockdown: Some(false),
        };
        assert!(!hlp.is_empty());
    }
}
