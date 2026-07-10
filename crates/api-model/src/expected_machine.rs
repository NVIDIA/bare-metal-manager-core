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
use crate::network_segment::NetworkSegmentType;

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

/// Controls how a BMC's IP address is assigned and whether it is retained.
///
/// - `Auto` (default): infer from `bmc_ip_address` -- a configured address is
///   treated as `Fixed`, no address is treated as `Retained`.
/// - `Dynamic`: a normal DHCP lease that may expire and change.
/// - `Fixed`: the operator-specified `bmc_ip_address` (static).
/// - `Retained`: an auto-allocated address pinned as Static (never expires).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "bmc_ip_allocation_t", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum BmcIpAllocationType {
    #[default]
    Auto,
    Dynamic,
    Fixed,
    Retained,
}

impl BmcIpAllocationType {
    /// Validate the mode against whether a `bmc_ip_address` is configured.
    pub fn validate(self, has_address: bool) -> Result<(), &'static str> {
        match self {
            BmcIpAllocationType::Fixed if !has_address => {
                Err("bmc_ip_allocation=fixed requires bmc_ip_address")
            }
            BmcIpAllocationType::Dynamic if has_address => {
                Err("bmc_ip_allocation=dynamic cannot be combined with bmc_ip_address")
            }
            BmcIpAllocationType::Retained if has_address => {
                Err("bmc_ip_allocation=retained cannot be combined with bmc_ip_address; use fixed")
            }
            _ => Ok(()),
        }
    }

    /// Whether an auto-allocated BMC IP should be retained (pinned as Static)
    /// instead of left as an expirable DHCP lease. Only meaningful with no address.
    pub fn retains_dynamic_ip(self, has_address: bool) -> bool {
        match self {
            BmcIpAllocationType::Auto => !has_address,
            BmcIpAllocationType::Retained => true,
            BmcIpAllocationType::Dynamic | BmcIpAllocationType::Fixed => false,
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
    /// The network segment type this NIC's first DHCP lease should come from.
    ///
    /// A NIC's segment is normally determined by its DHCP relay -- the segment
    /// whose prefix contains the relay address. Where segment prefixes nest or
    /// overlap, one relay can match several segments; declaring this narrows the
    /// choice to the segment of this type. `None` (with no legacy
    /// [`Self::nic_type`]) leaves the relay's match as-is. Resolved via
    /// [`Self::resolved_network_segment_type`].
    #[serde(default)]
    pub network_segment_type: Option<NetworkSegmentType>,
    /// Legacy free-form NIC-type segment hint (`bf3`, `onboard`, `oob`, ...).
    /// Kept for backward compatibility; prefer `network_segment_type`.
    pub nic_type: Option<String>,
    pub fixed_ip: Option<IpAddr>,
    pub fixed_mask: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_ip_addr_lossy")]
    pub fixed_gateway: Option<IpAddr>,
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

impl ExpectedHostNic {
    /// The network segment type to narrow this NIC's DHCP segment selection to,
    /// if the declaration names one. Prefers the typed
    /// [`Self::network_segment_type`]; otherwise maps the legacy
    /// [`Self::nic_type`] string so machines declared before the typed field
    /// keep their segment. `None` -> selection stays with whatever segment(s)
    /// the relay's prefix matches.
    pub fn resolved_network_segment_type(&self) -> Option<NetworkSegmentType> {
        if let Some(segment_type) = self.network_segment_type {
            return Some(segment_type);
        }
        // Legacy `nic_type` mapping -- droppable once declarations carry the
        // typed field. `bf3`/`dpu`/`onboard` named the admin segment, `bmc`/`oob`
        // the underlay; anything else left selection to the relay.
        match self.nic_type.as_deref()?.to_ascii_lowercase().as_str() {
            "bf3" | "dpu" | "onboard" => Some(NetworkSegmentType::Admin),
            "bmc" | "oob" => Some(NetworkSegmentType::Underlay),
            _ => None,
        }
    }
}

fn deserialize_optional_ip_addr_lossy<'de, D>(deserializer: D) -> Result<Option<IpAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?
        .and_then(|address| address.parse::<IpAddr>().ok()))
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
    /// Per-host control over how this BMC's IP is assigned and retained.
    /// Defaults to `BmcIpAllocationType::Auto`, which infers `Fixed` from a
    /// configured `bmc_ip_address` and otherwise `Retained` (pins an
    /// auto-allocated address as Static so it survives DHCP lease expiry).
    #[serde(default)]
    pub bmc_ip_allocation: BmcIpAllocationType,
    /// Per-host profile for settings that affect state-machine progression.
    /// Stored as a JSONB column on `expected_machines`; future state-machine
    /// knobs should be added here rather than as new flat columns.
    #[serde(default)]
    pub host_lifecycle_profile: HostLifecycleProfile,
}
// Important : new fields for expected machine (and data) should be optional _and_ serde(default),
// unless you want to go update all the files in each production deployment that autoload
// the expected machines on api startup

impl ExpectedMachineData {
    /// The MAC the operator declared as this host's boot interface via
    /// `ExpectedHostNic.primary`. This is the single source of declared boot
    /// intent the writers consult -- site-explorer ingestion, DHCP, and
    /// prediction promotion -- so they all agree on which NIC wins. The API
    /// enforces at most one `primary` host NIC, so the first match is the
    /// declaration. `None` leaves the boot interface to today's automation
    /// (DPU takeover during ingestion, else the `pick_boot_interface` fallback).
    pub fn declared_primary_mac(&self) -> Option<MacAddress> {
        self.host_nics
            .iter()
            .find(|nic| nic.primary == Some(true))
            .map(|nic| nic.mac_address)
    }
}

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
                bmc_ip_allocation: row.try_get("bmc_ip_allocation")?,
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
    pub address: Option<IpAddr>,     // The explored endpoint
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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;

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

    /// JSON deserialization of `ExpectedMachine`, projecting to the
    /// `host_lifecycle_profile.disable_lockdown` field under test. A missing
    /// `host_lifecycle_profile` defaults to `None` (equivalent to
    /// `HostLifecycleProfile::default()`, whose only field is `disable_lockdown`).
    #[test]
    fn host_lifecycle_profile_deserializes_from_json() {
        scenarios!(
            // serde_json::Error is not PartialEq, so discard it on the error path.
            run = |json| {
                serde_json::from_str::<ExpectedMachine>(json)
                    .map(|em| em.data.host_lifecycle_profile.disable_lockdown)
                    .map_err(drop)
            };
            "missing host_lifecycle_profile defaults to None" {
                r#"{
                            "bmc_mac_address": "AA:BB:CC:DD:EE:FF",
                            "bmc_username": "root",
                            "bmc_password": "pass",
                            "serial_number": "SN-1"
                        }"# => Yields(None),
            }

            "present host_lifecycle_profile parses disable_lockdown" {
                r#"{
                            "bmc_mac_address": "AA:BB:CC:DD:EE:FF",
                            "bmc_username": "root",
                            "bmc_password": "pass",
                            "serial_number": "SN-1",
                            "host_lifecycle_profile": {"disable_lockdown": true}
                        }"# => Yields(Some(true)),
            }
        );
    }

    #[test]
    fn expected_host_nic_deserializes_valid_fixed_gateway() {
        let json = r#"{
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "fixed_gateway": "2001:db8::1"
        }"#;
        let nic: ExpectedHostNic = serde_json::from_str(json).unwrap();

        assert_eq!(nic.fixed_gateway, Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn expected_host_nic_drops_invalid_fixed_gateway_on_deserialize() {
        let json = r#"{
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "fixed_gateway": "not-an-ip"
        }"#;
        let nic: ExpectedHostNic = serde_json::from_str(json).unwrap();

        assert_eq!(nic.fixed_gateway, None);
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

    /// `BmcIpAllocationType::validate` against whether a `bmc_ip_address` is
    /// configured, exhaustively over the four variants x has_address. Only three
    /// combinations are errors: `Fixed` without an address, and `Dynamic` /
    /// `Retained` with an address. `Auto` is always valid.
    #[test]
    fn bmc_ip_allocation_validate_covers_all_combinations() {
        struct Case {
            name: &'static str,
            mode: BmcIpAllocationType,
            has_address: bool,
            ok: bool,
        }

        let cases = [
            Case {
                name: "auto with address is valid",
                mode: BmcIpAllocationType::Auto,
                has_address: true,
                ok: true,
            },
            Case {
                name: "auto without address is valid",
                mode: BmcIpAllocationType::Auto,
                has_address: false,
                ok: true,
            },
            Case {
                name: "dynamic without address is valid",
                mode: BmcIpAllocationType::Dynamic,
                has_address: false,
                ok: true,
            },
            Case {
                name: "dynamic with address is rejected",
                mode: BmcIpAllocationType::Dynamic,
                has_address: true,
                ok: false,
            },
            Case {
                name: "fixed with address is valid",
                mode: BmcIpAllocationType::Fixed,
                has_address: true,
                ok: true,
            },
            Case {
                name: "fixed without address is rejected",
                mode: BmcIpAllocationType::Fixed,
                has_address: false,
                ok: false,
            },
            Case {
                name: "retained without address is valid",
                mode: BmcIpAllocationType::Retained,
                has_address: false,
                ok: true,
            },
            Case {
                name: "retained with address is rejected",
                mode: BmcIpAllocationType::Retained,
                has_address: true,
                ok: false,
            },
        ];

        for case in cases {
            assert_eq!(
                case.mode.validate(case.has_address).is_ok(),
                case.ok,
                "{}",
                case.name
            );
        }
    }

    /// `BmcIpAllocationType::retains_dynamic_ip` exhaustively over the four
    /// variants x has_address. `Retained` always retains; `Auto` retains only
    /// when there's no configured address; `Dynamic` and `Fixed` never retain.
    #[test]
    fn bmc_ip_allocation_retains_dynamic_ip_covers_all_combinations() {
        struct Case {
            name: &'static str,
            mode: BmcIpAllocationType,
            has_address: bool,
            retains: bool,
        }

        let cases = [
            Case {
                name: "auto with address does not retain",
                mode: BmcIpAllocationType::Auto,
                has_address: true,
                retains: false,
            },
            Case {
                name: "auto without address retains",
                mode: BmcIpAllocationType::Auto,
                has_address: false,
                retains: true,
            },
            Case {
                name: "dynamic without address does not retain",
                mode: BmcIpAllocationType::Dynamic,
                has_address: false,
                retains: false,
            },
            Case {
                name: "dynamic with address does not retain",
                mode: BmcIpAllocationType::Dynamic,
                has_address: true,
                retains: false,
            },
            Case {
                name: "fixed without address does not retain",
                mode: BmcIpAllocationType::Fixed,
                has_address: false,
                retains: false,
            },
            Case {
                name: "fixed with address does not retain",
                mode: BmcIpAllocationType::Fixed,
                has_address: true,
                retains: false,
            },
            Case {
                name: "retained without address retains",
                mode: BmcIpAllocationType::Retained,
                has_address: false,
                retains: true,
            },
            Case {
                name: "retained with address retains",
                mode: BmcIpAllocationType::Retained,
                has_address: true,
                retains: true,
            },
        ];

        for case in cases {
            assert_eq!(
                case.mode.retains_dynamic_ip(case.has_address),
                case.retains,
                "{}",
                case.name
            );
        }
    }

    /// The `BmcIpAllocationType` default is `Auto`, which the Unspecified wire
    /// mapping and the "infer from bmc_ip_address" behavior both rely on.
    #[test]
    fn bmc_ip_allocation_default_is_auto() {
        assert_eq!(BmcIpAllocationType::default(), BmcIpAllocationType::Auto);
    }

    /// `declared_primary_mac` returns the MAC of the one NIC flagged
    /// `primary: Some(true)`, and `None` when nothing is declared. `primary:
    /// Some(false)` is an explicit non-primary, not a declaration.
    #[test]
    fn declared_primary_mac_returns_the_flagged_nic() {
        let mac_a: MacAddress = "AA:BB:CC:00:00:01".parse().unwrap();
        let mac_b: MacAddress = "AA:BB:CC:00:00:02".parse().unwrap();

        let nic = |mac: MacAddress, primary: Option<bool>| ExpectedHostNic {
            mac_address: mac,
            primary,
            ..Default::default()
        };

        // Nothing declared -- empty, or only explicit non-primaries.
        assert_eq!(ExpectedMachineData::default().declared_primary_mac(), None);
        assert_eq!(
            ExpectedMachineData {
                host_nics: vec![nic(mac_a, None), nic(mac_b, Some(false))],
                ..Default::default()
            }
            .declared_primary_mac(),
            None
        );

        // The declared NIC wins.
        assert_eq!(
            ExpectedMachineData {
                host_nics: vec![nic(mac_a, Some(false)), nic(mac_b, Some(true))],
                ..Default::default()
            }
            .declared_primary_mac(),
            Some(mac_b)
        );
    }

    /// `resolved_network_segment_type` prefers the typed `network_segment_type`
    /// and otherwise maps the legacy `nic_type` string (case-insensitively),
    /// returning `None` when neither declaration names a segment type.
    #[test]
    fn resolved_network_segment_type_prefers_typed_field_then_legacy_nic_type() {
        struct Case {
            name: &'static str,
            network_segment_type: Option<NetworkSegmentType>,
            nic_type: Option<&'static str>,
            want: Option<NetworkSegmentType>,
        }

        let cases = [
            Case {
                name: "typed field selects its segment",
                network_segment_type: Some(NetworkSegmentType::Tenant),
                nic_type: None,
                want: Some(NetworkSegmentType::Tenant),
            },
            Case {
                name: "typed field wins over a legacy hint",
                network_segment_type: Some(NetworkSegmentType::Underlay),
                nic_type: Some("onboard"),
                want: Some(NetworkSegmentType::Underlay),
            },
            Case {
                name: "legacy onboard maps to admin",
                network_segment_type: None,
                nic_type: Some("onboard"),
                want: Some(NetworkSegmentType::Admin),
            },
            Case {
                name: "legacy bf3 maps to admin",
                network_segment_type: None,
                nic_type: Some("bf3"),
                want: Some(NetworkSegmentType::Admin),
            },
            Case {
                name: "legacy dpu maps to admin",
                network_segment_type: None,
                nic_type: Some("dpu"),
                want: Some(NetworkSegmentType::Admin),
            },
            Case {
                name: "legacy bmc maps to underlay",
                network_segment_type: None,
                nic_type: Some("bmc"),
                want: Some(NetworkSegmentType::Underlay),
            },
            Case {
                name: "legacy oob maps to underlay",
                network_segment_type: None,
                nic_type: Some("oob"),
                want: Some(NetworkSegmentType::Underlay),
            },
            Case {
                name: "legacy hint is case-insensitive",
                network_segment_type: None,
                nic_type: Some("BF3"),
                want: Some(NetworkSegmentType::Admin),
            },
            Case {
                name: "unknown legacy hint selects nothing",
                network_segment_type: None,
                nic_type: Some("cx8"),
                want: None,
            },
            Case {
                name: "nothing declared selects nothing",
                network_segment_type: None,
                nic_type: None,
                want: None,
            },
        ];

        for case in cases {
            let nic = ExpectedHostNic {
                mac_address: "AA:BB:CC:00:00:01".parse().unwrap(),
                network_segment_type: case.network_segment_type,
                nic_type: case.nic_type.map(String::from),
                ..Default::default()
            };
            assert_eq!(
                nic.resolved_network_segment_type(),
                case.want,
                "{}",
                case.name
            );
        }
    }
}
