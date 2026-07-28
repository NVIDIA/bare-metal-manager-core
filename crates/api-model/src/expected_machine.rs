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

use crate::machine_interface::InterfaceType;
use crate::metadata::Metadata;
use crate::network_segment::NetworkSegmentType;

/// Operator policy for how NICo treats a host's DPU hardware.
///
/// This is distinct from a device's observed operating mode. At the per-host
/// boundary, [`HostDpuPolicy::Manage`] retains the legacy inheritance behavior:
/// it defers to the site-wide policy before falling back to managed DPUs.
///
/// Backed by the Postgres enum `dpu_mode_t`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "dpu_mode_t")]
#[serde(rename_all = "snake_case")]
pub enum HostDpuPolicy {
    /// Manage DPUs normally, including upgrades, networking, and DPA agents.
    #[default]
    #[sqlx(rename = "dpu_mode")]
    #[serde(alias = "dpu_mode")]
    Manage,
    /// Configure physically present DPUs as NICs and manage the host as zero-DPU.
    #[sqlx(rename = "nic_mode")]
    #[serde(alias = "use_as_nic", alias = "nic_mode")]
    Nic,
    /// Do not configure or attach DPU hardware to the managed host.
    #[sqlx(rename = "no_dpu")]
    #[serde(alias = "no_dpu")]
    Ignore,
}

impl HostDpuPolicy {
    /// Resolve per-host and site-wide declarations into a concrete policy.
    ///
    /// Per-host [`HostDpuPolicy::Nic`] and [`HostDpuPolicy::Ignore`]
    /// override the site. Per-host [`HostDpuPolicy::Manage`] or a missing
    /// declaration inherits the site. A missing site declaration resolves to
    /// [`HostDpuPolicy::Manage`].
    pub fn resolve(per_host_policy: Option<Self>, site_policy: Option<Self>) -> Self {
        match per_host_policy {
            Some(Self::Nic) => Self::Nic,
            Some(Self::Ignore) => Self::Ignore,
            Some(Self::Manage) | None => site_policy.unwrap_or_default(),
        }
    }

    /// Whether this policy expects NICo to discover and manage the host's DPUs.
    pub fn expects_managed_dpus(self) -> bool {
        matches!(self, Self::Manage)
    }
}

#[derive(Deserialize)]
struct HostDpuPolicyFields {
    #[serde(default)]
    dpu_policy: Option<HostDpuPolicy>,
    #[serde(default)]
    dpu_mode: Option<HostDpuPolicy>,
}

fn deserialize_host_dpu_policy<'de, D>(deserializer: D) -> Result<HostDpuPolicy, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let fields = HostDpuPolicyFields::deserialize(deserializer)?;

    Ok(fields.dpu_policy.or(fields.dpu_mode).unwrap_or_default())
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

/// Identifies which machine endpoint an expected interface belongs to.
///
/// The role determines the resulting [`InterfaceType`] and whether the
/// interface has a role-defined primary state. It does not choose a network
/// segment or change the allocation policy available to that interface.
///
/// Host BMC identity remains on [`ExpectedMachine::bmc_mac_address`].
/// [NVIDIA/infra-controller#4103](https://github.com/NVIDIA/infra-controller/issues/4103)
/// tracks representing its network settings with the same interface model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedInterfaceRole {
    /// A host operating-system interface. This preserves the behavior of
    /// declarations created before interface roles were introduced.
    #[default]
    Host,
    /// The DPU operating-system interface.
    DpuOs,
    /// The DPU's Redfish/BMC interface.
    DpuBmc,
}

impl std::fmt::Display for ExpectedInterfaceRole {
    /// Write the canonical TOML/JSON spelling used for this role.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Host => "host",
            Self::DpuOs => "dpu_os",
            Self::DpuBmc => "dpu_bmc",
        })
    }
}

impl ExpectedInterfaceRole {
    /// Return whether this role participates in machine-wide Host primary
    /// selection.
    ///
    /// Serde also uses this predicate to omit the default Host role from stored
    /// JSON, keeping legacy Host declarations free of a new role field.
    pub fn is_host(&self) -> bool {
        matches!(self, Self::Host)
    }

    /// Return the database interface type produced by this endpoint role.
    ///
    /// Host and DPU OS endpoints both exchange operating-system data. A DPU
    /// BMC endpoint uses the BMC interface type so the existing BMC-specific
    /// routing and address behavior still applies.
    pub fn interface_type(self) -> InterfaceType {
        match self {
            Self::Host | Self::DpuOs => InterfaceType::Data,
            Self::DpuBmc => InterfaceType::Bmc,
        }
    }

    /// Return the primary-interface value fixed by this endpoint role.
    ///
    /// Host primary selection needs all Host declarations on the
    /// `ExpectedMachine`, so `None` tells the caller to use that machine-wide
    /// result. A DPU OS interface is always its DPU's primary data interface,
    /// while a DPU BMC interface is never primary.
    pub fn primary_interface_override(self) -> Option<bool> {
        match self {
            Self::Host => None,
            Self::DpuOs => Some(true),
            Self::DpuBmc => Some(false),
        }
    }
}

/// Controls how an expected interface receives and retains its IP address.
///
/// When the policy is omitted, [`ExpectedHostNic::resolved_ip_allocation`]
/// preserves the legacy configuration contract: an interface with
/// [`ExpectedHostNic::fixed_ip`] is fixed, and one without it is dynamic.
/// Explicit `Dynamic` differs from omission because it rejects a simultaneous
/// `fixed_ip` instead of inferring `Fixed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedInterfaceIpAllocation {
    /// Allocate a normal DHCP lease that may expire and change. A configured
    /// segment-type guard must match the segment selected by the DHCP relay.
    Dynamic,
    /// Reserve the operator-specified [`ExpectedHostNic::fixed_ip`]. Prefix
    /// containment finds the segment, and a configured segment-type guard must
    /// match it.
    Fixed,
    /// Allocate through DHCP, then change that address row to Static for the
    /// lifetime of this interface row. The address is not saved in
    /// `ExpectedMachine` for reuse after the interface is deleted and
    /// re-ingested, and changing the policy later does not convert that row
    /// back to DHCP. A configured segment-type guard must match the segment
    /// selected by the DHCP relay.
    Retained,
}

impl ExpectedInterfaceIpAllocation {
    /// Validate whether this explicit or resolved policy may be paired with
    /// the interface's `fixed_ip` declaration.
    ///
    /// Only `Fixed` accepts a configured address. `Dynamic` and `Retained`
    /// require DHCP to select one.
    pub fn validate(self, has_fixed_ip: bool) -> Result<(), &'static str> {
        match self {
            Self::Fixed if !has_fixed_ip => Err("ip_allocation=fixed requires fixed_ip"),
            Self::Dynamic if has_fixed_ip => {
                Err("ip_allocation=dynamic cannot be combined with fixed_ip")
            }
            Self::Retained if has_fixed_ip => {
                Err("ip_allocation=retained cannot be combined with fixed_ip; use fixed")
            }
            _ => Ok(()),
        }
    }
}

/// Configures one interface that NICo may encounter while ingesting an
/// `ExpectedMachine`.
///
/// Every role uses the same allocation and optional segment-guard fields. The
/// role only supplies endpoint-specific interface type and primary behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExpectedHostNic {
    /// MAC address used to match DHCP and discovered interface traffic to this
    /// declaration.
    pub mac_address: MacAddress,
    /// Which machine endpoint owns this interface. Missing values retain the
    /// legacy host-interface behavior.
    #[serde(default, skip_serializing_if = "ExpectedInterfaceRole::is_host")]
    pub role: ExpectedInterfaceRole,
    /// Optional IP allocation policy. Missing declarations infer `Fixed` when
    /// [`Self::fixed_ip`] is configured and `Dynamic` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_allocation: Option<ExpectedInterfaceIpAllocation>,
    /// Optional guard for the interface's network segment type.
    ///
    /// For an explicit allocation policy or DPU role, Dynamic and Retained use
    /// this as a guard on the segment selected by the DHCP relay, while Fixed
    /// uses it as a guard on the segment containing the configured address.
    ///
    /// A legacy Host declaration that omits `ip_allocation` keeps the earlier
    /// behavior where this field only narrows initial DHCP segment selection.
    /// This compatibility rule is exposed by [`Self::segment_type_guard`].
    /// `None` (with no legacy [`Self::nic_type`]) leaves DHCP selection
    /// unconstrained; a fixed IP still derives its segment from the address.
    /// Updates retain the existing full-replacement behavior, so omission
    /// clears this field.
    #[serde(default)]
    pub network_segment_type: Option<NetworkSegmentType>,
    /// Legacy free-form NIC-type segment hint (`bf3`, `onboard`, `oob`, ...).
    /// Kept for backward compatibility; prefer `network_segment_type`.
    pub nic_type: Option<String>,
    pub fixed_ip: Option<IpAddr>,
    pub fixed_mask: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_ip_addr_lossy")]
    pub fixed_gateway: Option<IpAddr>,
    /// Host-role interfaces may set `primary=true` to declare the host's boot
    /// interface. When one Host interface is declared primary, the other Host
    /// interfaces become non-primary. An explicit `false` remains accepted for
    /// compatibility but does not replace that machine-wide selection. DPU OS
    /// interfaces are primary data interfaces and DPU BMC interfaces are
    /// non-primary; those roles must omit this field.
    #[serde(default)]
    pub primary: Option<bool>,
}

impl ExpectedHostNic {
    /// Return the configured allocation policy or infer the legacy policy from
    /// whether this interface has a fixed IP.
    ///
    /// Omission must remain distinguishable from explicit `Dynamic`: old
    /// declarations supplied only `fixed_ip`, while explicit `Dynamic` rejects
    /// that same combination during validation. Inferring `Fixed` here does not
    /// opt a legacy Host declaration into the newer segment-type guard; see
    /// [`Self::segment_type_guard`].
    pub fn resolved_ip_allocation(&self) -> ExpectedInterfaceIpAllocation {
        self.ip_allocation.unwrap_or_else(|| {
            if self.fixed_ip.is_some() {
                ExpectedInterfaceIpAllocation::Fixed
            } else {
                ExpectedInterfaceIpAllocation::Dynamic
            }
        })
    }

    /// Validate the effective allocation policy against this interface's
    /// fixed-IP declaration.
    pub fn validate_ip_allocation(&self) -> Result<(), &'static str> {
        self.resolved_ip_allocation()
            .validate(self.fixed_ip.is_some())
    }

    /// Validate the declaration and require one resolved allocation policy.
    ///
    /// Callers that materialize Fixed or Retained state use this shared check
    /// so policy validation cannot drift between API, DHCP, and Site Explorer
    /// paths.
    pub fn require_ip_allocation(
        &self,
        required: ExpectedInterfaceIpAllocation,
    ) -> Result<(), &'static str> {
        self.validate_ip_allocation()?;
        if self.resolved_ip_allocation() == required {
            return Ok(());
        }

        Err(match required {
            ExpectedInterfaceIpAllocation::Dynamic => {
                "expected interface does not use dynamic IP allocation"
            }
            ExpectedInterfaceIpAllocation::Fixed => {
                "expected interface does not use fixed IP allocation"
            }
            ExpectedInterfaceIpAllocation::Retained => {
                "expected interface does not use retained IP allocation"
            }
        })
    }

    /// Return the configured address after validating that this interface uses
    /// Fixed allocation.
    pub fn fixed_reservation_ip(&self) -> Result<IpAddr, &'static str> {
        self.require_ip_allocation(ExpectedInterfaceIpAllocation::Fixed)?;
        self.fixed_ip.ok_or("ip_allocation=fixed requires fixed_ip")
    }

    /// Return the typed segment guard for declarations using the generalized
    /// ExpectedInterface policy contract.
    ///
    /// Before roles and allocation policies existed, a Host declaration could
    /// use `network_segment_type` only to narrow initial DHCP selection. Keep
    /// that behavior when both new fields are omitted. An explicit policy or a
    /// DPU role opts into the same guard semantics for every allocation path.
    pub fn segment_type_guard(&self) -> Option<NetworkSegmentType> {
        self.network_segment_type
            .filter(|_| self.ip_allocation.is_some() || !self.role.is_host())
    }

    /// Return the network segment type that narrows Dynamic or Retained DHCP
    /// segment selection, if the declaration names one. Prefers the typed
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
    /// Per-host DPU policy. The default [`HostDpuPolicy::Manage`] inherits the
    /// site policy. The legacy `dpu_mode` field and its values remain accepted
    /// during deserialization.
    ///
    /// This type is deserialization-only. The nested flattening is intentional
    /// for dual-key compatibility and is incompatible with `deny_unknown_fields`.
    #[serde(flatten, deserialize_with = "deserialize_host_dpu_policy")]
    pub dpu_policy: HostDpuPolicy,
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
            .find(|nic| nic.role.is_host() && nic.primary == Some(true))
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
                dpu_policy: row.try_get("dpu_mode")?,
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
    use carbide_test_support::{Check, check_values, scenarios, value_scenarios};

    use super::*;

    #[test]
    fn host_dpu_policy_resolves_legacy_declarations() {
        struct Declarations {
            per_host: Option<HostDpuPolicy>,
            site: Option<HostDpuPolicy>,
        }

        check_values(
            [
                Check {
                    scenario: "unset host, unset site",
                    input: Declarations {
                        per_host: None,
                        site: None,
                    },
                    expect: HostDpuPolicy::Manage,
                },
                Check {
                    scenario: "unset host, managed site",
                    input: Declarations {
                        per_host: None,
                        site: Some(HostDpuPolicy::Manage),
                    },
                    expect: HostDpuPolicy::Manage,
                },
                Check {
                    scenario: "unset host, NIC-mode site",
                    input: Declarations {
                        per_host: None,
                        site: Some(HostDpuPolicy::Nic),
                    },
                    expect: HostDpuPolicy::Nic,
                },
                Check {
                    scenario: "unset host, no-DPU site",
                    input: Declarations {
                        per_host: None,
                        site: Some(HostDpuPolicy::Ignore),
                    },
                    expect: HostDpuPolicy::Ignore,
                },
                Check {
                    scenario: "inheriting host, unset site",
                    input: Declarations {
                        per_host: Some(HostDpuPolicy::Manage),
                        site: None,
                    },
                    expect: HostDpuPolicy::Manage,
                },
                Check {
                    scenario: "inheriting host, managed site",
                    input: Declarations {
                        per_host: Some(HostDpuPolicy::Manage),
                        site: Some(HostDpuPolicy::Manage),
                    },
                    expect: HostDpuPolicy::Manage,
                },
                Check {
                    scenario: "inheriting host, NIC-mode site",
                    input: Declarations {
                        per_host: Some(HostDpuPolicy::Manage),
                        site: Some(HostDpuPolicy::Nic),
                    },
                    expect: HostDpuPolicy::Nic,
                },
                Check {
                    scenario: "inheriting host, no-DPU site",
                    input: Declarations {
                        per_host: Some(HostDpuPolicy::Manage),
                        site: Some(HostDpuPolicy::Ignore),
                    },
                    expect: HostDpuPolicy::Ignore,
                },
                Check {
                    scenario: "NIC-mode host, unset site",
                    input: Declarations {
                        per_host: Some(HostDpuPolicy::Nic),
                        site: None,
                    },
                    expect: HostDpuPolicy::Nic,
                },
                Check {
                    scenario: "NIC-mode host, managed site",
                    input: Declarations {
                        per_host: Some(HostDpuPolicy::Nic),
                        site: Some(HostDpuPolicy::Manage),
                    },
                    expect: HostDpuPolicy::Nic,
                },
                Check {
                    scenario: "NIC-mode host, NIC-mode site",
                    input: Declarations {
                        per_host: Some(HostDpuPolicy::Nic),
                        site: Some(HostDpuPolicy::Nic),
                    },
                    expect: HostDpuPolicy::Nic,
                },
                Check {
                    scenario: "NIC-mode host, no-DPU site",
                    input: Declarations {
                        per_host: Some(HostDpuPolicy::Nic),
                        site: Some(HostDpuPolicy::Ignore),
                    },
                    expect: HostDpuPolicy::Nic,
                },
                Check {
                    scenario: "no-DPU host, unset site",
                    input: Declarations {
                        per_host: Some(HostDpuPolicy::Ignore),
                        site: None,
                    },
                    expect: HostDpuPolicy::Ignore,
                },
                Check {
                    scenario: "no-DPU host, managed site",
                    input: Declarations {
                        per_host: Some(HostDpuPolicy::Ignore),
                        site: Some(HostDpuPolicy::Manage),
                    },
                    expect: HostDpuPolicy::Ignore,
                },
                Check {
                    scenario: "no-DPU host, NIC-mode site",
                    input: Declarations {
                        per_host: Some(HostDpuPolicy::Ignore),
                        site: Some(HostDpuPolicy::Nic),
                    },
                    expect: HostDpuPolicy::Ignore,
                },
                Check {
                    scenario: "no-DPU host, no-DPU site",
                    input: Declarations {
                        per_host: Some(HostDpuPolicy::Ignore),
                        site: Some(HostDpuPolicy::Ignore),
                    },
                    expect: HostDpuPolicy::Ignore,
                },
            ],
            |Declarations { per_host, site }| HostDpuPolicy::resolve(per_host, site),
        );
    }

    #[test]
    fn host_dpu_policy_expects_managed_dpus() {
        value_scenarios!(
            run = HostDpuPolicy::expects_managed_dpus;
            "manage" {
                HostDpuPolicy::Manage => true,
            }
            "use as NIC" {
                HostDpuPolicy::Nic => false,
            }
            "ignore" {
                HostDpuPolicy::Ignore => false,
            }
        );
    }

    #[test]
    fn host_dpu_policy_deserializes_new_and_legacy_values() {
        scenarios!(
            run = |json| serde_json::from_str::<HostDpuPolicy>(json).map_err(drop);
            "canonical policy values" {
                r#""manage""# => Yields(HostDpuPolicy::Manage),
                r#""nic""# => Yields(HostDpuPolicy::Nic),
                r#""ignore""# => Yields(HostDpuPolicy::Ignore),
            }

            "compatibility values" {
                r#""use_as_nic""# => Yields(HostDpuPolicy::Nic),
                r#""dpu_mode""# => Yields(HostDpuPolicy::Manage),
                r#""nic_mode""# => Yields(HostDpuPolicy::Nic),
                r#""no_dpu""# => Yields(HostDpuPolicy::Ignore),
            }
        );
    }

    #[test]
    fn host_dpu_policy_serializes_and_round_trips_canonical_values() {
        scenarios!(
            run = |policy| {
                let json = serde_json::to_string(&policy).map_err(drop)?;
                let recovered = serde_json::from_str::<HostDpuPolicy>(&json).map_err(drop)?;
                Ok::<_, ()>((json, recovered))
            };
            "default/manage" {
                HostDpuPolicy::default() => Yields((
                    r#""manage""#.to_string(),
                    HostDpuPolicy::Manage,
                )),
            }

            "NIC" {
                HostDpuPolicy::Nic => Yields((
                    r#""nic""#.to_string(),
                    HostDpuPolicy::Nic,
                )),
            }

            "ignore" {
                HostDpuPolicy::Ignore => Yields((
                    r#""ignore""#.to_string(),
                    HostDpuPolicy::Ignore,
                )),
            }
        );
    }

    #[test]
    fn expected_machine_deserializes_new_and_legacy_policy_fields() {
        scenarios!(
            run = |json| {
                serde_json::from_str::<ExpectedMachine>(json)
                    .map(|em| em.data.dpu_policy)
                    .map_err(drop)
            };
            "policy omitted" {
                r#"{
                    "bmc_mac_address": "AA:BB:CC:DD:EE:FF",
                    "bmc_username": "root",
                    "bmc_password": "pass",
                    "serial_number": "SN-1"
                }"# => Yields(HostDpuPolicy::Manage),
            }

            "canonical field and value" {
                r#"{
                    "bmc_mac_address": "AA:BB:CC:DD:EE:FF",
                    "bmc_username": "root",
                    "bmc_password": "pass",
                    "serial_number": "SN-1",
                    "dpu_policy": "nic"
                }"# => Yields(HostDpuPolicy::Nic),
            }

            "previous canonical field value remains accepted" {
                r#"{
                    "bmc_mac_address": "AA:BB:CC:DD:EE:FF",
                    "bmc_username": "root",
                    "bmc_password": "pass",
                    "serial_number": "SN-1",
                    "dpu_policy": "use_as_nic"
                }"# => Yields(HostDpuPolicy::Nic),
            }

            "legacy field and value" {
                r#"{
                    "bmc_mac_address": "AA:BB:CC:DD:EE:FF",
                    "bmc_username": "root",
                    "bmc_password": "pass",
                    "serial_number": "SN-1",
                    "dpu_mode": "no_dpu"
                }"# => Yields(HostDpuPolicy::Ignore),
            }

            "matching new and legacy fields" {
                r#"{
                    "bmc_mac_address": "AA:BB:CC:DD:EE:FF",
                    "bmc_username": "root",
                    "bmc_password": "pass",
                    "serial_number": "SN-1",
                    "dpu_policy": "nic",
                    "dpu_mode": "nic_mode"
                }"# => Yields(HostDpuPolicy::Nic),
            }

            "new field wins over conflicting legacy field" {
                r#"{
                    "bmc_mac_address": "AA:BB:CC:DD:EE:FF",
                    "bmc_username": "root",
                    "bmc_password": "pass",
                    "serial_number": "SN-1",
                    "dpu_policy": "ignore",
                    "dpu_mode": "dpu_mode"
                }"# => Yields(HostDpuPolicy::Ignore),
            }

            "explicit manage wins when legacy field comes first" {
                r#"{
                    "bmc_mac_address": "AA:BB:CC:DD:EE:FF",
                    "bmc_username": "root",
                    "bmc_password": "pass",
                    "serial_number": "SN-1",
                    "dpu_mode": "nic_mode",
                    "dpu_policy": "manage"
                }"# => Yields(HostDpuPolicy::Manage),
            }
        );
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
    fn expected_interface_role_preserves_legacy_json_format() {
        let legacy = r#"{
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "nic_type": "dpu"
        }"#;
        let interface: ExpectedHostNic = serde_json::from_str(legacy).unwrap();

        assert_eq!(interface.role, ExpectedInterfaceRole::Host);
        assert_eq!(interface.ip_allocation, None);
        let serialized = serde_json::to_value(interface).unwrap();
        assert_eq!(serialized.get("role"), None);
        assert_eq!(serialized.get("ip_allocation"), None);
    }

    #[test]
    fn expected_interface_roles_use_canonical_names() {
        check_values(
            [
                Check {
                    scenario: "Host remains omitted from stored JSON",
                    input: ExpectedInterfaceRole::Host,
                    expect: ("host".to_string(), None),
                },
                Check {
                    scenario: "DPU OS uses its canonical name",
                    input: ExpectedInterfaceRole::DpuOs,
                    expect: ("dpu_os".to_string(), Some(serde_json::json!("dpu_os"))),
                },
                Check {
                    scenario: "DPU BMC uses its canonical name",
                    input: ExpectedInterfaceRole::DpuBmc,
                    expect: ("dpu_bmc".to_string(), Some(serde_json::json!("dpu_bmc"))),
                },
            ],
            |role| {
                let serialized = serde_json::to_value(ExpectedHostNic {
                    role,
                    ..Default::default()
                })
                .unwrap();
                (role.to_string(), serialized.get("role").cloned())
            },
        );
    }

    #[test]
    fn expected_interface_roles_map_to_interface_behavior() {
        check_values(
            [
                Check {
                    scenario: "legacy host",
                    input: ExpectedInterfaceRole::Host,
                    expect: (true, InterfaceType::Data),
                },
                Check {
                    scenario: "DPU OS",
                    input: ExpectedInterfaceRole::DpuOs,
                    expect: (false, InterfaceType::Data),
                },
                Check {
                    scenario: "DPU BMC",
                    input: ExpectedInterfaceRole::DpuBmc,
                    expect: (false, InterfaceType::Bmc),
                },
            ],
            |role| (role.is_host(), role.interface_type()),
        );
    }

    #[test]
    fn expected_interface_roles_resolve_role_primary_state() {
        check_values(
            [
                Check {
                    scenario: "legacy Host keeps machine-wide selection",
                    input: ExpectedInterfaceRole::Host,
                    expect: None,
                },
                Check {
                    scenario: "DPU OS is always primary",
                    input: ExpectedInterfaceRole::DpuOs,
                    expect: Some(true),
                },
                Check {
                    scenario: "DPU BMC is never primary",
                    input: ExpectedInterfaceRole::DpuBmc,
                    expect: Some(false),
                },
            ],
            ExpectedInterfaceRole::primary_interface_override,
        );
    }

    #[test]
    fn expected_interface_ip_allocation_infers_and_validates_policy() {
        struct Declaration {
            policy: Option<ExpectedInterfaceIpAllocation>,
            fixed_ip: Option<IpAddr>,
        }

        let fixed_ip = Some("192.0.2.10".parse().unwrap());
        check_values(
            [
                Check {
                    scenario: "omitted policy without fixed IP infers dynamic",
                    input: Declaration {
                        policy: None,
                        fixed_ip: None,
                    },
                    expect: (ExpectedInterfaceIpAllocation::Dynamic, None),
                },
                Check {
                    scenario: "omitted policy with fixed IP infers fixed",
                    input: Declaration {
                        policy: None,
                        fixed_ip,
                    },
                    expect: (ExpectedInterfaceIpAllocation::Fixed, None),
                },
                Check {
                    scenario: "explicit dynamic without fixed IP is valid",
                    input: Declaration {
                        policy: Some(ExpectedInterfaceIpAllocation::Dynamic),
                        fixed_ip: None,
                    },
                    expect: (ExpectedInterfaceIpAllocation::Dynamic, None),
                },
                Check {
                    scenario: "explicit dynamic with fixed IP is rejected",
                    input: Declaration {
                        policy: Some(ExpectedInterfaceIpAllocation::Dynamic),
                        fixed_ip,
                    },
                    expect: (
                        ExpectedInterfaceIpAllocation::Dynamic,
                        Some("ip_allocation=dynamic cannot be combined with fixed_ip"),
                    ),
                },
                Check {
                    scenario: "explicit fixed with fixed IP is valid",
                    input: Declaration {
                        policy: Some(ExpectedInterfaceIpAllocation::Fixed),
                        fixed_ip,
                    },
                    expect: (ExpectedInterfaceIpAllocation::Fixed, None),
                },
                Check {
                    scenario: "explicit fixed without fixed IP is rejected",
                    input: Declaration {
                        policy: Some(ExpectedInterfaceIpAllocation::Fixed),
                        fixed_ip: None,
                    },
                    expect: (
                        ExpectedInterfaceIpAllocation::Fixed,
                        Some("ip_allocation=fixed requires fixed_ip"),
                    ),
                },
                Check {
                    scenario: "explicit retained without fixed IP is valid",
                    input: Declaration {
                        policy: Some(ExpectedInterfaceIpAllocation::Retained),
                        fixed_ip: None,
                    },
                    expect: (ExpectedInterfaceIpAllocation::Retained, None),
                },
                Check {
                    scenario: "explicit retained with fixed IP is rejected",
                    input: Declaration {
                        policy: Some(ExpectedInterfaceIpAllocation::Retained),
                        fixed_ip,
                    },
                    expect: (
                        ExpectedInterfaceIpAllocation::Retained,
                        Some("ip_allocation=retained cannot be combined with fixed_ip; use fixed"),
                    ),
                },
            ],
            |declaration| {
                let interface = ExpectedHostNic {
                    mac_address: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
                    ip_allocation: declaration.policy,
                    fixed_ip: declaration.fixed_ip,
                    ..Default::default()
                };
                (
                    interface.resolved_ip_allocation(),
                    interface.validate_ip_allocation().err(),
                )
            },
        );
    }

    /// Fixed reservation callers share one policy-and-address invariant.
    #[test]
    fn expected_interface_fixed_reservation_ip_validates_policy() {
        let fixed_ip = "192.0.2.10".parse().unwrap();
        check_values(
            [
                Check {
                    scenario: "legacy fixed address",
                    input: (None, Some(fixed_ip)),
                    expect: Ok(fixed_ip),
                },
                Check {
                    scenario: "explicit fixed address",
                    input: (Some(ExpectedInterfaceIpAllocation::Fixed), Some(fixed_ip)),
                    expect: Ok(fixed_ip),
                },
                Check {
                    scenario: "dynamic policy",
                    input: (Some(ExpectedInterfaceIpAllocation::Dynamic), None),
                    expect: Err("expected interface does not use fixed IP allocation"),
                },
                Check {
                    scenario: "fixed policy without an address",
                    input: (Some(ExpectedInterfaceIpAllocation::Fixed), None),
                    expect: Err("ip_allocation=fixed requires fixed_ip"),
                },
                Check {
                    scenario: "retained policy",
                    input: (Some(ExpectedInterfaceIpAllocation::Retained), None),
                    expect: Err("expected interface does not use fixed IP allocation"),
                },
            ],
            |(ip_allocation, fixed_ip)| {
                ExpectedHostNic {
                    ip_allocation,
                    fixed_ip,
                    ..Default::default()
                }
                .fixed_reservation_ip()
            },
        );
    }

    #[test]
    fn expected_interface_ip_allocation_json_uses_canonical_names() {
        check_values(
            [
                Check {
                    scenario: "dynamic",
                    input: ExpectedInterfaceIpAllocation::Dynamic,
                    expect: r#""dynamic""#.to_string(),
                },
                Check {
                    scenario: "fixed",
                    input: ExpectedInterfaceIpAllocation::Fixed,
                    expect: r#""fixed""#.to_string(),
                },
                Check {
                    scenario: "retained",
                    input: ExpectedInterfaceIpAllocation::Retained,
                    expect: r#""retained""#.to_string(),
                },
            ],
            |policy| serde_json::to_string(&policy).unwrap(),
        );
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

        let nic = |mac: MacAddress,
                   role: ExpectedInterfaceRole,
                   primary: Option<bool>|
         -> ExpectedHostNic {
            ExpectedHostNic {
                mac_address: mac,
                role,
                primary,
                ..Default::default()
            }
        };

        // Nothing declared -- empty, or only explicit non-primaries.
        assert_eq!(ExpectedMachineData::default().declared_primary_mac(), None);
        assert_eq!(
            ExpectedMachineData {
                host_nics: vec![
                    nic(mac_a, ExpectedInterfaceRole::Host, None),
                    nic(mac_b, ExpectedInterfaceRole::Host, Some(false)),
                ],
                ..Default::default()
            }
            .declared_primary_mac(),
            None
        );

        // The declared NIC wins.
        assert_eq!(
            ExpectedMachineData {
                host_nics: vec![
                    nic(mac_a, ExpectedInterfaceRole::Host, Some(false)),
                    nic(mac_b, ExpectedInterfaceRole::Host, Some(true)),
                ],
                ..Default::default()
            }
            .declared_primary_mac(),
            Some(mac_b)
        );

        assert_eq!(
            ExpectedMachineData {
                host_nics: vec![nic(mac_a, ExpectedInterfaceRole::DpuBmc, Some(true))],
                ..Default::default()
            }
            .declared_primary_mac(),
            None
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

    /// Explicit policies and DPU roles opt into universal segment guards,
    /// while a legacy Host declaration keeps first-DHCP selection behavior.
    #[test]
    fn segment_type_guard_preserves_legacy_host_compatibility() {
        struct Case {
            name: &'static str,
            role: ExpectedInterfaceRole,
            ip_allocation: Option<ExpectedInterfaceIpAllocation>,
            fixed_ip: Option<IpAddr>,
            network_segment_type: Option<NetworkSegmentType>,
            expected_guard: Option<NetworkSegmentType>,
        }

        for case in [
            Case {
                name: "legacy Host declaration",
                role: ExpectedInterfaceRole::Host,
                ip_allocation: None,
                fixed_ip: None,
                network_segment_type: Some(NetworkSegmentType::Admin),
                expected_guard: None,
            },
            Case {
                name: "legacy Host fixed IP inference",
                role: ExpectedInterfaceRole::Host,
                ip_allocation: None,
                fixed_ip: Some("192.0.2.10".parse().unwrap()),
                network_segment_type: Some(NetworkSegmentType::Admin),
                expected_guard: None,
            },
            Case {
                name: "explicit Host Dynamic policy",
                role: ExpectedInterfaceRole::Host,
                ip_allocation: Some(ExpectedInterfaceIpAllocation::Dynamic),
                fixed_ip: None,
                network_segment_type: Some(NetworkSegmentType::Admin),
                expected_guard: Some(NetworkSegmentType::Admin),
            },
            Case {
                name: "explicit Host Fixed policy",
                role: ExpectedInterfaceRole::Host,
                ip_allocation: Some(ExpectedInterfaceIpAllocation::Fixed),
                fixed_ip: Some("192.0.2.10".parse().unwrap()),
                network_segment_type: Some(NetworkSegmentType::Admin),
                expected_guard: Some(NetworkSegmentType::Admin),
            },
            Case {
                name: "explicit Host Retained policy",
                role: ExpectedInterfaceRole::Host,
                ip_allocation: Some(ExpectedInterfaceIpAllocation::Retained),
                fixed_ip: None,
                network_segment_type: Some(NetworkSegmentType::Admin),
                expected_guard: Some(NetworkSegmentType::Admin),
            },
            Case {
                name: "DPU OS role",
                role: ExpectedInterfaceRole::DpuOs,
                ip_allocation: None,
                fixed_ip: None,
                network_segment_type: Some(NetworkSegmentType::Admin),
                expected_guard: Some(NetworkSegmentType::Admin),
            },
            Case {
                name: "DPU BMC role",
                role: ExpectedInterfaceRole::DpuBmc,
                ip_allocation: None,
                fixed_ip: None,
                network_segment_type: Some(NetworkSegmentType::Underlay),
                expected_guard: Some(NetworkSegmentType::Underlay),
            },
            Case {
                name: "no typed segment",
                role: ExpectedInterfaceRole::DpuOs,
                ip_allocation: Some(ExpectedInterfaceIpAllocation::Dynamic),
                fixed_ip: None,
                network_segment_type: None,
                expected_guard: None,
            },
        ] {
            let interface = ExpectedHostNic {
                role: case.role,
                ip_allocation: case.ip_allocation,
                fixed_ip: case.fixed_ip,
                network_segment_type: case.network_segment_type,
                ..Default::default()
            };
            assert_eq!(
                interface.segment_type_guard(),
                case.expected_guard,
                "{}",
                case.name,
            );
        }
    }
}
