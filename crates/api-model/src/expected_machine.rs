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
use rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use uuid::Uuid;

use crate::metadata::Metadata;

/// Per-host DPU operating mode declared by a site operator on an
/// `ExpectedMachine`. This replaces the site-wide `force_dpu_nic_mode`
/// config flag; the flag is still honored as a fallback when
/// `DpuMode::default()` is in effect (i.e. the operator didn't set a
/// per-host value). `force_dpu_nic_mode` will eventually go away.
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

    /// Resolve a host's effective DPU mode from its (optional) per-host
    /// `ExpectedMachine.dpu_mode` value and the site-wide
    /// `force_dpu_nic_mode` "fallback" flag, which is deprecated more
    /// than a fallback, but for now I'm treating it as a fallback.
    ///
    /// Notes!
    /// - An explicit per-host `NicMode` or `NoDpu` always wins.
    /// - `DpuMode` (the default) or no `ExpectedMachine` at all means
    ///   back back to the site flag, where `force_dpu_nic_mode=true` means
    ///   `NicMode`, otherwise `DpuMode`.
    ///
    /// This keeps backwards compatibility with deployments that still rely
    /// on the `force_dpu_nic_mode` site-level flag; once all hosts have explicit
    /// modes configured (or we're happy with the `None` default), the flag can
    /// be retired.
    pub fn resolve(expected_mode: Option<DpuMode>, site_force_nic_mode: bool) -> DpuMode {
        match expected_mode {
            Some(DpuMode::NicMode) => DpuMode::NicMode,
            Some(DpuMode::NoDpu) => DpuMode::NoDpu,
            // `DpuMode` (default) or missing == let the site flag decide.
            _ if site_force_nic_mode => DpuMode::NicMode,
            _ => DpuMode::DpuMode,
        }
    }
}

impl From<DpuMode> for rpc::forge::DpuMode {
    fn from(mode: DpuMode) -> Self {
        match mode {
            DpuMode::DpuMode => rpc::forge::DpuMode::DpuMode,
            DpuMode::NicMode => rpc::forge::DpuMode::NicMode,
            DpuMode::NoDpu => rpc::forge::DpuMode::NoDpu,
        }
    }
}

impl From<rpc::forge::DpuMode> for DpuMode {
    fn from(mode: rpc::forge::DpuMode) -> Self {
        match mode {
            rpc::forge::DpuMode::DpuMode => DpuMode::DpuMode,
            rpc::forge::DpuMode::NicMode => DpuMode::NicMode,
            rpc::forge::DpuMode::NoDpu => DpuMode::NoDpu,
            // Unspecified (0) or any unknown value means "use the default",
            // which preserves behavior for old clients that don't send the
            // field at all.
            rpc::forge::DpuMode::Unspecified => DpuMode::default(),
        }
    }
}

/// A request to identify an ExpectedMachine by either ID or MAC address.
#[derive(Debug, Clone)]
pub struct ExpectedMachineRequest {
    pub id: Option<Uuid>,
    pub bmc_mac_address: Option<MacAddress>,
}

impl TryFrom<rpc::forge::ExpectedMachineRequest> for ExpectedMachineRequest {
    type Error = RpcDataConversionError;

    fn try_from(rpc: rpc::forge::ExpectedMachineRequest) -> Result<Self, Self::Error> {
        let id = rpc
            .id
            .map(|u| {
                Uuid::parse_str(&u.value)
                    .map_err(|_| RpcDataConversionError::InvalidArgument(u.value))
            })
            .transpose()?;
        let bmc_mac_address = if rpc.bmc_mac_address.is_empty() {
            None
        } else {
            Some(
                MacAddress::try_from(rpc.bmc_mac_address.as_str())
                    .map_err(|_| RpcDataConversionError::InvalidMacAddress(rpc.bmc_mac_address))?,
            )
        };

        Ok(ExpectedMachineRequest {
            id,
            bmc_mac_address,
        })
    }
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
}
// Important : new fields for expected machine (and data) should be optional _and_ serde(default),
// unless you want to go update all the files in each production deployment that autoload
// the expected machines on api startup

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
            },
        })
    }
}

impl From<ExpectedHostNic> for rpc::forge::ExpectedHostNic {
    fn from(expected_host_nic: ExpectedHostNic) -> Self {
        rpc::forge::ExpectedHostNic {
            mac_address: expected_host_nic.mac_address.to_string(),
            nic_type: expected_host_nic.nic_type,
            fixed_ip: expected_host_nic.fixed_ip,
            fixed_mask: expected_host_nic.fixed_mask,
            fixed_gateway: expected_host_nic.fixed_gateway,
            primary: expected_host_nic.primary,
        }
    }
}

impl From<rpc::forge::ExpectedHostNic> for ExpectedHostNic {
    fn from(expected_host_nic: rpc::forge::ExpectedHostNic) -> Self {
        ExpectedHostNic {
            mac_address: expected_host_nic.mac_address.parse().unwrap_or_default(),
            nic_type: expected_host_nic.nic_type,
            fixed_ip: expected_host_nic.fixed_ip,
            fixed_mask: expected_host_nic.fixed_mask,
            fixed_gateway: expected_host_nic.fixed_gateway,
            primary: expected_host_nic.primary,
        }
    }
}

impl From<ExpectedMachine> for rpc::forge::ExpectedMachine {
    fn from(expected_machine: ExpectedMachine) -> Self {
        let host_nics = expected_machine
            .data
            .host_nics
            .iter()
            .map(|x| x.clone().into())
            .collect();
        rpc::forge::ExpectedMachine {
            id: expected_machine.id.map(|u| ::rpc::common::Uuid {
                value: u.to_string(),
            }),
            bmc_mac_address: expected_machine.bmc_mac_address.to_string(),
            bmc_username: expected_machine.data.bmc_username,
            bmc_password: expected_machine.data.bmc_password,
            chassis_serial_number: expected_machine.data.serial_number,
            fallback_dpu_serial_numbers: expected_machine.data.fallback_dpu_serial_numbers,
            metadata: Some(expected_machine.data.metadata.into()),
            sku_id: expected_machine.data.sku_id,
            rack_id: expected_machine.data.rack_id,
            host_nics,
            default_pause_ingestion_and_poweron: expected_machine
                .data
                .default_pause_ingestion_and_poweron,
            // This should be removed after few releases.
            #[allow(deprecated)]
            dpf_enabled: expected_machine.data.dpf_enabled.unwrap_or_default(),
            is_dpf_enabled: expected_machine.data.dpf_enabled,
            // Optional configured BMC IP (proto optional string).
            bmc_ip_address: expected_machine
                .data
                .bmc_ip_address
                .map(|ip| ip.to_string()),
            bmc_retain_credentials: expected_machine.data.bmc_retain_credentials.filter(|&v| v),
            // Only emit `dpu_mode` when it's non-default (which matches the
            // bmc_retain_credentials filter pattern above).
            dpu_mode: match expected_machine.data.dpu_mode {
                DpuMode::DpuMode => None,
                other => Some(rpc::forge::DpuMode::from(other) as i32),
            },
        }
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

impl From<LinkedExpectedMachine> for rpc::forge::LinkedExpectedMachine {
    fn from(m: LinkedExpectedMachine) -> rpc::forge::LinkedExpectedMachine {
        rpc::forge::LinkedExpectedMachine {
            chassis_serial_number: m.serial_number,
            bmc_mac_address: m.bmc_mac_address.to_string(),
            interface_id: m.interface_id.map(|u| u.to_string()),
            explored_endpoint_address: m.address,
            machine_id: m.machine_id,
            expected_machine_id: m.expected_machine_id.map(|id| ::rpc::common::Uuid {
                value: id.to_string(),
            }),
        }
    }
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

impl From<UnexpectedMachine> for rpc::forge::UnexpectedMachine {
    fn from(m: UnexpectedMachine) -> rpc::forge::UnexpectedMachine {
        rpc::forge::UnexpectedMachine {
            address: m.address.to_string(),
            bmc_mac_address: m.bmc_mac_address.to_string(),
            machine_id: m.machine_id,
        }
    }
}

/// Parses gRPC `ExpectedMachine` into persisted model data, including optional `bmc_ip_address`
/// (empty or unset proto field becomes `None`; invalid strings fail conversion).
impl TryFrom<rpc::forge::ExpectedMachine> for ExpectedMachineData {
    type Error = RpcDataConversionError;

    fn try_from(em: rpc::forge::ExpectedMachine) -> Result<Self, Self::Error> {
        Ok(Self {
            bmc_username: em.bmc_username,
            bmc_password: em.bmc_password,
            serial_number: em.chassis_serial_number,
            fallback_dpu_serial_numbers: em.fallback_dpu_serial_numbers,
            sku_id: em.sku_id,
            metadata: metadata_from_request(em.metadata)?,
            host_nics: em.host_nics.into_iter().map(|nic| nic.into()).collect(),
            rack_id: em.rack_id,
            default_pause_ingestion_and_poweron: em.default_pause_ingestion_and_poweron,
            dpf_enabled: em.is_dpf_enabled,
            bmc_ip_address: match em.bmc_ip_address.as_deref() {
                None | Some("") => None,
                Some(s) => Some(s.parse::<IpAddr>().map_err(|_| {
                    RpcDataConversionError::InvalidArgument(format!("Invalid BMC IP address: {s}"))
                })?),
            },
            bmc_retain_credentials: em.bmc_retain_credentials,
            // `dpu_mode` is optional on the wire; missing / ::Unspecified
            // both fall back to `DpuMode::default()`, which is ::DpuMode,
            // so old clients continue to behave as before.
            dpu_mode: em
                .dpu_mode
                .map(|i| rpc::forge::DpuMode::try_from(i).unwrap_or_default())
                .map(DpuMode::from)
                .unwrap_or_default(),
        })
    }
}

/// If Metadata is retrieved as part of the ExpectedMachine creation, validate and use the Metadata
/// Otherwise assume empty Metadata
fn metadata_from_request(
    opt_metadata: Option<::rpc::forge::Metadata>,
) -> Result<Metadata, RpcDataConversionError> {
    Ok(match opt_metadata {
        None => Metadata {
            name: "".to_string(),
            description: "".to_string(),
            labels: Default::default(),
        },
        Some(m) => {
            // Note that this is unvalidated Metadata. It can contain non-ASCII names
            // and
            let m: Metadata = m.try_into()?;
            m.validate(false)
                .map_err(|e| RpcDataConversionError::InvalidArgument(e.to_string()))?;
            m
        }
    })
}

// default_uuid removed; ids are optional to support legacy rows with NULL ids

#[cfg(test)]
mod tests {
    use super::*;

    /// A completely-unset mode (client didn't set the field) should behave
    /// the same as `DpuMode` (default) for resolution purposes: the site
    /// flag decides.
    #[test]
    fn resolve_no_expected_mode_with_site_flag_off_returns_dpu_mode() {
        assert_eq!(DpuMode::resolve(None, false), DpuMode::DpuMode);
    }

    #[test]
    fn resolve_no_expected_mode_with_site_flag_on_returns_nic_mode() {
        assert_eq!(DpuMode::resolve(None, true), DpuMode::NicMode);
    }

    /// Explicit per-host `DpuMode` is indistinguishable from "not set" in
    /// the storage type (the default). So it also defers to the site flag
    /// -- existing `force_dpu_nic_mode` deployments keep working.
    #[test]
    fn resolve_explicit_dpu_mode_defers_to_site_flag() {
        assert_eq!(
            DpuMode::resolve(Some(DpuMode::DpuMode), false),
            DpuMode::DpuMode
        );
        assert_eq!(
            DpuMode::resolve(Some(DpuMode::DpuMode), true),
            DpuMode::NicMode
        );
    }

    /// An explicit per-host `NicMode` always wins, regardless of the site
    /// flag. This is the "I want this specific host in NIC mode" override.
    #[test]
    fn resolve_nic_mode_always_wins() {
        assert_eq!(
            DpuMode::resolve(Some(DpuMode::NicMode), false),
            DpuMode::NicMode
        );
        assert_eq!(
            DpuMode::resolve(Some(DpuMode::NicMode), true),
            DpuMode::NicMode
        );
    }

    /// An explicit per-host `NoDpu` always wins. Useful for hosts where
    /// the operator knows there's genuinely no DPU hardware (as opposed
    /// to "DPU present but used as NIC", which is `NicMode`).
    #[test]
    fn resolve_no_dpu_always_wins() {
        assert_eq!(
            DpuMode::resolve(Some(DpuMode::NoDpu), false),
            DpuMode::NoDpu
        );
        assert_eq!(DpuMode::resolve(Some(DpuMode::NoDpu), true), DpuMode::NoDpu);
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

    /// Unspecified (0) on the wire means "use the default." Old clients
    /// sending no value land here, and we want to preserve the DpuMode
    /// default so existing deployments keep their behavior.
    #[test]
    fn from_rpc_unspecified_maps_to_default() {
        assert_eq!(
            DpuMode::from(rpc::forge::DpuMode::Unspecified),
            DpuMode::default()
        );
        assert_eq!(DpuMode::default(), DpuMode::DpuMode);
    }

    #[test]
    fn rpc_enum_round_trips_all_named_variants() {
        for mode in [DpuMode::DpuMode, DpuMode::NicMode, DpuMode::NoDpu] {
            assert_eq!(DpuMode::from(rpc::forge::DpuMode::from(mode)), mode);
        }
    }
}
