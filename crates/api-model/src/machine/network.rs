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
use std::net::IpAddr;

use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Duration, Utc};
use config_version::ConfigVersion;
use health_report::HealthReport;
use serde::{Deserialize, Serialize};

use crate::instance::status::extension_service::InstanceExtensionServiceStatusObservation;
use crate::instance::status::network::InstanceNetworkStatusObservation;

/// The fabric interface status last reported by a DPU agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpuFabricInterfaceStatusObservation {
    pub interface_name: String,
    pub link_data: Option<DpuLinkStatusObservation>,
}

/// The persisted subset of link attributes reported for a DPU fabric interface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpuLinkStatusObservation {
    pub link_type: Option<String>,
    pub state: Option<String>,
    pub carrier_up: Option<bool>,
    pub mtu: Option<u32>,
    pub carrier_up_count: Option<u32>,
    pub carrier_down_count: Option<u32>,
}

/// The network status that was last reported by the networking subsystem
/// Stored in a Postgres JSON field so new fields have to be Option until fully deployed
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineNetworkStatusObservation {
    pub machine_id: MachineId,
    pub agent_version: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub network_config_version: Option<ConfigVersion>,
    pub client_certificate_expiry: Option<i64>,
    pub agent_version_superseded_at: Option<DateTime<Utc>>,
    pub instance_network_observation: Option<InstanceNetworkStatusObservation>,
    pub extension_service_observation: Option<InstanceExtensionServiceStatusObservation>,
    #[serde(default)]
    pub fabric_interfaces: Vec<DpuFabricInterfaceStatusObservation>,
}

impl MachineNetworkStatusObservation {
    pub fn any_observed_version_changed(&self, other: &Self) -> bool {
        if self.network_config_version != other.network_config_version {
            return true;
        }

        if match (
            &self.instance_network_observation,
            &other.instance_network_observation,
        ) {
            (None, Some(_)) => true,
            (Some(_), None) => true,
            (None, None) => false,
            (Some(a), Some(b)) => a.any_observed_version_changed(b),
        } {
            return true;
        }

        if match (
            &self.extension_service_observation,
            &other.extension_service_observation,
        ) {
            (None, Some(_)) => true,
            (Some(_), None) => true,
            (None, None) => false,
            (Some(a), Some(b)) => a.any_observed_version_changed(b),
        } {
            return true;
        }

        false
    }

    pub fn expired_version_health_report(
        &self,
        staleness_threshold: Duration,
        prevent_allocations: bool,
    ) -> Option<HealthReport> {
        let Some(agent_version) = self.agent_version.as_ref() else {
            return Some(health_report::HealthReport::stale_agent_version(
                "forge-dpu-agent".to_string(),
                self.machine_id.to_string(),
                "Agent version is not known".to_string(),
                prevent_allocations,
            ));
        };

        if agent_version == carbide_version::v!(build_version) {
            // Same version as the server, all good.
            return None;
        }

        match self.agent_version_superseded_at {
            Some(superseded_at) => {
                let staleness = Utc::now().signed_duration_since(superseded_at);
                if staleness > staleness_threshold {
                    Some(health_report::HealthReport::stale_agent_version(
                        "forge-dpu-agent".to_string(),
                        self.machine_id.to_string(),
                        format!(
                            "Agent version is {}, which is out of date since {}",
                            agent_version,
                            superseded_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        ),
                        prevent_allocations,
                    ))
                } else {
                    None
                }
            }
            None => {
                tracing::debug!(
                        machine_id = %self.machine_id,
                        agent_version = %agent_version,
                        "DPU is on a stale agent version which we don't know about. Cannot know how stale it is, will not prevent allocations");
                None
            }
        }
    }
}

/// Desired network configuration for an instance.
/// This is persisted to a Postgres JSON column, so only use Option
/// fields for easier migrations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedHostNetworkConfig {
    pub loopback_ip: Option<IpAddr>,
    pub secondary_overlay_vtep_ip: Option<IpAddr>,
    /// This is a host-level field of the "consolidated" network
    /// config served to all [DPU] agents within host machine group.
    /// This is set in the config for the host-specific row in the
    /// database, and we use it as a base layer of sorts for then
    /// merging in DPU-specific configs.
    pub use_admin_network: Option<bool>,
    pub quarantine_state: Option<ManagedHostQuarantineState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedHostQuarantineState {
    pub reason: Option<String>,
    pub mode: ManagedHostQuarantineMode,
}

impl ManagedHostQuarantineState {
    pub fn reason_str(&self) -> &str {
        self.reason.as_deref().unwrap_or("")
    }

    pub fn mode_str(&self) -> &str {
        self.mode.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedHostQuarantineMode {
    BlockAllTraffic,
}

impl ManagedHostQuarantineMode {
    fn as_str(&self) -> &'static str {
        match self {
            ManagedHostQuarantineMode::BlockAllTraffic => "BlockAllTraffic",
        }
    }
}

impl Default for ManagedHostNetworkConfig {
    fn default() -> Self {
        ManagedHostNetworkConfig {
            loopback_ip: None,
            secondary_overlay_vtep_ip: None,
            use_admin_network: Some(true),
            quarantine_state: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Check, scenarios, value_scenarios};
    use chrono::TimeZone;
    use config_version::ConfigVersion;

    use super::*;

    // A stable MachineId for status observations; `any_observed_version_changed`
    // never inspects it, so any valid id does.
    fn machine_id() -> MachineId {
        MachineId::from_str("fm100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg").unwrap()
    }

    // A fixed timestamp so observations built in tests compare deterministically.
    fn observed_at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    // ConfigVersion built from its string form so the timestamp is deterministic
    // (ConfigVersion::new() stamps `now()`, which makes two calls unequal).
    fn config_version(version_nr: u64) -> ConfigVersion {
        ConfigVersion::from_str(&format!("V{version_nr}-T1000000")).unwrap()
    }

    // A MachineNetworkStatusObservation carrying only the fields
    // `any_observed_version_changed` reads; everything else is a fixed default.
    fn network_status(
        network_config_version: Option<ConfigVersion>,
        instance_network_observation: Option<InstanceNetworkStatusObservation>,
        extension_service_observation: Option<InstanceExtensionServiceStatusObservation>,
    ) -> MachineNetworkStatusObservation {
        MachineNetworkStatusObservation {
            machine_id: machine_id(),
            agent_version: None,
            observed_at: observed_at(),
            network_config_version,
            client_certificate_expiry: None,
            agent_version_superseded_at: None,
            instance_network_observation,
            extension_service_observation,
            fabric_interfaces: Vec::new(),
        }
    }

    fn network_observation(
        config_version: ConfigVersion,
        instance_config_version: Option<ConfigVersion>,
    ) -> InstanceNetworkStatusObservation {
        InstanceNetworkStatusObservation {
            config_version,
            instance_config_version,
            interfaces: Vec::new(),
            observed_at: observed_at(),
        }
    }

    fn extension_observation(
        config_version: ConfigVersion,
        instance_config_version: Option<ConfigVersion>,
    ) -> InstanceExtensionServiceStatusObservation {
        InstanceExtensionServiceStatusObservation {
            config_version,
            instance_config_version,
            extension_service_statuses: Vec::new(),
            observed_at: observed_at(),
        }
    }

    // JSON round-trips: serialize a config to JSON and deserialize it back; the
    // config must survive intact. Covers the IPv4 case (existing Postgres JSON
    // still deserializes after Ipv4Addr -> IpAddr) and the IPv6 case (new v6
    // pools). The error type (serde_json::Error) is not PartialEq, so failing
    // rows would use `Fails`; all rows here round-trip cleanly.
    #[test]
    fn test_managed_host_network_config_json_roundtrip() {
        scenarios!(
            run = |config| {
                let json = serde_json::to_string(&config).map_err(drop)?;
                serde_json::from_str::<ManagedHostNetworkConfig>(&json).map_err(drop)
            };
            "ipv4 round-trip" {
                ManagedHostNetworkConfig {
                    loopback_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    secondary_overlay_vtep_ip: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5))),
                    use_admin_network: Some(true),
                    quarantine_state: None,
                } => Yields(ManagedHostNetworkConfig {
                    loopback_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    secondary_overlay_vtep_ip: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5))),
                    use_admin_network: Some(true),
                    quarantine_state: None,
                }),
            }

            "ipv6 round-trip" {
                ManagedHostNetworkConfig {
                    loopback_ip: Some(IpAddr::V6(Ipv6Addr::new(
                        0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
                    ))),
                    secondary_overlay_vtep_ip: Some(IpAddr::V6(Ipv6Addr::new(
                        0xfd00, 0, 0, 0, 0, 0, 0, 0x42,
                    ))),
                    use_admin_network: Some(false),
                    quarantine_state: None,
                } => Yields(ManagedHostNetworkConfig {
                    loopback_ip: Some(IpAddr::V6(Ipv6Addr::new(
                        0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
                    ))),
                    secondary_overlay_vtep_ip: Some(IpAddr::V6(Ipv6Addr::new(
                        0xfd00, 0, 0, 0, 0, 0, 0, 0x42,
                    ))),
                    use_admin_network: Some(false),
                    quarantine_state: None,
                }),
            }
        );
    }

    // Deserialize raw JSON (as it would already exist in the database) into the
    // IpAddr-typed config, projecting to the (loopback_ip, secondary_overlay_vtep_ip)
    // pair the original tests asserted. Covers legacy IPv4 JSON and IPv6 JSON.
    #[test]
    fn test_managed_host_network_config_deserialize_json() {
        scenarios!(
            run = |json| {
                serde_json::from_str::<ManagedHostNetworkConfig>(json)
                    .map(|c| (c.loopback_ip, c.secondary_overlay_vtep_ip))
                    .map_err(drop)
            };
            "legacy ipv4 json" {
                r#"{
                            "loopback_ip": "10.0.0.1",
                            "secondary_overlay_vtep_ip": "172.16.0.5",
                            "use_admin_network": true,
                            "quarantine_state": null
                        }"# => Yields((
                    Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5))),
                )),
            }

            "ipv6 json" {
                r#"{
                            "loopback_ip": "2001:db8::1",
                            "secondary_overlay_vtep_ip": null,
                            "use_admin_network": true,
                            "quarantine_state": null
                        }"# => Yields((
                    Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
                    None,
                )),
            }
        );
    }

    // Ensure that the JSON representation of an IPv4 address under IpAddr is
    // identical to what Ipv4Addr would have produced. It should be, but better
    // safe than sorry, and backwards compatibility is key here, even though
    // it's not really backwards.
    #[test]
    fn test_managed_host_network_config_ipv4_json_format_unchanged() {
        let config = ManagedHostNetworkConfig {
            loopback_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            secondary_overlay_vtep_ip: None,
            use_admin_network: Some(true),
            quarantine_state: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        // Ensure IpAddr serializes IPv4 same as Ipv4Addr.
        assert!(json.contains(r#""loopback_ip":"10.0.0.1""#), "json: {json}");
    }

    // Ensure default ManagedHostNetworkConfig is still all-None/Some(true),
    // etc etc, and unaffected by the type change to IpAddr for v6 support.
    // Folded from four hand-written asserts into a table that projects each
    // default field; equality of the whole default config is exercised by the
    // round-trip test.
    #[test]
    fn test_managed_host_network_config_default() {
        let default = ManagedHostNetworkConfig::default();
        value_scenarios!(
            run = |ip| ip;
            "loopback_ip defaults to None" {
                default.loopback_ip => None,
            }

            "secondary_overlay_vtep_ip defaults to None" {
                default.secondary_overlay_vtep_ip => None,
            }
        );
        value_scenarios!(
            run = |flag| flag;
            "use_admin_network defaults to Some(true)" {
                default.use_admin_network => Some(true),
            }
        );
        Check {
            scenario: "quarantine_state defaults to None",
            input: default.quarantine_state,
            expect: None,
        }
        .check(|qs| qs);
    }

    // Verify that IpAddr::to_string() produces the expected format for both
    // address families, since several call sites throughout the codebase
    // use .to_string() on the loopback_ip value. Folded from a pair of
    // hand-written asserts into a table covering both families plus the
    // boundary/canonicalization cases (zero, broadcast, all-ones,
    // loopback, embedded-IPv4) where formatting can surprise.
    #[test]
    fn test_ip_addr_to_string_format() {
        value_scenarios!(
            run = |ip| ip.to_string();
            "ipv4" {
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)) => "10.0.0.1".to_string(),
            }

            "ipv4 unspecified" {
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) => "0.0.0.0".to_string(),
            }

            "ipv4 broadcast" {
                IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)) => "255.255.255.255".to_string(),
            }

            "ipv4 loopback" {
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)) => "127.0.0.1".to_string(),
            }

            "ipv6 compressed" {
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)) => "2001:db8::1".to_string(),
            }

            "ipv6 unspecified collapses to ::" {
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)) => "::".to_string(),
            }

            "ipv6 loopback collapses to ::1" {
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)) => "::1".to_string(),
            }

            "ipv6 full (no run to compress)" {
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x42)) => "fd00:1:2:3:4:5:6:42".to_string(),
            }
        );
    }

    // ManagedHostQuarantineState::reason_str() returns the reason or an empty
    // string when None. ManagedHostQuarantineMode has a single variant today;
    // its as_str()/mode_str() must render it exactly so the persisted form is
    // stable.
    #[test]
    fn test_quarantine_reason_str() {
        value_scenarios!(
            run = |state| state.reason_str().to_string();
            "present reason passes through" {
                ManagedHostQuarantineState {
                    reason: Some("flooding the fabric".to_string()),
                    mode: ManagedHostQuarantineMode::BlockAllTraffic,
                } => "flooding the fabric".to_string(),
            }

            "empty reason stays empty" {
                ManagedHostQuarantineState {
                    reason: Some(String::new()),
                    mode: ManagedHostQuarantineMode::BlockAllTraffic,
                } => String::new(),
            }

            "missing reason yields empty string" {
                ManagedHostQuarantineState {
                    reason: None,
                    mode: ManagedHostQuarantineMode::BlockAllTraffic,
                } => String::new(),
            }
        );
    }

    #[test]
    fn test_quarantine_mode_str() {
        value_scenarios!(
            run = |mode| {
                ManagedHostQuarantineState { reason: None, mode }
                    .mode_str()
                    .to_string()
            };
            "block-all-traffic renders its name" {
                ManagedHostQuarantineMode::BlockAllTraffic => "BlockAllTraffic".to_string(),
            }
        );
    }

    // any_observed_version_changed compares the network config version and then
    // the two nested observations (instance-network and extension-service),
    // each via a None/Some pairing that delegates to the sub-observation's own
    // comparison. Enumerate every arm: matching versions, differing versions,
    // each None/Some transition, and a deeper change inside each Some/Some pair.
    #[test]
    fn test_any_observed_version_changed() {
        let v1 = config_version(1);
        let v2 = config_version(2);

        value_scenarios!(
            run = |(a, b)| a.any_observed_version_changed(&b);
            "identical observations -> unchanged" {
                (
                    network_status(Some(v1), None, None),
                    network_status(Some(v1), None, None),
                ) => false,
            }

            "both network config versions None -> unchanged" {
                (
                    network_status(None, None, None),
                    network_status(None, None, None),
                ) => false,
            }

            "network config version differs -> changed" {
                (
                    network_status(Some(v1), None, None),
                    network_status(Some(v2), None, None),
                ) => true,
            }

            "network config version None vs Some -> changed" {
                (
                    network_status(None, None, None),
                    network_status(Some(v1), None, None),
                ) => true,
            }

            "network config version Some vs None -> changed" {
                (
                    network_status(Some(v1), None, None),
                    network_status(None, None, None),
                ) => true,
            }

            "instance observation None vs Some -> changed" {
                (
                    network_status(Some(v1), None, None),
                    network_status(Some(v1), Some(network_observation(v1, None)), None),
                ) => true,
            }

            "instance observation Some vs None -> changed" {
                (
                    network_status(Some(v1), Some(network_observation(v1, None)), None),
                    network_status(Some(v1), None, None),
                ) => true,
            }

            "instance observation Some/Some identical -> unchanged" {
                (
                    network_status(Some(v1), Some(network_observation(v1, Some(v1))), None),
                    network_status(Some(v1), Some(network_observation(v1, Some(v1))), None),
                ) => false,
            }

            "instance observation inner config version differs -> changed" {
                (
                    network_status(Some(v1), Some(network_observation(v1, None)), None),
                    network_status(Some(v1), Some(network_observation(v2, None)), None),
                ) => true,
            }

            "instance observation inner instance-config version differs -> changed" {
                (
                    network_status(Some(v1), Some(network_observation(v1, Some(v1))), None),
                    network_status(Some(v1), Some(network_observation(v1, Some(v2))), None),
                ) => true,
            }

            "extension observation None vs Some -> changed" {
                (
                    network_status(Some(v1), None, None),
                    network_status(Some(v1), None, Some(extension_observation(v1, None))),
                ) => true,
            }

            "extension observation Some vs None -> changed" {
                (
                    network_status(Some(v1), None, Some(extension_observation(v1, None))),
                    network_status(Some(v1), None, None),
                ) => true,
            }

            "extension observation Some/Some identical -> unchanged" {
                (
                    network_status(Some(v1), None, Some(extension_observation(v1, Some(v1)))),
                    network_status(Some(v1), None, Some(extension_observation(v1, Some(v1)))),
                ) => false,
            }

            "extension observation inner config version differs -> changed" {
                (
                    network_status(Some(v1), None, Some(extension_observation(v1, None))),
                    network_status(Some(v1), None, Some(extension_observation(v2, None))),
                ) => true,
            }

            "extension observation inner instance-config version differs -> changed" {
                (
                    network_status(Some(v1), None, Some(extension_observation(v1, Some(v1)))),
                    network_status(Some(v1), None, Some(extension_observation(v1, Some(v2)))),
                ) => true,
            }
        );
    }

    // Parse pool strings as IpAddr (resource pools store values as strings and
    // parse them via IpAddr::from_str). Yielding the exact IpAddr value also
    // covers the original is_ipv4()/is_ipv6() family assertions. AddrParseError
    // is not PartialEq, so failing rows would use `Fails`; both rows parse.
    #[test]
    fn test_ip_addr_parse_from_pool_strings() {
        scenarios!(
            run = |s| s.parse::<IpAddr>().map_err(drop);
            "ipv4 string" {
                "10.0.0.1" => Yields(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            }

            "ipv6 string" {
                "2001:db8::1" => Yields(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            }

            "ipv4 unspecified" {
                "0.0.0.0" => Yields(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            }

            "ipv4 broadcast" {
                "255.255.255.255" => Yields(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))),
            }

            "ipv6 unspecified" {
                "::" => Yields(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))),
            }

            "ipv6 loopback" {
                "::1" => Yields(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
            }

            "empty string is rejected" {
                "" => Fails,
            }

            "non-address text is rejected" {
                "not-an-ip" => Fails,
            }

            "ipv4 octet out of range is rejected" {
                "256.0.0.1" => Fails,
            }

            "ipv4 with too few octets is rejected" {
                "10.0.0" => Fails,
            }

            "ipv4 with trailing whitespace is rejected" {
                "10.0.0.1 " => Fails,
            }

            "ipv6 with double :: is rejected" {
                "2001::db8::1" => Fails,
            }

            "cidr suffix is not an address" {
                "10.0.0.0/24" => Fails,
            }
        );
    }

    // Deserialize raw JSON whose shape is malformed or whose IP strings are
    // invalid; serde_json::Error is not PartialEq, so rejected rows use `Fails`.
    // Also covers a populated quarantine_state, which the earlier deserialize
    // table left null.
    #[test]
    fn test_managed_host_network_config_deserialize_errors() {
        scenarios!(
            run = |json| serde_json::from_str::<ManagedHostNetworkConfig>(json).map_err(drop);
            "well-formed with quarantine state" {
                r#"{
                            "loopback_ip": "10.0.0.1",
                            "secondary_overlay_vtep_ip": null,
                            "use_admin_network": false,
                            "quarantine_state": {
                                "reason": "noisy",
                                "mode": "BlockAllTraffic"
                            }
                        }"# => Yields(ManagedHostNetworkConfig {
                    loopback_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    secondary_overlay_vtep_ip: None,
                    use_admin_network: Some(false),
                    quarantine_state: Some(ManagedHostQuarantineState {
                        reason: Some("noisy".to_string()),
                        mode: ManagedHostQuarantineMode::BlockAllTraffic,
                    }),
                }),
            }

            "empty object defaults all optional fields" {
                "{}" => Yields(ManagedHostNetworkConfig {
                    loopback_ip: None,
                    secondary_overlay_vtep_ip: None,
                    use_admin_network: None,
                    quarantine_state: None,
                }),
            }

            "invalid loopback ip string is rejected" {
                r#"{"loopback_ip": "not-an-ip"}"# => Fails,
            }

            "unknown quarantine mode is rejected" {
                r#"{"quarantine_state": {"mode": "Nope"}}"# => Fails,
            }

            "wrong type for use_admin_network is rejected" {
                r#"{"use_admin_network": "true"}"# => Fails,
            }

            "truncated json is rejected" {
                r#"{"loopback_ip": "10.0.0.1""# => Fails,
            }

            "non-object json is rejected" {
                "[]" => Fails,
            }
        );
    }

    // The default config round-trips through JSON unchanged, and the
    // quarantine-state variant survives a round-trip too. Folds the prior
    // single-default assertion into the round-trip table that already exists
    // for the IP cases. serde_json::Error is not PartialEq, so failing rows
    // would use `Fails`.
    #[test]
    fn test_managed_host_network_config_default_and_quarantine_roundtrip() {
        scenarios!(
            run = |config| {
                let json = serde_json::to_string(&config).map_err(drop)?;
                serde_json::from_str::<ManagedHostNetworkConfig>(&json).map_err(drop)
            };
            "default round-trips" {
                ManagedHostNetworkConfig::default() => Yields(ManagedHostNetworkConfig::default()),
            }

            "quarantine state round-trips" {
                ManagedHostNetworkConfig {
                    loopback_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    secondary_overlay_vtep_ip: None,
                    use_admin_network: Some(true),
                    quarantine_state: Some(ManagedHostQuarantineState {
                        reason: Some("flooded".to_string()),
                        mode: ManagedHostQuarantineMode::BlockAllTraffic,
                    }),
                } => Yields(ManagedHostNetworkConfig {
                    loopback_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                    secondary_overlay_vtep_ip: None,
                    use_admin_network: Some(true),
                    quarantine_state: Some(ManagedHostQuarantineState {
                        reason: Some("flooded".to_string()),
                        mode: ManagedHostQuarantineMode::BlockAllTraffic,
                    }),
                }),
            }
        );
    }
}
