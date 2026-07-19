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

use carbide_uuid::rack::RackId;
use clap::ValueEnum;
use mac_address::MacAddress;
use serde::{Deserialize, Deserializer, Serialize};

/// Admin-CLI policy vocabulary translated to the stable Forge `DpuMode`
/// compatibility surface when a request is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum HostDpuPolicy {
    #[value(name = "unspecified", hide = true)]
    #[serde(
        rename = "unspecified",
        alias = "Unspecified",
        alias = "DpuModeUnspecified",
        alias = "dpu_mode_unspecified",
        alias = "DPU_MODE_UNSPECIFIED"
    )]
    Unspecified,
    #[value(name = "manage", alias = "dpu-mode")]
    #[serde(
        rename = "manage",
        alias = "DpuMode",
        alias = "dpu_mode",
        alias = "DPU_MODE"
    )]
    Manage,
    #[value(name = "nic", alias = "use-as-nic", alias = "nic-mode")]
    #[serde(
        rename = "nic",
        alias = "UseAsNic",
        alias = "use_as_nic",
        alias = "USE_AS_NIC",
        alias = "NicMode",
        alias = "nic_mode",
        alias = "NIC_MODE"
    )]
    Nic,
    #[value(name = "ignore", alias = "no-dpu")]
    #[serde(rename = "ignore", alias = "NoDpu", alias = "no_dpu", alias = "NO_DPU")]
    Ignore,
}

impl From<HostDpuPolicy> for rpc::forge::DpuMode {
    fn from(policy: HostDpuPolicy) -> Self {
        match policy {
            HostDpuPolicy::Unspecified => Self::Unspecified,
            HostDpuPolicy::Manage => Self::DpuMode,
            HostDpuPolicy::Nic => Self::NicMode,
            HostDpuPolicy::Ignore => Self::NoDpu,
        }
    }
}

impl From<rpc::forge::DpuMode> for HostDpuPolicy {
    fn from(mode: rpc::forge::DpuMode) -> Self {
        match mode {
            rpc::forge::DpuMode::Unspecified => Self::Unspecified,
            rpc::forge::DpuMode::DpuMode => Self::Manage,
            rpc::forge::DpuMode::NicMode => Self::Nic,
            rpc::forge::DpuMode::NoDpu => Self::Ignore,
        }
    }
}

fn deserialize_dpu_policy<'de, D>(deserializer: D) -> Result<Option<HostDpuPolicy>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DpuPolicyInput {
        Name(HostDpuPolicy),
        Number(i32),
    }

    Option::<DpuPolicyInput>::deserialize(deserializer)?
        .map(|value| match value {
            DpuPolicyInput::Name(policy) => Ok(policy),
            DpuPolicyInput::Number(policy) => rpc::forge::DpuMode::try_from(policy)
                .map(HostDpuPolicy::from)
                .map_err(serde::de::Error::custom),
        })
        .transpose()
}

/// Admin-CLI JSON shape for `replace-all` and file-based `update`.
#[derive(Debug, Deserialize)]
pub struct ExpectedMachineJson {
    #[serde(default)]
    pub id: Option<String>,
    pub bmc_mac_address: MacAddress,
    pub bmc_username: String,
    pub bmc_password: String,
    pub chassis_serial_number: String,
    pub fallback_dpu_serial_numbers: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<rpc::forge::Metadata>,
    pub sku_id: Option<String>,
    #[serde(default)]
    pub host_nics: Vec<rpc::forge::ExpectedHostNic>,
    pub rack_id: Option<RackId>,
    pub default_pause_ingestion_and_poweron: Option<bool>,
    pub dpf_enabled: Option<bool>,
    /// Optional static BMC IP. When set, the API pre-allocates a `machine_interface` for
    /// [`bmc_mac_address`](Self::bmc_mac_address) (same as `--bmc-ip-address` on add/patch).
    #[serde(default)]
    pub bmc_ip_address: Option<String>,
    #[serde(default)]
    pub bmc_retain_credentials: Option<bool>,
    /// Per-host DPU policy. None == defer to the site-wide
    /// `[site_explorer] dpu_policy` setting (falls back to `Manage` if that's
    /// also unset). The legacy `dpu_mode` field and values remain accepted.
    #[serde(default, deserialize_with = "deserialize_dpu_policy")]
    dpu_policy: Option<HostDpuPolicy>,
    #[serde(
        default,
        rename = "dpu_mode",
        deserialize_with = "deserialize_dpu_policy"
    )]
    legacy_dpu_policy: Option<HostDpuPolicy>,
    /// Per-host control over how this BMC's IP is assigned and retained. None ==
    /// the server default (`Auto`), which resolves to `fixed` when a
    /// `bmc_ip_address` is set and `retained` when it isn't.
    #[serde(default)]
    pub bmc_ip_allocation: Option<rpc::forge::BmcIpAllocationType>,
    /// Per-host lifecycle profile for settings that affect state-machine progression.
    #[serde(default)]
    pub host_lifecycle_profile: Option<HostLifecycleProfile>,
}

impl ExpectedMachineJson {
    pub fn dpu_policy(&self) -> Option<HostDpuPolicy> {
        match (self.dpu_policy, self.legacy_dpu_policy) {
            (Some(HostDpuPolicy::Unspecified), Some(legacy)) => Some(legacy),
            (canonical @ Some(_), _) => canonical,
            (None, legacy) => legacy,
        }
    }
}

/// JSON shape for `host_lifecycle_profile` nested object.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HostLifecycleProfile {
    /// If true, do not lock down the server as part of lifecycle management within the state machine.
    /// If unset or false, preserve the default behavior of locking down the server after configuring the BIOS.
    #[serde(default)]
    pub disable_lockdown: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct _ExpectedMachineMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub labels: HashMap<String, Option<String>>,
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{scenarios, value_scenarios};

    use super::*;

    #[test]
    fn expected_machine_json_deserializes_new_and_legacy_dpu_policy() {
        scenarios!(
            run = |policy_json| {
                let json = format!(
                    r#"{{
                        "bmc_mac_address": "AA:BB:CC:DD:EE:FF",
                        "bmc_username": "root",
                        "bmc_password": "pass",
                        "chassis_serial_number": "SN-1"
                        {policy_json}
                    }}"#,
                );
                serde_json::from_str::<ExpectedMachineJson>(&json)
                    .map(|machine| machine.dpu_policy())
                    .map_err(drop)
            };
            "policy omitted" {
                "" => Yields(None),
            }

            "canonical field and value" {
                r#", "dpu_policy": "nic""# =>
                    Yields(Some(HostDpuPolicy::Nic)),
            }

            "previous canonical policy value" {
                r#", "dpu_policy": "use_as_nic""# =>
                    Yields(Some(HostDpuPolicy::Nic)),
            }

            "legacy field and config value" {
                r#", "dpu_mode": "nic_mode""# =>
                    Yields(Some(HostDpuPolicy::Nic)),
            }

            "legacy field and generated Rust value" {
                r#", "dpu_mode": "NicMode""# =>
                    Yields(Some(HostDpuPolicy::Nic)),
            }

            "matching canonical and legacy fields" {
                r#", "dpu_policy": "nic", "dpu_mode": "nic_mode""# =>
                    Yields(Some(HostDpuPolicy::Nic)),
            }

            "canonical field wins" {
                r#", "dpu_policy": "ignore", "dpu_mode": "nic_mode""# =>
                    Yields(Some(HostDpuPolicy::Ignore)),
            }

            "unspecified canonical field falls back to legacy" {
                r#", "dpu_policy": "Unspecified", "dpu_mode": "nic_mode""# =>
                    Yields(Some(HostDpuPolicy::Nic)),
            }

            "unspecified canonical field remains explicit without legacy" {
                r#", "dpu_policy": "Unspecified""# =>
                    Yields(Some(HostDpuPolicy::Unspecified)),
            }

            "numeric field emitted by RPC JSON" {
                r#", "dpu_mode": 2"# =>
                    Yields(Some(HostDpuPolicy::Nic)),
            }

            "unknown numeric value" {
                r#", "dpu_mode": 99"# => Fails,
            }
        );
    }

    #[test]
    fn host_dpu_policy_maps_to_rpc_compatibility_mode() {
        value_scenarios!(
            run = |policy| {
                let mode = rpc::forge::DpuMode::from(policy);
                (mode, HostDpuPolicy::from(mode))
            };
            "unspecified" {
                HostDpuPolicy::Unspecified =>
                    (rpc::forge::DpuMode::Unspecified, HostDpuPolicy::Unspecified),
            }
            "manage" {
                HostDpuPolicy::Manage =>
                    (rpc::forge::DpuMode::DpuMode, HostDpuPolicy::Manage),
            }
            "NIC" {
                HostDpuPolicy::Nic =>
                    (rpc::forge::DpuMode::NicMode, HostDpuPolicy::Nic),
            }
            "ignore" {
                HostDpuPolicy::Ignore =>
                    (rpc::forge::DpuMode::NoDpu, HostDpuPolicy::Ignore),
            }
        );
    }

    #[test]
    fn expected_machine_json_round_trips_rpc_dpu_mode() {
        let output = rpc::forge::ExpectedMachine {
            bmc_mac_address: "AA:BB:CC:DD:EE:FF".to_string(),
            bmc_username: "root".to_string(),
            bmc_password: "pass".to_string(),
            chassis_serial_number: "SN-1".to_string(),
            dpu_mode: Some(rpc::forge::DpuMode::NicMode as i32),
            ..Default::default()
        };

        let json = serde_json::to_string(&output).expect("RPC output should serialize");
        let input = serde_json::from_str::<ExpectedMachineJson>(&json)
            .expect("RPC output should deserialize as file input");

        assert_eq!(input.dpu_policy(), Some(HostDpuPolicy::Nic));
    }
}
