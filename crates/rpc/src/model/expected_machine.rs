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

use mac_address::MacAddress;
use model::expected_machine::{
    DpuMode, ExpectedHostNic, ExpectedMachine, ExpectedMachineData, ExpectedMachineRequest,
    HostLifecycleProfile, LinkedExpectedMachine, UnexpectedMachine,
};
use model::metadata::Metadata;
use uuid::Uuid;

use crate as rpc;
use crate::errors::RpcDataConversionError;

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

impl From<ExpectedHostNic> for rpc::forge::ExpectedHostNic {
    fn from(expected_host_nic: ExpectedHostNic) -> Self {
        rpc::forge::ExpectedHostNic {
            mac_address: expected_host_nic.mac_address.to_string(),
            nic_type: expected_host_nic.nic_type,
            fixed_ip: expected_host_nic.fixed_ip.map(|ip| ip.to_string()),
            fixed_mask: expected_host_nic.fixed_mask,
            fixed_gateway: expected_host_nic.fixed_gateway.map(|ip| ip.to_string()),
            primary: expected_host_nic.primary,
        }
    }
}

impl TryFrom<rpc::forge::ExpectedHostNic> for ExpectedHostNic {
    type Error = RpcDataConversionError;

    fn try_from(expected_host_nic: rpc::forge::ExpectedHostNic) -> Result<Self, Self::Error> {
        let mac_address = expected_host_nic.mac_address.parse().map_err(|_| {
            RpcDataConversionError::InvalidMacAddress(expected_host_nic.mac_address.clone())
        })?;

        Ok(ExpectedHostNic {
            mac_address,
            nic_type: expected_host_nic.nic_type,
            fixed_ip: match expected_host_nic.fixed_ip.as_deref() {
                None | Some("") => None,
                Some(ip) => Some(ip.parse::<IpAddr>().map_err(|_| {
                    RpcDataConversionError::InvalidArgument(format!("Invalid fixed IP: {ip}"))
                })?),
            },
            fixed_mask: expected_host_nic.fixed_mask,
            fixed_gateway: match expected_host_nic.fixed_gateway.as_deref() {
                None | Some("") => None,
                Some(ip) => Some(ip.parse::<IpAddr>().map_err(|_| {
                    RpcDataConversionError::InvalidArgument(format!("Invalid fixed gateway: {ip}"))
                })?),
            },
            primary: expected_host_nic.primary,
        })
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
            id: expected_machine.id.map(|u| crate::common::Uuid {
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
            host_lifecycle_profile: (!expected_machine.data.host_lifecycle_profile.is_empty())
                .then_some(rpc::forge::HostLifecycleProfile {
                    disable_lockdown: expected_machine
                        .data
                        .host_lifecycle_profile
                        .disable_lockdown,
                }),
        }
    }
}

impl From<LinkedExpectedMachine> for rpc::forge::LinkedExpectedMachine {
    fn from(m: LinkedExpectedMachine) -> rpc::forge::LinkedExpectedMachine {
        rpc::forge::LinkedExpectedMachine {
            chassis_serial_number: m.serial_number,
            bmc_mac_address: m.bmc_mac_address.to_string(),
            interface_id: m.interface_id.map(|u| u.to_string()),
            explored_endpoint_address: m.address.map(|addr| addr.to_string()),
            machine_id: m.machine_id,
            expected_machine_id: m.expected_machine_id.map(|id| crate::common::Uuid {
                value: id.to_string(),
            }),
        }
    }
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
            host_nics: em
                .host_nics
                .into_iter()
                .map(ExpectedHostNic::try_from)
                .collect::<Result<Vec<_>, _>>()?,
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
            host_lifecycle_profile: em
                .host_lifecycle_profile
                .map(|hlp| HostLifecycleProfile {
                    disable_lockdown: hlp.disable_lockdown,
                })
                .unwrap_or_default(),
        })
    }
}

/// If Metadata is retrieved as part of the ExpectedMachine creation, validate and use the Metadata
/// Otherwise assume empty Metadata
fn metadata_from_request(
    opt_metadata: Option<crate::forge::Metadata>,
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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};
    use carbide_uuid::machine::{MachineId, MachineInterfaceId};
    use std::str::FromStr;

    use super::*;

    /// `DpuMode::from(rpc::forge::DpuMode)` maps each named variant onto its
    /// model twin, and Unspecified (what old clients send) onto the default —
    /// which keeps existing deployments behaving as before. The named rows also
    /// stand in for the model -> rpc -> model round trip, since the rpc input is
    /// exactly what `rpc::forge::DpuMode::from(model)` produces.
    #[test]
    fn rpc_dpu_mode_maps_to_model() {
        check_values(
            [
                Check {
                    scenario: "unspecified maps to default",
                    input: rpc::forge::DpuMode::Unspecified,
                    expect: DpuMode::default(),
                },
                Check {
                    scenario: "dpu mode round trips",
                    input: rpc::forge::DpuMode::DpuMode,
                    expect: DpuMode::DpuMode,
                },
                Check {
                    scenario: "nic mode round trips",
                    input: rpc::forge::DpuMode::NicMode,
                    expect: DpuMode::NicMode,
                },
                Check {
                    scenario: "no dpu round trips",
                    input: rpc::forge::DpuMode::NoDpu,
                    expect: DpuMode::NoDpu,
                },
            ],
            DpuMode::from,
        );
    }

    /// The DpuMode default is DpuMode, which is what the Unspecified mapping above
    /// relies on.
    #[test]
    fn dpu_mode_default_is_dpu_mode() {
        assert_eq!(DpuMode::default(), DpuMode::DpuMode);
    }

    #[test]
    fn expected_host_nic_rejects_invalid_mac_address() {
        let err = ExpectedHostNic::try_from(rpc::forge::ExpectedHostNic {
            mac_address: "not-a-mac".into(),
            ..Default::default()
        })
        .unwrap_err();

        assert!(
            matches!(err, RpcDataConversionError::InvalidMacAddress(mac) if mac == "not-a-mac")
        );
    }

    #[test]
    fn expected_machine_data_rejects_invalid_host_nic_mac_address() {
        let mut rpc_machine = make_rpc_expected_machine(None);
        rpc_machine.host_nics.push(rpc::forge::ExpectedHostNic {
            mac_address: "not-a-mac".into(),
            ..Default::default()
        });

        let Err(err) = ExpectedMachineData::try_from(rpc_machine) else {
            panic!("expected invalid host NIC MAC address");
        };

        assert!(
            matches!(err, RpcDataConversionError::InvalidMacAddress(mac) if mac == "not-a-mac")
        );
    }

    fn make_rpc_expected_machine(disable_lockdown: Option<bool>) -> rpc::forge::ExpectedMachine {
        rpc::forge::ExpectedMachine {
            bmc_mac_address: "AA:BB:CC:DD:EE:FF".into(),
            bmc_username: "root".into(),
            bmc_password: "pass".into(),
            chassis_serial_number: "SN-1".into(),
            host_lifecycle_profile: disable_lockdown.map(|dl| rpc::forge::HostLifecycleProfile {
                disable_lockdown: Some(dl),
            }),
            ..Default::default()
        }
    }

    /// `rpc::forge::DpuMode::from(model)` -- the model -> rpc direction. Each
    /// named model variant maps onto its rpc twin; the model has no
    /// Unspecified arm so every variant is named.
    #[test]
    fn model_dpu_mode_maps_to_rpc() {
        check_values(
            [
                Check {
                    scenario: "dpu mode",
                    input: DpuMode::DpuMode,
                    expect: rpc::forge::DpuMode::DpuMode,
                },
                Check {
                    scenario: "nic mode",
                    input: DpuMode::NicMode,
                    expect: rpc::forge::DpuMode::NicMode,
                },
                Check {
                    scenario: "no dpu",
                    input: DpuMode::NoDpu,
                    expect: rpc::forge::DpuMode::NoDpu,
                },
            ],
            rpc::forge::DpuMode::from,
        );
    }

    /// `ExpectedMachineRequest::try_from` parses the optional UUID id and the
    /// (possibly empty) BMC MAC string. Empty MAC and absent id both become
    /// `None`; a malformed UUID or MAC fails. The run closure projects the
    /// parsed request to `(id.is_some(), bmc_mac_address.is_some())` so the
    /// table is a single `bool`-pair shape.
    #[test]
    fn expected_machine_request_try_from_parses_id_and_mac() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        check_cases(
            [
                Case {
                    scenario: "id and mac both present",
                    input: rpc::forge::ExpectedMachineRequest {
                        bmc_mac_address: "AA:BB:CC:DD:EE:FF".into(),
                        id: Some(crate::common::Uuid {
                            value: uuid.into(),
                        }),
                    },
                    expect: Yields((true, true)),
                },
                Case {
                    scenario: "id absent, mac empty",
                    input: rpc::forge::ExpectedMachineRequest {
                        bmc_mac_address: "".into(),
                        id: None,
                    },
                    expect: Yields((false, false)),
                },
                Case {
                    scenario: "invalid uuid fails",
                    input: rpc::forge::ExpectedMachineRequest {
                        bmc_mac_address: "".into(),
                        id: Some(crate::common::Uuid {
                            value: "not-a-uuid".into(),
                        }),
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "invalid mac fails",
                    input: rpc::forge::ExpectedMachineRequest {
                        bmc_mac_address: "not-a-mac".into(),
                        id: None,
                    },
                    expect: Fails,
                },
            ],
            |req| {
                let parsed = ExpectedMachineRequest::try_from(req).map_err(drop)?;
                Ok::<_, ()>((parsed.id.is_some(), parsed.bmc_mac_address.is_some()))
            },
        );
    }

    /// `rpc::forge::ExpectedHostNic::from(model)` -- the infallible model -> rpc
    /// direction. Each row projects the produced proto to
    /// `(mac_address, fixed_ip, fixed_gateway, primary)` so present vs absent
    /// optionals and the MAC/IP stringification are all visible.
    #[test]
    fn expected_host_nic_to_rpc_maps_fields() {
        check_values(
            [
                Check {
                    scenario: "all optionals present",
                    input: ExpectedHostNic {
                        mac_address: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
                        nic_type: Some("bf3".into()),
                        fixed_ip: Some("10.0.0.5".parse().unwrap()),
                        fixed_mask: Some("255.255.255.0".into()),
                        fixed_gateway: Some("10.0.0.1".parse().unwrap()),
                        primary: Some(true),
                    },
                    expect: (
                        "AA:BB:CC:DD:EE:FF".to_string(),
                        Some("10.0.0.5".to_string()),
                        Some("10.0.0.1".to_string()),
                        Some(true),
                    ),
                },
                Check {
                    scenario: "optionals absent",
                    input: ExpectedHostNic {
                        mac_address: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
                        nic_type: None,
                        fixed_ip: None,
                        fixed_mask: None,
                        fixed_gateway: None,
                        primary: None,
                    },
                    expect: ("AA:BB:CC:DD:EE:FF".to_string(), None, None, None),
                },
            ],
            |nic| {
                let rpc: rpc::forge::ExpectedHostNic = nic.into();
                (rpc.mac_address, rpc.fixed_ip, rpc.fixed_gateway, rpc.primary)
            },
        );
    }

    /// `ExpectedHostNic::try_from(rpc)` -- the fallible rpc -> model direction.
    /// Empty-string `fixed_ip` / `fixed_gateway` collapse to `None` (same as
    /// absent); malformed MAC, IP, or gateway each fail. The run closure
    /// projects success to `(fixed_ip.is_some(), fixed_gateway.is_some())`.
    #[test]
    fn expected_host_nic_try_from_handles_optionals_and_errors() {
        let base = || rpc::forge::ExpectedHostNic {
            mac_address: "AA:BB:CC:DD:EE:FF".into(),
            ..Default::default()
        };
        check_cases(
            [
                Case {
                    scenario: "valid ip and gateway",
                    input: rpc::forge::ExpectedHostNic {
                        fixed_ip: Some("10.0.0.5".into()),
                        fixed_gateway: Some("10.0.0.1".into()),
                        ..base()
                    },
                    expect: Yields((true, true)),
                },
                Case {
                    scenario: "empty-string ip and gateway become none",
                    input: rpc::forge::ExpectedHostNic {
                        fixed_ip: Some("".into()),
                        fixed_gateway: Some("".into()),
                        ..base()
                    },
                    expect: Yields((false, false)),
                },
                Case {
                    scenario: "absent ip and gateway are none",
                    input: base(),
                    expect: Yields((false, false)),
                },
                Case {
                    scenario: "invalid mac fails",
                    input: rpc::forge::ExpectedHostNic {
                        mac_address: "not-a-mac".into(),
                        ..Default::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "invalid fixed ip fails",
                    input: rpc::forge::ExpectedHostNic {
                        fixed_ip: Some("not-an-ip".into()),
                        ..base()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "invalid fixed gateway fails",
                    input: rpc::forge::ExpectedHostNic {
                        fixed_gateway: Some("not-an-ip".into()),
                        ..base()
                    },
                    expect: Fails,
                },
            ],
            |rpc_nic| {
                let nic = ExpectedHostNic::try_from(rpc_nic).map_err(drop)?;
                Ok::<_, ()>((nic.fixed_ip.is_some(), nic.fixed_gateway.is_some()))
            },
        );
    }

    /// `rpc::forge::LinkedExpectedMachine::from(model)` -- the infallible
    /// projection. Each row checks `(interface_id, explored_endpoint_address,
    /// machine_id.is_some(), expected_machine_id.is_some())` so present vs
    /// absent optionals are all covered.
    #[test]
    fn linked_expected_machine_to_rpc_maps_fields() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        check_values(
            [
                Check {
                    scenario: "optionals present",
                    input: LinkedExpectedMachine {
                        serial_number: "SN-1".into(),
                        bmc_mac_address: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
                        interface_id: Some(MachineInterfaceId::nil()),
                        address: Some("10.0.0.5".parse().unwrap()),
                        machine_id: Some(
                            MachineId::from_str(
                                "fm100htjsaledfasinabqqer70e2ua5ksqj4kfjii0v0a90vulps48c1h7g",
                            )
                            .unwrap(),
                        ),
                        expected_machine_id: Some(uuid),
                    },
                    expect: (
                        Some(MachineInterfaceId::nil().to_string()),
                        Some("10.0.0.5".to_string()),
                        true,
                        true,
                    ),
                },
                Check {
                    scenario: "optionals absent",
                    input: LinkedExpectedMachine {
                        serial_number: "SN-1".into(),
                        bmc_mac_address: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
                        interface_id: None,
                        address: None,
                        machine_id: None,
                        expected_machine_id: None,
                    },
                    expect: (None, None, false, false),
                },
            ],
            |m| {
                let rpc: rpc::forge::LinkedExpectedMachine = m.into();
                (
                    rpc.interface_id,
                    rpc.explored_endpoint_address,
                    rpc.machine_id.is_some(),
                    rpc.expected_machine_id.is_some(),
                )
            },
        );
    }

    /// `rpc::forge::UnexpectedMachine::from(model)` -- the infallible
    /// projection, including the optional `machine_id`. Each row checks
    /// `(address, bmc_mac_address, machine_id.is_some())`.
    #[test]
    fn unexpected_machine_to_rpc_maps_fields() {
        check_values(
            [
                Check {
                    scenario: "machine id present",
                    input: UnexpectedMachine {
                        address: "10.0.0.5".parse().unwrap(),
                        bmc_mac_address: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
                        machine_id: Some(
                            MachineId::from_str(
                                "fm100htjsaledfasinabqqer70e2ua5ksqj4kfjii0v0a90vulps48c1h7g",
                            )
                            .unwrap(),
                        ),
                    },
                    expect: (
                        "10.0.0.5".to_string(),
                        "AA:BB:CC:DD:EE:FF".to_string(),
                        true,
                    ),
                },
                Check {
                    scenario: "machine id absent",
                    input: UnexpectedMachine {
                        address: "10.0.0.5".parse().unwrap(),
                        bmc_mac_address: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
                        machine_id: None,
                    },
                    expect: (
                        "10.0.0.5".to_string(),
                        "AA:BB:CC:DD:EE:FF".to_string(),
                        false,
                    ),
                },
            ],
            |m| {
                let rpc: rpc::forge::UnexpectedMachine = m.into();
                (rpc.address, rpc.bmc_mac_address, rpc.machine_id.is_some())
            },
        );
    }

    /// `ExpectedMachineData::try_from(rpc)` resolves the optional `dpu_mode`
    /// field: each named wire value maps to its model twin, while a missing
    /// field and an Unspecified (0) value both fall back to the default
    /// (`DpuMode::DpuMode`), preserving old-client behavior.
    #[test]
    fn expected_machine_data_resolves_dpu_mode() {
        check_cases(
            [
                Case {
                    scenario: "missing field falls back to default",
                    input: None,
                    expect: Yields(DpuMode::DpuMode),
                },
                Case {
                    scenario: "unspecified falls back to default",
                    input: Some(rpc::forge::DpuMode::Unspecified as i32),
                    expect: Yields(DpuMode::DpuMode),
                },
                Case {
                    scenario: "dpu mode",
                    input: Some(rpc::forge::DpuMode::DpuMode as i32),
                    expect: Yields(DpuMode::DpuMode),
                },
                Case {
                    scenario: "nic mode",
                    input: Some(rpc::forge::DpuMode::NicMode as i32),
                    expect: Yields(DpuMode::NicMode),
                },
                Case {
                    scenario: "no dpu",
                    input: Some(rpc::forge::DpuMode::NoDpu as i32),
                    expect: Yields(DpuMode::NoDpu),
                },
                Case {
                    scenario: "unknown enum value falls back to default",
                    input: Some(999),
                    expect: Yields(DpuMode::DpuMode),
                },
            ],
            |dpu_mode| {
                let mut rpc = make_rpc_expected_machine(None);
                rpc.dpu_mode = dpu_mode;
                ExpectedMachineData::try_from(rpc)
                    .map(|d| d.dpu_mode)
                    .map_err(drop)
            },
        );
    }

    /// `ExpectedMachineData::try_from(rpc)` parses the optional `bmc_ip_address`
    /// wire string: empty and absent both become `None`, a valid v4/v6 string
    /// parses, and a malformed string fails the whole conversion. The run
    /// closure projects success to `bmc_ip_address.is_some()`.
    #[test]
    fn expected_machine_data_parses_bmc_ip_address() {
        check_cases(
            [
                Case {
                    scenario: "absent is none",
                    input: None,
                    expect: Yields(false),
                },
                Case {
                    scenario: "empty string is none",
                    input: Some("".to_string()),
                    expect: Yields(false),
                },
                Case {
                    scenario: "valid v4 parses",
                    input: Some("10.0.0.5".to_string()),
                    expect: Yields(true),
                },
                Case {
                    scenario: "valid v6 parses",
                    input: Some("2001:db8::1".to_string()),
                    expect: Yields(true),
                },
                Case {
                    scenario: "invalid string fails",
                    input: Some("not-an-ip".to_string()),
                    expect: Fails,
                },
            ],
            |bmc_ip_address| {
                let mut rpc = make_rpc_expected_machine(None);
                rpc.bmc_ip_address = bmc_ip_address;
                ExpectedMachineData::try_from(rpc)
                    .map(|d| d.bmc_ip_address.is_some())
                    .map_err(drop)
            },
        );
    }

    /// `metadata_from_request` (via `ExpectedMachineData::try_from`): an absent
    /// proto Metadata yields empty model metadata, a present-and-valid one is
    /// carried through, and a present-but-invalid one (here an empty label key)
    /// fails validation. The run closure projects success to the parsed
    /// metadata name.
    #[test]
    fn expected_machine_data_validates_metadata() {
        check_cases(
            [
                Case {
                    scenario: "absent metadata yields empty name",
                    input: None,
                    expect: Yields(String::new()),
                },
                Case {
                    scenario: "valid metadata is carried through",
                    input: Some(rpc::forge::Metadata {
                        name: "my-host".into(),
                        description: "desc".into(),
                        labels: vec![],
                    }),
                    expect: Yields("my-host".to_string()),
                },
                Case {
                    scenario: "invalid metadata (empty label key) fails",
                    input: Some(rpc::forge::Metadata {
                        name: "my-host".into(),
                        description: "desc".into(),
                        labels: vec![rpc::forge::Label {
                            key: "".into(),
                            value: Some("v".into()),
                        }],
                    }),
                    expect: Fails,
                },
            ],
            |metadata| {
                let mut rpc = make_rpc_expected_machine(None);
                rpc.metadata = metadata;
                ExpectedMachineData::try_from(rpc)
                    .map(|d| d.metadata.name)
                    .map_err(drop)
            },
        );
    }

    /// `rpc::forge::ExpectedMachine::from(model)` only emits `dpu_mode` on the
    /// wire when it's non-default -- the default `DpuMode` collapses to `None`
    /// (matching the bmc_retain_credentials filter pattern), while `NicMode`
    /// and `NoDpu` are emitted as their i32 wire values.
    #[test]
    fn expected_machine_to_rpc_emits_non_default_dpu_mode() {
        check_values(
            [
                Check {
                    scenario: "default dpu mode is omitted",
                    input: DpuMode::DpuMode,
                    expect: None,
                },
                Check {
                    scenario: "nic mode is emitted",
                    input: DpuMode::NicMode,
                    expect: Some(rpc::forge::DpuMode::NicMode as i32),
                },
                Check {
                    scenario: "no dpu is emitted",
                    input: DpuMode::NoDpu,
                    expect: Some(rpc::forge::DpuMode::NoDpu as i32),
                },
            ],
            |dpu_mode| {
                let em = ExpectedMachine {
                    id: None,
                    bmc_mac_address: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
                    data: ExpectedMachineData {
                        dpu_mode,
                        ..Default::default()
                    },
                };
                let rpc: rpc::forge::ExpectedMachine = em.into();
                rpc.dpu_mode
            },
        );
    }

    /// `rpc::forge::ExpectedMachine::from(model)` only emits
    /// `bmc_retain_credentials` when it's `Some(true)`; `Some(false)` and
    /// `None` both collapse to `None` on the wire (the filter pattern).
    #[test]
    fn expected_machine_to_rpc_filters_bmc_retain_credentials() {
        check_values(
            [
                Check {
                    scenario: "some true is emitted",
                    input: Some(true),
                    expect: Some(true),
                },
                Check {
                    scenario: "some false is filtered out",
                    input: Some(false),
                    expect: None,
                },
                Check {
                    scenario: "none stays none",
                    input: None,
                    expect: None,
                },
            ],
            |bmc_retain_credentials| {
                let em = ExpectedMachine {
                    id: None,
                    bmc_mac_address: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
                    data: ExpectedMachineData {
                        bmc_retain_credentials,
                        ..Default::default()
                    },
                };
                let rpc: rpc::forge::ExpectedMachine = em.into();
                rpc.bmc_retain_credentials
            },
        );
    }

    /// `rpc::forge::ExpectedMachine::from(model)` mirrors the optional
    /// `dpf_enabled` onto both the deprecated `dpf_enabled` bool (defaulting to
    /// `false` when unset) and the optional `is_dpf_enabled`. Each row checks
    /// `(dpf_enabled, is_dpf_enabled)`.
    #[test]
    fn expected_machine_to_rpc_mirrors_dpf_enabled() {
        #[allow(deprecated)]
        check_values(
            [
                Check {
                    scenario: "some true",
                    input: Some(true),
                    expect: (true, Some(true)),
                },
                Check {
                    scenario: "some false",
                    input: Some(false),
                    expect: (false, Some(false)),
                },
                Check {
                    scenario: "none defaults bool to false",
                    input: None,
                    expect: (false, None),
                },
            ],
            |dpf_enabled| {
                let em = ExpectedMachine {
                    id: None,
                    bmc_mac_address: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
                    data: ExpectedMachineData {
                        dpf_enabled,
                        ..Default::default()
                    },
                };
                let rpc: rpc::forge::ExpectedMachine = em.into();
                (rpc.dpf_enabled, rpc.is_dpf_enabled)
            },
        );
    }

    /// `rpc::forge::ExpectedMachine::from(model)` only emits the
    /// `host_lifecycle_profile` message when the model profile is non-empty
    /// (any field set); an empty profile collapses to `None` on the wire.
    #[test]
    fn expected_machine_to_rpc_omits_empty_host_lifecycle_profile() {
        check_values(
            [
                Check {
                    scenario: "empty profile is omitted",
                    input: HostLifecycleProfile::default(),
                    expect: None,
                },
                Check {
                    scenario: "disable_lockdown set is emitted",
                    input: HostLifecycleProfile {
                        disable_lockdown: Some(true),
                    },
                    expect: Some(Some(true)),
                },
            ],
            |host_lifecycle_profile| {
                let em = ExpectedMachine {
                    id: None,
                    bmc_mac_address: "AA:BB:CC:DD:EE:FF".parse().unwrap(),
                    data: ExpectedMachineData {
                        host_lifecycle_profile,
                        ..Default::default()
                    },
                };
                let rpc: rpc::forge::ExpectedMachine = em.into();
                rpc.host_lifecycle_profile.map(|p| p.disable_lockdown)
            },
        );
    }

    /// `disable_lockdown` survives the rpc -> data -> rpc round trip: each input
    /// is projected to (data-side disable_lockdown, back-side host_lifecycle_profile
    /// mapped to its disable_lockdown). A `None` input yields no profile on the way
    /// back, so the back-side projection is `None` rather than `Some(None)`.
    #[test]
    fn disable_lockdown_round_trips_through_proto() {
        check_cases(
            [
                Case {
                    scenario: "true",
                    input: Some(true),
                    expect: Yields((Some(true), Some(Some(true)))),
                },
                Case {
                    scenario: "false",
                    input: Some(false),
                    expect: Yields((Some(false), Some(Some(false)))),
                },
                Case {
                    scenario: "none",
                    input: None,
                    expect: Yields((None, None)),
                },
            ],
            |disable_lockdown| {
                let data =
                    ExpectedMachineData::try_from(make_rpc_expected_machine(disable_lockdown))
                        .map_err(drop)?;
                let data_side = data.host_lifecycle_profile.disable_lockdown;

                let em = ExpectedMachine {
                    id: None,
                    bmc_mac_address: "AA:BB:CC:DD:EE:FF".parse().map_err(drop)?,
                    data,
                };
                let back: rpc::forge::ExpectedMachine = em.into();
                let back_side = back.host_lifecycle_profile.map(|p| p.disable_lockdown);

                Ok::<_, ()>((data_side, back_side))
            },
        );
    }
}
