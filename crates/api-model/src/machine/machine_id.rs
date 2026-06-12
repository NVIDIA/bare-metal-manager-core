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

use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
use sha2::{Digest, Sha256};

use crate::hardware_info::HardwareInfo;

/// Generates a temporary Machine ID for a host from the hardware fingerprint
/// of the attached DPU
///
/// Returns `None` if no sufficient data is available
///
/// Panics of the Machine is not a DPU
pub fn host_id_from_dpu_hardware_info(
    hardware_info: &HardwareInfo,
) -> Result<MachineId, MissingHardwareInfo> {
    assert!(hardware_info.is_dpu(), "Method can only be called on a DPU");

    from_hardware_info_with_type(hardware_info, MachineType::PredictedHost)
}

/// Generates a Machine ID from a hardware fingerprint
///
/// Returns `None` if no sufficient data is available
pub fn from_hardware_info_with_type(
    hardware_info: &HardwareInfo,
    machine_type: MachineType,
) -> Result<MachineId, MissingHardwareInfo> {
    let bytes;
    let source;
    let all_serials;

    if let Some(cert) = &hardware_info.tpm_ek_certificate {
        bytes = cert.as_bytes();
        if bytes.is_empty() {
            return Err(MissingHardwareInfo::TPMCertEmpty);
        }
        source = MachineIdSource::Tpm;
    } else if let Some(dmi_data) = &hardware_info.dmi_data {
        // We need at least 1 valid serial number
        if dmi_data.product_serial.is_empty()
            && dmi_data.board_serial.is_empty()
            && dmi_data.chassis_serial.is_empty()
        {
            return Err(MissingHardwareInfo::Serial);
        }

        all_serials = format!(
            "p{}-b{}-c{}",
            dmi_data.product_serial, dmi_data.board_serial, dmi_data.chassis_serial
        );
        bytes = all_serials.as_bytes();
        source = MachineIdSource::ProductBoardChassisSerial;
    } else {
        return Err(MissingHardwareInfo::All);
    }

    let mut hasher = Sha256::new();
    hasher.update(bytes);

    Ok(MachineId::new(
        source,
        hasher.finalize().into(),
        machine_type,
    ))
}

/// Generates a Machine ID from a hardware fingerprint
///
/// Returns `None` if no sufficient data is available
pub fn from_hardware_info(hardware_info: &HardwareInfo) -> Result<MachineId, MissingHardwareInfo> {
    let machine_type = if hardware_info.is_dpu() {
        MachineType::Dpu
    } else {
        MachineType::Host
    };

    from_hardware_info_with_type(hardware_info, machine_type)
}

#[derive(Debug, Copy, Clone, PartialEq, thiserror::Error)]
pub enum MissingHardwareInfo {
    #[error("The TPM certificate has no bytes")]
    TPMCertEmpty,
    #[error("Serial number missing (product, board and chassis)")]
    Serial,
    #[error("TPM and DMI data are both missing")]
    All,
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};
    use carbide_uuid::machine::MACHINE_ID_LENGTH;

    use super::*;
    use crate::hardware_info::{DmiData, TpmEkCertificate};

    // Build a `HardwareInfo` carrying only the two fields the ID derivation looks
    // at — an optional TPM certificate and optional DMI serials — leaving every
    // other field defaulted. `tpm` is the certificate bytes (when present) and
    // `serials` is the (product, board, chassis) triple folded into `DmiData`.
    fn info_for_id(tpm: Option<Vec<u8>>, serials: Option<(&str, &str, &str)>) -> HardwareInfo {
        HardwareInfo {
            tpm_ek_certificate: tpm.map(TpmEkCertificate::from),
            dmi_data: serials.map(|(product, board, chassis)| DmiData {
                product_serial: product.to_string(),
                board_serial: board.to_string(),
                chassis_serial: chassis.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    const TEST_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/hardware_info/test_data");

    lazy_static::lazy_static! {
        /// A valid DNS domain name. Regex is copied from a k8s error message for DNS name validation
        static ref DOMAIN_NAME_RE: regex::Regex = regex::Regex::new(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$").unwrap();
    }

    fn test_derive_machine_id(
        fingerprint: &mut HardwareInfo,
        expected_type: MachineType,
        constructor: fn(&HardwareInfo) -> Result<MachineId, MissingHardwareInfo>,
    ) {
        fingerprint.tpm_ek_certificate = Some(TpmEkCertificate::from(vec![1, 2, 3, 4]));

        fn validate_id(
            machine_id: MachineId,
            expected_source: MachineIdSource,
            expected_type: MachineType,
        ) {
            let serialized = machine_id.to_string();
            println!("Serialized: {serialized}");
            assert!(
                DOMAIN_NAME_RE.is_match(&serialized),
                "{serialized} is not a valid DNS name"
            );

            let expected_prefix =
                format!("{}{}", expected_type.id_prefix(), expected_source.id_char());

            assert!(serialized.starts_with(&expected_prefix));
            assert_eq!(serialized.len(), MACHINE_ID_LENGTH);
            let parsed: MachineId = serialized.parse().unwrap();
            assert_eq!(parsed, machine_id);
            assert_eq!(parsed.source(), expected_source);
            assert_eq!(parsed.machine_type(), expected_type);
        }

        let machine_id_tpm = constructor(fingerprint).unwrap();
        validate_id(machine_id_tpm, MachineIdSource::Tpm, expected_type);

        fingerprint.tpm_ek_certificate = None;
        let machine_id_product_serial = constructor(fingerprint).unwrap();
        validate_id(
            machine_id_product_serial,
            MachineIdSource::ProductBoardChassisSerial,
            expected_type,
        );

        fingerprint
            .dmi_data
            .as_mut()
            .unwrap()
            .product_serial
            .clear();
        let machine_id_product_serial = constructor(fingerprint).unwrap();
        validate_id(
            machine_id_product_serial,
            MachineIdSource::ProductBoardChassisSerial,
            expected_type,
        );

        fingerprint.dmi_data.as_mut().unwrap().board_serial.clear();
        let machine_id_product_serial = constructor(fingerprint).unwrap();
        validate_id(
            machine_id_product_serial,
            MachineIdSource::ProductBoardChassisSerial,
            expected_type,
        );

        fingerprint
            .dmi_data
            .as_mut()
            .unwrap()
            .chassis_serial
            .clear();
        assert!(constructor(fingerprint).is_err());
    }

    // Each row loads a hardware-info fixture and derives a Machine ID through one
    // constructor, expecting a given MachineType. `test_derive_machine_id` does all
    // the assertions internally (and panics on mismatch), so each row just expects
    // the run to complete, i.e. `Yields(())`.
    #[test]
    fn derive_machine_id() {
        type Constructor = fn(&HardwareInfo) -> Result<MachineId, MissingHardwareInfo>;

        check_cases(
            [
                Case {
                    scenario: "host machine id from x86 fingerprint",
                    input: (
                        "x86_info.json",
                        MachineType::Host,
                        from_hardware_info as Constructor,
                    ),
                    expect: Yields(()),
                },
                Case {
                    scenario: "dpu machine id from dpu fingerprint",
                    input: (
                        "dpu_info.json",
                        MachineType::Dpu,
                        from_hardware_info as Constructor,
                    ),
                    expect: Yields(()),
                },
                Case {
                    scenario: "predicted-host machine id from dpu fingerprint",
                    input: (
                        "dpu_info.json",
                        MachineType::PredictedHost,
                        host_id_from_dpu_hardware_info as Constructor,
                    ),
                    expect: Yields(()),
                },
            ],
            |(fixture, expected_type, constructor)| -> Result<(), ()> {
                let path = format!("{TEST_DATA_DIR}/{fixture}");
                let data = std::fs::read(path).unwrap();
                let mut fingerprint = serde_json::from_slice::<HardwareInfo>(&data).unwrap();

                test_derive_machine_id(&mut fingerprint, expected_type, constructor);
                Ok(())
            },
        );
    }

    // The error paths of `from_hardware_info_with_type`: a present-but-empty TPM
    // certificate, DMI data with every serial blank, and neither TPM nor DMI
    // present each map to a distinct `MissingHardwareInfo`. A non-empty TPM cert,
    // or DMI data with at least one serial, derives an ID and so `Yields`.
    #[test]
    fn from_hardware_info_with_type_error_paths() {
        check_cases(
            [
                Case {
                    scenario: "present but empty TPM cert is rejected",
                    input: info_for_id(Some(vec![]), None),
                    expect: FailsWith(MissingHardwareInfo::TPMCertEmpty),
                },
                Case {
                    scenario: "empty TPM cert is rejected even with valid serials present",
                    input: info_for_id(Some(vec![]), Some(("p1", "b1", "c1"))),
                    expect: FailsWith(MissingHardwareInfo::TPMCertEmpty),
                },
                Case {
                    scenario: "DMI data with all serials blank is rejected",
                    input: info_for_id(None, Some(("", "", ""))),
                    expect: FailsWith(MissingHardwareInfo::Serial),
                },
                Case {
                    scenario: "neither TPM nor DMI present",
                    input: info_for_id(None, None),
                    expect: FailsWith(MissingHardwareInfo::All),
                },
                Case {
                    scenario: "non-empty TPM cert derives an ID",
                    input: info_for_id(Some(vec![1, 2, 3, 4]), None),
                    expect: Yields(()),
                },
                Case {
                    scenario: "product serial alone derives an ID",
                    input: info_for_id(None, Some(("p1", "", ""))),
                    expect: Yields(()),
                },
                Case {
                    scenario: "board serial alone derives an ID",
                    input: info_for_id(None, Some(("", "b1", ""))),
                    expect: Yields(()),
                },
                Case {
                    scenario: "chassis serial alone derives an ID",
                    input: info_for_id(None, Some(("", "", "c1"))),
                    expect: Yields(()),
                },
                Case {
                    scenario: "all three serials present derives an ID",
                    input: info_for_id(None, Some(("p1", "b1", "c1"))),
                    expect: Yields(()),
                },
            ],
            // Drop the derived ID so a success is `Ok(())`: the `Yields(())` rows
            // assert an ID was derived, while the error rows keep their exact
            // `MissingHardwareInfo` for the `FailsWith` checks.
            |info| from_hardware_info_with_type(&info, MachineType::Host).map(drop),
        );
    }

    // Which `MachineIdSource` the derivation selects: a present TPM certificate
    // wins outright, and falls through to the product/board/chassis serial source
    // only when no TPM certificate is present.
    #[test]
    fn from_hardware_info_with_type_selects_source() {
        check_cases(
            [
                Case {
                    scenario: "TPM certificate selects the Tpm source",
                    input: info_for_id(Some(vec![9]), None),
                    expect: Yields(MachineIdSource::Tpm),
                },
                Case {
                    scenario: "TPM certificate wins even when serials are present",
                    input: info_for_id(Some(vec![9]), Some(("p1", "b1", "c1"))),
                    expect: Yields(MachineIdSource::Tpm),
                },
                Case {
                    scenario: "serials select the ProductBoardChassisSerial source",
                    input: info_for_id(None, Some(("p1", "", ""))),
                    expect: Yields(MachineIdSource::ProductBoardChassisSerial),
                },
            ],
            |info| {
                from_hardware_info_with_type(&info, MachineType::Host)
                    .map(|id| id.source())
                    .map_err(drop)
            },
        );
    }

    // The requested `MachineType` is carried onto the derived ID unchanged,
    // independent of which hardware source produced the fingerprint.
    #[test]
    fn from_hardware_info_with_type_carries_machine_type() {
        check_cases(
            [
                Case {
                    scenario: "Host onto a TPM-derived ID",
                    input: (info_for_id(Some(vec![7]), None), MachineType::Host),
                    expect: Yields(MachineType::Host),
                },
                Case {
                    scenario: "Dpu onto a TPM-derived ID",
                    input: (info_for_id(Some(vec![7]), None), MachineType::Dpu),
                    expect: Yields(MachineType::Dpu),
                },
                Case {
                    scenario: "PredictedHost onto a TPM-derived ID",
                    input: (info_for_id(Some(vec![7]), None), MachineType::PredictedHost),
                    expect: Yields(MachineType::PredictedHost),
                },
                Case {
                    scenario: "Host onto a serial-derived ID",
                    input: (
                        info_for_id(None, Some(("p1", "b1", "c1"))),
                        MachineType::Host,
                    ),
                    expect: Yields(MachineType::Host),
                },
                Case {
                    scenario: "Dpu onto a serial-derived ID",
                    input: (
                        info_for_id(None, Some(("p1", "b1", "c1"))),
                        MachineType::Dpu,
                    ),
                    expect: Yields(MachineType::Dpu),
                },
                Case {
                    scenario: "PredictedHost onto a serial-derived ID",
                    input: (
                        info_for_id(None, Some(("p1", "b1", "c1"))),
                        MachineType::PredictedHost,
                    ),
                    expect: Yields(MachineType::PredictedHost),
                },
            ],
            |(info, ty)| {
                from_hardware_info_with_type(&info, ty)
                    .map(|id| id.machine_type())
                    .map_err(drop)
            },
        );
    }

    // The derivation is a deterministic hash: the same fingerprint and type
    // produce the same ID string, and the string fields differing on type/source
    // change the rendered prefix.
    #[test]
    fn from_hardware_info_with_type_is_deterministic() {
        check_values(
            [
                Check {
                    scenario: "same TPM cert and type yields the same id string",
                    input: (
                        info_for_id(Some(vec![1, 2, 3]), None),
                        info_for_id(Some(vec![1, 2, 3]), None),
                    ),
                    expect: true,
                },
                Check {
                    scenario: "different TPM certs yield different id strings",
                    input: (
                        info_for_id(Some(vec![1, 2, 3]), None),
                        info_for_id(Some(vec![4, 5, 6]), None),
                    ),
                    expect: false,
                },
                Check {
                    scenario: "different serials yield different id strings",
                    input: (
                        info_for_id(None, Some(("p1", "b1", "c1"))),
                        info_for_id(None, Some(("p2", "b1", "c1"))),
                    ),
                    expect: false,
                },
                Check {
                    scenario: "same serials yield the same id string",
                    input: (
                        info_for_id(None, Some(("p1", "b1", "c1"))),
                        info_for_id(None, Some(("p1", "b1", "c1"))),
                    ),
                    expect: true,
                },
            ],
            |(left, right)| {
                let left = from_hardware_info_with_type(&left, MachineType::Host).unwrap();
                let right = from_hardware_info_with_type(&right, MachineType::Host).unwrap();
                left.to_string() == right.to_string()
            },
        );
    }

    // The rendered ID string opens with the type+source prefix the constructed
    // fingerprint and requested type imply (see `MachineType::id_prefix` and
    // `MachineIdSource::id_char`).
    #[test]
    fn from_hardware_info_with_type_renders_expected_prefix() {
        check_cases(
            [
                Case {
                    scenario: "host + TPM renders fm100ht",
                    input: (
                        info_for_id(Some(vec![1]), None),
                        MachineType::Host,
                        "fm100ht",
                    ),
                    expect: Yields(true),
                },
                Case {
                    scenario: "dpu + TPM renders fm100dt",
                    input: (
                        info_for_id(Some(vec![1]), None),
                        MachineType::Dpu,
                        "fm100dt",
                    ),
                    expect: Yields(true),
                },
                Case {
                    scenario: "predicted host + serial renders fm100ps",
                    input: (
                        info_for_id(None, Some(("p1", "b1", "c1"))),
                        MachineType::PredictedHost,
                        "fm100ps",
                    ),
                    expect: Yields(true),
                },
                Case {
                    scenario: "host + serial renders fm100hs",
                    input: (
                        info_for_id(None, Some(("p1", "b1", "c1"))),
                        MachineType::Host,
                        "fm100hs",
                    ),
                    expect: Yields(true),
                },
            ],
            |(info, ty, prefix)| {
                from_hardware_info_with_type(&info, ty)
                    .map(|id| id.to_string().starts_with(prefix))
                    .map_err(drop)
            },
        );
    }

    // The rendered ID string is exactly `MACHINE_ID_LENGTH` characters regardless
    // of which source or type produced it.
    #[test]
    fn from_hardware_info_with_type_renders_fixed_length() {
        check_values(
            [
                Check {
                    scenario: "TPM-derived host id length",
                    input: (info_for_id(Some(vec![1, 2]), None), MachineType::Host),
                    expect: MACHINE_ID_LENGTH,
                },
                Check {
                    scenario: "serial-derived dpu id length",
                    input: (
                        info_for_id(None, Some(("p1", "b1", "c1"))),
                        MachineType::Dpu,
                    ),
                    expect: MACHINE_ID_LENGTH,
                },
                Check {
                    scenario: "serial-derived predicted-host id length",
                    input: (
                        info_for_id(None, Some(("", "b1", ""))),
                        MachineType::PredictedHost,
                    ),
                    expect: MACHINE_ID_LENGTH,
                },
            ],
            |(info, ty)| {
                from_hardware_info_with_type(&info, ty)
                    .unwrap()
                    .to_string()
                    .len()
            },
        );
    }
}
