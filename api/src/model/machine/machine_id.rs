/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

// use std::fmt::Write;
use std::str::FromStr;

use crate::model::hardware_info::HardwareInfo;
use ::rpc::errors::RpcDataConversionError;
use data_encoding::BASE32_DNSSEC;
use forge_uuid::machine::{MachineId, MachineIdSource, MachineType, MACHINE_ID_HARDWARE_ID_LENGTH};
use sha2::{Digest, Sha256};

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
    let hash: [u8; 32] = hasher.finalize().into();

    // BASE32_DNSSEC is chosen to just generate lowercase characters and
    // numbers - which will result in valid DNS names for MachineIds.
    let encoded = BASE32_DNSSEC.encode(&hash);
    assert_eq!(encoded.len(), MACHINE_ID_HARDWARE_ID_LENGTH);

    Ok(MachineId::new(source, encoded, machine_type))
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

/// Converts a RPC MachineId into the internal data format
pub fn try_parse_machine_id(
    id: &rpc::common::MachineId,
) -> Result<MachineId, RpcDataConversionError> {
    MachineId::from_str(id.id.as_str())
        .map_err(|_| RpcDataConversionError::InvalidMachineId(id.id.clone()))
}

#[cfg(test)]
mod tests {
    use crate::model::hardware_info::TpmEkCertificate;
    use forge_uuid::machine::MACHINE_ID_LENGTH;

    use super::*;

    const TEST_DATA_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/model/hardware_info/test_data"
    );

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
            println!("Serialized: {}", serialized);
            assert!(
                DOMAIN_NAME_RE.is_match(&serialized),
                "{} is not a valid DNS name",
                serialized
            );

            let expected_prefix = format!(
                "fm100{}{}",
                expected_type.id_char(),
                expected_source.id_char()
            );

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

    #[test]
    fn derive_host_machine_id() {
        let path = format!("{}/x86_info.json", TEST_DATA_DIR);
        let data = std::fs::read(path).unwrap();
        let mut fingerprint = serde_json::from_slice::<HardwareInfo>(&data).unwrap();

        test_derive_machine_id(&mut fingerprint, MachineType::Host, from_hardware_info);
    }

    #[test]
    fn derive_dpu_machine_id() {
        let path = format!("{}/dpu_info.json", TEST_DATA_DIR);
        let data = std::fs::read(path).unwrap();
        let mut fingerprint = serde_json::from_slice::<HardwareInfo>(&data).unwrap();

        test_derive_machine_id(&mut fingerprint, MachineType::Dpu, from_hardware_info);
    }

    #[test]
    fn derive_host_machine_id_from_dpu_fingerprint() {
        let path = format!("{}/dpu_info.json", TEST_DATA_DIR);
        let data = std::fs::read(path).unwrap();
        let mut fingerprint = serde_json::from_slice::<HardwareInfo>(&data).unwrap();

        test_derive_machine_id(
            &mut fingerprint,
            MachineType::PredictedHost,
            host_id_from_dpu_hardware_info,
        );
    }

    #[test]
    fn validate_remote_id() {
        let dpu_id = try_parse_machine_id(&::rpc::common::MachineId {
            id: "fm100dsg4ekcb4sdi6hkqn0iojhj18okrr8vct64luh8957lfe8e69vme20".to_string(),
        })
        .unwrap();

        assert_eq!(
            "d33nk2ne8p59qr988hssbc84gb2b0s34vcq5j7pm5jnrbnhc6880",
            dpu_id.remote_id()
        );
    }
}
