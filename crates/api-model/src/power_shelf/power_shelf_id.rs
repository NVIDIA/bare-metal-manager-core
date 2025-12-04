/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_uuid::power_shelf::{PowerShelfId, PowerShelfIdSource, PowerShelfType};
use sha2::{Digest, Sha256};

/// Generates a Power Shelf ID from the hardware fingerprint
///
/// Returns `None` if no sufficient data is available
pub fn from_hardware_info_with_type(
    serial: &str,
    vendor: &str,
    model: &str,
    source: PowerShelfIdSource,
    power_shelf_type: PowerShelfType,
) -> Result<PowerShelfId, MissingHardwareInfo> {
    let bytes = format!("s{}-b{}-c{}", serial, vendor, model);
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_bytes());

    Ok(PowerShelfId::new(
        source,
        hasher.finalize().into(),
        power_shelf_type,
    ))
}

/// Generates a Power Shelf ID from a hardware fingerprint
pub fn from_hardware_info(
    serial: &str,
    vendor: &str,
    model: &str,
    source: PowerShelfIdSource,
    power_shelf_type: PowerShelfType,
) -> Result<PowerShelfId, MissingHardwareInfo> {
    from_hardware_info_with_type(serial, vendor, model, source, power_shelf_type)
}

#[derive(Debug, Copy, Clone, PartialEq, thiserror::Error)]
#[allow(dead_code)]
pub enum MissingHardwareInfo {
    #[error("The TPM certificate has no bytes")]
    TPMCertEmpty,
    #[error("Serial number missing (product, board and chassis)")]
    Serial,
    #[error("TPM and DMI data are both missing")]
    All,
}
