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

use carbide_uuid::switch::{SwitchId, SwitchIdSource, SwitchType};
use sha2::{Digest, Sha256};

/// Generates a Switch ID from the hardware fingerprint
///
/// Returns `None` if no sufficient data is available
pub fn from_hardware_info_with_type(
    serial: &str,
    vendor: &str,
    model: &str,
    source: SwitchIdSource,
    switch_type: SwitchType,
) -> Result<SwitchId, MissingHardwareInfo> {
    let bytes = format!("s{}-b{}-c{}", serial, vendor, model);
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_bytes());

    Ok(SwitchId::new(source, hasher.finalize().into(), switch_type))
}

/// Generates a Switch ID from a hardware fingerprint
pub fn from_hardware_info(
    serial: &str,
    vendor: &str,
    model: &str,
    source: SwitchIdSource,
    switch_type: SwitchType,
) -> Result<SwitchId, MissingHardwareInfo> {
    from_hardware_info_with_type(serial, vendor, model, source, switch_type)
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
