/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_uuid::machine::MachineId;

use crate::CarbideError;
use crate::api::log_machine_id;

/// Converts a MachineID from RPC format to Model format
/// and logs the MachineID as MachineID for the current request.
pub fn convert_and_log_machine_id(id: Option<&MachineId>) -> Result<MachineId, CarbideError> {
    let machine_id = match id {
        Some(id) => *id,
        None => {
            return Err(CarbideError::MissingArgument("Machine ID"));
        }
    };
    log_machine_id(&machine_id);

    Ok(machine_id)
}
