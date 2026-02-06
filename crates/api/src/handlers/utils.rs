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
