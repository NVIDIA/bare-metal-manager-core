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
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
#[sqlx(type_name = "bmc_machine_type_t")]
pub enum BmcMachineType {
    Dpu = 0,
    Host,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
#[allow(clippy::enum_variant_names)]
pub enum BmcMachineError {
    /// An unrecoverable error has occurred during redfish client creation or max retries was exceeded.
    RedfishConnection { message: String },
    ///  An unrecoverable error has occurred during redfish command execution or max retries was exceeded.
    RedfishCommand { command: String, message: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum BmcMachineState {
    /// Bmc machine got discovered through DHCP interface
    Init,
    Error(BmcMachineError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_controller_state() {
        let state = BmcMachineState::Init {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"init\"}");
        assert_eq!(
            serde_json::from_str::<BmcMachineState>(&serialized).unwrap(),
            state
        );
    }
}
