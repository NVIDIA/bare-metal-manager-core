use std::{fmt::Display, ops::Deref};

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
#[serde(tag = "error_type", rename_all = "lowercase")]
#[allow(clippy::enum_variant_names)]
pub enum BmcMachineError {
    /// An unrecoverable error has occurred during redfish client creation or max retries was exceeded.
    RedfishConnection { message: String },
    ///  An unrecoverable error has occurred during redfish command execution or max retries was exceeded.
    RedfishCommand { command: String, message: String },
    /// Unsupported firmware version - The card is with a firmware version that is not supported, please manually upgrade and rediscover.
    UnsupportedBmcFirmware,
    /// An unrecoverable error has occurred during BMC firmware update or max retries was exceeded.
    BmcFirmwareUpdateError { message: String },
    /// Reboot state form more then 15 minutes
    RebootTimeExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "firmware_type", rename_all = "lowercase")]
pub enum FirmwareType {
    Bmc,
    Cec,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "sub_state", rename_all = "lowercase")]
pub enum Substate {
    UploadFirmware,
    WaitForUpdateCompletion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum BmcMachineState {
    /// Bmc machine got discovered through DHCP interface
    Initializing,
    /// Bmc firmware update
    FirmwareUpdate {
        firmwaretype: FirmwareType,
        substate: Substate,
    },
    /// Bmc machine is being rebooted
    BmcReboot,
    /// DPU machine is being configuring: (change UEFI password, set secure boot to disabled,
    /// move to restricted mode, and change boot order to OOB).
    Configuring,
    /// DPU machine is being rebooted (ARM from BMC POV).
    DpuReboot,
    /// DPU BMC was configured successfully.
    Initialized,
    /// An error has occurred.
    Error(BmcMachineError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_controller_state() {
        let state = BmcMachineState::Initializing {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"initializing\"}");
        assert_eq!(
            serde_json::from_str::<BmcMachineState>(&serialized).unwrap(),
            state
        );

        let error_state = BmcMachineState::Error(BmcMachineError::RedfishConnection {
            message: "failed to connect".to_string(),
        });
        let error_state_serialized = serde_json::to_string(&error_state).unwrap();
        assert_eq!(
            serde_json::from_str::<BmcMachineState>(&error_state_serialized).unwrap(),
            error_state
        );

        let firmware_state = BmcMachineState::FirmwareUpdate {
            firmwaretype: FirmwareType::Bmc,
            substate: Substate::UploadFirmware,
        };
        let firmware_state_serialized = serde_json::to_string(&firmware_state).unwrap();
        assert_eq!(firmware_state_serialized, "{\"state\":\"firmwareupdate\",\"firmwaretype\":{\"firmware_type\":\"bmc\"},\"substate\":{\"sub_state\":\"uploadfirmware\"}}");
        assert_eq!(
            serde_json::from_str::<BmcMachineState>(&firmware_state_serialized).unwrap(),
            firmware_state
        );
    }
}

impl Display for FirmwareType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for Substate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for BmcMachineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BmcMachineState::Initializing => write!(f, "BMC/Initializing"),
            BmcMachineState::Error(error_type) => write!(f, "BMC/Error({:#?})", error_type),
            BmcMachineState::Configuring => write!(f, "BMC/Configuring"),
            BmcMachineState::DpuReboot => write!(f, "BMC/DpuReboot"),
            BmcMachineState::Initialized => write!(f, "BMC/Initialized"),
            BmcMachineState::FirmwareUpdate {
                firmwaretype,
                substate,
            } => {
                write!(f, "BMC/FirmwareUpdate/{}-{}", firmwaretype, substate)
            }
            BmcMachineState::BmcReboot => write!(f, "BMC/BmcReboot"),
        }
    }
}

pub struct RpcBmcMachineTypeWrapper(rpc::forge::BmcMachineType);

impl From<BmcMachineType> for RpcBmcMachineTypeWrapper {
    fn from(value: BmcMachineType) -> Self {
        RpcBmcMachineTypeWrapper(match value {
            BmcMachineType::Dpu => rpc::forge::BmcMachineType::DpuBmc,
            BmcMachineType::Host => rpc::forge::BmcMachineType::HostBmc,
        })
    }
}

impl Deref for RpcBmcMachineTypeWrapper {
    type Target = rpc::forge::BmcMachineType;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
