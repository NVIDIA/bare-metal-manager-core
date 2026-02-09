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
use std::borrow::Cow;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::Instant;

mod bmc_state;
mod bug;
mod combined_server;
mod combined_service;
mod http;
mod hw;
mod json;
mod machine_info;
mod middleware_router;
mod mock_machine_router;
mod redfish;
pub mod tls;

pub use combined_server::{CombinedServer, ListenerOrAddress};
pub use machine_info::{DpuFirmwareVersions, DpuMachineInfo, HostMachineInfo, MachineInfo};
pub use mock_machine_router::{
    BmcCommand, SetSystemPowerError, SetSystemPowerResult, machine_router,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum HostHardwareType {
    #[serde(rename = "dell_poweredge_r750")]
    DellPowerEdgeR750,
    // #[serde(rename = "wiwynn_gb200_nvl")]
    // WiwynnGB200Nvl,
}

#[derive(Debug, Copy, Clone, Default)]
pub enum MockPowerState {
    #[default]
    On,
    Off,
    PowerCycling {
        since: Instant,
    },
}

// Simulate a 5-second power cycle
pub const POWER_CYCLE_DELAY: Duration = Duration::from_secs(5);

pub trait PowerControl: std::fmt::Debug + Send + Sync {
    fn get_power_state(&self) -> MockPowerState;
    fn send_power_command(&self, reset_type: SystemPowerControl)
    -> Result<(), SetSystemPowerError>;
    fn set_power_state(&self, reset_type: SystemPowerControl) -> Result<(), SetSystemPowerError> {
        type C = SystemPowerControl;
        match (reset_type, self.get_power_state()) {
            (
                C::GracefulShutdown | C::ForceOff | C::GracefulRestart | C::ForceRestart,
                MockPowerState::Off,
            ) => Err(SetSystemPowerError::BadRequest(
                "bmc-mock: cannot power off machine, it is already off".to_string(),
            )),
            (C::On | C::ForceOn, MockPowerState::On) => Err(SetSystemPowerError::BadRequest(
                "bmc-mock: cannot power on machine, it is already on".to_string(),
            )),
            (_, MockPowerState::PowerCycling { since }) if since.elapsed() < POWER_CYCLE_DELAY => {
                Err(SetSystemPowerError::BadRequest(format!(
                    "bmc-mock: cannot reset machine, it is in the middle of power cycling since {:?} ago",
                    since.elapsed()
                )))
            }
            _ => Ok(()),
        }?;
        self.send_power_command(reset_type)
    }
}

pub trait HostnameQuerying: std::fmt::Debug + Send + Sync {
    fn get_hostname(&'_ self) -> Cow<'_, str>;
}

// https://www.dmtf.org/sites/default/files/standards/documents/DSP2046_2023.3.html
// 6.5.5.1 ResetType
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone, Copy)]
pub enum SystemPowerControl {
    /// Power on a machine
    On,
    /// Graceful host shutdown
    GracefulShutdown,
    /// Forcefully powers a machine off
    ForceOff,
    /// Graceful restart. Asks the OS to restart via ACPI
    /// - Might restart DPUs if no OS is running
    /// - Will not apply pending BIOS/UEFI setting changes
    GracefulRestart,
    /// Force restart. This is equivalent to pressing the reset button on the front panel.
    /// - Will not restart DPUs
    /// - Will apply pending BIOS/UEFI setting changes
    ForceRestart,

    //
    // libredfish doesn't support these yet, and not all vendors provide them
    //

    // Cut then restore the power
    PowerCycle,

    // Forcefully power a machine on (?)
    ForceOn,

    // Like it says, pretend the button got pressed
    PushPowerButton,

    // Non-maskable interrupt then power off
    Nmi,

    // Write state to disk and power off
    Suspend,

    // VM / Hypervisor
    Pause,
    Resume,
}
