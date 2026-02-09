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
pub mod api_client;
pub mod api_throttler;
mod bmc_mock_wrapper;
mod config;
mod dhcp_wrapper;
mod dpu_machine;
mod host_machine;
mod machine_a_tron;
mod machine_state_machine;
mod machine_utils;
mod mock_ssh_server;
mod subnet;
mod tabs;
mod tui;
mod tui_host_logs;
mod vpc;

use std::time::{Duration, Instant};

pub use bmc_mock_wrapper::BmcMockRegistry;
pub use config::{
    MachineATronArgs, MachineATronConfig, MachineATronContext, MachineConfig, PersistedDpuMachine,
    PersistedHostMachine,
};
pub use dpu_machine::DpuMachineHandle;
pub use host_machine::HostMachineHandle;
pub use machine_a_tron::{AppEvent, MachineATron};
pub use machine_state_machine::BmcRegistrationMode;
pub use mock_ssh_server::{
    Credentials as MockSshCredentials, MockSshServerHandle, PromptBehavior,
    spawn as spawn_mock_ssh_server,
};
pub use tui::{Tui, UiUpdate};
pub use tui_host_logs::TuiHostLogs;

/// Add a Duration to an Instant, defaulting to a time in the far future if there is an overflow.
/// This allows using Duration::MAX and being able to add it to Instant::now(), which overflows by
/// default.
pub fn saturating_add_duration_to_instant(instant: Instant, duration: Duration) -> Instant {
    instant
        .checked_add(duration)
        // Roughly 30 years from now
        .unwrap_or(Instant::now() + Duration::from_secs(30 * 365 * 24 * 3600))
}
