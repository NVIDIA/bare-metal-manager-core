/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
