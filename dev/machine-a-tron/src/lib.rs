pub mod api_client;
pub mod api_throttler;
mod bmc_mock_wrapper;
mod config;
mod dhcp_relay;
mod dpu_machine;
mod host_machine;
mod machine_a_tron;
mod machine_state_machine;
mod machine_utils;
mod subnet;
mod tabs;
mod tui;
mod tui_host_logs;
mod vpc;

pub use bmc_mock_wrapper::BmcMockRegistry;
pub use config::{
    MachineATronArgs, MachineATronConfig, MachineATronContext, MachineConfig, PersistedDpuMachine,
    PersistedHostMachine,
};
pub use dhcp_relay::DhcpRelayService;
pub use host_machine::HostMachineActor;
pub use machine_a_tron::{AppEvent, MachineATron};
pub use machine_state_machine::BmcRegistrationMode;
use std::time::{Duration, Instant};
pub use tui::{Tui, UiEvent};
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
