// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers used across component-manager backends and state controllers.

// ---------------------------------------------------------------------------
// Power-state observation
// ---------------------------------------------------------------------------

/// Outcome of interpreting a single-device `get_power_state` poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowerStatePollOutcome {
    Observed(String),
    BackendError(String),
    NoPowerState,
    NoResult,
}

/// Common surface shared by switch and power-shelf power-state poll results.
pub trait ComponentPowerStateResult {
    fn power_state(&self) -> Option<&str>;
    fn error(&self) -> Option<&str>;
}

/// Interpret the first entry from a component-manager `get_power_state` response.
pub fn interpret_power_state_poll<T: ComponentPowerStateResult>(
    results: Vec<T>,
) -> PowerStatePollOutcome {
    let Some(result) = results.into_iter().next() else {
        return PowerStatePollOutcome::NoResult;
    };

    if let Some(error) = result.error() {
        return PowerStatePollOutcome::BackendError(error.to_owned());
    }

    match result.power_state() {
        Some(power_state) => PowerStatePollOutcome::Observed(power_state.to_owned()),
        None => PowerStatePollOutcome::NoPowerState,
    }
}

#[cfg(test)]
mod tests {
    use mac_address::MacAddress;

    use super::*;
    use crate::nv_switch_manager::SwitchPowerStateResult;
    use crate::power_shelf_manager::PowerShelfPowerStateResult;

    fn test_mac() -> MacAddress {
        "AA:BB:CC:DD:EE:FF".parse().unwrap()
    }

    #[test]
    fn interpret_switch_power_state_poll_observed() {
        let outcome = interpret_power_state_poll(vec![SwitchPowerStateResult {
            bmc_mac: test_mac(),
            power_state: Some("on".into()),
            error: None,
        }]);
        assert_eq!(outcome, PowerStatePollOutcome::Observed("on".to_owned()));
    }

    #[test]
    fn interpret_power_shelf_power_state_poll_backend_error() {
        let outcome = interpret_power_state_poll(vec![PowerShelfPowerStateResult {
            pmc_mac: test_mac(),
            power_state: None,
            error: Some("rms failed".into()),
        }]);
        assert_eq!(
            outcome,
            PowerStatePollOutcome::BackendError("rms failed".to_owned())
        );
    }

    #[test]
    fn interpret_power_state_poll_no_result() {
        let outcome = interpret_power_state_poll(Vec::<SwitchPowerStateResult>::new());
        assert_eq!(outcome, PowerStatePollOutcome::NoResult);
    }
}
