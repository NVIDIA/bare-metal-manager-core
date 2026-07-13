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

/// The agent-reported event whose processing tried to wake the machine's
/// state handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, carbide_instrument::LabelValue)]
pub(crate) enum WakeupTrigger {
    RebootCompleted,
    CleanupCompleted,
    ScoutFirmwareUpgradeStatus,
    DpuNetworkStatus,
}

/// An agent report was recorded but the machine's state handler could not be
/// woken: the machine sits idle until the next periodic enqueue, so the rate
/// of these is a leading "machine stuck" signal.
#[derive(carbide_instrument::Event)]
#[event(
    name = "carbide_state_handler_wakeup_failures_total",
    component = "nico-api",
    log = warn,
    metric = counter,
    message = "Failed to wake up state handler for machine",
    describe = "The amount of times a machine's state handler could not be woken after an \
                agent-reported event"
)]
pub(crate) struct StateHandlerWakeupFailed {
    #[label]
    pub(crate) trigger: WakeupTrigger,
    #[context]
    pub(crate) machine_id: MachineId,
    #[context]
    pub(crate) err: String,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use carbide_instrument::testing::{MetricsCapture, capture_logs};

    use super::*;

    /// One emit writes the WARN line (machine id and error as fields) AND
    /// moves the counter, with every trigger variant rendering as its
    /// snake_case label value on both sides.
    #[test]
    fn wakeup_failure_logs_and_counts_by_trigger() {
        let machine_id =
            MachineId::from_str("fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30")
                .expect("a valid machine id");

        let metrics = MetricsCapture::start();
        let logs = capture_logs(|| {
            for trigger in [
                WakeupTrigger::RebootCompleted,
                WakeupTrigger::CleanupCompleted,
                WakeupTrigger::ScoutFirmwareUpgradeStatus,
                WakeupTrigger::DpuNetworkStatus,
            ] {
                carbide_instrument::emit(StateHandlerWakeupFailed {
                    trigger,
                    machine_id,
                    err: "enqueue failed".to_string(),
                });
            }
        });

        assert_eq!(logs.len(), 4);
        for log in &logs {
            assert_eq!(log.level, tracing::Level::WARN);
            assert_eq!(log.message, "Failed to wake up state handler for machine");
        }
        let field = |log: &carbide_instrument::testing::CapturedLog, name: &str| {
            log.fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(
            field(&logs[0], "trigger"),
            Some("reboot_completed".to_string())
        );
        assert_eq!(field(&logs[0], "machine_id"), Some(machine_id.to_string()));
        assert_eq!(field(&logs[0], "err"), Some("enqueue failed".to_string()));

        for label in [
            "reboot_completed",
            "cleanup_completed",
            "scout_firmware_upgrade_status",
            "dpu_network_status",
        ] {
            assert_eq!(
                metrics.counter_delta(
                    "carbide_state_handler_wakeup_failures_total",
                    &[("trigger", label)],
                ),
                1.0,
                "counter for trigger={label}"
            );
        }
    }
}
