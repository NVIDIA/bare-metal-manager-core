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

//! Control-loop and stream counters for scout. Every event here is metric-only
//! (`log = off`): the human-readable side is already carried by the existing
//! `tracing` lines at each site, and the process-wide log rate rides on
//! `carbide_log_events_total{level, component}` once `log_events::register`
//! runs. These counters add the per-action and per-stream-outcome rates that a
//! log line alone can't total.

use carbide_instrument::{Event, LabelValue, Outcome};
use rpc::forge_agent_control_response as fac;

/// Which control-loop action scout handled, as a bounded metric label: one
/// variant per [`fac::Action`] arm the service loop can dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub enum ScoutAction {
    Noop,
    Reset,
    Discovery,
    Rebuild,
    Retry,
    Measure,
    LogError,
    MachineValidation,
    MlxAction,
    FirmwareUpgrade,
}

impl From<&fac::Action> for ScoutAction {
    fn from(action: &fac::Action) -> Self {
        match action {
            fac::Action::Noop(_) => Self::Noop,
            fac::Action::Reset(_) => Self::Reset,
            fac::Action::Discovery(_) => Self::Discovery,
            fac::Action::Rebuild(_) => Self::Rebuild,
            fac::Action::Retry(_) => Self::Retry,
            fac::Action::Measure(_) => Self::Measure,
            fac::Action::LogError(_) => Self::LogError,
            fac::Action::MachineValidation(_) => Self::MachineValidation,
            fac::Action::MlxAction(_) => Self::MlxAction,
            fac::Action::FirmwareUpgrade(_) => Self::FirmwareUpgrade,
        }
    }
}

/// Scout finished handling one control-loop action, whatever the result.
#[derive(Event)]
#[event(
    name = "carbide_scout_actions_total",
    component = "nico-scout",
    log = off,
    metric = counter,
    describe = "Number of scout control-loop actions handled, by action and outcome."
)]
pub struct ScoutActionHandled {
    #[label]
    pub action: ScoutAction,
    #[label]
    pub outcome: Outcome,
}

/// A scout stream connection attempt resolved -- `ok` once the bidirectional
/// stream is established, `error` when the client could not be built.
#[derive(Event)]
#[event(
    name = "carbide_scout_stream_connections_total",
    component = "nico-scout",
    log = off,
    metric = counter,
    describe = "Number of scout stream connection attempts, by outcome."
)]
pub struct ScoutStreamConnection {
    #[label]
    pub outcome: Outcome,
}

/// The scout stream closed or errored and the loop looped back to re-establish
/// it after the reconnect delay.
#[derive(Event)]
#[event(
    name = "carbide_scout_stream_reconnects_total",
    component = "nico-scout",
    log = off,
    metric = counter,
    describe = "Number of scout stream reconnect cycles after a stream closed or errored."
)]
pub struct ScoutStreamReconnect {}

#[cfg(test)]
mod tests {
    use carbide_instrument::emit;
    use carbide_instrument::testing::MetricsCapture;
    use carbide_test_support::{Check, check_values};

    use super::*;

    #[test]
    fn scout_action_maps_every_dispatchable_action() {
        check_values(
            [
                Check {
                    scenario: "noop",
                    input: fac::Action::Noop(fac::Noop {}),
                    expect: ScoutAction::Noop,
                },
                Check {
                    scenario: "reset",
                    input: fac::Action::Reset(fac::Reset {}),
                    expect: ScoutAction::Reset,
                },
                Check {
                    scenario: "discovery",
                    input: fac::Action::Discovery(fac::Discovery {}),
                    expect: ScoutAction::Discovery,
                },
                Check {
                    scenario: "rebuild",
                    input: fac::Action::Rebuild(fac::Rebuild {}),
                    expect: ScoutAction::Rebuild,
                },
                Check {
                    scenario: "retry",
                    input: fac::Action::Retry(fac::Retry {}),
                    expect: ScoutAction::Retry,
                },
                Check {
                    scenario: "measure",
                    input: fac::Action::Measure(fac::Measure {}),
                    expect: ScoutAction::Measure,
                },
                Check {
                    scenario: "log error",
                    input: fac::Action::LogError(fac::LogError {}),
                    expect: ScoutAction::LogError,
                },
                Check {
                    scenario: "machine validation",
                    input: fac::Action::MachineValidation(fac::MachineValidation::default()),
                    expect: ScoutAction::MachineValidation,
                },
                Check {
                    scenario: "mlx action",
                    input: fac::Action::MlxAction(fac::MlxAction::default()),
                    expect: ScoutAction::MlxAction,
                },
                Check {
                    scenario: "firmware upgrade",
                    input: fac::Action::FirmwareUpgrade(fac::FirmwareUpgrade::default()),
                    expect: ScoutAction::FirmwareUpgrade,
                },
            ],
            |action| ScoutAction::from(&action),
        );
    }

    #[test]
    fn scout_counters_move_per_label() {
        let metrics = MetricsCapture::start();

        // Labels chosen so no other test in this binary shares them.
        emit(ScoutActionHandled {
            action: ScoutAction::FirmwareUpgrade,
            outcome: Outcome::Error,
        });
        emit(ScoutStreamConnection {
            outcome: Outcome::Ok,
        });
        emit(ScoutStreamReconnect {});
        emit(ScoutStreamReconnect {});

        assert_eq!(
            metrics.counter_delta(
                "carbide_scout_actions_total",
                &[("action", "firmware_upgrade"), ("outcome", "error")],
            ),
            1.0
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_scout_stream_connections_total",
                &[("outcome", "ok")],
            ),
            1.0
        );
        assert_eq!(
            metrics.counter_delta("carbide_scout_stream_reconnects_total", &[]),
            2.0
        );
    }
}
