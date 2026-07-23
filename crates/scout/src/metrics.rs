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

//! Scout control-loop and stream events.
//!
//! `ScoutActionHandled` and `ScoutStreamReconnect` pair their counters with
//! the records operators use to diagnose those outcomes.
//! `ScoutStreamConnection` remains metric-only because the surrounding stream
//! lifecycle logs already carry the endpoint and machine context.
//! The storage cleanup Event keeps each device's terminal record together with
//! the duration histogram operators use to compare NVMe and HDD/SAS cleanup.

use std::time::Duration;

use carbide_instrument::{DynamicLog, DynamicMessage, Event, LabelValue, LogAt, Outcome};
use carbide_uuid::machine::MachineId;
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

/// `ScoutActionHandled` records a completed control-loop action and keeps its
/// outcome counter paired with the corresponding success or failure record.
#[derive(Event)]
#[event(
    event_name = "scout_action_handled",
    metric_name = "carbide_scout_actions_total",
    component = "nico-scout",
    log = info,
    metric = counter,
    message = dynamic,
    describe = "Number of scout control-loop actions handled, by action and outcome."
)]
pub struct ScoutActionHandled {
    #[label]
    pub action: ScoutAction,
    #[label]
    pub outcome: Outcome,
    /// `action_name` retains the protobuf's uppercase spelling from the
    /// original log. The existing `action` metric label also renders its
    /// bounded `snake_case` value into the record, so both values are
    /// intentional.
    #[context]
    pub action_name: &'static str,
    /// `error` carries failure detail. Successful actions use `""` because
    /// Event context fields are present on every generated record.
    #[context]
    pub error: String,
}

impl DynamicMessage for ScoutActionHandled {
    fn message(&self) -> &'static str {
        match self.outcome {
            Outcome::Ok => "Successfully served action",
            Outcome::Error => "Failed to serve action",
        }
    }
}

/// `ScoutStreamConnection` records whether scout established its bidirectional
/// stream. `error` covers both client construction and the opening stream RPC.
#[derive(Event)]
#[event(
    event_name = "scout_stream_connection",
    metric_name = "carbide_scout_stream_connections_total",
    component = "nico-scout",
    log = off,
    metric = counter,
    describe = "Number of scout stream connection attempts, by outcome."
)]
pub struct ScoutStreamConnection {
    #[label]
    pub outcome: Outcome,
}

/// `ScoutStreamReconnect` records the retry boundary after a stream closes or
/// errors. Endpoint and machine context stay on the warning, while the counter
/// tracks how often scout reaches the fixed reconnect delay.
#[derive(Event)]
#[event(
    event_name = "scout_stream_reconnect",
    metric_name = "carbide_scout_stream_reconnects_total",
    component = "nico-scout",
    log = warn,
    metric = counter,
    message = "scout stream reconnecting after 10s delay",
    describe = "Number of scout stream reconnect cycles after a stream closed or errored."
)]
pub struct ScoutStreamReconnect {
    #[context]
    pub api_endpoint: String,
    #[context]
    pub machine_id: MachineId,
}

/// Which storage cleanup path scout ran for a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum StorageDeviceType {
    Nvme,
    HddSas,
}

/// `ScoutStorageDeviceCleanup` records one device's terminal result. The
/// enclosing cleanup span keeps the device path on the record, while this
/// Event adds the bounded labels and duration sample.
#[derive(Event)]
#[event(
    event_name = "scout_storage_device_cleanup",
    metric_name = "carbide_scout_storage_device_cleanup_duration_seconds",
    component = "nico-scout",
    log = dynamic,
    metric = histogram,
    message = dynamic,
    describe = "Duration of per-device scout storage cleanup operations, by device type and outcome."
)]
pub(crate) struct ScoutStorageDeviceCleanup {
    #[label]
    device_type: StorageDeviceType,
    #[label]
    outcome: Outcome,
    #[observation]
    took: Duration,
    /// `duration` retains the existing Debug-formatted log field; `took`
    /// records the same value in seconds.
    #[context]
    duration: String,
    /// Failure detail; successful cleanup uses `""` because an Event keeps one
    /// stable set of context fields.
    #[context]
    error: String,
}

impl ScoutStorageDeviceCleanup {
    pub(crate) fn new<E>(
        device_type: StorageDeviceType,
        duration: Duration,
        result: &Result<(), E>,
    ) -> Self
    where
        E: std::fmt::Display,
    {
        Self {
            device_type,
            outcome: Outcome::from(result),
            took: duration,
            duration: format!("{duration:?}"),
            error: result
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_default(),
        }
    }
}

impl DynamicLog for ScoutStorageDeviceCleanup {
    fn log_at(&self) -> LogAt {
        match self.outcome {
            Outcome::Ok => LogAt::Level(tracing::Level::INFO),
            Outcome::Error => LogAt::Level(tracing::Level::ERROR),
        }
    }
}

impl DynamicMessage for ScoutStorageDeviceCleanup {
    fn message(&self) -> &'static str {
        match self.outcome {
            Outcome::Ok => "Cleanup completed successfully",
            Outcome::Error => "Cleanup failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use carbide_instrument::emit;
    use carbide_instrument::testing::{CapturedFieldKind, MetricsCapture, capture_logs};
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
    fn scout_action_outcomes_log_and_count() {
        struct ActionCase {
            action: ScoutAction,
            outcome: Outcome,
            action_name: &'static str,
            error: &'static str,
            action_label: &'static str,
            outcome_label: &'static str,
        }

        #[derive(Debug, PartialEq)]
        struct LogObservation {
            metadata_name: String,
            level: tracing::Level,
            message: String,
            event_name: Option<String>,
            metric_name: Option<String>,
            action: Option<String>,
            outcome: Option<String>,
            action_name: Option<String>,
            error: Option<String>,
        }

        #[derive(Debug, PartialEq)]
        struct Observation {
            log_count: usize,
            log: Option<LogObservation>,
            counter_delta: f64,
        }

        fn expected_log(
            message: &str,
            action: &str,
            outcome: &str,
            action_name: &str,
            error: &str,
        ) -> Option<LogObservation> {
            Some(LogObservation {
                metadata_name: "scout_action_handled".to_string(),
                level: tracing::Level::INFO,
                message: message.to_string(),
                event_name: Some("scout_action_handled".to_string()),
                metric_name: Some("carbide_scout_actions_total".to_string()),
                action: Some(action.to_string()),
                outcome: Some(outcome.to_string()),
                action_name: Some(action_name.to_string()),
                error: Some(error.to_string()),
            })
        }

        check_values(
            [
                Check {
                    scenario: "successful firmware upgrade action",
                    input: ActionCase {
                        action: ScoutAction::FirmwareUpgrade,
                        outcome: Outcome::Ok,
                        action_name: "FIRMWARE_UPGRADE",
                        error: "",
                        action_label: "firmware_upgrade",
                        outcome_label: "ok",
                    },
                    expect: Observation {
                        log_count: 1,
                        log: expected_log(
                            "Successfully served action",
                            "firmware_upgrade",
                            "ok",
                            "FIRMWARE_UPGRADE",
                            "",
                        ),
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "failed machine validation action",
                    input: ActionCase {
                        action: ScoutAction::MachineValidation,
                        outcome: Outcome::Error,
                        action_name: "MACHINE_VALIDATION",
                        error: "validation command failed",
                        action_label: "machine_validation",
                        outcome_label: "error",
                    },
                    expect: Observation {
                        log_count: 1,
                        log: expected_log(
                            "Failed to serve action",
                            "machine_validation",
                            "error",
                            "MACHINE_VALIDATION",
                            "validation command failed",
                        ),
                        counter_delta: 1.0,
                    },
                },
            ],
            |case| {
                let ActionCase {
                    action,
                    outcome,
                    action_name,
                    error,
                    action_label,
                    outcome_label,
                } = case;
                let metrics = MetricsCapture::start();
                let logs = capture_logs(|| {
                    emit(ScoutActionHandled {
                        action,
                        outcome,
                        action_name,
                        error: error.to_string(),
                    });
                });
                let log = logs.first().map(|log| LogObservation {
                    metadata_name: log.metadata_name.clone(),
                    level: log.level,
                    message: log.message.clone(),
                    event_name: log.field("event_name").map(str::to_string),
                    metric_name: log.field("metric_name").map(str::to_string),
                    action: log.field("action").map(str::to_string),
                    outcome: log.field("outcome").map(str::to_string),
                    action_name: log.field("action_name").map(str::to_string),
                    error: log.field("error").map(str::to_string),
                });

                Observation {
                    log_count: logs.len(),
                    log,
                    counter_delta: metrics.counter_delta(
                        "carbide_scout_actions_total",
                        &[("action", action_label), ("outcome", outcome_label)],
                    ),
                }
            },
        );
    }

    #[test]
    fn scout_stream_connection_counter_moves_per_outcome() {
        struct ConnectionCase {
            outcome: Outcome,
            outcome_label: &'static str,
        }

        #[derive(Debug, PartialEq)]
        struct Observation {
            log_count: usize,
            counter_delta: f64,
        }

        check_values(
            [
                Check {
                    scenario: "stream connected",
                    input: ConnectionCase {
                        outcome: Outcome::Ok,
                        outcome_label: "ok",
                    },
                    expect: Observation {
                        log_count: 0,
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "stream connection failed",
                    input: ConnectionCase {
                        outcome: Outcome::Error,
                        outcome_label: "error",
                    },
                    expect: Observation {
                        log_count: 0,
                        counter_delta: 1.0,
                    },
                },
            ],
            |ConnectionCase {
                 outcome,
                 outcome_label,
             }| {
                let metrics = MetricsCapture::start();
                let logs = capture_logs(|| emit(ScoutStreamConnection { outcome }));
                Observation {
                    log_count: logs.len(),
                    counter_delta: metrics.counter_delta(
                        "carbide_scout_stream_connections_total",
                        &[("outcome", outcome_label)],
                    ),
                }
            },
        );
    }

    #[test]
    fn scout_stream_reconnect_logs_and_counts() {
        let metrics = MetricsCapture::start();
        let machine_id =
            MachineId::from_str("fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30")
                .expect("valid machine id");
        let logs = capture_logs(|| {
            emit(ScoutStreamReconnect {
                api_endpoint: "https://[::1]:1079".to_string(),
                machine_id,
            });
        });

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].metadata_name, "scout_stream_reconnect");
        assert_eq!(logs[0].level, tracing::Level::WARN);
        assert_eq!(logs[0].message, "scout stream reconnecting after 10s delay");
        assert_eq!(logs[0].field("event_name"), Some("scout_stream_reconnect"));
        assert_eq!(
            logs[0].field("metric_name"),
            Some("carbide_scout_stream_reconnects_total")
        );
        assert_eq!(logs[0].field("api_endpoint"), Some("https://[::1]:1079"));
        let machine_id = machine_id.to_string();
        assert_eq!(logs[0].field("machine_id"), Some(machine_id.as_str()));

        assert_eq!(
            metrics.counter_delta("carbide_scout_stream_reconnects_total", &[]),
            1.0
        );
    }

    #[test]
    fn storage_device_cleanup_logs_and_records_duration() {
        const METRIC_NAME: &str = "carbide_scout_storage_device_cleanup_duration_seconds";

        enum CleanupCase {
            Succeeded {
                device_type: StorageDeviceType,
                duration: Duration,
            },
            Failed {
                device_type: StorageDeviceType,
                duration: Duration,
                error: &'static str,
            },
        }

        #[derive(Debug, PartialEq)]
        struct LogObservation {
            metadata_name: String,
            level: tracing::Level,
            message: String,
            event_name: Option<String>,
            metric_name: Option<String>,
            device_type: Option<String>,
            outcome: Option<String>,
            duration: Option<String>,
            duration_kind: Option<CapturedFieldKind>,
            error: Option<String>,
            error_kind: Option<CapturedFieldKind>,
        }

        #[derive(Debug, PartialEq)]
        struct Observation {
            log_count: usize,
            log: Option<LogObservation>,
            histogram_count_delta: u64,
            histogram_sum_delta: f64,
        }

        fn observe(case: CleanupCase) -> Observation {
            let metrics = MetricsCapture::start();
            let (device_type, duration, result) = match case {
                CleanupCase::Succeeded {
                    device_type,
                    duration,
                } => (device_type, duration, Ok(())),
                CleanupCase::Failed {
                    device_type,
                    duration,
                    error,
                } => (device_type, duration, Err(error)),
            };
            let device_type_label = device_type.label_value().to_string();
            let outcome_label = match result {
                Ok(()) => "ok",
                Err(_) => "error",
            };
            let labels = [
                ("device_type", device_type_label.as_str()),
                ("outcome", outcome_label),
            ];
            let logs = capture_logs(|| {
                emit(ScoutStorageDeviceCleanup::new(
                    device_type,
                    duration,
                    &result,
                ));
            });
            let log = logs.first().map(|log| LogObservation {
                metadata_name: log.metadata_name.clone(),
                level: log.level,
                message: log.message.clone(),
                event_name: log.field("event_name").map(str::to_string),
                metric_name: log.field("metric_name").map(str::to_string),
                device_type: log.field("device_type").map(str::to_string),
                outcome: log.field("outcome").map(str::to_string),
                duration: log.field("duration").map(str::to_string),
                duration_kind: log.field_kind("duration"),
                error: log.field("error").map(str::to_string),
                error_kind: log.field_kind("error"),
            });

            Observation {
                log_count: logs.len(),
                log,
                histogram_count_delta: metrics.histogram_count_delta(METRIC_NAME, &labels),
                histogram_sum_delta: metrics.histogram_sum_delta(METRIC_NAME, &labels),
            }
        }

        check_values(
            [
                Check {
                    scenario: "NVMe cleanup succeeded",
                    input: CleanupCase::Succeeded {
                        device_type: StorageDeviceType::Nvme,
                        duration: Duration::from_millis(250),
                    },
                    expect: Observation {
                        log_count: 1,
                        log: Some(LogObservation {
                            metadata_name: "scout_storage_device_cleanup".to_string(),
                            level: tracing::Level::INFO,
                            message: "Cleanup completed successfully".to_string(),
                            event_name: Some("scout_storage_device_cleanup".to_string()),
                            metric_name: Some(METRIC_NAME.to_string()),
                            device_type: Some("nvme".to_string()),
                            outcome: Some("ok".to_string()),
                            duration: Some("250ms".to_string()),
                            duration_kind: Some(CapturedFieldKind::Debug),
                            error: Some(String::new()),
                            error_kind: Some(CapturedFieldKind::Debug),
                        }),
                        histogram_count_delta: 1,
                        histogram_sum_delta: 0.25,
                    },
                },
                Check {
                    scenario: "NVMe cleanup failed",
                    input: CleanupCase::Failed {
                        device_type: StorageDeviceType::Nvme,
                        duration: Duration::from_millis(500),
                        error: "NVMe sanitize command failed",
                    },
                    expect: Observation {
                        log_count: 1,
                        log: Some(LogObservation {
                            metadata_name: "scout_storage_device_cleanup".to_string(),
                            level: tracing::Level::ERROR,
                            message: "Cleanup failed".to_string(),
                            event_name: Some("scout_storage_device_cleanup".to_string()),
                            metric_name: Some(METRIC_NAME.to_string()),
                            device_type: Some("nvme".to_string()),
                            outcome: Some("error".to_string()),
                            duration: Some("500ms".to_string()),
                            duration_kind: Some(CapturedFieldKind::Debug),
                            error: Some("NVMe sanitize command failed".to_string()),
                            error_kind: Some(CapturedFieldKind::Debug),
                        }),
                        histogram_count_delta: 1,
                        histogram_sum_delta: 0.5,
                    },
                },
                Check {
                    scenario: "HDD/SAS cleanup succeeded",
                    input: CleanupCase::Succeeded {
                        device_type: StorageDeviceType::HddSas,
                        duration: Duration::from_millis(750),
                    },
                    expect: Observation {
                        log_count: 1,
                        log: Some(LogObservation {
                            metadata_name: "scout_storage_device_cleanup".to_string(),
                            level: tracing::Level::INFO,
                            message: "Cleanup completed successfully".to_string(),
                            event_name: Some("scout_storage_device_cleanup".to_string()),
                            metric_name: Some(METRIC_NAME.to_string()),
                            device_type: Some("hdd_sas".to_string()),
                            outcome: Some("ok".to_string()),
                            duration: Some("750ms".to_string()),
                            duration_kind: Some(CapturedFieldKind::Debug),
                            error: Some(String::new()),
                            error_kind: Some(CapturedFieldKind::Debug),
                        }),
                        histogram_count_delta: 1,
                        histogram_sum_delta: 0.75,
                    },
                },
                Check {
                    scenario: "HDD/SAS cleanup failed",
                    input: CleanupCase::Failed {
                        device_type: StorageDeviceType::HddSas,
                        duration: Duration::from_secs(1),
                        error: "HDD security erase failed",
                    },
                    expect: Observation {
                        log_count: 1,
                        log: Some(LogObservation {
                            metadata_name: "scout_storage_device_cleanup".to_string(),
                            level: tracing::Level::ERROR,
                            message: "Cleanup failed".to_string(),
                            event_name: Some("scout_storage_device_cleanup".to_string()),
                            metric_name: Some(METRIC_NAME.to_string()),
                            device_type: Some("hdd_sas".to_string()),
                            outcome: Some("error".to_string()),
                            duration: Some("1s".to_string()),
                            duration_kind: Some(CapturedFieldKind::Debug),
                            error: Some("HDD security erase failed".to_string()),
                            error_kind: Some(CapturedFieldKind::Debug),
                        }),
                        histogram_count_delta: 1,
                        histogram_sum_delta: 1.0,
                    },
                },
            ],
            observe,
        );
    }
}
