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

use std::net::IpAddr;
use std::time::Duration;

use ::carbide_utils::metrics::SharedMetricsHolder;
use carbide_instrument::{DynamicLog, Event, LabelValue, LogAt, Outcome, emit};
use libredfish::model::task::TaskState;
use libredfish::{RedfishError, SystemPowerControl};
use model::firmware::FirmwareComponentType;
use opentelemetry::StringValue;
use opentelemetry::metrics::Meter;

#[derive(Clone, Debug)]
pub struct PreingestionMetrics {
    pub machines_in_preingestion: usize,
    pub waiting_for_installation: usize,
    pub delayed_uploading: u64,
}

impl PreingestionMetrics {
    pub fn new() -> Self {
        Self {
            machines_in_preingestion: 0,
            waiting_for_installation: 0,
            delayed_uploading: 0,
        }
    }
}
fn hydrate_meter(meter: Meter, shared_metrics: SharedMetricsHolder<PreingestionMetrics>) {
    {
        let metrics = shared_metrics.clone();
        meter
            .u64_observable_gauge("carbide_preingestion_total")
            .with_description(
                "Number of known machines currently being evaluated prior to ingestion",
            )
            .with_callback(move |observer| {
                metrics.if_available(|metrics, attrs| {
                    observer.observe(metrics.machines_in_preingestion as u64, attrs);
                });
            })
            .build();
    }

    {
        let metrics = shared_metrics.clone();
        meter
                .u64_observable_gauge("carbide_preingestion_waiting_installation")
                .with_description(
                    "Number of machines which have had firmware uploaded to them and are currently in the process of installing that firmware"
                ).with_callback(move |observer| {
                metrics.if_available(|metrics, attrs| {
                    observer.observe(metrics.waiting_for_installation as u64, attrs)
                });
            }).build();
    }

    {
        let metrics = shared_metrics;
        meter
            .u64_observable_gauge("carbide_preingestion_waiting_download")
            .with_description("Number of machines that are waiting for firmware downloads on other machines to complete before doing their own")
            .with_callback(move |observer| {
                metrics.if_available(|metrics, attrs| {
                    observer.observe(
                        metrics.delayed_uploading,
                        attrs,
                    );
                });
            })
            .build();
    }
}

pub struct MetricHolder {
    last_iteration_metrics: SharedMetricsHolder<PreingestionMetrics>,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: std::time::Duration) -> Self {
        let last_iteration_metrics = SharedMetricsHolder::with_hold_period(hold_period);
        hydrate_meter(meter, last_iteration_metrics.clone());
        Self {
            last_iteration_metrics,
        }
    }

    /// Updates the most recent metrics
    pub fn update_metrics(&self, metrics: PreingestionMetrics) {
        self.last_iteration_metrics.update(metrics);
    }
}

// ---------------------------------------------------------------------------
// Occurrence events (the instrumentation framework). These land on the global
// meter -- carbide-api's meter provider exposes them on /metrics -- and are
// separate from the point-in-time gauges above, which stay on the
// `SharedMetricsHolder` pattern and the `Meter` passed into `MetricHolder`.
// ---------------------------------------------------------------------------

/// How a BFB copy ended, as a bounded metric label. `Ok` and `Error` are the
/// spawned copy task's own result; `Timeout` is the state machine giving up
/// on a copy whose task died without ever reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum BfbCopyOutcome {
    Ok,
    Error,
    Timeout,
}

/// A BFB copy to a DPU rshim ran to completion, or timed out. The event owns
/// the completion log line (INFO on success, ERROR otherwise) and records the
/// copy's duration -- a roughly 30-minute operation whose duration previously
/// existed only as log timestamps.
#[derive(Event)]
#[event(
    name = "carbide_preingestion_bfb_copy_duration_seconds",
    component = "preingestion-manager",
    log = dynamic,
    metric = histogram,
    message = "BFB copy finished",
    describe = "Duration of preingestion BFB copies to a DPU rshim, by outcome; the _count \
                series, split by outcome, is the copy and failure rate."
)]
pub(crate) struct BfbCopyFinished {
    #[label]
    pub outcome: BfbCopyOutcome,
    #[observation]
    pub took: Duration,
    #[context]
    pub address: IpAddr,
    /// The copy failure, when there was one; empty on success.
    #[context]
    pub error: String,
}

impl DynamicLog for BfbCopyFinished {
    fn log_at(&self) -> LogAt {
        match self.outcome {
            BfbCopyOutcome::Ok => LogAt::Level(tracing::Level::INFO),
            BfbCopyOutcome::Error | BfbCopyOutcome::Timeout => LogAt::Level(tracing::Level::ERROR),
        }
    }
}

/// The Redfish route a preingestion firmware upload went through, as a
/// bounded metric label: `SimpleUpdate` is the BFB image-URI path,
/// `Multipart` the standard file push, and `HttpPush` the fallback when a
/// BMC does not support multipart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum FirmwareUploadMethod {
    SimpleUpdate,
    Multipart,
    HttpPush,
}

/// A preingestion firmware upload to a BMC finished. Metric-only: each upload
/// site in `initiate_update` keeps its own log line untouched (their messages
/// differ per route), and this counter is the shared rate beside them. A
/// multipart attempt a BMC rejects as unsupported counts as a `multipart`
/// error followed by the `http_push` fallback's own outcome.
#[derive(Event)]
#[event(
    name = "carbide_preingestion_firmware_upload_total",
    component = "preingestion-manager",
    log = off,
    metric = counter,
    describe = "Number of preingestion firmware uploads to a BMC, by upload method and outcome."
)]
pub(crate) struct FirmwareUploadFinished {
    #[label]
    pub method: FirmwareUploadMethod,
    #[label]
    pub outcome: Outcome,
}

/// `FirmwareComponentType` as a bounded metric label. The manual impl is the
/// framework's reviewed escape hatch: the type is a fieldless enum in
/// `model::firmware` (bounded by construction), and the orphan rule keeps the
/// derive out of reach from here. The rendering mirrors what
/// `#[derive(LabelValue)]` would produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FirmwareComponentLabel(pub FirmwareComponentType);

impl LabelValue for FirmwareComponentLabel {
    fn label_value(&self) -> StringValue {
        StringValue::from(match self.0 {
            FirmwareComponentType::Bmc => "bmc",
            FirmwareComponentType::Cec => "cec",
            FirmwareComponentType::Uefi => "uefi",
            FirmwareComponentType::Nic => "nic",
            FirmwareComponentType::CpldMb => "cpld_mb",
            FirmwareComponentType::CpldPdb => "cpld_pdb",
            FirmwareComponentType::HGXBmc => "hgx_bmc",
            FirmwareComponentType::CombinedBmcUefi => "combined_bmc_uefi",
            FirmwareComponentType::Gpu => "gpu",
            FirmwareComponentType::Cx7 => "cx7",
            FirmwareComponentType::Unknown => "unknown",
        })
    }
}

/// The terminal state a firmware upgrade's Redfish task reported, as a
/// bounded metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum UpgradeTaskFinalState {
    Completed,
    Exception,
    Interrupted,
    Killed,
    Cancelled,
}

impl UpgradeTaskFinalState {
    /// Maps a failed Redfish task state onto the label. `Killed` doubles as
    /// the fallback for anything outside the failure states the caller
    /// matches -- the same fallback the site's failure text has always used
    /// for an absent state.
    pub(crate) fn from_failed_task_state(state: TaskState) -> Self {
        match state {
            TaskState::Exception => Self::Exception,
            TaskState::Interrupted => Self::Interrupted,
            TaskState::Cancelled => Self::Cancelled,
            _ => Self::Killed,
        }
    }
}

/// A preingestion firmware upgrade's Redfish task reached a terminal state.
/// Successes are counted silently (the surrounding INFO lines already narrate
/// them); a failure owns the WARN line, so an endpoint failing over and over
/// shows up as a moving error series.
#[derive(Event)]
#[event(
    name = "carbide_preingestion_firmware_upgrade_tasks_total",
    component = "preingestion-manager",
    log = dynamic,
    metric = counter,
    message = "Firmware upgrade task finished",
    describe = "Number of preingestion firmware upgrade Redfish tasks reaching a terminal \
                state, by firmware component, final task state, and outcome."
)]
pub(crate) struct FirmwareUpgradeTaskFinished {
    #[label]
    pub firmware: FirmwareComponentLabel,
    #[label]
    pub final_state: UpgradeTaskFinalState,
    #[label]
    pub outcome: Outcome,
    #[context]
    pub address: IpAddr,
    /// The task's last reported message, when it failed; empty on success.
    #[context]
    pub error: String,
}

impl DynamicLog for FirmwareUpgradeTaskFinished {
    fn log_at(&self) -> LogAt {
        match self.outcome {
            Outcome::Ok => LogAt::Off,
            Outcome::Error => LogAt::Level(tracing::Level::WARN),
        }
    }
}

/// The Redfish power operation performed, as a bounded metric label. Host
/// power controls mirror `SystemPowerControl` variant for variant; the BMC
/// and chassis resets are the two reset calls preingestion also issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum PowerOperation {
    On,
    GracefulShutdown,
    ForceOff,
    GracefulRestart,
    ForceRestart,
    AcPowercycle,
    PowerCycle,
    BmcReset,
    ChassisReset,
}

impl From<SystemPowerControl> for PowerOperation {
    fn from(control: SystemPowerControl) -> Self {
        match control {
            SystemPowerControl::On => Self::On,
            SystemPowerControl::GracefulShutdown => Self::GracefulShutdown,
            SystemPowerControl::ForceOff => Self::ForceOff,
            SystemPowerControl::GracefulRestart => Self::GracefulRestart,
            SystemPowerControl::ForceRestart => Self::ForceRestart,
            SystemPowerControl::ACPowercycle => Self::AcPowercycle,
            SystemPowerControl::PowerCycle => Self::PowerCycle,
        }
    }
}

impl PowerOperation {
    /// Whether `RedfishError::UnnecessaryOperation` means this operation's
    /// goal already held. libredfish maps every HTTP 409 onto that error: for
    /// an operation that targets a power state a 409 means "already in the
    /// requested state", which is success in all but name. Restarts and
    /// powercycles are transitions with no requested state to already be in
    /// -- a 409 is the BMC refusing the operation (a powercycle on a chassis
    /// that must first be off, a restart of a host that is not running) --
    /// and the BMC and chassis resets likewise, so for all of those it stays
    /// an error.
    fn treats_unnecessary_as_ok(self) -> bool {
        matches!(self, Self::On | Self::GracefulShutdown | Self::ForceOff)
    }
}

/// A preingestion Redfish power operation completed. Metric-only: every call
/// site keeps its own log line (each already reports the endpoint and error
/// at its own level), and this counter is the shared failure-rate signal
/// beside them.
#[derive(Event)]
#[event(
    name = "carbide_preingestion_power_control_total",
    component = "preingestion-manager",
    log = off,
    metric = counter,
    describe = "Number of preingestion Redfish power operations (host power control, BMC and \
                chassis resets), by operation and outcome."
)]
pub(crate) struct PowerControlFinished {
    #[label]
    pub operation: PowerOperation,
    #[label]
    pub outcome: Outcome,
}

/// Wraps one preingestion Redfish power operation: the result is returned
/// untouched, and its outcome ticks `carbide_preingestion_power_control_total`.
/// For operations that target a power state (`On`, `GracefulShutdown`,
/// `ForceOff`), `RedfishError::UnnecessaryOperation` counts as `ok` (the
/// requested state already held); for restarts, powercycles, and the BMC and
/// chassis resets it counts as `error` -- there is no state to already be in,
/// so a 409 is a refusal (see [`PowerOperation::treats_unnecessary_as_ok`]).
pub(crate) async fn count_power_op<T>(
    operation: PowerOperation,
    call: impl Future<Output = Result<T, RedfishError>>,
) -> Result<T, RedfishError> {
    let result = call.await;
    let outcome = match &result {
        Ok(_) => Outcome::Ok,
        Err(RedfishError::UnnecessaryOperation) if operation.treats_unnecessary_as_ok() => {
            Outcome::Ok
        }
        Err(_) => Outcome::Error,
    };
    emit(PowerControlFinished { operation, outcome });
    result
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use carbide_instrument::testing::{MetricsCapture, capture_logs};
    use carbide_test_support::{Check, check_values};
    use carbide_utils::test_support::test_meter::TestMeter;
    use prometheus_text_parser::ParsedPrometheusMetrics;

    use super::*;

    #[test]
    fn test_metrics_collector() {
        let mut metrics = PreingestionMetrics::new();
        metrics.delayed_uploading = 10;
        metrics.waiting_for_installation = 15;
        metrics.machines_in_preingestion = 20;
        let test_meter = TestMeter::default();

        let metric_holder = Arc::new(MetricHolder::new(test_meter.meter(), Duration::MAX));
        metric_holder.update_metrics(metrics);

        assert_eq!(
            test_meter
                .export_metrics()
                .parse::<ParsedPrometheusMetrics>()
                .unwrap(),
            include_str!("fixtures/test_metrics_collector.txt")
                .parse::<ParsedPrometheusMetrics>()
                .unwrap()
        );
    }

    /// The label vocabularies are the dashboard contract: every power
    /// operation renders as its snake_case name, and the `From` mapping
    /// covers `SystemPowerControl` variant for variant.
    #[test]
    fn power_operation_label_covers_every_system_power_control() {
        check_values(
            [
                Check {
                    scenario: "power on",
                    input: PowerOperation::from(SystemPowerControl::On),
                    expect: "on".to_string(),
                },
                Check {
                    scenario: "graceful shutdown",
                    input: PowerOperation::from(SystemPowerControl::GracefulShutdown),
                    expect: "graceful_shutdown".to_string(),
                },
                Check {
                    scenario: "force off",
                    input: PowerOperation::from(SystemPowerControl::ForceOff),
                    expect: "force_off".to_string(),
                },
                Check {
                    scenario: "graceful restart",
                    input: PowerOperation::from(SystemPowerControl::GracefulRestart),
                    expect: "graceful_restart".to_string(),
                },
                Check {
                    scenario: "force restart",
                    input: PowerOperation::from(SystemPowerControl::ForceRestart),
                    expect: "force_restart".to_string(),
                },
                Check {
                    scenario: "AC powercycle",
                    input: PowerOperation::from(SystemPowerControl::ACPowercycle),
                    expect: "ac_powercycle".to_string(),
                },
                Check {
                    scenario: "powercycle",
                    input: PowerOperation::from(SystemPowerControl::PowerCycle),
                    expect: "power_cycle".to_string(),
                },
                Check {
                    scenario: "BMC reset",
                    input: PowerOperation::BmcReset,
                    expect: "bmc_reset".to_string(),
                },
                Check {
                    scenario: "chassis reset",
                    input: PowerOperation::ChassisReset,
                    expect: "chassis_reset".to_string(),
                },
            ],
            |operation| operation.label_value().to_string(),
        );
    }

    /// The manual `LabelValue` impl must render exactly what the derive
    /// would: the variant's snake_case name, for every component type.
    #[test]
    fn firmware_component_label_renders_snake_case() {
        check_values(
            [
                Check {
                    scenario: "BMC",
                    input: FirmwareComponentType::Bmc,
                    expect: "bmc".to_string(),
                },
                Check {
                    scenario: "CEC",
                    input: FirmwareComponentType::Cec,
                    expect: "cec".to_string(),
                },
                Check {
                    scenario: "UEFI",
                    input: FirmwareComponentType::Uefi,
                    expect: "uefi".to_string(),
                },
                Check {
                    scenario: "NIC",
                    input: FirmwareComponentType::Nic,
                    expect: "nic".to_string(),
                },
                Check {
                    scenario: "CPLD MB",
                    input: FirmwareComponentType::CpldMb,
                    expect: "cpld_mb".to_string(),
                },
                Check {
                    scenario: "CPLD PDB",
                    input: FirmwareComponentType::CpldPdb,
                    expect: "cpld_pdb".to_string(),
                },
                Check {
                    scenario: "HGX BMC",
                    input: FirmwareComponentType::HGXBmc,
                    expect: "hgx_bmc".to_string(),
                },
                Check {
                    scenario: "combined BMC+UEFI",
                    input: FirmwareComponentType::CombinedBmcUefi,
                    expect: "combined_bmc_uefi".to_string(),
                },
                Check {
                    scenario: "GPU",
                    input: FirmwareComponentType::Gpu,
                    expect: "gpu".to_string(),
                },
                Check {
                    scenario: "CX7",
                    input: FirmwareComponentType::Cx7,
                    expect: "cx7".to_string(),
                },
                Check {
                    scenario: "unknown",
                    input: FirmwareComponentType::Unknown,
                    expect: "unknown".to_string(),
                },
            ],
            |component| FirmwareComponentLabel(component).label_value().to_string(),
        );
    }

    /// `from_failed_task_state` maps each terminal failure to its own label
    /// value, and anything outside the failure set falls back to `killed`.
    #[test]
    fn upgrade_task_final_state_maps_failure_states() {
        check_values(
            [
                Check {
                    scenario: "exception",
                    input: TaskState::Exception,
                    expect: "exception".to_string(),
                },
                Check {
                    scenario: "interrupted",
                    input: TaskState::Interrupted,
                    expect: "interrupted".to_string(),
                },
                Check {
                    scenario: "cancelled",
                    input: TaskState::Cancelled,
                    expect: "cancelled".to_string(),
                },
                Check {
                    scenario: "killed",
                    input: TaskState::Killed,
                    expect: "killed".to_string(),
                },
                Check {
                    scenario: "fallback outside the failure set",
                    input: TaskState::Running,
                    expect: "killed".to_string(),
                },
            ],
            |state| {
                UpgradeTaskFinalState::from_failed_task_state(state)
                    .label_value()
                    .to_string()
            },
        );
    }

    /// One emit per copy: the histogram records the duration under the copy's
    /// outcome, and the event owns the completion line -- INFO for a success,
    /// ERROR for a failure or timeout.
    #[test]
    fn bfb_copy_finished_records_duration_and_owns_the_completion_line() {
        let metrics = MetricsCapture::start();
        let logs = capture_logs(|| {
            emit(BfbCopyFinished {
                outcome: BfbCopyOutcome::Ok,
                took: Duration::from_secs(90),
                address: IpAddr::from([10, 0, 0, 5]),
                error: String::new(),
            });
            emit(BfbCopyFinished {
                outcome: BfbCopyOutcome::Error,
                took: Duration::from_secs(30),
                address: IpAddr::from([10, 0, 0, 6]),
                error: "ssh connection reset".to_string(),
            });
            emit(BfbCopyFinished {
                outcome: BfbCopyOutcome::Timeout,
                took: Duration::from_secs(2100),
                address: IpAddr::from([10, 0, 0, 7]),
                error: "BFB copy timed out after 35 minutes".to_string(),
            });
        });

        assert_eq!(logs.len(), 3, "every outcome writes its line: {logs:?}");
        assert_eq!(logs[0].level, tracing::Level::INFO);
        assert_eq!(logs[1].level, tracing::Level::ERROR);
        assert_eq!(logs[2].level, tracing::Level::ERROR);

        for (outcome, seconds) in [("ok", 90.0), ("error", 30.0), ("timeout", 2100.0)] {
            assert_eq!(
                metrics.histogram_count_delta(
                    "carbide_preingestion_bfb_copy_duration_seconds",
                    &[("outcome", outcome)],
                ),
                1,
                "one observation under outcome={outcome}",
            );
            let sum = metrics.histogram_sum_delta(
                "carbide_preingestion_bfb_copy_duration_seconds",
                &[("outcome", outcome)],
            );
            assert!(
                (sum - seconds).abs() < 1e-9,
                "outcome={outcome} records {seconds}s, got {sum}"
            );
        }
    }

    /// Upload outcomes count per method without constructing any log line;
    /// the `initiate_update` sites keep their own messages.
    #[test]
    fn firmware_upload_counts_by_method_without_logging() {
        let metrics = MetricsCapture::start();
        let logs = capture_logs(|| {
            emit(FirmwareUploadFinished {
                method: FirmwareUploadMethod::SimpleUpdate,
                outcome: Outcome::Ok,
            });
            emit(FirmwareUploadFinished {
                method: FirmwareUploadMethod::Multipart,
                outcome: Outcome::Error,
            });
            emit(FirmwareUploadFinished {
                method: FirmwareUploadMethod::HttpPush,
                outcome: Outcome::Ok,
            });
        });

        assert!(
            logs.is_empty(),
            "log = off must not construct any log line, got {logs:?}"
        );
        for (method, outcome, expect) in [
            ("simple_update", "ok", 1.0),
            ("multipart", "error", 1.0),
            ("http_push", "ok", 1.0),
            ("multipart", "ok", 0.0),
        ] {
            assert_eq!(
                metrics.counter_delta(
                    "carbide_preingestion_firmware_upload_total",
                    &[("method", method), ("outcome", outcome)],
                ),
                expect,
                "series method={method} outcome={outcome}",
            );
        }
    }

    /// Successes are counted silently; a failure owns the WARN line with the
    /// endpoint and the task's message as context.
    #[test]
    fn firmware_upgrade_task_failures_own_the_warn_line() {
        let metrics = MetricsCapture::start();
        let logs = capture_logs(|| {
            emit(FirmwareUpgradeTaskFinished {
                firmware: FirmwareComponentLabel(FirmwareComponentType::Bmc),
                final_state: UpgradeTaskFinalState::Completed,
                outcome: Outcome::Ok,
                address: IpAddr::from([10, 0, 0, 5]),
                error: String::new(),
            });
            emit(FirmwareUpgradeTaskFinished {
                firmware: FirmwareComponentLabel(FirmwareComponentType::Uefi),
                final_state: UpgradeTaskFinalState::Exception,
                outcome: Outcome::Error,
                address: IpAddr::from([10, 0, 0, 6]),
                error: "flash verification failed".to_string(),
            });
        });

        assert_eq!(logs.len(), 1, "only the failure logs: {logs:?}");
        assert_eq!(logs[0].level, tracing::Level::WARN);

        assert_eq!(
            metrics.counter_delta(
                "carbide_preingestion_firmware_upgrade_tasks_total",
                &[
                    ("firmware", "bmc"),
                    ("final_state", "completed"),
                    ("outcome", "ok"),
                ],
            ),
            1.0,
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_preingestion_firmware_upgrade_tasks_total",
                &[
                    ("firmware", "uefi"),
                    ("final_state", "exception"),
                    ("outcome", "error"),
                ],
            ),
            1.0,
        );
    }

    /// The wrapper returns the call's result untouched and splits
    /// `UnnecessaryOperation` (libredfish's mapping of every HTTP 409) by
    /// operation: `ok` for operations that target a power state, where it
    /// means "already in the requested state", and `error` for restarts,
    /// powercycles, and the BMC and chassis resets, where a 409 is the BMC
    /// refusing the operation. Every other error counts as `error`. No log
    /// line: the call sites own their own.
    #[test]
    fn count_power_op_splits_unnecessary_operation_by_operation() {
        use futures_util::FutureExt as _;

        let metrics = MetricsCapture::start();
        let logs = capture_logs(|| {
            count_power_op(PowerOperation::ForceOff, std::future::ready(Ok(())))
                .now_or_never()
                .expect("ready future")
                .expect("ok result passes through");
            count_power_op(
                PowerOperation::ForceOff,
                std::future::ready(Err::<(), _>(RedfishError::UnnecessaryOperation)),
            )
            .now_or_never()
            .expect("ready future")
            .expect_err("the error itself still propagates");
            count_power_op(
                PowerOperation::AcPowercycle,
                std::future::ready(Err::<(), _>(RedfishError::UnnecessaryOperation)),
            )
            .now_or_never()
            .expect("ready future")
            .expect_err("the error itself still propagates");
            count_power_op(
                PowerOperation::ForceRestart,
                std::future::ready(Err::<(), _>(RedfishError::UnnecessaryOperation)),
            )
            .now_or_never()
            .expect("ready future")
            .expect_err("the error itself still propagates");
            count_power_op(
                PowerOperation::BmcReset,
                std::future::ready(Err::<(), _>(RedfishError::UnnecessaryOperation)),
            )
            .now_or_never()
            .expect("ready future")
            .expect_err("the error itself still propagates");
            count_power_op(
                PowerOperation::ChassisReset,
                std::future::ready(Err::<(), _>(RedfishError::UnnecessaryOperation)),
            )
            .now_or_never()
            .expect("ready future")
            .expect_err("the error itself still propagates");
            count_power_op(
                PowerOperation::BmcReset,
                std::future::ready(Err::<(), _>(RedfishError::NotSupported(
                    "no such reset".to_string(),
                ))),
            )
            .now_or_never()
            .expect("ready future")
            .expect_err("the error itself still propagates");
        });

        assert!(
            logs.is_empty(),
            "log = off must not construct any log line, got {logs:?}"
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_preingestion_power_control_total",
                &[("operation", "force_off"), ("outcome", "ok")],
            ),
            2.0,
            "a real success and an already-in-state 409 both count as ok",
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_preingestion_power_control_total",
                &[("operation", "bmc_reset"), ("outcome", "error")],
            ),
            2.0,
            "for a BMC reset a 409 is a refusal, not an outcome that already held",
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_preingestion_power_control_total",
                &[("operation", "chassis_reset"), ("outcome", "error")],
            ),
            1.0,
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_preingestion_power_control_total",
                &[("operation", "ac_powercycle"), ("outcome", "error")],
            ),
            1.0,
            "a powercycle has no state to already be in; its 409 is a refusal",
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_preingestion_power_control_total",
                &[("operation", "force_restart"), ("outcome", "error")],
            ),
            1.0,
            "a restart has no state to already be in; its 409 is a refusal",
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_preingestion_power_control_total",
                &[("operation", "bmc_reset"), ("outcome", "ok")],
            ),
            0.0,
            "an untouched label pair must not move",
        );
    }
}
