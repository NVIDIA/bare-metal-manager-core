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

/// `ScoutStreamResponseDropped` records a response scout could not return
/// after the outbound request stream closed. The stream loop still breaks and
/// reconnects, while this Event identifies the response that was lost.
#[derive(Event)]
#[event(
    event_name = "scout_stream_response_dropped",
    metric_name = "carbide_scout_stream_responses_dropped_total",
    component = "nico-scout",
    log = error,
    metric = counter,
    message = "scout stream failed to send response",
    describe = "Number of scout stream responses dropped after the outbound request stream closed."
)]
pub(crate) struct ScoutStreamResponseDropped {
    #[context]
    pub api_endpoint: String,
    #[context]
    pub machine_id: MachineId,
    #[context]
    pub error: String,
}

/// Which firmware-upgrade input is being downloaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum FirmwareDownloadKind {
    Script,
    Artifact,
}

/// What Scout will do after a failed firmware download attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum FirmwareDownloadNextAction {
    Retry,
    GiveUp,
}

/// A firmware download attempt failed.
#[derive(Event)]
#[event(
    event_name = "scout_firmware_download_attempt_failed",
    metric_name = "carbide_scout_firmware_download_attempt_failures_total",
    component = "nico-scout",
    log = warn,
    metric = counter,
    message = "[firmware_upgrade] download attempt failed; retrying",
    describe = "Number of failed Scout firmware download attempts, by download kind and next action."
)]
pub(crate) struct ScoutFirmwareDownloadAttemptFailed {
    #[label]
    pub kind: FirmwareDownloadKind,
    #[label]
    pub next_action: FirmwareDownloadNextAction,
    #[context(value)]
    pub attempt: i64,
    #[context]
    pub url: String,
    #[context]
    pub error: String,
    #[context(value)]
    pub retry_delay_seconds: f64,
}

/// The bounded operation vocabulary for Scout's MLX failure counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum ScoutMlxOperation {
    DeviceReportPublish,
    InfoReport,
    ObservationReport,
    Reconciliation,
    ProfileCompare,
    LockdownStatus,
    DeviceInfo,
    RegistryShow,
    ConfigQuery,
    ConfigCompare,
}

/// Where an MLX operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum ScoutMlxFailureStage {
    Create,
    Publish,
    Decode,
    Validate,
    Discover,
    Initialize,
    Lookup,
    Execute,
    Serialize,
}

/// The bounded class of an MLX failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum ScoutMlxFailureKind {
    InvalidRequest,
    NotFound,
    Backend,
    Serialization,
    Rpc,
}

impl ScoutMlxFailureStage {
    fn failure_kind(self) -> ScoutMlxFailureKind {
        match self {
            Self::Create | Self::Discover | Self::Initialize | Self::Execute => {
                ScoutMlxFailureKind::Backend
            }
            Self::Publish => ScoutMlxFailureKind::Rpc,
            Self::Decode | Self::Validate => ScoutMlxFailureKind::InvalidRequest,
            Self::Lookup => ScoutMlxFailureKind::NotFound,
            Self::Serialize => ScoutMlxFailureKind::Serialization,
        }
    }
}

// The operation, request, device, profile, registry, config, and
// reconciliation families all feed `carbide_scout_mlx_failures_total`, but
// their existing diagnostics need different context. Keep separate `Event`
// structs so each log retains its fields without filling unrelated fields
// with empty values.
//
// Named constructors own each valid (`operation`, `failure_stage`) pair and
// derive `failure_kind` from the stage. That makes contradictory metric
// series unrepresentable at call sites. The dynamic log and message matches
// still have generic fallbacks: `emit()` is diagnostic plumbing and must not
// panic if a future constructor reaches a pair its matching table does not
// know yet.

/// An MLX failure whose existing diagnostic only carries an error.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_operation_failed",
    metric_name = "carbide_scout_mlx_failures_total",
    component = "nico-scout",
    log = dynamic,
    metric = counter,
    message = dynamic,
    describe = "Number of Scout MLX observation and read failures, by operation, failure stage, and failure kind."
)]
pub(crate) struct ScoutMlxOperationFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[label]
    failure_kind: ScoutMlxFailureKind,
    #[context]
    error: String,
}

impl ScoutMlxOperationFailed {
    fn new(
        operation: ScoutMlxOperation,
        failure_stage: ScoutMlxFailureStage,
        error: String,
    ) -> Self {
        Self {
            operation,
            failure_stage,
            failure_kind: failure_stage.failure_kind(),
            error,
        }
    }

    pub(crate) fn device_report_create(error: String) -> Self {
        Self::new(
            ScoutMlxOperation::DeviceReportPublish,
            ScoutMlxFailureStage::Create,
            error,
        )
    }

    pub(crate) fn device_report_publish(error: String) -> Self {
        Self::new(
            ScoutMlxOperation::DeviceReportPublish,
            ScoutMlxFailureStage::Publish,
            error,
        )
    }

    pub(crate) fn observation_report_publish(error: String) -> Self {
        Self::new(
            ScoutMlxOperation::ObservationReport,
            ScoutMlxFailureStage::Publish,
            error,
        )
    }

    pub(crate) fn profile_compare_decode(error: String) -> Self {
        Self::new(
            ScoutMlxOperation::ProfileCompare,
            ScoutMlxFailureStage::Decode,
            error,
        )
    }

    pub(crate) fn profile_compare_serialize(error: String) -> Self {
        Self::new(
            ScoutMlxOperation::ProfileCompare,
            ScoutMlxFailureStage::Serialize,
            error,
        )
    }

    pub(crate) fn lockdown_status_initialize(error: String) -> Self {
        Self::new(
            ScoutMlxOperation::LockdownStatus,
            ScoutMlxFailureStage::Initialize,
            error,
        )
    }

    pub(crate) fn info_report_decode(error: String) -> Self {
        Self::new(
            ScoutMlxOperation::InfoReport,
            ScoutMlxFailureStage::Decode,
            error,
        )
    }

    pub(crate) fn info_report_execute(error: String) -> Self {
        Self::new(
            ScoutMlxOperation::InfoReport,
            ScoutMlxFailureStage::Execute,
            error,
        )
    }
}

impl DynamicLog for ScoutMlxOperationFailed {
    fn log_at(&self) -> LogAt {
        match (self.operation, self.failure_stage) {
            (
                ScoutMlxOperation::DeviceReportPublish,
                ScoutMlxFailureStage::Create | ScoutMlxFailureStage::Publish,
            ) => LogAt::Level(tracing::Level::WARN),
            (ScoutMlxOperation::ObservationReport, ScoutMlxFailureStage::Publish)
            | (ScoutMlxOperation::ProfileCompare, ScoutMlxFailureStage::Decode)
            | (ScoutMlxOperation::ProfileCompare, ScoutMlxFailureStage::Serialize)
            | (ScoutMlxOperation::LockdownStatus, ScoutMlxFailureStage::Initialize)
            | (ScoutMlxOperation::InfoReport, ScoutMlxFailureStage::Decode)
            | (ScoutMlxOperation::InfoReport, ScoutMlxFailureStage::Execute) => {
                LogAt::Level(tracing::Level::ERROR)
            }
            _ => LogAt::Level(tracing::Level::ERROR),
        }
    }
}

impl DynamicMessage for ScoutMlxOperationFailed {
    fn message(&self) -> &'static str {
        match (self.operation, self.failure_stage) {
            (ScoutMlxOperation::DeviceReportPublish, ScoutMlxFailureStage::Create) => {
                "failed to create PublishMlxDeviceReportRequest"
            }
            (ScoutMlxOperation::DeviceReportPublish, ScoutMlxFailureStage::Publish) => {
                "failed to publish PublishMlxDeviceReportRequest"
            }
            (ScoutMlxOperation::ObservationReport, ScoutMlxFailureStage::Publish) => {
                "Error from publish_mlx_observation_report"
            }
            (ScoutMlxOperation::ProfileCompare, ScoutMlxFailureStage::Decode) => {
                "[scout_stream::mlx_device] failed to parse profile"
            }
            (ScoutMlxOperation::ProfileCompare, ScoutMlxFailureStage::Serialize) => {
                "[scout_stream::mlx_device] profile compare result failed to serialize"
            }
            (ScoutMlxOperation::LockdownStatus, ScoutMlxFailureStage::Initialize) => {
                "[scout_stream::mlx_device] lockdown manager initialization failed"
            }
            (ScoutMlxOperation::InfoReport, ScoutMlxFailureStage::Decode) => {
                "[scout_stream::mlx_device] device report request failed to parse filters"
            }
            (ScoutMlxOperation::InfoReport, ScoutMlxFailureStage::Execute) => {
                "[scout_stream::mlx_device] device report generation failed"
            }
            _ => "Scout MLX operation failed",
        }
    }
}

/// An MLX request failed validation before it had additional context.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_request_rejected",
    metric_name = "carbide_scout_mlx_failures_total",
    component = "nico-scout",
    log = dynamic,
    metric = counter,
    message = dynamic,
    describe = "Number of Scout MLX observation and read failures, by operation, failure stage, and failure kind."
)]
pub(crate) struct ScoutMlxRequestRejected {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[label]
    failure_kind: ScoutMlxFailureKind,
}

impl ScoutMlxRequestRejected {
    fn new(operation: ScoutMlxOperation) -> Self {
        let failure_stage = ScoutMlxFailureStage::Validate;
        Self {
            operation,
            failure_stage,
            failure_kind: failure_stage.failure_kind(),
        }
    }

    pub(crate) fn profile_compare() -> Self {
        Self::new(ScoutMlxOperation::ProfileCompare)
    }

    pub(crate) fn reconciliation() -> Self {
        Self::new(ScoutMlxOperation::Reconciliation)
    }
}

impl DynamicLog for ScoutMlxRequestRejected {
    fn log_at(&self) -> LogAt {
        match self.operation {
            ScoutMlxOperation::ProfileCompare => LogAt::Off,
            ScoutMlxOperation::Reconciliation => LogAt::Level(tracing::Level::ERROR),
            _ => LogAt::Level(tracing::Level::WARN),
        }
    }
}

impl DynamicMessage for ScoutMlxRequestRejected {
    fn message(&self) -> &'static str {
        match self.operation {
            ScoutMlxOperation::ProfileCompare => "no serializable profile data in message",
            ScoutMlxOperation::Reconciliation => "handle_mlxreport_action dev_pci_name empty",
            _ => "Scout MLX request rejected",
        }
    }
}

/// An MLX device read failed.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_device_operation_failed",
    metric_name = "carbide_scout_mlx_failures_total",
    component = "nico-scout",
    log = error,
    metric = counter,
    message = dynamic,
    describe = "Number of Scout MLX observation and read failures, by operation, failure stage, and failure kind."
)]
pub(crate) struct ScoutMlxDeviceOperationFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[label]
    failure_kind: ScoutMlxFailureKind,
    #[context]
    device_id: String,
    #[context]
    error: String,
}

impl ScoutMlxDeviceOperationFailed {
    fn new(
        operation: ScoutMlxOperation,
        failure_stage: ScoutMlxFailureStage,
        device_id: String,
        error: String,
    ) -> Self {
        Self {
            operation,
            failure_stage,
            failure_kind: failure_stage.failure_kind(),
            device_id,
            error,
        }
    }

    pub(crate) fn lockdown_status_execute(device_id: String, error: String) -> Self {
        Self::new(
            ScoutMlxOperation::LockdownStatus,
            ScoutMlxFailureStage::Execute,
            device_id,
            error,
        )
    }

    pub(crate) fn device_info_discover(device_id: String, error: String) -> Self {
        Self::new(
            ScoutMlxOperation::DeviceInfo,
            ScoutMlxFailureStage::Discover,
            device_id,
            error,
        )
    }
}

impl DynamicMessage for ScoutMlxDeviceOperationFailed {
    fn message(&self) -> &'static str {
        match (self.operation, self.failure_stage) {
            (ScoutMlxOperation::LockdownStatus, ScoutMlxFailureStage::Execute) => {
                "[scout_stream::mlx_device] lockdown status check failed"
            }
            (ScoutMlxOperation::DeviceInfo, ScoutMlxFailureStage::Discover) => {
                "[scout_stream::mlx_device] device info request failed"
            }
            _ => "[scout_stream::mlx_device] device operation failed",
        }
    }
}

/// A profile comparison failed against one device.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_profile_operation_failed",
    metric_name = "carbide_scout_mlx_failures_total",
    component = "nico-scout",
    log = error,
    metric = counter,
    message = "[scout_stream::mlx_device] profile compare against device failed",
    describe = "Number of Scout MLX observation and read failures, by operation, failure stage, and failure kind."
)]
pub(crate) struct ScoutMlxProfileOperationFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[label]
    failure_kind: ScoutMlxFailureKind,
    #[context]
    device_id: String,
    #[context]
    profile_name: String,
    #[context]
    error: String,
}

impl ScoutMlxProfileOperationFailed {
    pub(crate) fn profile_compare_execute(
        device_id: String,
        profile_name: String,
        error: String,
    ) -> Self {
        let failure_stage = ScoutMlxFailureStage::Execute;
        Self {
            operation: ScoutMlxOperation::ProfileCompare,
            failure_stage,
            failure_kind: failure_stage.failure_kind(),
            device_id,
            profile_name,
            error,
        }
    }
}

/// A registry-show request named a registry Scout does not know.
///
/// Registry show preserves its existing error severity. Config query and
/// comparison use the warning-level `Event` below for the same lookup failure.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_registry_lookup_failed",
    metric_name = "carbide_scout_mlx_failures_total",
    component = "nico-scout",
    log = error,
    metric = counter,
    message = "[scout_stream::mlx_device] variable registry not found",
    describe = "Number of Scout MLX observation and read failures, by operation, failure stage, and failure kind."
)]
pub(crate) struct ScoutMlxRegistryLookupFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[label]
    failure_kind: ScoutMlxFailureKind,
    #[context]
    registry_name: String,
}

impl ScoutMlxRegistryLookupFailed {
    pub(crate) fn registry_show_lookup(registry_name: String) -> Self {
        let failure_stage = ScoutMlxFailureStage::Lookup;
        Self {
            operation: ScoutMlxOperation::RegistryShow,
            failure_stage,
            failure_kind: failure_stage.failure_kind(),
            registry_name,
        }
    }
}

/// A config read named a registry Scout does not know.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_config_registry_lookup_failed",
    metric_name = "carbide_scout_mlx_failures_total",
    component = "nico-scout",
    log = warn,
    metric = counter,
    message = "[scout_stream::mlx_device] config registry not found",
    describe = "Number of Scout MLX observation and read failures, by operation, failure stage, and failure kind."
)]
pub(crate) struct ScoutMlxConfigRegistryLookupFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[label]
    failure_kind: ScoutMlxFailureKind,
    #[context]
    device_id: String,
    #[context]
    registry_name: String,
}

impl ScoutMlxConfigRegistryLookupFailed {
    fn new(operation: ScoutMlxOperation, device_id: String, registry_name: String) -> Self {
        let failure_stage = ScoutMlxFailureStage::Lookup;
        Self {
            operation,
            failure_stage,
            failure_kind: failure_stage.failure_kind(),
            device_id,
            registry_name,
        }
    }

    pub(crate) fn config_query_lookup(device_id: String, registry_name: String) -> Self {
        Self::new(ScoutMlxOperation::ConfigQuery, device_id, registry_name)
    }

    pub(crate) fn config_compare_lookup(device_id: String, registry_name: String) -> Self {
        Self::new(ScoutMlxOperation::ConfigCompare, device_id, registry_name)
    }
}

/// An MLX config read failed after registry lookup.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_config_operation_failed",
    metric_name = "carbide_scout_mlx_failures_total",
    component = "nico-scout",
    log = error,
    metric = counter,
    message = dynamic,
    describe = "Number of Scout MLX observation and read failures, by operation, failure stage, and failure kind."
)]
pub(crate) struct ScoutMlxConfigOperationFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[label]
    failure_kind: ScoutMlxFailureKind,
    #[context]
    device_id: String,
    #[context]
    registry_name: String,
    #[context]
    error: String,
}

impl ScoutMlxConfigOperationFailed {
    fn new(
        operation: ScoutMlxOperation,
        failure_stage: ScoutMlxFailureStage,
        device_id: String,
        registry_name: String,
        error: String,
    ) -> Self {
        Self {
            operation,
            failure_stage,
            failure_kind: failure_stage.failure_kind(),
            device_id,
            registry_name,
            error,
        }
    }

    pub(crate) fn config_query_serialize(
        device_id: String,
        registry_name: String,
        error: String,
    ) -> Self {
        Self::new(
            ScoutMlxOperation::ConfigQuery,
            ScoutMlxFailureStage::Serialize,
            device_id,
            registry_name,
            error,
        )
    }

    pub(crate) fn config_query_execute(
        device_id: String,
        registry_name: String,
        error: String,
    ) -> Self {
        Self::new(
            ScoutMlxOperation::ConfigQuery,
            ScoutMlxFailureStage::Execute,
            device_id,
            registry_name,
            error,
        )
    }

    pub(crate) fn config_compare_serialize(
        device_id: String,
        registry_name: String,
        error: String,
    ) -> Self {
        Self::new(
            ScoutMlxOperation::ConfigCompare,
            ScoutMlxFailureStage::Serialize,
            device_id,
            registry_name,
            error,
        )
    }

    pub(crate) fn config_compare_execute(
        device_id: String,
        registry_name: String,
        error: String,
    ) -> Self {
        Self::new(
            ScoutMlxOperation::ConfigCompare,
            ScoutMlxFailureStage::Execute,
            device_id,
            registry_name,
            error,
        )
    }
}

impl DynamicMessage for ScoutMlxConfigOperationFailed {
    fn message(&self) -> &'static str {
        match (self.operation, self.failure_stage) {
            (ScoutMlxOperation::ConfigQuery, ScoutMlxFailureStage::Serialize) => {
                "[scout_stream::mlx_device] config query result failed to serialize"
            }
            (ScoutMlxOperation::ConfigQuery, ScoutMlxFailureStage::Execute) => {
                "[scout_stream::mlx_device] config query against device failed"
            }
            (ScoutMlxOperation::ConfigCompare, ScoutMlxFailureStage::Serialize) => {
                "[scout_stream::mlx_device] config compare result failed to serialize"
            }
            (ScoutMlxOperation::ConfigCompare, ScoutMlxFailureStage::Execute) => {
                "[scout_stream::mlx_device] config compare against device failed"
            }
            _ => "[scout_stream::mlx_device] config operation failed",
        }
    }
}

/// Scout could not reconcile one MLX command with its target device.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_reconciliation_failed",
    metric_name = "carbide_scout_mlx_failures_total",
    component = "nico-scout",
    log = error,
    metric = counter,
    message = dynamic,
    describe = "Number of Scout MLX observation and read failures, by operation, failure stage, and failure kind."
)]
pub(crate) struct ScoutMlxReconciliationFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[label]
    failure_kind: ScoutMlxFailureKind,
    #[context]
    pci_name: String,
    #[context]
    error: String,
}

impl ScoutMlxReconciliationFailed {
    fn new(failure_stage: ScoutMlxFailureStage, pci_name: String, error: String) -> Self {
        Self {
            operation: ScoutMlxOperation::Reconciliation,
            failure_stage,
            failure_kind: failure_stage.failure_kind(),
            pci_name,
            error,
        }
    }

    pub(crate) fn decode(pci_name: String, error: String) -> Self {
        Self::new(ScoutMlxFailureStage::Decode, pci_name, error)
    }

    pub(crate) fn discover(pci_name: String, error: String) -> Self {
        Self::new(ScoutMlxFailureStage::Discover, pci_name, error)
    }
}

impl DynamicMessage for ScoutMlxReconciliationFailed {
    fn message(&self) -> &'static str {
        match self.failure_stage {
            ScoutMlxFailureStage::Decode => "handle_mlxreport_action error decoding command",
            ScoutMlxFailureStage::Discover => {
                "handle_mlxreport_action error from discover_device::from_str"
            }
            _ => "handle_mlxreport_action failed",
        }
    }
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
    fn firmware_download_attempt_failures_share_one_bounded_metric() {
        struct AttemptCase {
            kind: FirmwareDownloadKind,
            kind_label: &'static str,
            next_action: FirmwareDownloadNextAction,
            next_action_label: &'static str,
            retry_delay_seconds: f64,
        }

        #[derive(Debug, PartialEq)]
        struct Observation {
            counter_delta: f64,
            level: tracing::Level,
            message: String,
            kind: Option<String>,
            next_action: Option<String>,
            attempt: Option<String>,
            url: Option<String>,
            error: Option<String>,
            retry_delay_seconds: Option<String>,
        }

        check_values(
            [
                Check {
                    scenario: "script attempt will retry",
                    input: AttemptCase {
                        kind: FirmwareDownloadKind::Script,
                        kind_label: "script",
                        next_action: FirmwareDownloadNextAction::Retry,
                        next_action_label: "retry",
                        retry_delay_seconds: 4.0,
                    },
                    expect: Observation {
                        counter_delta: 1.0,
                        level: tracing::Level::WARN,
                        message: "[firmware_upgrade] download attempt failed; retrying".to_string(),
                        kind: Some("script".to_string()),
                        next_action: Some("retry".to_string()),
                        attempt: Some("2".to_string()),
                        url: Some("https://firmware.example/script.sh".to_string()),
                        error: Some("HTTP 503".to_string()),
                        retry_delay_seconds: Some("4".to_string()),
                    },
                },
                Check {
                    scenario: "artifact attempt will give up",
                    input: AttemptCase {
                        kind: FirmwareDownloadKind::Artifact,
                        kind_label: "artifact",
                        next_action: FirmwareDownloadNextAction::GiveUp,
                        next_action_label: "give_up",
                        retry_delay_seconds: 0.0,
                    },
                    expect: Observation {
                        counter_delta: 1.0,
                        level: tracing::Level::WARN,
                        message: "[firmware_upgrade] download attempt failed; retrying".to_string(),
                        kind: Some("artifact".to_string()),
                        next_action: Some("give_up".to_string()),
                        attempt: Some("2".to_string()),
                        url: Some("https://firmware.example/image.bin".to_string()),
                        error: Some("HTTP 503".to_string()),
                        retry_delay_seconds: Some("0".to_string()),
                    },
                },
            ],
            |case| {
                let metrics = MetricsCapture::start();
                let url = match case.kind {
                    FirmwareDownloadKind::Script => "https://firmware.example/script.sh",
                    FirmwareDownloadKind::Artifact => "https://firmware.example/image.bin",
                };
                let logs = capture_logs(|| {
                    emit(ScoutFirmwareDownloadAttemptFailed {
                        kind: case.kind,
                        next_action: case.next_action,
                        attempt: 2,
                        url: url.to_string(),
                        error: "HTTP 503".to_string(),
                        retry_delay_seconds: case.retry_delay_seconds,
                    });
                });
                let log = &logs[0];

                Observation {
                    counter_delta: metrics.counter_delta(
                        "carbide_scout_firmware_download_attempt_failures_total",
                        &[
                            ("kind", case.kind_label),
                            ("next_action", case.next_action_label),
                        ],
                    ),
                    level: log.level,
                    message: log.message.clone(),
                    kind: log.field("kind").map(str::to_string),
                    next_action: log.field("next_action").map(str::to_string),
                    attempt: log.field("attempt").map(str::to_string),
                    url: log.field("url").map(str::to_string),
                    error: log.field("error").map(str::to_string),
                    retry_delay_seconds: log.field("retry_delay_seconds").map(str::to_string),
                }
            },
        );
    }

    #[test]
    fn mlx_failure_stages_derive_one_failure_kind() {
        check_values(
            [
                Check {
                    scenario: "create failures come from the backend",
                    input: ScoutMlxFailureStage::Create,
                    expect: ScoutMlxFailureKind::Backend,
                },
                Check {
                    scenario: "publish failures come from the RPC",
                    input: ScoutMlxFailureStage::Publish,
                    expect: ScoutMlxFailureKind::Rpc,
                },
                Check {
                    scenario: "decode failures reject the request",
                    input: ScoutMlxFailureStage::Decode,
                    expect: ScoutMlxFailureKind::InvalidRequest,
                },
                Check {
                    scenario: "validation failures reject the request",
                    input: ScoutMlxFailureStage::Validate,
                    expect: ScoutMlxFailureKind::InvalidRequest,
                },
                Check {
                    scenario: "discovery failures come from the backend",
                    input: ScoutMlxFailureStage::Discover,
                    expect: ScoutMlxFailureKind::Backend,
                },
                Check {
                    scenario: "initialization failures come from the backend",
                    input: ScoutMlxFailureStage::Initialize,
                    expect: ScoutMlxFailureKind::Backend,
                },
                Check {
                    scenario: "lookup failures are not found",
                    input: ScoutMlxFailureStage::Lookup,
                    expect: ScoutMlxFailureKind::NotFound,
                },
                Check {
                    scenario: "execution failures come from the backend",
                    input: ScoutMlxFailureStage::Execute,
                    expect: ScoutMlxFailureKind::Backend,
                },
                Check {
                    scenario: "serialization failures keep their own class",
                    input: ScoutMlxFailureStage::Serialize,
                    expect: ScoutMlxFailureKind::Serialization,
                },
            ],
            ScoutMlxFailureStage::failure_kind,
        );
    }

    #[test]
    fn mlx_dynamic_contracts_preserve_existing_severity_and_messages() {
        #[derive(Clone, Copy)]
        enum ContractCase {
            DeviceReportCreate,
            DeviceReportPublish,
            ObservationReportPublish,
            ProfileCompareDecode,
            ProfileCompareSerialize,
            LockdownStatusInitialize,
            InfoReportDecode,
            InfoReportExecute,
            ProfileCompareRequest,
            ReconciliationRequest,
            LockdownStatusExecute,
            DeviceInfoDiscover,
            ConfigQuerySerialize,
            ConfigQueryExecute,
            ConfigCompareSerialize,
            ConfigCompareExecute,
            ReconciliationDecode,
            ReconciliationDiscover,
            OperationFallback,
            RequestFallback,
            DeviceFallback,
            ConfigFallback,
            ReconciliationFallback,
        }

        #[derive(Debug, PartialEq)]
        struct Contract {
            log_at: LogAt,
            message: &'static str,
        }

        fn contract<E>(event: &E) -> Contract
        where
            E: Event,
        {
            Contract {
                log_at: event.log_at(),
                message: event.message(),
            }
        }

        let warn = |message| Contract {
            log_at: LogAt::Level(tracing::Level::WARN),
            message,
        };
        let error = |message| Contract {
            log_at: LogAt::Level(tracing::Level::ERROR),
            message,
        };

        check_values(
            [
                Check {
                    scenario: "device report creation",
                    input: ContractCase::DeviceReportCreate,
                    expect: warn("failed to create PublishMlxDeviceReportRequest"),
                },
                Check {
                    scenario: "device report publication",
                    input: ContractCase::DeviceReportPublish,
                    expect: warn("failed to publish PublishMlxDeviceReportRequest"),
                },
                Check {
                    scenario: "observation report publication",
                    input: ContractCase::ObservationReportPublish,
                    expect: error("Error from publish_mlx_observation_report"),
                },
                Check {
                    scenario: "profile decode",
                    input: ContractCase::ProfileCompareDecode,
                    expect: error("[scout_stream::mlx_device] failed to parse profile"),
                },
                Check {
                    scenario: "profile result serialization",
                    input: ContractCase::ProfileCompareSerialize,
                    expect: error(
                        "[scout_stream::mlx_device] profile compare result failed to serialize",
                    ),
                },
                Check {
                    scenario: "lockdown manager initialization",
                    input: ContractCase::LockdownStatusInitialize,
                    expect: error(
                        "[scout_stream::mlx_device] lockdown manager initialization failed",
                    ),
                },
                Check {
                    scenario: "info report filter decode",
                    input: ContractCase::InfoReportDecode,
                    expect: error(
                        "[scout_stream::mlx_device] device report request failed to parse filters",
                    ),
                },
                Check {
                    scenario: "info report execution",
                    input: ContractCase::InfoReportExecute,
                    expect: error("[scout_stream::mlx_device] device report generation failed"),
                },
                Check {
                    scenario: "missing profile request",
                    input: ContractCase::ProfileCompareRequest,
                    expect: Contract {
                        log_at: LogAt::Off,
                        message: "no serializable profile data in message",
                    },
                },
                Check {
                    scenario: "empty reconciliation PCI request",
                    input: ContractCase::ReconciliationRequest,
                    expect: error("handle_mlxreport_action dev_pci_name empty"),
                },
                Check {
                    scenario: "lockdown status execution",
                    input: ContractCase::LockdownStatusExecute,
                    expect: error("[scout_stream::mlx_device] lockdown status check failed"),
                },
                Check {
                    scenario: "device information discovery",
                    input: ContractCase::DeviceInfoDiscover,
                    expect: error("[scout_stream::mlx_device] device info request failed"),
                },
                Check {
                    scenario: "config query result serialization",
                    input: ContractCase::ConfigQuerySerialize,
                    expect: error(
                        "[scout_stream::mlx_device] config query result failed to serialize",
                    ),
                },
                Check {
                    scenario: "config query execution",
                    input: ContractCase::ConfigQueryExecute,
                    expect: error("[scout_stream::mlx_device] config query against device failed"),
                },
                Check {
                    scenario: "config comparison result serialization",
                    input: ContractCase::ConfigCompareSerialize,
                    expect: error(
                        "[scout_stream::mlx_device] config compare result failed to serialize",
                    ),
                },
                Check {
                    scenario: "config comparison execution",
                    input: ContractCase::ConfigCompareExecute,
                    expect: error(
                        "[scout_stream::mlx_device] config compare against device failed",
                    ),
                },
                Check {
                    scenario: "reconciliation command decode",
                    input: ContractCase::ReconciliationDecode,
                    expect: error("handle_mlxreport_action error decoding command"),
                },
                Check {
                    scenario: "reconciliation device discovery",
                    input: ContractCase::ReconciliationDiscover,
                    expect: error("handle_mlxreport_action error from discover_device::from_str"),
                },
                Check {
                    scenario: "unknown operation pair remains diagnostic",
                    input: ContractCase::OperationFallback,
                    expect: error("Scout MLX operation failed"),
                },
                Check {
                    scenario: "unknown request operation remains diagnostic",
                    input: ContractCase::RequestFallback,
                    expect: warn("Scout MLX request rejected"),
                },
                Check {
                    scenario: "unknown device pair remains diagnostic",
                    input: ContractCase::DeviceFallback,
                    expect: error("[scout_stream::mlx_device] device operation failed"),
                },
                Check {
                    scenario: "unknown config pair remains diagnostic",
                    input: ContractCase::ConfigFallback,
                    expect: error("[scout_stream::mlx_device] config operation failed"),
                },
                Check {
                    scenario: "unknown reconciliation stage remains diagnostic",
                    input: ContractCase::ReconciliationFallback,
                    expect: error("handle_mlxreport_action failed"),
                },
            ],
            |case| match case {
                ContractCase::DeviceReportCreate => contract(
                    &ScoutMlxOperationFailed::device_report_create("failure".to_string()),
                ),
                ContractCase::DeviceReportPublish => contract(
                    &ScoutMlxOperationFailed::device_report_publish("failure".to_string()),
                ),
                ContractCase::ObservationReportPublish => contract(
                    &ScoutMlxOperationFailed::observation_report_publish("failure".to_string()),
                ),
                ContractCase::ProfileCompareDecode => contract(
                    &ScoutMlxOperationFailed::profile_compare_decode("failure".to_string()),
                ),
                ContractCase::ProfileCompareSerialize => contract(
                    &ScoutMlxOperationFailed::profile_compare_serialize("failure".to_string()),
                ),
                ContractCase::LockdownStatusInitialize => contract(
                    &ScoutMlxOperationFailed::lockdown_status_initialize("failure".to_string()),
                ),
                ContractCase::InfoReportDecode => contract(
                    &ScoutMlxOperationFailed::info_report_decode("failure".to_string()),
                ),
                ContractCase::InfoReportExecute => contract(
                    &ScoutMlxOperationFailed::info_report_execute("failure".to_string()),
                ),
                ContractCase::ProfileCompareRequest => {
                    contract(&ScoutMlxRequestRejected::profile_compare())
                }
                ContractCase::ReconciliationRequest => {
                    contract(&ScoutMlxRequestRejected::reconciliation())
                }
                ContractCase::LockdownStatusExecute => {
                    contract(&ScoutMlxDeviceOperationFailed::lockdown_status_execute(
                        "device".to_string(),
                        "failure".to_string(),
                    ))
                }
                ContractCase::DeviceInfoDiscover => {
                    contract(&ScoutMlxDeviceOperationFailed::device_info_discover(
                        "device".to_string(),
                        "failure".to_string(),
                    ))
                }
                ContractCase::ConfigQuerySerialize => {
                    contract(&ScoutMlxConfigOperationFailed::config_query_serialize(
                        "device".to_string(),
                        "registry".to_string(),
                        "failure".to_string(),
                    ))
                }
                ContractCase::ConfigQueryExecute => {
                    contract(&ScoutMlxConfigOperationFailed::config_query_execute(
                        "device".to_string(),
                        "registry".to_string(),
                        "failure".to_string(),
                    ))
                }
                ContractCase::ConfigCompareSerialize => {
                    contract(&ScoutMlxConfigOperationFailed::config_compare_serialize(
                        "device".to_string(),
                        "registry".to_string(),
                        "failure".to_string(),
                    ))
                }
                ContractCase::ConfigCompareExecute => {
                    contract(&ScoutMlxConfigOperationFailed::config_compare_execute(
                        "device".to_string(),
                        "registry".to_string(),
                        "failure".to_string(),
                    ))
                }
                ContractCase::ReconciliationDecode => {
                    contract(&ScoutMlxReconciliationFailed::decode(
                        "device".to_string(),
                        "failure".to_string(),
                    ))
                }
                ContractCase::ReconciliationDiscover => {
                    contract(&ScoutMlxReconciliationFailed::discover(
                        "device".to_string(),
                        "failure".to_string(),
                    ))
                }
                ContractCase::OperationFallback => contract(&ScoutMlxOperationFailed::new(
                    ScoutMlxOperation::ConfigQuery,
                    ScoutMlxFailureStage::Create,
                    "failure".to_string(),
                )),
                ContractCase::RequestFallback => contract(&ScoutMlxRequestRejected::new(
                    ScoutMlxOperation::ConfigQuery,
                )),
                ContractCase::DeviceFallback => contract(&ScoutMlxDeviceOperationFailed::new(
                    ScoutMlxOperation::ConfigQuery,
                    ScoutMlxFailureStage::Create,
                    "device".to_string(),
                    "failure".to_string(),
                )),
                ContractCase::ConfigFallback => contract(&ScoutMlxConfigOperationFailed::new(
                    ScoutMlxOperation::DeviceInfo,
                    ScoutMlxFailureStage::Publish,
                    "device".to_string(),
                    "registry".to_string(),
                    "failure".to_string(),
                )),
                ContractCase::ReconciliationFallback => {
                    contract(&ScoutMlxReconciliationFailed::new(
                        ScoutMlxFailureStage::Serialize,
                        "device".to_string(),
                        "failure".to_string(),
                    ))
                }
            },
        );
    }

    #[test]
    fn mlx_request_rejections_count_with_existing_diagnostics() {
        #[derive(Clone, Copy)]
        enum RequestCase {
            ProfileCompare,
            Reconciliation,
        }

        #[derive(Debug, PartialEq)]
        struct Observation {
            counter_delta: f64,
            logs: Vec<(tracing::Level, String)>,
        }

        check_values(
            [
                Check {
                    scenario: "missing profile data remains metric-only",
                    input: RequestCase::ProfileCompare,
                    expect: Observation {
                        counter_delta: 1.0,
                        logs: Vec::new(),
                    },
                },
                Check {
                    scenario: "empty reconciliation PCI retains its error",
                    input: RequestCase::Reconciliation,
                    expect: Observation {
                        counter_delta: 1.0,
                        logs: vec![(
                            tracing::Level::ERROR,
                            "handle_mlxreport_action dev_pci_name empty".to_string(),
                        )],
                    },
                },
            ],
            |case| {
                let (event, operation) = match case {
                    RequestCase::ProfileCompare => (
                        ScoutMlxRequestRejected::profile_compare(),
                        "profile_compare",
                    ),
                    RequestCase::Reconciliation => {
                        (ScoutMlxRequestRejected::reconciliation(), "reconciliation")
                    }
                };
                let metrics = MetricsCapture::start();
                let logs = capture_logs(|| emit(event));

                Observation {
                    counter_delta: metrics.counter_delta(
                        "carbide_scout_mlx_failures_total",
                        &[
                            ("operation", operation),
                            ("failure_stage", "validate"),
                            ("failure_kind", "invalid_request"),
                        ],
                    ),
                    logs: logs
                        .into_iter()
                        .map(|log| (log.level, log.message))
                        .collect(),
                }
            },
        );
    }

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
    fn scout_stream_response_drop_logs_and_counts() {
        let metrics = MetricsCapture::start();
        let machine_id =
            MachineId::from_str("fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30")
                .expect("valid machine id");
        let logs = capture_logs(|| {
            emit(ScoutStreamResponseDropped {
                api_endpoint: "https://[::1]:1079".to_string(),
                machine_id,
                error: "request stream closed".to_string(),
            });
        });

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].metadata_name, "scout_stream_response_dropped");
        assert_eq!(logs[0].level, tracing::Level::ERROR);
        assert_eq!(logs[0].message, "scout stream failed to send response");
        assert_eq!(
            logs[0].field("event_name"),
            Some("scout_stream_response_dropped")
        );
        assert_eq!(
            logs[0].field("metric_name"),
            Some("carbide_scout_stream_responses_dropped_total")
        );
        assert_eq!(logs[0].field("api_endpoint"), Some("https://[::1]:1079"));
        let machine_id = machine_id.to_string();
        assert_eq!(logs[0].field("machine_id"), Some(machine_id.as_str()));
        assert_eq!(logs[0].field("error"), Some("request stream closed"));

        assert_eq!(
            metrics.counter_delta("carbide_scout_stream_responses_dropped_total", &[]),
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
