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

use carbide_instrument::{
    DynamicLog, DynamicMessage, Event, LabelValue, LogAt, MetricFamily, Outcome,
};
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
    ReconciliationLock,
    ReconciliationUnlock,
    ProfileSync,
    ProfileCompare,
    ProfileApply,
    ProfileReset,
    LockdownLock,
    LockdownUnlock,
    LockdownStatus,
    DeviceInfo,
    RegistryShow,
    ConfigQuery,
    ConfigCompare,
    ConfigSet,
    ConfigSync,
    FirmwareFlash,
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

/// Every failure stage belongs to exactly one failure kind, so the family
/// derives the `failure_kind` label from `failure_stage` through this
/// conversion rather than letting a call site supply the pair.
impl From<ScoutMlxFailureStage> for ScoutMlxFailureKind {
    fn from(stage: ScoutMlxFailureStage) -> Self {
        match stage {
            ScoutMlxFailureStage::Create
            | ScoutMlxFailureStage::Discover
            | ScoutMlxFailureStage::Initialize
            | ScoutMlxFailureStage::Execute => ScoutMlxFailureKind::Backend,
            ScoutMlxFailureStage::Publish => ScoutMlxFailureKind::Rpc,
            ScoutMlxFailureStage::Decode | ScoutMlxFailureStage::Validate => {
                ScoutMlxFailureKind::InvalidRequest
            }
            ScoutMlxFailureStage::Lookup => ScoutMlxFailureKind::NotFound,
            ScoutMlxFailureStage::Serialize => ScoutMlxFailureKind::Serialization,
        }
    }
}

/// `ScoutMlxFailures` is the one metric behind every Scout MLX failure below:
/// which operation failed, where it failed, and what class of failure it was.
/// The Events that record it keep their own severity, wording, and diagnostic
/// context, and the derive checks each one against the labels they supply.
///
/// `failure_kind` is not one of those: it follows from `failure_stage`, so the
/// family computes it and no call site can pair the two contradictorily.
#[derive(MetricFamily)]
#[metric(
    name = "carbide_scout_mlx_failures_total",
    kind = counter,
    component = "nico-scout",
    describe = "Number of Scout MLX observation, read, mutation, and recovery failures, by operation, failure stage, and failure kind."
)]
#[derived(failure_kind: ScoutMlxFailureKind, from = failure_stage)]
pub(crate) struct ScoutMlxFailures {
    operation: ScoutMlxOperation,
    failure_stage: ScoutMlxFailureStage,
}

// The operation, request, device, profile, registry, config, firmware, and
// reconciliation groups all record `ScoutMlxFailures`, but their existing
// diagnostics need different context. Keep separate `Event` structs so each log
// retains its fields without filling unrelated fields with empty values.
//
// Named constructors still own each valid (`operation`, `failure_stage`) pair,
// so a call site names the situation rather than assembling one. The dynamic
// log and message matches keep generic fallbacks: `emit()` is diagnostic
// plumbing and must not panic if a future constructor reaches a pair its
// matching table does not know yet.

/// An MLX failure whose existing diagnostic only carries an error.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_operation_failed",
    metric_family = ScoutMlxFailures,
    log = dynamic,
    message = dynamic
)]
pub(crate) struct ScoutMlxOperationFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
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

    pub(crate) fn profile_sync_decode(error: String) -> Self {
        Self::new(
            ScoutMlxOperation::ProfileSync,
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

    pub(crate) fn profile_sync_serialize(error: String) -> Self {
        Self::new(
            ScoutMlxOperation::ProfileSync,
            ScoutMlxFailureStage::Serialize,
            error,
        )
    }

    pub(crate) fn lockdown_lock_initialize(error: String) -> Self {
        Self::new(
            ScoutMlxOperation::LockdownLock,
            ScoutMlxFailureStage::Initialize,
            error,
        )
    }

    pub(crate) fn lockdown_unlock_initialize(error: String) -> Self {
        Self::new(
            ScoutMlxOperation::LockdownUnlock,
            ScoutMlxFailureStage::Initialize,
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
            (
                ScoutMlxOperation::ProfileCompare | ScoutMlxOperation::ProfileSync,
                ScoutMlxFailureStage::Decode,
            ) => "[scout_stream::mlx_device] failed to parse profile",
            (ScoutMlxOperation::ProfileCompare, ScoutMlxFailureStage::Serialize) => {
                "[scout_stream::mlx_device] profile compare result failed to serialize"
            }
            (ScoutMlxOperation::ProfileSync, ScoutMlxFailureStage::Serialize) => {
                "[scout_stream::mlx_device] profile sync result failed to serialize"
            }
            (
                ScoutMlxOperation::LockdownLock
                | ScoutMlxOperation::LockdownUnlock
                | ScoutMlxOperation::LockdownStatus,
                ScoutMlxFailureStage::Initialize,
            ) => "[scout_stream::mlx_device] lockdown manager initialization failed",
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
    metric_family = ScoutMlxFailures,
    log = dynamic,
    message = dynamic
)]
pub(crate) struct ScoutMlxRequestRejected {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
}

impl ScoutMlxRequestRejected {
    fn new(operation: ScoutMlxOperation) -> Self {
        let failure_stage = ScoutMlxFailureStage::Validate;
        Self {
            operation,
            failure_stage,
        }
    }

    pub(crate) fn profile_compare() -> Self {
        Self::new(ScoutMlxOperation::ProfileCompare)
    }

    pub(crate) fn profile_sync() -> Self {
        Self::new(ScoutMlxOperation::ProfileSync)
    }

    pub(crate) fn reconciliation() -> Self {
        Self::new(ScoutMlxOperation::Reconciliation)
    }
}

impl DynamicLog for ScoutMlxRequestRejected {
    fn log_at(&self) -> LogAt {
        match self.operation {
            ScoutMlxOperation::ProfileCompare | ScoutMlxOperation::ProfileSync => LogAt::Off,
            ScoutMlxOperation::Reconciliation => LogAt::Level(tracing::Level::ERROR),
            _ => LogAt::Level(tracing::Level::WARN),
        }
    }
}

impl DynamicMessage for ScoutMlxRequestRejected {
    fn message(&self) -> &'static str {
        match self.operation {
            ScoutMlxOperation::ProfileCompare => "no serializable profile data in message",
            ScoutMlxOperation::ProfileSync => "no serializable profile data in message",
            ScoutMlxOperation::Reconciliation => "handle_mlxreport_action dev_pci_name empty",
            _ => "Scout MLX request rejected",
        }
    }
}

/// An MLX device read failed.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_device_operation_failed",
    metric_family = ScoutMlxFailures,
    log = error,
    message = dynamic
)]
pub(crate) struct ScoutMlxDeviceOperationFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
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

    pub(crate) fn lockdown_lock_execute(device_id: String, error: String) -> Self {
        Self::new(
            ScoutMlxOperation::LockdownLock,
            ScoutMlxFailureStage::Execute,
            device_id,
            error,
        )
    }

    pub(crate) fn lockdown_unlock_execute(device_id: String, error: String) -> Self {
        Self::new(
            ScoutMlxOperation::LockdownUnlock,
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
            (ScoutMlxOperation::LockdownLock, ScoutMlxFailureStage::Execute) => {
                "[scout_stream::mlx_device] lockdown lock failed"
            }
            (ScoutMlxOperation::LockdownUnlock, ScoutMlxFailureStage::Execute) => {
                "[scout_stream::mlx_device] lockdown unlock failed"
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
    metric_family = ScoutMlxFailures,
    log = error,
    message = dynamic
)]
pub(crate) struct ScoutMlxProfileOperationFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
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
            device_id,
            profile_name,
            error,
        }
    }

    pub(crate) fn profile_sync_execute(
        device_id: String,
        profile_name: String,
        error: String,
    ) -> Self {
        let failure_stage = ScoutMlxFailureStage::Execute;
        Self {
            operation: ScoutMlxOperation::ProfileSync,
            failure_stage,
            device_id,
            profile_name,
            error,
        }
    }
}

impl DynamicMessage for ScoutMlxProfileOperationFailed {
    fn message(&self) -> &'static str {
        match self.operation {
            ScoutMlxOperation::ProfileCompare => {
                "[scout_stream::mlx_device] profile compare against device failed"
            }
            ScoutMlxOperation::ProfileSync => {
                "[scout_stream::mlx_device] profile sync to device failed"
            }
            _ => "[scout_stream::mlx_device] profile operation failed",
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
    metric_family = ScoutMlxFailures,
    log = error,
    message = "[scout_stream::mlx_device] variable registry not found"
)]
pub(crate) struct ScoutMlxRegistryLookupFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[context]
    registry_name: String,
}

impl ScoutMlxRegistryLookupFailed {
    pub(crate) fn registry_show_lookup(registry_name: String) -> Self {
        let failure_stage = ScoutMlxFailureStage::Lookup;
        Self {
            operation: ScoutMlxOperation::RegistryShow,
            failure_stage,
            registry_name,
        }
    }
}

/// A config read named a registry Scout does not know.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_config_registry_lookup_failed",
    metric_family = ScoutMlxFailures,
    log = warn,
    message = "[scout_stream::mlx_device] config registry not found"
)]
pub(crate) struct ScoutMlxConfigRegistryLookupFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
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

    pub(crate) fn config_set_lookup(device_id: String, registry_name: String) -> Self {
        Self::new(ScoutMlxOperation::ConfigSet, device_id, registry_name)
    }

    pub(crate) fn config_sync_lookup(device_id: String, registry_name: String) -> Self {
        Self::new(ScoutMlxOperation::ConfigSync, device_id, registry_name)
    }
}

/// An MLX configuration operation failed after registry lookup.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_config_operation_failed",
    metric_family = ScoutMlxFailures,
    log = error,
    message = dynamic
)]
pub(crate) struct ScoutMlxConfigOperationFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
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

    pub(crate) fn config_set_execute(
        device_id: String,
        registry_name: String,
        error: String,
    ) -> Self {
        Self::new(
            ScoutMlxOperation::ConfigSet,
            ScoutMlxFailureStage::Execute,
            device_id,
            registry_name,
            error,
        )
    }

    pub(crate) fn config_sync_serialize(
        device_id: String,
        registry_name: String,
        error: String,
    ) -> Self {
        Self::new(
            ScoutMlxOperation::ConfigSync,
            ScoutMlxFailureStage::Serialize,
            device_id,
            registry_name,
            error,
        )
    }

    pub(crate) fn config_sync_execute(
        device_id: String,
        registry_name: String,
        error: String,
    ) -> Self {
        Self::new(
            ScoutMlxOperation::ConfigSync,
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
            (ScoutMlxOperation::ConfigSet, ScoutMlxFailureStage::Execute) => {
                "[scout_stream::mlx_device] config set to device failed"
            }
            (ScoutMlxOperation::ConfigSync, ScoutMlxFailureStage::Serialize) => {
                "[scout_stream::mlx_device] config sync result failed to serialize"
            }
            (ScoutMlxOperation::ConfigSync, ScoutMlxFailureStage::Execute) => {
                "[scout_stream::mlx_device] config sync to device failed"
            }
            _ => "[scout_stream::mlx_device] config operation failed",
        }
    }
}

/// Resetting one device's MLX configuration to its factory defaults failed.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_profile_reset_failed",
    metric_family = ScoutMlxFailures,
    log = error,
    message = "mlxconfig reset failed"
)]
pub(crate) struct ScoutMlxProfileResetFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[context]
    device: String,
    #[context]
    error: String,
}

impl ScoutMlxProfileResetFailed {
    pub(crate) fn execute(device: String, error: String) -> Self {
        let failure_stage = ScoutMlxFailureStage::Execute;
        Self {
            operation: ScoutMlxOperation::ProfileReset,
            failure_stage,
            device,
            error,
        }
    }
}

/// Applying one tenant profile after its device reset failed.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_profile_apply_failed",
    metric_family = ScoutMlxFailures,
    log = error,
    message = "mlxconfig profile sync failed"
)]
pub(crate) struct ScoutMlxProfileApplyFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[context]
    device: String,
    #[context]
    profile: String,
    #[context]
    error: String,
}

impl ScoutMlxProfileApplyFailed {
    pub(crate) fn execute(device: String, profile: String, error: String) -> Self {
        let failure_stage = ScoutMlxFailureStage::Execute;
        Self {
            operation: ScoutMlxOperation::ProfileApply,
            failure_stage,
            device,
            profile,
            error,
        }
    }
}

/// Scout could not initialize a firmware flasher for one MLX device.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_firmware_flasher_initialization_failed",
    metric_family = ScoutMlxFailures,
    log = error,
    message = "failed to create FirmwareFlasher"
)]
pub(crate) struct ScoutMlxFirmwareFlasherInitializationFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[context]
    device: String,
    #[context]
    part_number: String,
    #[context]
    psid: String,
    #[context]
    error: String,
}

impl ScoutMlxFirmwareFlasherInitializationFailed {
    pub(crate) fn new(device: String, part_number: String, psid: String, error: String) -> Self {
        let failure_stage = ScoutMlxFailureStage::Initialize;
        Self {
            operation: ScoutMlxOperation::FirmwareFlash,
            failure_stage,
            device,
            part_number,
            psid,
            error,
        }
    }
}

/// Scout initialized a firmware flasher, but applying its profile failed.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_firmware_flash_failed",
    metric_family = ScoutMlxFailures,
    log = error,
    message = "firmware flash failed"
)]
pub(crate) struct ScoutMlxFirmwareFlashFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[context]
    device: String,
    #[context]
    part_number: String,
    #[context]
    psid: String,
    #[context]
    firmware_url: String,
    #[context]
    target_version: String,
    #[context]
    error: String,
}

impl ScoutMlxFirmwareFlashFailed {
    pub(crate) fn execute(
        device: String,
        part_number: String,
        psid: String,
        firmware_url: String,
        target_version: String,
        error: String,
    ) -> Self {
        let failure_stage = ScoutMlxFailureStage::Execute;
        Self {
            operation: ScoutMlxOperation::FirmwareFlash,
            failure_stage,
            device,
            part_number,
            psid,
            firmware_url,
            target_version,
            error,
        }
    }
}

/// Scout could not reconcile one MLX command with its target device.
#[derive(Event)]
#[event(
    event_name = "scout_mlx_reconciliation_failed",
    metric_family = ScoutMlxFailures,
    log = dynamic,
    message = dynamic
)]
pub(crate) struct ScoutMlxReconciliationFailed {
    #[label]
    operation: ScoutMlxOperation,
    #[label]
    failure_stage: ScoutMlxFailureStage,
    #[context]
    pci_name: String,
    #[context]
    error: String,
}

impl ScoutMlxReconciliationFailed {
    fn new(
        operation: ScoutMlxOperation,
        failure_stage: ScoutMlxFailureStage,
        pci_name: String,
        error: String,
    ) -> Self {
        Self {
            operation,
            failure_stage,
            pci_name,
            error,
        }
    }

    pub(crate) fn decode(pci_name: String, error: String) -> Self {
        Self::new(
            ScoutMlxOperation::Reconciliation,
            ScoutMlxFailureStage::Decode,
            pci_name,
            error,
        )
    }

    pub(crate) fn discover(pci_name: String, error: String) -> Self {
        Self::new(
            ScoutMlxOperation::Reconciliation,
            ScoutMlxFailureStage::Discover,
            pci_name,
            error,
        )
    }

    pub(crate) fn lock(pci_name: String, error: String) -> Self {
        Self::new(
            ScoutMlxOperation::ReconciliationLock,
            ScoutMlxFailureStage::Execute,
            pci_name,
            error,
        )
    }

    pub(crate) fn unlock(pci_name: String, error: String) -> Self {
        Self::new(
            ScoutMlxOperation::ReconciliationUnlock,
            ScoutMlxFailureStage::Execute,
            pci_name,
            error,
        )
    }
}

impl DynamicLog for ScoutMlxReconciliationFailed {
    fn log_at(&self) -> LogAt {
        match (self.operation, self.failure_stage) {
            (
                ScoutMlxOperation::ReconciliationLock | ScoutMlxOperation::ReconciliationUnlock,
                ScoutMlxFailureStage::Execute,
            ) => LogAt::Level(tracing::Level::INFO),
            _ => LogAt::Level(tracing::Level::ERROR),
        }
    }
}

impl DynamicMessage for ScoutMlxReconciliationFailed {
    fn message(&self) -> &'static str {
        match (self.operation, self.failure_stage) {
            (ScoutMlxOperation::Reconciliation, ScoutMlxFailureStage::Decode) => {
                "handle_mlxreport_action error decoding command"
            }
            (ScoutMlxOperation::Reconciliation, ScoutMlxFailureStage::Discover) => {
                "handle_mlxreport_action error from discover_device::from_str"
            }
            (ScoutMlxOperation::ReconciliationLock, ScoutMlxFailureStage::Execute) => {
                "handle_mlxreport_action error from lock_device"
            }
            (ScoutMlxOperation::ReconciliationUnlock, ScoutMlxFailureStage::Execute) => {
                "handle_mlxreport_action error from unlock_device"
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
            ScoutMlxFailureKind::from,
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
            ProfileSyncDecode,
            ProfileSyncSerialize,
            LockdownStatusInitialize,
            LockdownLockInitialize,
            LockdownUnlockInitialize,
            InfoReportDecode,
            InfoReportExecute,
            ProfileCompareRequest,
            ProfileSyncRequest,
            ReconciliationRequest,
            LockdownStatusExecute,
            LockdownLockExecute,
            LockdownUnlockExecute,
            DeviceInfoDiscover,
            ProfileCompareExecute,
            ProfileSyncExecute,
            ConfigQuerySerialize,
            ConfigQueryExecute,
            ConfigCompareSerialize,
            ConfigCompareExecute,
            ConfigSetExecute,
            ConfigSyncSerialize,
            ConfigSyncExecute,
            ReconciliationDecode,
            ReconciliationDiscover,
            ReconciliationLock,
            ReconciliationUnlock,
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
        let info = |message| Contract {
            log_at: LogAt::Level(tracing::Level::INFO),
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
                    scenario: "profile sync decode",
                    input: ContractCase::ProfileSyncDecode,
                    expect: error("[scout_stream::mlx_device] failed to parse profile"),
                },
                Check {
                    scenario: "profile sync result serialization",
                    input: ContractCase::ProfileSyncSerialize,
                    expect: error(
                        "[scout_stream::mlx_device] profile sync result failed to serialize",
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
                    scenario: "lockdown lock manager initialization",
                    input: ContractCase::LockdownLockInitialize,
                    expect: error(
                        "[scout_stream::mlx_device] lockdown manager initialization failed",
                    ),
                },
                Check {
                    scenario: "lockdown unlock manager initialization",
                    input: ContractCase::LockdownUnlockInitialize,
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
                    scenario: "missing profile sync request",
                    input: ContractCase::ProfileSyncRequest,
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
                    scenario: "lockdown lock execution",
                    input: ContractCase::LockdownLockExecute,
                    expect: error("[scout_stream::mlx_device] lockdown lock failed"),
                },
                Check {
                    scenario: "lockdown unlock execution",
                    input: ContractCase::LockdownUnlockExecute,
                    expect: error("[scout_stream::mlx_device] lockdown unlock failed"),
                },
                Check {
                    scenario: "device information discovery",
                    input: ContractCase::DeviceInfoDiscover,
                    expect: error("[scout_stream::mlx_device] device info request failed"),
                },
                Check {
                    scenario: "profile sync execution",
                    input: ContractCase::ProfileSyncExecute,
                    expect: error("[scout_stream::mlx_device] profile sync to device failed"),
                },
                Check {
                    scenario: "profile comparison execution",
                    input: ContractCase::ProfileCompareExecute,
                    expect: error(
                        "[scout_stream::mlx_device] profile compare against device failed",
                    ),
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
                    scenario: "config set execution",
                    input: ContractCase::ConfigSetExecute,
                    expect: error("[scout_stream::mlx_device] config set to device failed"),
                },
                Check {
                    scenario: "config sync result serialization",
                    input: ContractCase::ConfigSyncSerialize,
                    expect: error(
                        "[scout_stream::mlx_device] config sync result failed to serialize",
                    ),
                },
                Check {
                    scenario: "config sync execution",
                    input: ContractCase::ConfigSyncExecute,
                    expect: error("[scout_stream::mlx_device] config sync to device failed"),
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
                    scenario: "reconciliation lock execution",
                    input: ContractCase::ReconciliationLock,
                    expect: info("handle_mlxreport_action error from lock_device"),
                },
                Check {
                    scenario: "reconciliation unlock execution",
                    input: ContractCase::ReconciliationUnlock,
                    expect: info("handle_mlxreport_action error from unlock_device"),
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
                ContractCase::ProfileSyncDecode => contract(
                    &ScoutMlxOperationFailed::profile_sync_decode("failure".to_string()),
                ),
                ContractCase::ProfileSyncSerialize => contract(
                    &ScoutMlxOperationFailed::profile_sync_serialize("failure".to_string()),
                ),
                ContractCase::LockdownStatusInitialize => contract(
                    &ScoutMlxOperationFailed::lockdown_status_initialize("failure".to_string()),
                ),
                ContractCase::LockdownLockInitialize => contract(
                    &ScoutMlxOperationFailed::lockdown_lock_initialize("failure".to_string()),
                ),
                ContractCase::LockdownUnlockInitialize => contract(
                    &ScoutMlxOperationFailed::lockdown_unlock_initialize("failure".to_string()),
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
                ContractCase::ProfileSyncRequest => {
                    contract(&ScoutMlxRequestRejected::profile_sync())
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
                ContractCase::LockdownLockExecute => {
                    contract(&ScoutMlxDeviceOperationFailed::lockdown_lock_execute(
                        "device".to_string(),
                        "failure".to_string(),
                    ))
                }
                ContractCase::LockdownUnlockExecute => {
                    contract(&ScoutMlxDeviceOperationFailed::lockdown_unlock_execute(
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
                ContractCase::ProfileSyncExecute => {
                    contract(&ScoutMlxProfileOperationFailed::profile_sync_execute(
                        "device".to_string(),
                        "profile".to_string(),
                        "failure".to_string(),
                    ))
                }
                ContractCase::ProfileCompareExecute => {
                    contract(&ScoutMlxProfileOperationFailed::profile_compare_execute(
                        "device".to_string(),
                        "profile".to_string(),
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
                ContractCase::ConfigSetExecute => {
                    contract(&ScoutMlxConfigOperationFailed::config_set_execute(
                        "device".to_string(),
                        "registry".to_string(),
                        "failure".to_string(),
                    ))
                }
                ContractCase::ConfigSyncSerialize => {
                    contract(&ScoutMlxConfigOperationFailed::config_sync_serialize(
                        "device".to_string(),
                        "registry".to_string(),
                        "failure".to_string(),
                    ))
                }
                ContractCase::ConfigSyncExecute => {
                    contract(&ScoutMlxConfigOperationFailed::config_sync_execute(
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
                ContractCase::ReconciliationLock => contract(&ScoutMlxReconciliationFailed::lock(
                    "device".to_string(),
                    "failure".to_string(),
                )),
                ContractCase::ReconciliationUnlock => {
                    contract(&ScoutMlxReconciliationFailed::unlock(
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
                        ScoutMlxOperation::Reconciliation,
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
            ProfileSync,
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
                    scenario: "missing profile sync data remains metric-only",
                    input: RequestCase::ProfileSync,
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
                    RequestCase::ProfileSync => {
                        (ScoutMlxRequestRejected::profile_sync(), "profile_sync")
                    }
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
    fn mlx_mutation_events_keep_context_out_of_metric_labels() {
        #[derive(Clone, Copy)]
        enum MutationCase {
            ProfileReset,
            ProfileApply,
            FirmwareInitialize,
            FirmwareExecute,
        }

        struct Expected {
            operation: &'static str,
            failure_stage: &'static str,
            event_name: &'static str,
            message: &'static str,
            context: Vec<(&'static str, &'static str)>,
        }

        #[derive(Debug, PartialEq)]
        struct Observation {
            counter_delta: f64,
            level: tracing::Level,
            event_name: Option<String>,
            message: String,
            context: Vec<(String, String, Option<CapturedFieldKind>)>,
        }

        let expected = |case| match case {
            MutationCase::ProfileReset => Expected {
                operation: "profile_reset",
                failure_stage: "execute",
                event_name: "scout_mlx_profile_reset_failed",
                message: "mlxconfig reset failed",
                context: vec![("device", "device"), ("error", "failure")],
            },
            MutationCase::ProfileApply => Expected {
                operation: "profile_apply",
                failure_stage: "execute",
                event_name: "scout_mlx_profile_apply_failed",
                message: "mlxconfig profile sync failed",
                context: vec![
                    ("device", "device"),
                    ("profile", "profile"),
                    ("error", "failure"),
                ],
            },
            MutationCase::FirmwareInitialize => Expected {
                operation: "firmware_flash",
                failure_stage: "initialize",
                event_name: "scout_mlx_firmware_flasher_initialization_failed",
                message: "failed to create FirmwareFlasher",
                context: vec![
                    ("device", "device"),
                    ("part_number", "part-number"),
                    ("psid", "psid"),
                    ("error", "failure"),
                ],
            },
            MutationCase::FirmwareExecute => Expected {
                operation: "firmware_flash",
                failure_stage: "execute",
                event_name: "scout_mlx_firmware_flash_failed",
                message: "firmware flash failed",
                context: vec![
                    ("device", "device"),
                    ("part_number", "part-number"),
                    ("psid", "psid"),
                    ("firmware_url", "https://firmware.example/fw.bin"),
                    ("target_version", "1.2.3"),
                    ("error", "failure"),
                ],
            },
        };
        let expected_observation = |case| {
            let expected = expected(case);
            Observation {
                counter_delta: 1.0,
                level: tracing::Level::ERROR,
                event_name: Some(expected.event_name.to_string()),
                message: expected.message.to_string(),
                context: expected
                    .context
                    .into_iter()
                    .map(|(name, value)| {
                        (
                            name.to_string(),
                            value.to_string(),
                            Some(CapturedFieldKind::Debug),
                        )
                    })
                    .collect(),
            }
        };

        check_values(
            [
                Check {
                    scenario: "profile reset failure",
                    input: MutationCase::ProfileReset,
                    expect: expected_observation(MutationCase::ProfileReset),
                },
                Check {
                    scenario: "profile apply failure",
                    input: MutationCase::ProfileApply,
                    expect: expected_observation(MutationCase::ProfileApply),
                },
                Check {
                    scenario: "firmware flasher initialization failure",
                    input: MutationCase::FirmwareInitialize,
                    expect: expected_observation(MutationCase::FirmwareInitialize),
                },
                Check {
                    scenario: "firmware flash execution failure",
                    input: MutationCase::FirmwareExecute,
                    expect: expected_observation(MutationCase::FirmwareExecute),
                },
            ],
            |case| {
                let expected = expected(case);
                let metrics = MetricsCapture::start();
                let logs = capture_logs(|| match case {
                    MutationCase::ProfileReset => emit(ScoutMlxProfileResetFailed::execute(
                        "device".to_string(),
                        "failure".to_string(),
                    )),
                    MutationCase::ProfileApply => emit(ScoutMlxProfileApplyFailed::execute(
                        "device".to_string(),
                        "profile".to_string(),
                        "failure".to_string(),
                    )),
                    MutationCase::FirmwareInitialize => {
                        emit(ScoutMlxFirmwareFlasherInitializationFailed::new(
                            "device".to_string(),
                            "part-number".to_string(),
                            "psid".to_string(),
                            "failure".to_string(),
                        ))
                    }
                    MutationCase::FirmwareExecute => emit(ScoutMlxFirmwareFlashFailed::execute(
                        "device".to_string(),
                        "part-number".to_string(),
                        "psid".to_string(),
                        "https://firmware.example/fw.bin".to_string(),
                        "1.2.3".to_string(),
                        "failure".to_string(),
                    )),
                });
                let log = &logs[0];

                Observation {
                    counter_delta: metrics.counter_delta(
                        "carbide_scout_mlx_failures_total",
                        &[
                            ("operation", expected.operation),
                            ("failure_stage", expected.failure_stage),
                            ("failure_kind", "backend"),
                        ],
                    ),
                    level: log.level,
                    event_name: log.field("event_name").map(str::to_string),
                    message: log.message.clone(),
                    context: expected
                        .context
                        .iter()
                        .map(|(name, _)| {
                            (
                                (*name).to_string(),
                                log.field(name).unwrap().to_string(),
                                log.field_kind(name),
                            )
                        })
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
