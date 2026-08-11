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

//! Handler for SwitchControllerState::FetchInfo.

use carbide_instrument::{Event, LabelValue, emit};
use carbide_uuid::switch::SwitchId;
use model::switch::{Switch, SwitchControllerState, ValidatingState};
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::SwitchStateHandlerContextObjects;
use crate::endpoint;

/// The step that prevented `FetchInfo` from enriching a switch. These errors
/// remain best-effort: the controller still moves to `Validating`, while this
/// label lets operators see which dependency left the location data unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
enum SwitchSlotTrayEnrichmentFailureStage {
    EndpointResolution,
    BackendRequest,
    BackendResponse,
    DatabaseUpdate,
}

/// `FetchInfo` could not enrich a switch with its RMS slot and tray. These
/// failures stay best-effort -- the controller still moves to `Validating` --
/// so the variant names which dependency left the location data unset. Only
/// the stages that actually reached a backend hold one.
#[derive(Event)]
#[event(
    event_name = "switch_slot_tray_enrichment_failed",
    metric_name = "carbide_switch_slot_tray_enrichment_failures_total",
    component = "switch-controller",
    metric = counter,
    log = warn,
    describe = "Number of switch slot and tray enrichment failures, by failure stage.",
    labels(failure_stage: SwitchSlotTrayEnrichmentFailureStage),
)]
enum SwitchSlotTrayEnrichmentFailed {
    /// The switch endpoint could not be resolved, so the backend was never
    /// reached.
    #[event(
        labels(failure_stage = EndpointResolution),
        message = "Failed to resolve switch endpoint for slot and tray lookup"
    )]
    EndpointResolution {
        #[context]
        error: String,
        #[context]
        switch_id: String,
    },

    /// The component-manager request itself failed.
    #[event(
        labels(failure_stage = BackendRequest),
        message = "Failed to reach the component manager for slot and tray"
    )]
    BackendRequest {
        #[context]
        error: String,
        #[context]
        switch_id: String,
        #[context]
        backend: String,
    },

    /// The backend answered, but its result could not be used.
    #[event(
        labels(failure_stage = BackendResponse),
        message = "Could not read slot and tray from the component manager's answer"
    )]
    BackendResponse {
        #[context]
        error: String,
        #[context]
        switch_id: String,
        #[context]
        backend: String,
    },

    /// The location data was fetched but could not be written back.
    #[event(
        labels(failure_stage = DatabaseUpdate),
        message = "Failed to update slot_number and tray_index for switch"
    )]
    Persistence {
        #[context]
        error: String,
        #[context]
        switch_id: String,
    },
}

/// Handles the FetchInfo state for a switch.
pub async fn handle_fetch_info(
    switch_id: &SwitchId,
    state: &Switch,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    if let (Some(_rack_id), Some(component_manager)) =
        (&state.rack_id, &ctx.services.component_manager)
    {
        match endpoint::resolve_switch_endpoint(
            switch_id,
            &ctx.services.db_pool,
            &ctx.services.credential_manager,
        )
        .await
        {
            Ok(endpoint) => match component_manager
                .nv_switch
                .get_slot_and_tray(std::slice::from_ref(&endpoint))
                .await
            {
                Ok(results) => {
                    if let Some(result) = results.into_iter().next() {
                        if let Some(error) = result.error.as_deref() {
                            emit(SwitchSlotTrayEnrichmentFailed::BackendResponse {
                                error: error.to_string(),
                                switch_id: switch_id.to_string(),
                                backend: component_manager.nv_switch.name().to_string(),
                            });
                        }
                        let mut update_txn = ctx.services.db_pool.begin().await?;
                        if let Err(e) = db::switch::update_slot_and_tray(
                            &mut update_txn,
                            switch_id,
                            result.slot_number,
                            result.tray_index,
                        )
                        .await
                        {
                            emit(SwitchSlotTrayEnrichmentFailed::Persistence {
                                error: e.to_string(),
                                switch_id: switch_id.to_string(),
                            });
                            update_txn.rollback().await?;
                        } else {
                            update_txn.commit().await?;
                        }
                    }
                }
                Err(error) => {
                    emit(SwitchSlotTrayEnrichmentFailed::BackendRequest {
                        error: error.to_string(),
                        switch_id: switch_id.to_string(),
                        backend: component_manager.nv_switch.name().to_string(),
                    });
                }
            },
            Err(error) => {
                emit(SwitchSlotTrayEnrichmentFailed::EndpointResolution {
                    error: error.to_string(),
                    switch_id: switch_id.to_string(),
                });
            }
        }
    }

    tracing::info!(
        %switch_id,
        "Switch slot and tray fetch complete, transitioning to Validating"
    );
    Ok(StateHandlerOutcome::transition(
        SwitchControllerState::Validating {
            validating_state: ValidatingState::ValidationComplete,
        },
    ))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use carbide_instrument::testing::{MetricsCapture, capture_logs};
    use carbide_test_support::{Check, check_values};

    use super::*;

    const METRIC: &str = "carbide_switch_slot_tray_enrichment_failures_total";
    const ERROR: &str = "simulated failure";
    const SWITCH_ID: &str = "sw100nsner0op5osl6n85t7772j010jmhafm934n7oej4mlome3okrn9b60";

    #[derive(Clone, Copy)]
    enum FailureCase {
        EndpointResolution,
        BackendRequest,
        BackendResponse,
        DatabaseUpdate,
    }

    #[derive(Debug, PartialEq)]
    struct Observation {
        log_count: usize,
        level: tracing::Level,
        message: String,
        event_name: Option<String>,
        metric_name: Option<String>,
        failure_stage: Option<String>,
        error: Option<String>,
        switch_id: Option<String>,
        backend: Option<String>,
        counter_delta: f64,
    }

    #[test]
    fn slot_tray_enrichment_failures_keep_their_logs_and_count_by_stage() {
        check_values(
            [
                Check {
                    scenario: "endpoint resolution",
                    input: FailureCase::EndpointResolution,
                    expect: Observation {
                        log_count: 1,
                        level: tracing::Level::WARN,
                        message: "Failed to resolve switch endpoint for slot and tray lookup"
                            .to_string(),
                        event_name: Some("switch_slot_tray_enrichment_failed".to_string()),
                        metric_name: Some(METRIC.to_string()),
                        failure_stage: Some("endpoint_resolution".to_string()),
                        error: Some(ERROR.to_string()),
                        switch_id: Some(SWITCH_ID.to_string()),
                        backend: None,
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "backend request",
                    input: FailureCase::BackendRequest,
                    expect: Observation {
                        log_count: 1,
                        level: tracing::Level::WARN,
                        message: "Failed to reach the component manager for slot and tray"
                            .to_string(),
                        event_name: Some("switch_slot_tray_enrichment_failed".to_string()),
                        metric_name: Some(METRIC.to_string()),
                        failure_stage: Some("backend_request".to_string()),
                        error: Some(ERROR.to_string()),
                        switch_id: Some(SWITCH_ID.to_string()),
                        backend: Some("rms".to_string()),
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "backend response",
                    input: FailureCase::BackendResponse,
                    expect: Observation {
                        log_count: 1,
                        level: tracing::Level::WARN,
                        message: "Could not read slot and tray from the component manager's answer"
                            .to_string(),
                        event_name: Some("switch_slot_tray_enrichment_failed".to_string()),
                        metric_name: Some(METRIC.to_string()),
                        failure_stage: Some("backend_response".to_string()),
                        error: Some(ERROR.to_string()),
                        switch_id: Some(SWITCH_ID.to_string()),
                        backend: Some("rms".to_string()),
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "database update",
                    input: FailureCase::DatabaseUpdate,
                    expect: Observation {
                        log_count: 1,
                        level: tracing::Level::WARN,
                        message: "Failed to update slot_number and tray_index for switch"
                            .to_string(),
                        event_name: Some("switch_slot_tray_enrichment_failed".to_string()),
                        metric_name: Some(METRIC.to_string()),
                        failure_stage: Some("database_update".to_string()),
                        error: Some(ERROR.to_string()),
                        switch_id: Some(SWITCH_ID.to_string()),
                        backend: None,
                        counter_delta: 1.0,
                    },
                },
            ],
            |case| {
                let failure_stage_label = match case {
                    FailureCase::EndpointResolution => "endpoint_resolution",
                    FailureCase::BackendRequest => "backend_request",
                    FailureCase::BackendResponse => "backend_response",
                    FailureCase::DatabaseUpdate => "database_update",
                };
                let metrics = MetricsCapture::start();
                let switch_id = SwitchId::from_str(SWITCH_ID).unwrap();
                let logs = capture_logs(|| match case {
                    FailureCase::EndpointResolution => {
                        emit(SwitchSlotTrayEnrichmentFailed::EndpointResolution {
                            error: ERROR.to_string(),
                            switch_id: switch_id.to_string(),
                        });
                    }
                    FailureCase::BackendRequest => {
                        emit(SwitchSlotTrayEnrichmentFailed::BackendRequest {
                            error: ERROR.to_string(),
                            switch_id: switch_id.to_string(),
                            backend: "rms".to_string(),
                        });
                    }
                    FailureCase::BackendResponse => {
                        emit(SwitchSlotTrayEnrichmentFailed::BackendResponse {
                            error: ERROR.to_string(),
                            switch_id: switch_id.to_string(),
                            backend: "rms".to_string(),
                        });
                    }
                    FailureCase::DatabaseUpdate => {
                        emit(SwitchSlotTrayEnrichmentFailed::Persistence {
                            error: ERROR.to_string(),
                            switch_id: switch_id.to_string(),
                        });
                    }
                });
                let log = logs.first().expect("failure Event logged");

                Observation {
                    log_count: logs.len(),
                    level: log.level,
                    message: log.message.clone(),
                    event_name: log.field("event_name").map(str::to_string),
                    metric_name: log.field("metric_name").map(str::to_string),
                    failure_stage: log.field("failure_stage").map(str::to_string),
                    error: log.field("error").map(str::to_string),
                    switch_id: log.field("switch_id").map(str::to_string),
                    backend: log.field("backend").map(str::to_string),
                    counter_delta: metrics
                        .counter_delta(METRIC, &[("failure_stage", failure_stage_label)]),
                }
            },
        );
    }
}
