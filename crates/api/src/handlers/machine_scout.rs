/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge as rpc;
use ::rpc::forge_agent_control_response::forge_agent_control_extra_info::KeyValuePair;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    BomValidating, CleanupState, FailureCause, FailureDetails, FailureSource, InstanceState,
    MachineState, MachineValidatingState, ManagedHostState, MeasuringState, ValidationState,
    get_action_for_dpu_state,
};
use model::machine_validation::{MachineValidationState, MachineValidationStatus};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::metrics::ApiMetricsEmitter;
use crate::api::{Api, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

// Transitions the machine to Ready state.
// Called by 'forge-scout discovery' once cleanup succeeds.
pub(crate) async fn cleanup_machine_completed(
    api: &Api,
    request: Request<rpc::MachineCleanupInfo>,
) -> Result<Response<rpc::MachineCleanupResult>, Status> {
    log_request_data(&request);

    let cleanup_info = request.into_inner();
    tracing::info!(?cleanup_info, "cleanup_machine_completed");

    let machine_id = convert_and_log_machine_id(cleanup_info.machine_id.as_ref())?;

    // Load machine from DB
    let (machine, mut txn) = api
        .load_machine(&machine_id, MachineSearchConfig::default())
        .await?;
    db::machine::update_cleanup_time(&machine, &mut txn).await?;

    if let Some(nvme_result) = cleanup_info.nvme
        && rpc::machine_cleanup_info::CleanupResult::Error as i32 == nvme_result.result
    {
        // NVME Cleanup failed. Move machine to failed state.
        db::machine::update_failure_details(
            &machine,
            &mut txn,
            FailureDetails {
                cause: FailureCause::NVMECleanFailed {
                    err: nvme_result.message.to_string(),
                },
                failed_at: chrono::Utc::now(),
                source: FailureSource::Scout,
            },
        )
        .await?;
    }

    txn.commit().await?;

    // State handler should mark Machine as Adopted and reboot host for bios/bmc lockdown.
    // Wake it up
    if machine_id.machine_type().is_host()
        && let Err(err) = api
            .machine_state_handler_enqueuer
            .enqueue_object(&machine_id)
            .await
    {
        tracing::warn!(%err, %machine_id, "Failed to wake up state handler for machine");
    }

    Ok(Response::new(rpc::MachineCleanupResult {}))
}

// Invoked by forge-scout whenever a certain Machine can not be properly acted on
pub(crate) fn report_forge_scout_error(
    _api: &Api,
    request: Request<rpc::ForgeScoutErrorReport>,
) -> Result<Response<rpc::ForgeScoutErrorReportResult>, Status> {
    log_request_data(&request);
    let _machine_id = convert_and_log_machine_id(request.into_inner().machine_id.as_ref())?;

    // `log_request_data` will already provide us the error message
    // Therefore we don't have to do anything else
    Ok(Response::new(rpc::ForgeScoutErrorReportResult {}))
}

// Called on x86 boot by 'forge-scout auto-detect --uuid=<uuid>'.
// Tells it whether to discover or cleanup based on current machine state.
pub(crate) async fn forge_agent_control(
    api: &Api,
    request: Request<rpc::ForgeAgentControlRequest>,
) -> Result<Response<rpc::ForgeAgentControlResponse>, Status> {
    log_request_data(&request);

    use ::rpc::forge_agent_control_response::Action;

    let machine_id = convert_and_log_machine_id(request.into_inner().machine_id.as_ref())?;

    let (machine, mut txn) = api
        .load_machine(&machine_id, MachineSearchConfig::default())
        .await?;

    let is_dpu = machine.is_dpu();
    let host_machine = if !is_dpu {
        machine.clone()
    } else {
        db::machine::find_host_by_dpu_machine_id(&mut txn, &machine_id)
            .await?
            .ok_or(CarbideError::NotFoundError {
                kind: "machine",
                id: machine_id.to_string(),
            })?
    };

    if !is_dpu {
        db::machine::update_scout_contact_time(&machine_id, &mut txn).await?;
    }

    // Respond based on machine current state
    let state = host_machine.current_state();
    let (action, action_data) = if is_dpu {
        get_action_for_dpu_state(state, &machine_id).map_err(CarbideError::from)?
    } else {
        match state {
            ManagedHostState::HostInit {
                machine_state: MachineState::Init,
            } => (Action::Retry, None),
            ManagedHostState::Validation {
                validation_state:
                    ValidationState::MachineValidation {
                        machine_validation:
                            MachineValidatingState::MachineValidating {
                                context,
                                id,
                                completed,
                                total,
                                is_enabled,
                            },
                    },
            } => {
                tracing::info!(
                    " context : {} id: {} is_enabled: {}, completed {}, total {}",
                    context,
                    id,
                    is_enabled,
                    completed,
                    total,
                );
                if *is_enabled {
                    db::machine_validation::update_status(
                        &mut txn,
                        id,
                        MachineValidationStatus {
                            state: MachineValidationState::InProgress,
                            ..MachineValidationStatus::default()
                        },
                    )
                    .await?;
                    let machine_validation =
                        db::machine_validation::find_by_id(&mut txn, id).await?;
                    (
                        Action::MachineValidation,
                        Some(
                            rpc::forge_agent_control_response::ForgeAgentControlExtraInfo {
                                pair: [
                                    KeyValuePair {
                                        key: "Context".to_string(),
                                        value: context.clone(),
                                    },
                                    KeyValuePair {
                                        key: "ValidationId".to_string(),
                                        value: id.to_string(),
                                    },
                                    KeyValuePair {
                                        key: "IsEnabled".to_string(),
                                        value: is_enabled.to_string(),
                                    },
                                    KeyValuePair {
                                        key: "MachineValidationFilter".to_string(),
                                        value: serde_json::to_string(&machine_validation.filter)
                                            .map_err(CarbideError::from)?,
                                    },
                                ]
                                .to_vec(),
                            },
                        ),
                    )
                } else {
                    // This avoids sending Machine validation command scout
                    tracing::info!("Skipped machine validation",);
                    (Action::Noop, None)
                }
            }
            ManagedHostState::HostInit {
                machine_state: MachineState::WaitingForDiscovery,
            }
            | ManagedHostState::Failed {
                details:
                    FailureDetails {
                        cause: FailureCause::Discovery { .. },
                        ..
                    },
                ..
            } => (Action::Discovery, None),
            // If the API is configured with attestation_enabled, and
            // the machine has been Discovered (and progressed on to the
            // point where it is WaitingForMeasurements), then let Scout (or
            // whoever the caller is) know that it's time for measurements
            // to be sent.
            ManagedHostState::Measuring {
                measuring_state: MeasuringState::WaitingForMeasurements,
            } => (Action::Measure, None),
            ManagedHostState::WaitingForCleanup {
                cleanup_state: CleanupState::HostCleanup { .. },
            }
            | ManagedHostState::Failed {
                details:
                    FailureDetails {
                        cause: FailureCause::NVMECleanFailed { .. },
                        ..
                    },
                ..
            } => {
                let last_cleanup_time = host_machine.last_cleanup_time;
                let state_version = host_machine.state.version;
                tracing::info!(
                    "last_cleanup_time: {:?}, state_version: {:?}",
                    last_cleanup_time,
                    state_version
                );
                // Check scout has already cleaned up the machine
                if last_cleanup_time.unwrap_or_default() > state_version.timestamp() {
                    tracing::info!("Cleanup is already done");
                    (Action::Noop, None)
                } else {
                    (Action::Reset, None)
                }
            }
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::UpdatingInventory(_),
            } => {
                tracing::info!(
                    "Request Discovery {} < {}",
                    machine.last_discovery_time.unwrap_or_default(),
                    machine.current_version().timestamp()
                );
                if machine.last_discovery_time.unwrap_or_default()
                    < machine.current_version().timestamp()
                {
                    (Action::Discovery, None)
                } else {
                    (Action::Noop, None)
                }
            }
            ManagedHostState::Assigned {
                instance_state: InstanceState::WaitingForDpaToBeReady,
            } => match crate::handlers::dpa::process_scout_req(api, &mut txn, machine_id).await {
                Ok((action, einfo)) => (action, einfo),
                Err(e) => {
                    tracing::error!("Error returned from process_scout_req: {e}");
                    (Action::Noop, None)
                }
            },

            _ => {
                // Later this might go to site admin dashboard for manual intervention
                tracing::info!(
                    machine_id = %machine.id,
                    machine_type = "Host",
                    %state,
                    "forge agent control",
                );
                (Action::Noop, None)
            }
        }
    };
    tracing::info!(
        machine_id = %machine.id,
        action = action.as_str_name(),
        "forge agent control",
    );

    txn.commit().await?;

    Ok(Response::new(rpc::ForgeAgentControlResponse {
        action: action as i32,
        data: action_data,
    }))
}

/// Records reboot duration metric for a machine if applicable
fn record_reboot_duration_metric(
    metric_emitter: &ApiMetricsEmitter,
    machine: &model::machine::Machine,
) {
    let Some(last_reboot_requested) = &machine.last_reboot_requested else {
        return;
    };

    // Skip recording metrics for PowerOff requests
    if matches!(
        last_reboot_requested.mode,
        model::machine::MachineLastRebootRequestedMode::PowerOff
    ) {
        return;
    }

    let reboot_duration_secs = (chrono::Utc::now() - last_reboot_requested.time).num_seconds();

    // Only record positive durations (in case of clock skew)
    if reboot_duration_secs <= 0 {
        return;
    }

    // Extract product name and vendor from hardware info
    let product_name = machine
        .hardware_info
        .as_ref()
        .and_then(|hi| hi.dmi_data.as_ref())
        .map(|dmi| dmi.product_name.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let vendor = machine
        .hardware_info
        .as_ref()
        .and_then(|hi| hi.dmi_data.as_ref())
        .map(|dmi| dmi.sys_vendor.clone())
        .unwrap_or_else(|| "unknown".to_string());

    metric_emitter.record_machine_reboot_duration(
        reboot_duration_secs as u64,
        product_name,
        vendor,
        last_reboot_requested.mode.to_string(),
    );
}

// Host has rebooted
pub(crate) async fn reboot_completed(
    api: &Api,
    request: Request<rpc::MachineRebootCompletedRequest>,
) -> Result<Response<rpc::MachineRebootCompletedResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    let machine_id = convert_and_log_machine_id(req.machine_id.as_ref())?;

    let (machine, mut txn) = api
        .load_machine(&machine_id, MachineSearchConfig::default())
        .await?;

    record_reboot_duration_metric(&api.metric_emitter, &machine);

    db::machine::update_reboot_time(&machine, &mut txn).await?;

    txn.commit().await?;

    // Wake up the state handler for the machine
    // Don't do it for DPUs - state handlers only run on hosts
    if (machine_id.machine_type().is_host() || machine_id.machine_type().is_predicted_host())
        && let Err(err) = api
            .machine_state_handler_enqueuer
            .enqueue_object(&machine_id)
            .await
    {
        tracing::warn!(%err, %machine_id, "Failed to wake up state handler for machine");
    }

    Ok(Response::new(rpc::MachineRebootCompletedResponse {}))
}
