/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! State Handler implementation for Dpa Interfaces

use std::collections::HashMap;
use std::sync::Arc;

use itertools::Itertools;
use libredfish::Redfish;
use libredfish::model::component_integrity::{ComponentIntegrities, ComponentIntegrity};
use libredfish::model::task::TaskState;
use model::attestation::spdm::{
    AttestationDeviceState, AttestationState, AttestationStatus, DeviceType,
    EvidenceResultAppraisalPolicyDeviceStates, FetchDataDeviceStates, SpdmAttestationStatus,
    SpdmHandlerError, SpdmMachineDeviceAttestation, SpdmMachineDeviceMetadata, SpdmMachineSnapshot,
    SpdmMachineStateSnapshot, SpdmObjectId, VerificationDeviceStates, Verifier,
    from_component_integrity,
};
use model::bmc_info::BmcInfo;
use nras::{DeviceAttestationInfo, EvidenceCertificate, RawAttestationOutcome, VerifierClient};
use sqlx::PgConnection;

use crate::state_controller::spdm::context::SpdmStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
    StateHandlerOutcomeWithTransaction,
};

#[derive(Debug, Clone)]
pub struct SpdmAttestationStateHandler {
    device_handler: SpdmAttestationDeviceStateHandler,
}

impl SpdmAttestationStateHandler {
    pub fn new(verifier: Arc<dyn Verifier>, nras_config: nras::Config) -> Self {
        Self {
            device_handler: SpdmAttestationDeviceStateHandler::new(verifier, nras_config),
        }
    }

    fn record_metrics(
        &self,
        _state: &mut SpdmMachineSnapshot,
        _ctx: &mut StateHandlerContext<SpdmStateHandlerContextObjects>,
    ) {
    }
}

#[derive(Debug, Clone)]
pub struct SpdmAttestationDeviceStateHandler {
    verifier: Arc<dyn Verifier>,
    nras_config: nras::Config,
}

impl SpdmAttestationDeviceStateHandler {
    pub fn new(verifier: Arc<dyn Verifier>, nras_config: nras::Config) -> Self {
        Self {
            verifier,
            nras_config,
        }
    }
}

// Check if all devices are in expected sync state.
fn sync_state_achieved(
    expected_state: &AttestationDeviceState,
    state: &SpdmMachineStateSnapshot,
) -> bool {
    state.devices_state.values().all(|x| {
        x == expected_state || matches!(x, AttestationDeviceState::AttestationCompleted { .. })
    })
}

/// Creates a SpdmMachineStateSnapshot based on the major (machine) state.
/// This is a helper function which is called when all devices are reached into Sync state and
/// ready to move to next machine (major) state.
/// DB is updated with all devices based on the returned value.
fn next_state_snapshot(
    major_state: &AttestationState,
    state: &SpdmMachineStateSnapshot,
) -> SpdmMachineStateSnapshot {
    let (new_machine_state, device_state, update_device_version) = match major_state {
        AttestationState::CheckIfAttestationSupported => (
            AttestationState::FetchAttestationTargetsAndUpdateDb,
            AttestationDeviceState::NotApplicable,
            false,
        ),

        AttestationState::FetchAttestationTargetsAndUpdateDb => (
            AttestationState::FetchData,
            AttestationDeviceState::FetchData(FetchDataDeviceStates::FetchMetadata),
            // all devices are updated in db already in state handler.
            false,
        ),

        AttestationState::FetchData => (
            AttestationState::Verification,
            AttestationDeviceState::Verification(VerificationDeviceStates::GetVerifierResponse),
            true,
        ),
        AttestationState::Verification => (
            AttestationState::ApplyEvidenceResultAppraisalPolicy,
            AttestationDeviceState::ApplyEvidenceResultAppraisalPolicy(
                EvidenceResultAppraisalPolicyDeviceStates::ApplyAppraisalPolicy,
            ),
            true,
        ),
        AttestationState::Completed | AttestationState::ApplyEvidenceResultAppraisalPolicy => (
            AttestationState::Completed,
            AttestationDeviceState::AttestationCompleted {
                status: model::attestation::spdm::AttestationStatus::Success,
            },
            true,
        ),
    };

    SpdmMachineStateSnapshot {
        machine_state: new_machine_state,
        devices_state: HashMap::from_iter(state.devices_state.clone().into_iter().map(|x| {
            (
                x.0,
                // Update device state only if attestation is pending. If attestation is completed
                // (success/failure), do not over-write the state again.
                if matches!(x.1, AttestationDeviceState::AttestationCompleted { .. }) {
                    x.1
                } else {
                    device_state.clone()
                },
            )
        })),
        device_state: None,
        machine_version: state.machine_version,
        device_version: None,
        update_machine_version: true,
        update_device_version,
    }
}

fn get_sync_sub_state(
    main_state: &AttestationState,
) -> Result<AttestationDeviceState, StateHandlerError /*replace it with own error type*/> {
    match main_state {
        AttestationState::CheckIfAttestationSupported
        | AttestationState::Completed
        | AttestationState::FetchAttestationTargetsAndUpdateDb => Err(
            StateHandlerError::GenericError(eyre::eyre!("Not Supported!!")),
        ),
        AttestationState::FetchData => Ok(AttestationDeviceState::FetchData(
            FetchDataDeviceStates::Collected,
        )),
        AttestationState::Verification => Ok(AttestationDeviceState::Verification(
            VerificationDeviceStates::VerificationCompleted,
        )),
        AttestationState::ApplyEvidenceResultAppraisalPolicy => {
            Ok(AttestationDeviceState::ApplyEvidenceResultAppraisalPolicy(
                EvidenceResultAppraisalPolicyDeviceStates::AppraisalPolicyValidationCompleted,
            ))
        }
    }
}

async fn redfish_client(
    bmc_info: &BmcInfo,
    ctx: &mut StateHandlerContext<'_, SpdmStateHandlerContextObjects>,
) -> Result<Box<dyn Redfish>, StateHandlerError> {
    ctx.services
        .redfish_client_pool
        .create_client_for_ingested_host(
            bmc_info
                .ip_addr()
                .map_err(StateHandlerError::GenericError)?,
            bmc_info.port,
            &ctx.services.db_pool,
        )
        .await
        .map_err(StateHandlerError::from)
}

// Rules:
// ComponentIntegrityTypeVersion should be >= 1.1.0.
// ComponentIntegrityType should be SPDM.
// ComponentIntegrityEnabled should be true.
// Once these all conditions are true, a device can be proceed with attestation.
fn get_components_supporting_spdm(integrities: &ComponentIntegrities) -> Vec<&ComponentIntegrity> {
    let supported_versions = ["1.1.0"]; // This can be configurable value.
    let mut supported_components = vec![];

    for component in &integrities.members {
        if !component.component_integrity_enabled {
            // Component Integrity is not enabled
            continue;
        }

        if component.component_integrity_type != "SPDM" {
            // Not SPDM, may be TPM.
            continue;
        }

        if !supported_versions.contains(&component.component_integrity_type_version.as_str()) {
            continue;
        }

        supported_components.push(component);
    }

    supported_components
}

#[async_trait::async_trait]
impl StateHandler for SpdmAttestationStateHandler {
    type ObjectId = SpdmObjectId;
    type State = SpdmMachineSnapshot;
    type ControllerState = SpdmMachineStateSnapshot;
    type ContextObjects = SpdmStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        object_id: &Self::ObjectId,
        state: &mut SpdmMachineSnapshot,
        controller_state: &SpdmMachineStateSnapshot,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<SpdmMachineStateSnapshot>, StateHandlerError>
    {
        // TODO: Fix txn_held_across_await in handle_object_state_inner, then move it back inline
        let pool = ctx.services.db_pool.clone();
        let mut txn = pool.begin().await?;
        let outcome = self
            .handle_object_state_inner(object_id, state, controller_state, &mut txn, ctx)
            .await?;
        Ok(outcome.with_txn(Some(txn)))
    }
}

impl SpdmAttestationStateHandler {
    #[allow(txn_held_across_await)]
    async fn handle_object_state_inner(
        &self,
        object_id: &SpdmObjectId,
        state: &mut SpdmMachineSnapshot,
        controller_state: &SpdmMachineStateSnapshot,
        txn: &mut PgConnection,
        ctx: &mut StateHandlerContext<'_, SpdmStateHandlerContextObjects>,
    ) -> Result<StateHandlerOutcome<SpdmMachineStateSnapshot>, StateHandlerError> {
        // record metrics irrespective of the state of the machine
        self.record_metrics(state, ctx);

        let machine_id = object_id.0;
        match controller_state.machine_state {
            AttestationState::CheckIfAttestationSupported => {
                let redfish_client = redfish_client(&state.bmc_info, ctx).await?;
                let root = redfish_client.get_service_root().await.map_err(|error| {
                    StateHandlerError::RedfishError {
                        operation: "fetch system root",
                        error,
                    }
                })?;

                let status = if root.component_integrity.is_none() {
                    SpdmAttestationStatus::NotSupported
                } else {
                    db::attestation::spdm::update_started_time(txn, &machine_id)
                        .await
                        .map_err(StateHandlerError::from)?;
                    SpdmAttestationStatus::Started
                };
                db::attestation::spdm::update_attestation_status(txn, &machine_id, &status)
                    .await
                    .map_err(StateHandlerError::from)?;

                // Update state only if attestation is supported.
                // In any case if status is set as not_supported, this machine won't be picked for
                // next iterations.
                Ok(if status == SpdmAttestationStatus::Started {
                    StateHandlerOutcome::transition(next_state_snapshot(
                        &controller_state.machine_state,
                        controller_state,
                    ))
                } else {
                    StateHandlerOutcome::do_nothing()
                })
            }
            AttestationState::FetchAttestationTargetsAndUpdateDb => {
                let redfish_client = redfish_client(&state.bmc_info, ctx).await?;
                let component_integrities = redfish_client
                    .get_component_integrities()
                    .await
                    .map_err(|error| StateHandlerError::RedfishError {
                        operation: "fetch system root",
                        error,
                    })?;

                let components = get_components_supporting_spdm(&component_integrities);

                if components.is_empty() {
                    db::attestation::spdm::update_attestation_status(
                        txn,
                        &machine_id,
                        &SpdmAttestationStatus::NotSupported,
                    )
                    .await
                    .map_err(StateHandlerError::from)?;
                }

                // The validation that list is not changed is done by SKU validation. SKU
                // validation checks that the device profile is not changed over time. If any
                // device list is changed and SKU validation is passed, means SRE has approved the
                // change request.
                // Validating again is not needed.
                // Remove existing device list and over-write with this list.
                let devices = components
                    .into_iter()
                    .map(|x| from_component_integrity(x.clone(), machine_id))
                    .collect_vec();

                db::attestation::spdm::insert_devices(txn, &machine_id, devices)
                    .await
                    .map_err(StateHandlerError::from)?;

                Ok(StateHandlerOutcome::transition(next_state_snapshot(
                    &controller_state.machine_state,
                    controller_state,
                )))
            }
            AttestationState::FetchData
            | AttestationState::Verification
            | AttestationState::ApplyEvidenceResultAppraisalPolicy => {
                // Since state machine's new changes, now next iteration runs again with same set of
                // object_ids. This will fail because in previous state
                // (FetchAttestationTargetsAndUpdateDb) the db is updated with correct devices
                // associated with the host.
                // If we return wait here, state machine will run next iteration after some delay
                // post fetching latest object id and associated device ids.
                if object_id.1.is_none() {
                    return Ok(StateHandlerOutcome::wait(format!(
                        "Waiting for device id allocation for host: {object_id:?}."
                    )));
                }
                let outcome = self
                    .device_handler
                    .handle_object_state_inner(object_id, state, controller_state, txn, ctx)
                    .await?;

                if matches!(outcome, StateHandlerOutcome::Transition { .. })
                    || matches!(outcome, StateHandlerOutcome::Wait { .. })
                {
                    return Ok(outcome);
                }

                // Nothing to be done. Check if sync state is achieved.
                if sync_state_achieved(
                    &get_sync_sub_state(&controller_state.machine_state)?,
                    controller_state,
                ) {
                    let next_state =
                        next_state_snapshot(&controller_state.machine_state, controller_state);
                    // If attestation is completed, update status as completed so that this machine
                    // won't be scheduled in next iteration.
                    if next_state
                        .devices_state
                        .values()
                        .all(|x| matches!(x, AttestationDeviceState::AttestationCompleted { .. }))
                    {
                        db::attestation::spdm::update_attestation_status(
                            txn,
                            &machine_id,
                            &SpdmAttestationStatus::Completed,
                        )
                        .await?;
                    }

                    // Move to next major state.
                    return Ok(StateHandlerOutcome::transition(next_state));
                }

                // TODO: Set status completed
                Ok(StateHandlerOutcome::do_nothing())
            }
            AttestationState::Completed => Ok(StateHandlerOutcome::do_nothing()),
        }
    }
}

#[async_trait::async_trait]
impl StateHandler for SpdmAttestationDeviceStateHandler {
    type ObjectId = SpdmObjectId;
    type State = SpdmMachineSnapshot;
    type ControllerState = SpdmMachineStateSnapshot;
    type ContextObjects = SpdmStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        object_id: &Self::ObjectId,
        state: &mut SpdmMachineSnapshot,
        controller_state: &Self::ControllerState,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<Self::ControllerState>, StateHandlerError> {
        // TODO: Fix txn_held_across_await in handle_object_state_inner, then move it back inline
        let mut txn = ctx.services.db_pool.begin().await?;
        let outcome = self
            .handle_object_state_inner(object_id, state, controller_state, &mut txn, ctx)
            .await?;
        Ok(outcome.with_txn(Some(txn)))
    }
}

impl SpdmAttestationDeviceStateHandler {
    #[allow(txn_held_across_await)]
    async fn handle_object_state_inner(
        &self,
        object_id: &SpdmObjectId,
        state: &mut SpdmMachineSnapshot,
        controller_state: &SpdmMachineStateSnapshot,
        txn: &mut PgConnection,
        ctx: &mut StateHandlerContext<'_, SpdmStateHandlerContextObjects>,
    ) -> Result<StateHandlerOutcome<SpdmMachineStateSnapshot>, StateHandlerError> {
        let Some(device_id) = &object_id.1 else {
            // Somehow device-id is missing from object_id in device handling state. This should
            // never happen, but if happens there is no way to recover.
            return Err(StateHandlerError::MissingData {
                object_id: object_id.to_string(),
                missing: "device_id",
            });
        };

        let Some(device_state) = &controller_state.device_state else {
            // Somehow device-state is missing from device_state in device handling state. This should
            // never happen, but if happens there is no way to recover.
            return Ok(StateHandlerOutcome::transition(attestation_complete(
                controller_state,
                AttestationStatus::Failure {
                    cause: SpdmHandlerError::MissingData {
                        field: "device_state".to_string(),
                        machine_id: object_id.0,
                        device_id: device_id.clone(),
                    },
                },
            )));
        };

        let Some(device) = &state.device else {
            // device details are missing from state in device handling state. This should
            // never happen, but if happens there is no way to recover.
            return Ok(StateHandlerOutcome::transition(attestation_complete(
                controller_state,
                AttestationStatus::Failure {
                    cause: SpdmHandlerError::MissingData {
                        field: "device_details".to_string(),
                        machine_id: object_id.0,
                        device_id: device_id.clone(),
                    },
                },
            )));
        };

        match device_state {
            AttestationDeviceState::FetchData(fetch_measurement_device_states) => {
                match fetch_measurement_device_states {
                    FetchDataDeviceStates::FetchMetadata => {
                        // Right now only metadata needed is firmware version.
                        let redfish_client = redfish_client(&state.bmc_info, ctx).await?;
                        let firmware_version = match redfish_client
                            .get_firmware_for_component(device_id)
                            .await
                        {
                            Ok(x) => x.version,
                            Err(libredfish::RedfishError::NotSupported(msg)) => {
                                tracing::info!(
                                    "Device attestation is not supported for device: {device_id}, machine: {}, msg: {msg}",
                                    object_id.0
                                );
                                return Ok(StateHandlerOutcome::transition(attestation_complete(
                                    controller_state,
                                    AttestationStatus::NotSupported
                                )));
                            }
                            Err(error) => {
                                return Err(StateHandlerError::RedfishError {
                                    operation: "fetch firmware version",
                                    error,
                                });
                            }
                        };

                        let metadata = SpdmMachineDeviceMetadata { firmware_version };
                        db::attestation::spdm::update_metadata(
                            txn,
                            &object_id.0,
                            device_id,
                            &metadata,
                        )
                        .await?;

                        Ok(StateHandlerOutcome::transition(get_device_state_snapshot(
                            controller_state,
                            AttestationDeviceState::FetchData(
                                FetchDataDeviceStates::FetchCertificate,
                            ),
                        )))
                    }
                    FetchDataDeviceStates::FetchCertificate => {
                        let redfish_client = redfish_client(&state.bmc_info, ctx).await?;
                        let Some(url) = &device.ca_certificate_link else {
                            // This is an unrecoverable error due to db discrepancy.
                            return Ok(StateHandlerOutcome::transition(attestation_complete(
                                controller_state,
                                AttestationStatus::Failure {
                                    cause: SpdmHandlerError::MissingData {
                                        field: "ca_certificate link".to_string(),
                                        machine_id: object_id.0,
                                        device_id: device_id.clone(),
                                    },
                                },
                            )));
                        };
                        let ca_certificate = redfish_client
                            .get_component_ca_certificate(url.as_str())
                            .await
                            .map_err(|error| StateHandlerError::RedfishError {
                                operation: "fetch certificate",
                                error,
                            })?;

                        db::attestation::spdm::update_certificate(
                            txn,
                            &object_id.0,
                            device_id,
                            &ca_certificate,
                        )
                        .await?;
                        Ok(StateHandlerOutcome::transition(get_device_state_snapshot(
                            controller_state,
                            AttestationDeviceState::FetchData(FetchDataDeviceStates::Trigger {
                                retry_count: 0,
                            }),
                        )))
                    }
                    FetchDataDeviceStates::Trigger { retry_count } => {
                        // firmware version and certificate are collected. Let's trigger the
                        // measurement collection now.
                        let redfish_client = redfish_client(&state.bmc_info, ctx).await?;
                        let Some(url) = &device.evidence_target else {
                            // This is an unrecoverable error due to db discrepancy.
                            return Ok(StateHandlerOutcome::transition(attestation_complete(
                                controller_state,
                                AttestationStatus::Failure {
                                    cause: SpdmHandlerError::MissingData {
                                        field: "evidence_target link".to_string(),
                                        machine_id: object_id.0,
                                        device_id: device_id.clone(),
                                    },
                                },
                            )));
                        };
                        let task = redfish_client
                            .trigger_evidence_collection(
                                url.as_str(),
                                device.nonce.to_string().as_str(),
                            )
                            .await
                            .map_err(|error| StateHandlerError::RedfishError {
                                operation: "trigger measurement collection",
                                error,
                            })?;

                        Ok(StateHandlerOutcome::transition(get_device_state_snapshot(
                            controller_state,
                            AttestationDeviceState::FetchData(FetchDataDeviceStates::Poll {
                                task_id: task.id,
                                retry_count: *retry_count,
                            }),
                        )))
                    }
                    FetchDataDeviceStates::Poll {
                        task_id,
                        retry_count,
                    } => {
                        let redfish_client = redfish_client(&state.bmc_info, ctx).await?;
                        let task = redfish_client.get_task(task_id).await.map_err(|e| {
                            StateHandlerError::RedfishError {
                                operation: "get_task_state",
                                error: e,
                            }
                        })?;

                        match task.task_state {
                            Some(TaskState::Completed) => {
                                Ok(StateHandlerOutcome::transition(get_device_state_snapshot(
                                    controller_state,
                                    AttestationDeviceState::FetchData(
                                        FetchDataDeviceStates::Collect,
                                    ),
                                )))
                            }
                            Some(TaskState::Running)
                            | Some(TaskState::New)
                            | Some(TaskState::Starting) => Ok(StateHandlerOutcome::wait(format!(
                                "Measurement collection is pending {}%",
                                task.percent_complete.unwrap_or_default(),
                            ))),
                            task_state => {
                                let err =
                                    task.messages.iter().map(|t| t.message.clone()).join("\n");
                                tracing::error!(
                                    "Error while triggering measurement: {}: State: {:?}",
                                    err,
                                    task_state
                                );
                                Ok(StateHandlerOutcome::transition(get_device_state_snapshot(
                                    controller_state,
                                    if *retry_count > 4 {
                                        // retry count exhausted.
                                        AttestationDeviceState::AttestationCompleted {
                                        status:
                                            model::attestation::spdm::AttestationStatus::Failure {
                                                cause: SpdmHandlerError::TriggerMeasurementFail(
                                                    err,
                                                ),
                                            },
                                    }
                                    } else {
                                        AttestationDeviceState::FetchData(
                                            FetchDataDeviceStates::Trigger {
                                                retry_count: *retry_count + 1,
                                            },
                                        )
                                    },
                                )))
                            }
                        }
                    }
                    FetchDataDeviceStates::Collect => {
                        let Some(url) = &device.evidence_target else {
                            // This is an unrecoverable error due to db discrepancy.
                            return Ok(StateHandlerOutcome::transition(attestation_complete(
                                controller_state,
                                AttestationStatus::Failure {
                                    cause: SpdmHandlerError::MissingData {
                                        field: "evidence_target link in Collect".to_string(),
                                        machine_id: object_id.0,
                                        device_id: device_id.clone(),
                                    },
                                },
                            )));
                        };
                        let redfish_client = redfish_client(&state.bmc_info, ctx).await?;
                        let evidence = redfish_client.get_evidence(url).await.map_err(|e| {
                            StateHandlerError::RedfishError {
                                operation: "get_task_state",
                                error: e,
                            }
                        })?;
                        db::attestation::spdm::update_evidence(
                            txn,
                            &object_id.0,
                            device_id,
                            &evidence,
                        )
                        .await?;
                        Ok(StateHandlerOutcome::transition(get_device_state_snapshot(
                            controller_state,
                            AttestationDeviceState::FetchData(FetchDataDeviceStates::Collected),
                        )))
                    }
                    FetchDataDeviceStates::Collected => Ok(StateHandlerOutcome::do_nothing()),
                }
            }
            AttestationDeviceState::Verification(verification_device_states) => {
                match verification_device_states {
                    VerificationDeviceStates::GetVerifierResponse => {
                        let client = self.verifier.client(self.nras_config.clone());
                        let response = perform_attestation(client.as_ref(), device).await;
                        match response {
                            Ok(res) => {
                                Ok(StateHandlerOutcome::transition(get_device_state_snapshot(
                                    controller_state,
                                    AttestationDeviceState::Verification(
                                        VerificationDeviceStates::VerifyResponse {
                                            state: res,
                                        },
                                    ),
                                )))
                            },
                            // Not supported.
                            Err(err @ SpdmHandlerError::VerifierNotImplemented{ .. }) => {
                                Ok(StateHandlerOutcome::transition(attestation_complete(
                                    controller_state,
                                    AttestationStatus::Failure { cause: err }
                                )))
                            }
                            Err(e) => Err(StateHandlerError::from(e)),
                        }

                    }
                    VerificationDeviceStates::VerifyResponse { state } => {
                        let processed_response = self
                            .verifier
                            .parse_attestation_outcome(
                                &self.nras_config,
                                state
                            )
                            .await
                            .map_err(SpdmHandlerError::from)?;

                        let next_state = if processed_response.attestation_passed {
                            get_device_state_snapshot(
                                controller_state,
                                AttestationDeviceState::Verification(
                                    VerificationDeviceStates::VerificationCompleted,
                                ),
                            )
                        } else {
                            let mut error_vecs: Vec<String> = Vec::new();
                            for (key, values) in processed_response.devices {
                                // create a string with key/value pair of response received from
                                // verifier for a component like GPU0.
                                let parsed_values = values.iter().map(|(x, y)| format!("{}: {}", x, y)).join("\n");
                                // push this to error_vec in the format of
                                // "GPU0 - x-nvidia-gpu-vbios-rim-fetched": true\nsub: NVIDIA-GPU-ATTESTATION\nAND-MORE......."
                                error_vecs.push(format!("{} - {}", key, parsed_values));
                            }
                            let error_string = error_vecs.into_iter().join("\n");
                            attestation_complete(controller_state, AttestationStatus::Failure { cause: SpdmHandlerError::VerificationFailed(error_string) })
                        };

                        Ok(StateHandlerOutcome::transition(next_state))
                    }
                    VerificationDeviceStates::VerificationCompleted => {
                        Ok(StateHandlerOutcome::do_nothing())
                    }
                }
            }
            AttestationDeviceState::ApplyEvidenceResultAppraisalPolicy(
                evidence_result_appraisal_policy_device_states,
            ) => match evidence_result_appraisal_policy_device_states {
                EvidenceResultAppraisalPolicyDeviceStates::ApplyAppraisalPolicy => {
                        Ok(StateHandlerOutcome::transition(get_device_state_snapshot(
                            controller_state,
                            AttestationDeviceState::ApplyEvidenceResultAppraisalPolicy(
                                EvidenceResultAppraisalPolicyDeviceStates::AppraisalPolicyValidationCompleted
                            ),
                        )))
                },
                EvidenceResultAppraisalPolicyDeviceStates::AppraisalPolicyValidationCompleted => {
                    Ok(StateHandlerOutcome::do_nothing())
                }
            },
            AttestationDeviceState::AttestationCompleted { status: _ } => {
                // Attestation is completed. Nothing to be done.
                Ok(StateHandlerOutcome::do_nothing())
            }
            AttestationDeviceState::NotApplicable => Ok(StateHandlerOutcome::do_nothing()),
        }
    }
}

fn get_device_state_snapshot(
    controller_state: &SpdmMachineStateSnapshot,
    device_state: AttestationDeviceState,
) -> SpdmMachineStateSnapshot {
    SpdmMachineStateSnapshot {
        machine_state: controller_state.machine_state.clone(),
        devices_state: HashMap::new(),
        device_state: Some(device_state),
        machine_version: controller_state.machine_version,
        device_version: controller_state.device_version,
        update_machine_version: false,
        update_device_version: true,
    }
}

async fn perform_attestation(
    client: &dyn VerifierClient,
    device: &SpdmMachineDeviceAttestation,
) -> Result<RawAttestationOutcome, SpdmHandlerError> {
    let Some(ca_certificate) = &device.ca_certificate else {
        return Err(SpdmHandlerError::MissingData {
            field: "ca certificate".to_string(),
            machine_id: device.machine_id,
            device_id: device.device_id.clone(),
        });
    };

    let Some(evidence) = &device.evidence else {
        return Err(SpdmHandlerError::MissingData {
            field: "evidence".to_string(),
            machine_id: device.machine_id,
            device_id: device.device_id.clone(),
        });
    };

    let device_attestation_info = DeviceAttestationInfo {
        ec: vec![EvidenceCertificate {
            evidence: evidence.signed_measurements.clone(),
            certificate: ca_certificate.certificate_string.clone(),
        }],
        architecture: nras::MachineArchitecture::Blackwell,
        nonce: device.nonce.to_string(),
    };

    let device_type: DeviceType = device.device_id.parse()?;
    let response = match device_type {
        DeviceType::Gpu => client.attest_gpu(&device_attestation_info).await,
        DeviceType::Cx7 => client.attest_cx7(&device_attestation_info).await,
        DeviceType::Unknown => {
            return Err(SpdmHandlerError::VerifierNotImplemented {
                module: "state_handler".to_string(),
                machine_id: device.machine_id,
                device_id: device.device_id.clone(),
            });
        }
    };

    match response {
        Ok(res) => Ok(res),
        Err(nras::NrasError::NotImplemented) => Err(SpdmHandlerError::VerifierNotImplemented {
            module: "verifier".to_string(),
            machine_id: device.machine_id,
            device_id: device.device_id.clone(),
        }),
        Err(err) => Err(SpdmHandlerError::NrasError(err)),
    }
}

fn attestation_complete(
    controller_state: &SpdmMachineStateSnapshot,
    status: AttestationStatus,
) -> SpdmMachineStateSnapshot {
    get_device_state_snapshot(
        controller_state,
        AttestationDeviceState::AttestationCompleted { status },
    )
}
