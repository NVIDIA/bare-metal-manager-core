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

use std::sync::Arc;

use carbide_redfish::libredfish::conv::IntoModel;
use carbide_redfish::libredfish::error::state_handler_redfish_error as redfish_error;
use itertools::Itertools;
use libredfish::Redfish;
use libredfish::model::task::TaskState;
use model::attestation::spdm::{
    DeviceType, SpdmAttestationState, SpdmDeviceAttestation, SpdmHandlerError,
    SpdmMachineDeviceMetadata, SpdmObjectId, Verifier,
};
use model::bmc_info::BmcInfo;
use nras::{DeviceAttestationInfo, EvidenceCertificate, RawAttestationOutcome, VerifierClient};
use state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::SpdmStateHandlerContextObjects;

#[derive(Debug, Clone)]
pub struct SpdmAttestationStateHandler {
    verifier: Arc<dyn Verifier>,
    nras_config: nras::Config,
}

impl SpdmAttestationStateHandler {
    pub fn new(verifier: Arc<dyn Verifier>, nras_config: nras::Config) -> Self {
        Self {
            verifier,
            nras_config,
        }
    }

    fn record_metrics(
        &self,
        _state: &mut SpdmDeviceAttestation,
        _ctx: &mut StateHandlerContext<SpdmStateHandlerContextObjects>,
    ) {
    }
}

async fn redfish_client(
    bmc_info: &BmcInfo,
    ctx: &mut StateHandlerContext<'_, SpdmStateHandlerContextObjects>,
) -> Result<Box<dyn Redfish>, StateHandlerError> {
    let ip_addr = bmc_info
        .ip_addr()
        .map_err(StateHandlerError::GenericError)?;
    let bmc_access_info = db::machine_interface::lookup_bmc_access_info(
        &ctx.services.db_pool,
        ip_addr,
        bmc_info.port,
    )
    .await?;

    ctx.services
        .redfish_client_pool
        .client_by_info(&bmc_access_info)
        .await
        .map_err(StateHandlerError::from)
}

#[async_trait::async_trait]
impl StateHandler for SpdmAttestationStateHandler {
    type ObjectId = SpdmObjectId;
    type State = SpdmDeviceAttestation;
    type ControllerState = SpdmAttestationState;
    type ContextObjects = SpdmStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        object_id: &Self::ObjectId,
        snapshot: &mut SpdmDeviceAttestation,
        controller_state: &SpdmAttestationState,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<SpdmAttestationState>, StateHandlerError> {
        // record metrics irrespective of the state of the machine
        self.record_metrics(snapshot, ctx);

        let transition_to_cancelled;
        let controller_state = if snapshot.cancelled_at.is_some()
            && controller_state != &SpdmAttestationState::Cancelled
        {
            transition_to_cancelled = true;
            &SpdmAttestationState::Cancelled
        } else {
            transition_to_cancelled = false;
            controller_state
        };

        let SpdmObjectId(machine_id, device_id) = object_id;

        match controller_state {
            SpdmAttestationState::FetchMetadata => {
                let redfish_client = redfish_client(&snapshot.bmc_info, ctx).await?;

                let firmware_version = match redfish_client
                    .get_firmware_for_component(device_id)
                    .await
                {
                    Ok(x) => x.version,
                    Err(libredfish::RedfishError::NotSupported(msg)) => {
                        tracing::info!(
                            "Device attestation is not supported for device (firmware version not available): {device_id}, machine: {machine_id}, msg: {msg}"
                        );
                        return Ok(StateHandlerOutcome::transition(
                            SpdmAttestationState::Passed,
                        ));
                    }
                    Err(error) => {
                        return Err(redfish_error("fetch firmware version", error));
                    }
                };

                let metadata = SpdmMachineDeviceMetadata { firmware_version };
                let mut txn = ctx.services.db_pool.begin().await?;
                db::attestation::spdm::update_metadata(&mut txn, machine_id, device_id, &metadata)
                    .await?;
                Ok(
                    StateHandlerOutcome::transition(SpdmAttestationState::FetchCertificate)
                        .with_txn(txn),
                )
            }
            SpdmAttestationState::FetchCertificate => {
                let redfish_client = redfish_client(&snapshot.bmc_info, ctx).await?;
                let Some(url) = &snapshot.ca_certificate_link else {
                    // This is an unrecoverable error due to db discrepancy.
                    return Ok(StateHandlerOutcome::transition(
                        SpdmAttestationState::Failed(
                            "Could not get ca_certificate_link from DB".to_string(),
                        ),
                    ));
                };
                let ca_certificate = redfish_client
                    .get_component_ca_certificate(url.as_str())
                    .await
                    .map_err(|error| redfish_error("fetch certificate", error))?;

                let mut txn = ctx.services.db_pool.begin().await?;
                db::attestation::spdm::update_certificate(
                    &mut txn,
                    &object_id.0,
                    device_id,
                    &ca_certificate.into_model(),
                )
                .await?;
                Ok(StateHandlerOutcome::transition(
                    SpdmAttestationState::TriggerEvidenceCollection { retry_count: 0 },
                )
                .with_txn(txn))
            }
            SpdmAttestationState::TriggerEvidenceCollection { retry_count } => {
                // firmware version and certificate are collected. Let's trigger the
                // measurement collection now.
                let redfish_client = redfish_client(&snapshot.bmc_info, ctx).await?;
                let Some(url) = &snapshot.evidence_target else {
                    // This is an unrecoverable error due to db discrepancy.
                    return Ok(StateHandlerOutcome::transition(
                        SpdmAttestationState::Failed(
                            "Could not get evidence_target from DB".to_string(),
                        ),
                    ));
                };
                let nonce = snapshot.nonce_hex();
                let task = redfish_client
                    .trigger_evidence_collection(url.as_str(), nonce.as_str())
                    .await
                    .map_err(|error| redfish_error("trigger measurement collection", error))?;

                Ok(StateHandlerOutcome::transition(
                    SpdmAttestationState::PollEvidenceCollection {
                        task_id: task.id,
                        retry_count: *retry_count,
                    },
                ))
            }
            SpdmAttestationState::PollEvidenceCollection {
                task_id,
                retry_count,
            } => {
                let redfish_client = redfish_client(&snapshot.bmc_info, ctx).await?;
                let task = redfish_client
                    .get_task(task_id)
                    .await
                    .map_err(|e| redfish_error("get_task_state", e))?;

                match task.task_state {
                    Some(TaskState::Completed) => {
                        // read the result
                        let Some(url) = &snapshot.evidence_target else {
                            // This is an unrecoverable error due to db discrepancy.
                            return Ok(StateHandlerOutcome::transition(
                                SpdmAttestationState::Failed(
                                    "Could not get evidence target from DB".to_string(),
                                ),
                            ));
                        };
                        let evidence = redfish_client
                            .get_evidence(url)
                            .await
                            .map_err(|e| redfish_error("get_task_state", e))?;
                        let mut txn = ctx.services.db_pool.begin().await?;
                        db::attestation::spdm::update_evidence(
                            &mut txn,
                            &object_id.0,
                            device_id,
                            &evidence.into_model(),
                        )
                        .await?;
                        Ok(
                            StateHandlerOutcome::transition(SpdmAttestationState::NrasVerification)
                                .with_txn(txn),
                        )
                    }
                    Some(TaskState::Running) | Some(TaskState::New) | Some(TaskState::Starting) => {
                        Ok(StateHandlerOutcome::wait(format!(
                            "Measurement collection is pending {}%",
                            task.percent_complete.unwrap_or_default(),
                        )))
                    }
                    task_state => {
                        let err = task.messages.iter().map(|t| t.message.clone()).join("\n");
                        tracing::error!(
                            "Error while triggering measurement: {}: State: {:?}",
                            err,
                            task_state
                        );
                        if *retry_count > 4 {
                            Ok(StateHandlerOutcome::transition(
                                SpdmAttestationState::Failed(
                                    "Too many retries triggering evidence collection".to_string(),
                                ),
                            ))
                        } else {
                            Ok(StateHandlerOutcome::transition(
                                SpdmAttestationState::TriggerEvidenceCollection {
                                    retry_count: retry_count + 1,
                                },
                            ))
                        }
                    }
                }
            }
            SpdmAttestationState::NrasVerification => {
                let client = self.verifier.client(self.nras_config.clone());
                let raw_attest_outcome = perform_attestation(client.as_ref(), snapshot).await?;

                let processed_response = self
                    .verifier
                    .parse_attestation_outcome(&self.nras_config, &raw_attest_outcome)
                    .await
                    .map_err(SpdmHandlerError::from)?;

                if processed_response.attestation_passed {
                    Ok(StateHandlerOutcome::transition(
                        SpdmAttestationState::ApplyAppraisalPolicy,
                    ))
                } else {
                    Ok(StateHandlerOutcome::transition(
                        SpdmAttestationState::Failed(format!(
                            "Failed NRAS: {:#?}",
                            processed_response.devices
                        )),
                    ))
                }
            }
            SpdmAttestationState::ApplyAppraisalPolicy => {
                // nothing defined here yet, so just move to completed
                Ok(StateHandlerOutcome::transition(
                    SpdmAttestationState::Passed,
                ))
            }
            SpdmAttestationState::Passed => {
                let mut txn = ctx.services.db_pool.begin().await?;
                db::attestation::spdm::set_completed_at(&mut txn, machine_id, device_id).await?;
                Ok(StateHandlerOutcome::do_nothing().with_txn(txn))
            }
            SpdmAttestationState::Failed(_reason) => {
                let mut txn = ctx.services.db_pool.begin().await?;
                db::attestation::spdm::set_completed_at(&mut txn, machine_id, device_id).await?;
                Ok(StateHandlerOutcome::do_nothing().with_txn(txn))
            }
            SpdmAttestationState::Cancelled => {
                let mut txn = ctx.services.db_pool.begin().await?;
                db::attestation::spdm::set_completed_at(&mut txn, machine_id, device_id).await?;
                if transition_to_cancelled {
                    Ok(
                        StateHandlerOutcome::transition(SpdmAttestationState::Cancelled)
                            .with_txn(txn),
                    )
                } else {
                    Ok(StateHandlerOutcome::do_nothing().with_txn(txn))
                }
            }
        }
    }
}
async fn perform_attestation(
    client: &dyn VerifierClient,
    device: &SpdmDeviceAttestation,
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

    let firmware_version = device
        .metadata
        .as_ref()
        .and_then(|m| m.firmware_version.clone())
        .ok_or_else(|| SpdmHandlerError::MissingData {
            field: "firmware_version".to_string(),
            machine_id: device.machine_id,
            device_id: device.device_id.clone(),
        })?;

    let device_attestation_info = DeviceAttestationInfo {
        ec: vec![EvidenceCertificate {
            evidence: evidence.signed_measurements.clone(),
            certificate: nras::certificate_to_base64(&ca_certificate.certificate_string),
            firmware_version,
        }],
        architecture: nras::MachineArchitecture::Blackwell,
        nonce: device.nonce_hex(),
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
