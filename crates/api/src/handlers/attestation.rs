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
use ::rpc::common::MachineIdList;
use ::rpc::forge::{self as rpc};
use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use db::{AnnotatedSqlxError, ObjectFilter};
use itertools::Itertools;
use libredfish::model::component_integrity::{ComponentIntegrities, ComponentIntegrity};
use model::attestation::spdm::{SpdmAttestationState, SpdmDeviceAttestation};
use model::bmc_info::BmcInfo;
use model::machine::machine_search_config::MachineSearchConfig;
use sqlx::PgPool;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

pub(crate) async fn trigger_machine_attestation(
    api: &Api,
    request: Request<MachineId>,
) -> Result<Response<rpc::SpdmMachineAttestationTriggerResponse>, Status> {
    log_request_data(&request);

    let machine_id = request.get_ref();
    log_machine_id(machine_id);

    let mut db_reader = api.db_reader();

    let machines = db::machine::find(
        &mut db_reader,
        ObjectFilter::List(&[*machine_id]),
        MachineSearchConfig::default(),
    )
    .await?;
    let bmc_info = match machines.len() {
        0 => {
            return Err(Status::from(CarbideError::NotFoundError {
                kind: "machine",
                id: format!("{}", machine_id),
            }));
        }
        1 => &machines[0].bmc_info,
        _ => {
            return Err(Status::from(CarbideError::Internal {
                message: format!("Found more than one machine for machine id {}", machine_id),
            }));
        }
    };

    let redfish_client = api
        .redfish_pool
        .create_client_for_ingested_host(
            bmc_info.ip_addr().map_err(|e| CarbideError::Internal {
                message: format!("{}", e),
            })?,
            bmc_info.port,
            &api.database_connection,
        )
        .await
        .map_err(|e| CarbideError::RedfishClientCreation {
            inner: Box::new(e),
            machine_id: *machine_id,
        })?;

    let records_inserted =
        trigger_attestation(api.pg_pool(), redfish_client, bmc_info, machine_id).await?;

    Ok(Response::new(rpc::SpdmMachineAttestationTriggerResponse {
        machine_id: Some(*machine_id),
        devices_under_attestation: records_inserted as i32,
    }))
}

pub async fn trigger_attestation(
    db_pool: &PgPool,
    redfish_client: Box<dyn libredfish::Redfish>,
    bmc_info: &BmcInfo,
    machine_id: &MachineId,
) -> Result<u64, CarbideError> {
    // retrieve bmc info for a machine and create redfish client
    // get service root
    // - absent -> return NotSupported
    // get component integrities and create/insert device attestations
    // - if none, return NotSupported

    let service_root = redfish_client
        .get_service_root()
        .await
        .map_err(CarbideError::RedfishError)?;

    if service_root.component_integrity.is_none() {
        // let's treat 0 devices under attestation as NotSupported
        return Ok(0);
    }

    let component_integrities = redfish_client
        .get_component_integrities()
        .await
        .map_err(|e| {
            CarbideError::AttestationError(format!("Error getting component integrities: {}", e))
        })?;

    let components = get_components_supporting_spdm(&component_integrities);

    if components.is_empty() {
        // let's treat 0 devices under attestation as NotSupported
        return Ok(0);
    }

    // The validation that list is not changed is done by SKU validation. SKU
    // validation checks that the device profile is not changed over time. If any
    // device list is changed and SKU validation is passed, means SRE has approved the
    // change request.
    // Validating again is not needed.
    // Remove existing device list and over-write with this list.
    let time_now = Utc::now();
    let device_attestations = components
        .into_iter()
        .map(|x| from_component_integrity(x.clone(), machine_id, &time_now, bmc_info))
        .collect_vec();

    let mut txn = db_pool
        .begin()
        .await
        .map_err(|e| AnnotatedSqlxError::new("trigger_attestation begin", e))?;

    let records_inserted = db::attestation::spdm::insert_device_attestations(
        &mut txn,
        machine_id,
        device_attestations,
    )
    .await
    .map_err(|e| {
        CarbideError::AttestationError(format!(
            "Error inserting device attestations into DB: {}",
            e
        ))
    })?;

    txn.commit()
        .await
        .map_err(|e| AnnotatedSqlxError::new("trigger_attestation commit", e))?;

    tracing::info!(
        "SPDM attestation commenced for machine {}, scheduled {} SPDM device attestations",
        machine_id,
        records_inserted
    );

    Ok(records_inserted)
}

pub(crate) async fn cancel_machine_attestation(
    api: &Api,
    request: Request<MachineId>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let machine_id = request.get_ref();
    log_machine_id(machine_id);

    let mut txn = api.txn_begin().await?;
    db::attestation::spdm::cancel_machine_attestation(&mut txn, machine_id).await?;
    txn.commit().await?;

    Ok(Response::new(()))
}

pub(crate) async fn list_machine_ids_under_attestation(
    api: &Api,
    request: Request<()>,
) -> Result<Response<MachineIdList>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;
    let machine_ids = db::attestation::spdm::list_machine_ids(&mut txn).await?;
    txn.commit().await?;

    Ok(Response::new(MachineIdList { machine_ids }))
}

#[allow(txn_without_commit)]
pub(crate) async fn list_attestations_for_machine_id(
    api: &Api,
    request: Request<MachineId>,
) -> Result<Response<rpc::SpdmListAttestationsResponse>, Status> {
    log_request_data(&request);

    let machine_id = request.get_ref();
    log_machine_id(machine_id);

    let mut txn = api.txn_begin().await?;
    let attestations_details =
        db::attestation::spdm::get_attestations_for_machine_id(&mut txn, machine_id).await?;

    Ok(Response::new(rpc::SpdmListAttestationsResponse {
        attestations_details: attestations_details
            .iter()
            .map(|elem| {
                std::convert::Into::<::rpc::forge::SpdmAttestationDetails>::into((*elem).clone())
            })
            .collect(),
    }))
}

pub(crate) async fn get_machine_attestations_status(
    api: &Api,
    request: Request<MachineId>,
) -> Result<Response<rpc::SpdmMachineAttestationStatusResponse>, Status> {
    log_request_data(&request);

    let machine_id = request.get_ref();
    log_machine_id(machine_id);

    let mut txn = api.txn_begin().await?;
    let attestation_status =
        db::attestation::spdm::get_attestation_status_for_machine_id(&mut txn, machine_id).await?;
    txn.commit().await?;

    Ok(Response::new(rpc::SpdmMachineAttestationStatusResponse {
        machine_id: Some(*machine_id),
        attestation_status: attestation_status.into(),
    }))
}

pub(crate) async fn attest_quote(
    api: &Api,
    request: Request<rpc::AttestQuoteRequest>,
) -> std::result::Result<Response<rpc::AttestQuoteResponse>, Status> {
    log_request_data(&request);

    let mut request = request.into_inner();

    // TODO: consider if this code can be turned into a templated function and reused
    // in bind_attest_key
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

    let mut txn = api.txn_begin().await?;

    let ak_pub_bytes =
        match db::attestation::secret_ak_pub::get_by_secret(&mut txn, &request.credential).await? {
            Some(entry) => entry.ak_pub,
            None => {
                return Err(CarbideError::AttestQuoteError(
                    "Could not form SQL query to fetch AK Pub".into(),
                )
                .into());
            }
        };

    // Make sure sure the signature can at least be verified
    // as valid or invalid. If it can't be verified in any
    // way at all, return an error.
    let signature_valid = crate::attestation::verify_signature(
        &ak_pub_bytes,
        &request.attestation,
        &request.signature,
    )
    .inspect_err(|_| {
        tracing::warn!(
            "PCR signature verification failed (event log: {})",
            crate::attestation::event_log_to_string(&request.event_log)
        );
    })?;

    // Make sure we can verify the the PCR hash one way
    // or another. If it can't be, return an error.
    let pcr_hash_matches =
        crate::attestation::verify_pcr_hash(&request.attestation, &request.pcr_values)
            .inspect_err(|_| {
                tracing::warn!(
                    "PCR hash verification failed (event log: {})",
                    crate::attestation::event_log_to_string(&request.event_log)
                );
            })?;

    // And now pass on through the computed signature
    // validity and PCR hash match to see if execution can
    // continue (the event log goes with, since it will be
    // logged in the event of an invalid signature or PCR
    // hash mismatch).
    crate::attestation::verify_quote_state(signature_valid, pcr_hash_matches, &request.event_log)?;

    // If we've reached this point, we can now clean up
    // now ephemeral secret data from the database, and send
    // off the PCR values as a MeasurementReport.
    db::attestation::secret_ak_pub::delete(&mut txn, &request.credential).await?;

    let pcr_values: ::measured_boot::pcr::PcrRegisterValueVec = request
        .pcr_values
        .drain(..)
        .map(hex::encode)
        .collect::<Vec<String>>()
        .into();

    // In this case, we're not doing anything with
    // the resulting report (at least not yet), so just
    // throw it away.
    let report =
        db::measured_boot::report::new(&mut txn, machine_id, pcr_values.into_inner().as_slice())
            .await
            .map_err(|e| CarbideError::Internal {
                message: format!(
                    "Failed storing measurement report: (machine_id: {}, err: {})",
                    &machine_id, e
                ),
            })?;

    // if the attestation was successful and enabled, we can now vend the certs
    // - get attestation result
    // - if enabled and not successful, send response without certs
    // - else send response with certs
    let attestation_failed = if api.runtime_config.attestation_enabled {
        !crate::attestation::has_passed_attestation(&mut txn, &machine_id, &report.report_id)
            .await?
    } else {
        false
    };

    txn.commit().await?;

    if attestation_failed {
        tracing::info!(
            "Attestation failed for machine with id {} - not vending any certs",
            machine_id
        );
        return Ok(Response::new(rpc::AttestQuoteResponse {
            success: false,
            machine_certificate: None,
        }));
    }

    let id_str = machine_id.to_string();
    let certificate = if std::env::var("UNSUPPORTED_CERTIFICATE_PROVIDER").is_ok() {
        forge_secrets::certificates::Certificate::default()
    } else {
        api.certificate_provider
            .get_certificate(id_str.as_str(), None, None)
            .await
            .map_err(|err| CarbideError::ClientCertificateError(err.to_string()))?
    };

    tracing::info!(
        "Attestation succeeded for machine with id {} - sending a cert back. Attestion_enabled is {}",
        machine_id,
        api.runtime_config.attestation_enabled
    );
    Ok(Response::new(rpc::AttestQuoteResponse {
        success: true,
        machine_certificate: Some(certificate.into()),
    }))
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

fn from_component_integrity(
    integrity: ComponentIntegrity,
    machine_id: &MachineId,
    time_now: &DateTime<Utc>,
    bmc_info: &BmcInfo,
) -> SpdmDeviceAttestation {
    let ca_certificate_link = integrity
        .spdm
        .map(|x| x.identity_authentication)
        .map(|x| x.component_certificate)
        .map(|x| x.odata_id);

    let evidence_target =
        if let Some(Some(data)) = integrity.actions.map(|x| x.get_signed_measurements) {
            Some(data.target)
        } else {
            None
        };

    SpdmDeviceAttestation {
        machine_id: *machine_id,
        device_id: integrity.id,
        nonce: uuid::Uuid::new_v4(),
        bmc_info: bmc_info.clone(),
        state: SpdmAttestationState::FetchMetadata,
        state_version: ConfigVersion::initial(),
        state_outcome: None,
        metadata: None,
        ca_certificate_link,
        ca_certificate: None,
        evidence_target,
        evidence: None,
        started_at: *time_now,
        cancelled_at: None,
        completed_at: None,
    }
}

#[cfg(not(feature = "linux-build"))]
pub(crate) async fn attest_quote(
    _api: &Api,
    _request: Request<rpc::AttestQuoteRequest>,
) -> std::result::Result<Response<rpc::AttestQuoteResponse>, Status> {
    unimplemented!()
}
