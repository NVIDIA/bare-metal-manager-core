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
use ::rpc::forge::{self as rpc, AttestationResponse};
use config_version::ConfigVersion;
use db::attestation::spdm::{
    insert_or_update_machine_attestation_request, load_details_for_machine_ids,
};
use itertools::Itertools;
use model::attestation::spdm::SpdmMachineAttestation;
use tonic::{Request, Response, Status};
#[cfg(feature = "linux-build")]
use tss_esapi::{
    structures::{Attest, Public as TssPublic, Signature},
    traits::UnMarshall,
};

#[cfg(feature = "linux-build")]
use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

pub(crate) async fn trigger_machine_attestation(
    api: &Api,
    request: Request<rpc::AttestationData>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let request = request.get_ref();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

    let mut txn = api.txn_begin().await?;
    let machines = load_details_for_machine_ids(&mut txn, &[machine_id]).await?;

    let state_version = if let Some(machine) = machines.first() {
        machine.machine.state_version.increment()
    } else {
        ConfigVersion::initial()
    };

    let attestation_request = SpdmMachineAttestation {
        machine_id,
        requested_at: chrono::Utc::now(),
        started_at: None,
        canceled_at: None,
        state: model::attestation::spdm::AttestationState::CheckIfAttestationSupported,
        state_version,
        state_outcome: None,
        attestation_status: model::attestation::spdm::SpdmAttestationStatus::NotStarted,
    };
    insert_or_update_machine_attestation_request(&mut txn, &attestation_request).await?;
    txn.commit().await?;

    Ok(Response::new(()))
}

pub(crate) async fn cancel_machine_attestation(
    api: &Api,
    request: Request<rpc::AttestationData>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let request = request.get_ref();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

    let mut txn = api.txn_begin().await?;
    db::attestation::spdm::cancel_machine_attestation(&mut txn, &machine_id).await?;
    txn.commit().await?;

    Ok(Response::new(()))
}

pub(crate) async fn list_machine_ids_under_attestation(
    api: &Api,
    _request: Request<rpc::AttestationIdsRequest>,
) -> Result<Response<MachineIdList>, Status> {
    log_request_data(&_request);

    let mut txn = api.txn_begin().await?;
    let machine_ids = db::attestation::spdm::find_machine_ids(&mut txn).await?;
    txn.commit().await?;

    Ok(Response::new(MachineIdList { machine_ids }))
}

pub(crate) async fn list_machines_under_attestation(
    api: &Api,
    request: Request<rpc::AttestationMachineList>,
) -> Result<Response<AttestationResponse>, Status> {
    log_request_data(&request);
    let request = request.get_ref();

    let mut txn = api.txn_begin().await?;
    let details =
        db::attestation::spdm::load_details_for_machine_ids(&mut txn, &request.machine_ids).await?;
    txn.commit().await?;

    Ok(Response::new(AttestationResponse {
        machines: details.into_iter().map(|x| x.into()).collect_vec(),
    }))
}

#[cfg(feature = "linux-build")]
#[allow(txn_held_across_await)]
pub(crate) async fn attest_quote(
    api: &Api,
    request: Request<rpc::AttestQuoteRequest>,
) -> std::result::Result<Response<rpc::AttestQuoteResponse>, Status> {
    use db::WithTransaction;
    use futures_util::FutureExt;

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
                return Err(Status::from(CarbideError::AttestQuoteError(
                    "Could not form SQL query to fetch AK Pub".into(),
                )));
            }
        };

    let ak_pub = TssPublic::unmarshall(ak_pub_bytes.as_slice())
        .map_err(|e| CarbideError::AttestQuoteError(format!("Could not unmarshal AK Pub: {e}")))?;

    let attest = Attest::unmarshall(&request.attestation).map_err(|e| {
        CarbideError::AttestQuoteError(format!("Could not unmarshall Attest struct: {e}"))
    })?;

    let signature = Signature::unmarshall(&request.signature).map_err(|e| {
        CarbideError::AttestQuoteError(format!("Could not unmarshall Signature struct: {e}"))
    })?;

    // Make sure sure the signature can at least be verified
    // as valid or invalid. If it can't be verified in any
    // way at all, return an error.
    let signature_valid =
        crate::attestation::verify_signature(&ak_pub, &request.attestation, &signature)
            .inspect_err(|_| {
                tracing::warn!(
                    "PCR signature verification failed (event log: {})",
                    crate::attestation::event_log_to_string(&request.event_log)
                );
            })?;

    // Make sure we can verify the the PCR hash one way
    // or another. If it can't be, return an error.
    let pcr_hash_matches = crate::attestation::verify_pcr_hash(&attest, &request.pcr_values)
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
            .map_err(|e| {
                Status::internal(format!(
                    "Failed storing measurement report: (machine_id: {}, err: {})",
                    &machine_id, e
                ))
            })?;

    txn.commit().await?;

    // if the attestation was successful and enabled, we can now vend the certs
    // - get attestation result
    // - if enabled and not successful, send response without certs
    // - else send response with certs
    let attestation_failed = if api.runtime_config.attestation_enabled {
        !api.with_txn(|txn| {
            crate::attestation::has_passed_attestation(txn, &machine_id, &report.report_id).boxed()
        })
        .await??
    } else {
        false
    };

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

#[cfg(not(feature = "linux-build"))]
pub(crate) async fn attest_quote(
    _api: &Api,
    _request: Request<rpc::AttestQuoteRequest>,
) -> std::result::Result<Response<rpc::AttestQuoteResponse>, Status> {
    unimplemented!()
}
