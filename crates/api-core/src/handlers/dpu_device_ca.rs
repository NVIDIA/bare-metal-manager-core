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

//! Management of trusted NVIDIA BlueField device root CA certificates
//! (`dpu_device_ca_certs`), against which DPU IRoT device-identity chains are
//! verified. Mirrors [`super::tpm_ca`]; unlike the TPM path there is no EK
//! verification-status backfill — device-rooted ids are assigned at discovery.

use ::rpc::forge as rpc;
use db::attestation as db_attest;
use tonic::{Request, Response};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::x509::X509Name;

use crate::api::{Api, log_request_data};
use crate::{CarbideError, attestation as attest};

pub(crate) async fn dpu_add_device_ca_cert(
    api: &Api,
    request: Request<rpc::DpuDeviceCaCert>,
) -> Result<Response<rpc::DpuDeviceCaAddedStatus>, tonic::Status> {
    log_request_data(&request);

    let payload = request.into_inner();
    let ca_cert_bytes = payload.ca_cert.as_slice();

    // The stored bytes are parsed strictly at verification time
    // (`verify_device_cert_chain` rejects trailing bytes), so reject them at
    // ingestion — a root seeded with trailing data could never match and would
    // only produce confusing verification warnings later.
    let (rest, _) = X509Certificate::from_der(ca_cert_bytes)
        .map_err(|e| CarbideError::InvalidArgument(format!("invalid CA certificate: {e}")))?;
    if !rest.is_empty() {
        return Err(CarbideError::InvalidArgument(format!(
            "CA certificate has {} trailing byte(s) after the DER data; \
             re-export the certificate without extra data",
            rest.len()
        ))
        .into());
    }

    // Parse the CA cert: extract validity window + subject (in DER).
    let (not_valid_before, not_valid_after, subject) = attest::extract_ca_fields(ca_cert_bytes)?;

    let mut txn = api.txn_begin().await?;
    let db_ca_cert = db_attest::dpu_device_ca_certs::insert(
        &mut txn,
        &not_valid_before,
        &not_valid_after,
        ca_cert_bytes,
        subject.as_slice(),
    )
    .await?
    .ok_or_else(|| {
        tonic::Status::already_exists("this DPU device CA certificate is already trusted")
    })?;
    txn.commit().await?;

    Ok(Response::new(rpc::DpuDeviceCaAddedStatus {
        id: Some(rpc::DpuDeviceCaCertId {
            ca_cert_id: db_ca_cert.id,
        }),
    }))
}

pub(crate) async fn dpu_show_device_ca_certs(
    api: &Api,
    request: &Request<()>,
) -> Result<Response<rpc::DpuDeviceCaCertDetailCollection>, tonic::Status> {
    log_request_data(request);

    let mut txn = api.txn_begin().await?;
    let ca_certs = db_attest::dpu_device_ca_certs::get_all(&mut txn).await?;
    txn.commit().await?;

    let dpu_device_ca_cert_details = ca_certs
        .iter()
        .map(|entry| rpc::DpuDeviceCaCertDetail {
            ca_cert_id: entry.id,
            not_valid_before: entry.not_valid_before.to_rfc2822(),
            not_valid_after: entry.not_valid_after.to_rfc2822(),
            ca_cert_subject: X509Name::from_der(&entry.cert_subject)
                .map(|x| x.1.to_string())
                .unwrap_or("Could not parse CA subject name".to_string()),
        })
        .collect();

    Ok(Response::new(rpc::DpuDeviceCaCertDetailCollection {
        dpu_device_ca_cert_details,
    }))
}

pub(crate) async fn dpu_delete_device_ca_cert(
    api: &Api,
    request: Request<rpc::DpuDeviceCaCertId>,
) -> Result<Response<()>, tonic::Status> {
    log_request_data(&request);

    let ca_cert_id = request.into_inner().ca_cert_id;

    let mut txn = api.txn_begin().await?;
    db_attest::dpu_device_ca_certs::delete(&mut txn, ca_cert_id).await?;
    txn.commit().await?;

    Ok(Response::new(()))
}
