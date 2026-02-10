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

use std::fs;
use std::fs::File;
use std::io::Write;
use std::process::Command;

use byteorder::{BigEndian, ByteOrder};
use carbide_uuid::machine::MachineId;
use carbide_uuid::measured_boot::MeasurementReportId;
use db::db_read::DbReader;
use model::hardware_info::TpmEkCertificate;
use model::machine::MeasuringState;
use num_bigint_dig::BigUint;
use pkcs1::LineEnding;
use rsa::RsaPublicKey;
use rsa::pkcs1::EncodeRsaPublicKey;
use sha2::Digest;
use sqlx::PgConnection;
use temp_dir::TempDir;
use tss_esapi::structures::Signature::RsaPss;
use tss_esapi::structures::{Attest, AttestInfo, Public, Signature};
use tss_esapi::traits::UnMarshall;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey as x509_parser_pub_key;

use crate::attestation::get_ek_cert_by_machine_id;
use crate::state_controller::machine::{MeasuringOutcome, handle_measuring_state};
use crate::{CarbideError, CarbideResult};

const RSA_PUBKEY_EXPONENT: u32 = 65537u32;

/// VerifyQuoteState is a simple enum used to track
/// the state of a verify_quote call, specifically as
/// it relates to verifying the signature and PCR hash.
/// It is used for appropriate logging and error handling.
pub enum VerifyQuoteState {
    Success,
    SignatureInvalid,
    VerifyHashNoMatch,
    CompleteFailure,
}

impl VerifyQuoteState {
    pub fn from_results(signature_valid: bool, pcr_hash_matches: bool) -> Self {
        match (signature_valid, pcr_hash_matches) {
            (true, true) => Self::Success,
            (false, true) => Self::SignatureInvalid,
            (true, false) => Self::VerifyHashNoMatch,
            (false, false) => Self::CompleteFailure,
        }
    }
}

/// verify_quote_state takes the input signature validity,
/// PCR hash matching result, and a reference to the event
/// log, and will check to see if things are good (or if an
/// error needs to be returned + the event log dumped to log).
pub fn verify_quote_state(
    signature_valid: bool,
    pcr_hash_matches: bool,
    event_log: &Option<Vec<u8>>,
) -> Result<(), CarbideError> {
    let quote_state = VerifyQuoteState::from_results(signature_valid, pcr_hash_matches);
    match quote_state {
        VerifyQuoteState::Success => Ok(()),
        VerifyQuoteState::SignatureInvalid => {
            tracing::warn!(
                "PCR signature invalid (event log: {}",
                event_log_to_string(event_log)
            );
            Err(CarbideError::AttestQuoteError(
                "PCR signature invalid (see logs for full event log)".to_string(),
            ))
        }
        VerifyQuoteState::VerifyHashNoMatch => {
            tracing::warn!(
                "PCR hash mismatch (event log: {}",
                event_log_to_string(event_log)
            );
            Err(CarbideError::AttestQuoteError(
                "PCR hash does not match (see logs for full event log)".to_string(),
            ))
        }
        VerifyQuoteState::CompleteFailure => {
            tracing::warn!(
                "PCR signature invalid and PCR hash mismatch (event log: {}",
                event_log_to_string(event_log)
            );
            Err(CarbideError::AttestQuoteError(
                "PCR signature invalid and PCR hash mismatch (see logs for full event log)"
                    .to_string(),
            ))
        }
    }
}

pub fn cli_make_cred(
    pub_key: rsa::RsaPublicKey,
    ak_name_serialized: &Vec<u8>,
    session_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CarbideError> {
    // now construct the temp directory
    let tmp_dir = TempDir::with_prefix("make_cred")
        .map_err(|e| CarbideError::AttestBindKeyError(format!("Could not create TempDir: {e}")))?;
    let tmp_dir_path = tmp_dir.path();

    // create a file to write the EK key to
    let ek_file_path = tmp_dir_path.join("ek.dat");
    let mut ek_file = File::create(ek_file_path.clone())
        .map_err(|e| CarbideError::AttestBindKeyError(format!("Could not create EK file: {e}")))?;

    // serialize the public key to a PEM format and write it to the file
    let pem_pub_key = pub_key.to_pkcs1_pem(LineEnding::default()).map_err(|e| {
        CarbideError::AttestBindKeyError(format!(
            "Could not convert EK RsaPublicKey to PEM format: {e}"
        ))
    })?;

    ek_file.write_all(pem_pub_key.as_bytes()).map_err(|e| {
        CarbideError::AttestBindKeyError(format!("Could not write EK Pub to PEM file: {e}"))
    })?;

    // now write AK name to the file in hexadecimal format
    let ak_name_hex = hex::encode(ak_name_serialized);

    let session_key_path = tmp_dir_path.join("session_key.dat");
    let session_key_path_str =
        session_key_path
            .to_str()
            .ok_or(CarbideError::AttestBindKeyError(
                "Could not join seession_key_path".to_string(),
            ))?;

    let mut session_key_file = File::create(session_key_path.clone()).map_err(|e| {
        CarbideError::AttestBindKeyError(format!("Could not create file for session key: {e}"))
    })?;
    session_key_file.write_all(session_key).map_err(|e| {
        CarbideError::AttestBindKeyError(format!("Could not write session key to file: {e}"))
    })?;

    // construct the command to execute make_credential
    let ek_file_path_str = ek_file_path
        .to_str()
        .ok_or(CarbideError::AttestBindKeyError(
            "Could not convert ek_file_path to str".to_string(),
        ))?;

    let cred_out_path = tmp_dir_path.join("mkcred.out");
    let cred_out_path_str = cred_out_path
        .to_str()
        .ok_or(CarbideError::AttestBindKeyError(
            "Could not join cred_out_path".to_string(),
        ))?;

    let cmd_str = format!(
        "tpm2 makecredential -u {ek_file_path_str} -s {session_key_path_str} -n {ak_name_hex} -o {cred_out_path_str} -G rsa -V --tcti=none"
    );

    tracing::debug!("make credential command is {}", cmd_str);
    // execute the makecredential command
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd_str)
        .output()
        .map_err(|e| {
            CarbideError::AttestBindKeyError(format!(
                "Could not execute makecredential command: {e}"
            ))
        })?;

    if !output.stderr.is_empty() {
        tracing::error!(
            "tpm2 makecredential returned error: {}",
            String::from_utf8_lossy(output.stderr.as_slice())
        );
    }

    let creds = fs::read(cred_out_path).map_err(|e| {
        CarbideError::AttestBindKeyError(format!("Could not create creds file: {e}"))
    })?;

    let (cred_blob, encr_secret) = extract_cred_secret(&creds)?;

    Ok((cred_blob, encr_secret))
}

pub fn verify_signature(
    ak_pub: &Public,
    attest_vec: &Vec<u8>,
    signature: &Signature,
) -> CarbideResult<bool> {
    // let's take hash of the original attestation
    let mut hasher = sha2::Sha256::new();
    hasher.update(attest_vec.as_slice());
    let attest_hash = hasher.finalize();

    let unique = match ak_pub {
        tss_esapi::structures::Public::Rsa { unique, .. } => unique,
        _ => {
            return Err(CarbideError::AttestQuoteError(
                "AK Pub is not an RSA key".to_string(),
            ));
        }
    };

    // now, we construct the actual public key from the modulus and exponent
    let modulus = BigUint::from_bytes_be(unique.value());
    let exponent: BigUint = BigUint::from(RSA_PUBKEY_EXPONENT);

    let pub_key = RsaPublicKey::new(modulus, exponent).map_err(|e| {
        CarbideError::AttestQuoteError(format!("Could not create RsaPublicKey: {e}"))
    })?;

    let rsa_signature = match signature {
        RsaPss(rsa_signature) => rsa_signature,
        _ => {
            return Err(CarbideError::AttestQuoteError(
                "unknown signature type".to_string(),
            ));
        }
    };

    match pub_key.verify(
        rsa::Pss::new::<sha2::Sha256>(),
        &attest_hash,
        rsa_signature.signature().value(),
    ) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn verify_pcr_hash(attest: &Attest, pcr_values: &[Vec<u8>]) -> CarbideResult<bool> {
    let attest_digest = match attest.attested() {
        AttestInfo::Quote { info } => info.pcr_digest(),
        _other => {
            return Err(CarbideError::AttestQuoteError(
                "Incorrect Attestation Type".into(),
            ));
        }
    };

    let mut hasher = sha2::Sha256::new();

    pcr_values.iter().for_each(|buf| {
        hasher.update(buf);
    });

    let computed_pcr_hash = hasher.finalize();

    // rust --check returns a error about deprecated usage of `as_slice`
    // an older version of generic-array is used by sha2::digest
    // but it does not show as_slice as deprecated - https://docs.rs/generic-array/0.14.7/generic_array/struct.GenericArray.html
    // TODO - fix as_slice() usage
    #[allow(deprecated)]
    if attest_digest.value() == computed_pcr_hash.as_slice() {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn extract_cred_secret(creds: &[u8]) -> CarbideResult<(Vec<u8>, Vec<u8>)> {
    let magic_header_offset: usize = 8; // 4 bytes for magic number and 4 bytes for version

    // get length for cred blob
    // read cred blob
    let cred_blob_offset: usize = 2;
    let secret_offset: usize = 2;

    if creds.len() < magic_header_offset + cred_blob_offset {
        return Err(CarbideError::AttestBindKeyError(format!(
            "Creds file is too short: {0} bytes",
            creds.len()
        )));
    }

    let cred_blob_size_bytes =
        &creds[magic_header_offset..(magic_header_offset + cred_blob_offset)];
    let cred_blob_size = BigEndian::read_u16(cred_blob_size_bytes);

    let cred_blob_end_idx: usize =
        magic_header_offset + cred_blob_offset + usize::from(cred_blob_size);

    if creds.len() < cred_blob_end_idx + secret_offset - 1 {
        return Err(CarbideError::AttestBindKeyError(format!(
            "Creds file is too short: {0} bytes",
            creds.len()
        )));
    }
    let cred_blob = Vec::from(&creds[magic_header_offset + cred_blob_offset..cred_blob_end_idx]);

    // read secret
    let secret = Vec::from(&creds[cred_blob_end_idx + secret_offset..]);

    Ok((cred_blob, secret))
}

/// event_log_to_string converts the input event log (which
/// comes to us via the proto as an Option<Vec<u8>) into a String,
/// for passing to tracing/logging.
///
/// since the event log is currently "best effort", we'll log a
/// little "error" in <>'s if we notice there's no event log.
pub fn event_log_to_string(event_log: &Option<Vec<u8>>) -> String {
    event_log
        .as_ref()
        .map(|log_utf8| {
            String::from_utf8(log_utf8.to_vec())
                .unwrap_or(String::from("<event log failed utf8 conversion>"))
        })
        .unwrap_or(String::from("<event log empty>"))
}

pub async fn compare_pub_key_against_cert(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    ek_pub: &Vec<u8>,
) -> CarbideResult<(bool, rsa::RsaPublicKey)> {
    let tpm_ek_cert = get_ek_cert_by_machine_id(txn, machine_id).await?;

    do_compare_pub_key_against_cert(&tpm_ek_cert, ek_pub)
}

pub fn do_compare_pub_key_against_cert(
    tpm_ek_cert: &TpmEkCertificate,
    ek_pub: &Vec<u8>,
) -> CarbideResult<(bool, rsa::RsaPublicKey)> {
    // compare the pub key and the cert

    let cert = X509Certificate::from_der(tpm_ek_cert.as_bytes())
        .map_err(|e| {
            CarbideError::AttestBindKeyError(format!("Could not unmarshall EK Cert: {e}"))
        })?
        .1;

    let pub_key_cert_data = cert.public_key().parsed().map_err(|e| {
        CarbideError::AttestBindKeyError(format!("Could not get EK Cert Data: {e}"))
    })?;

    let ek_cert_modulus = match pub_key_cert_data {
        x509_parser_pub_key::RSA(rsa_pub_key) => rsa_pub_key.modulus,
        _rest => {
            return Err(CarbideError::AttestBindKeyError(
                "TPM EK is not in RSA format".to_string(),
            ));
        }
    };

    // now, we construct the actual public key from the modulus and exponent
    let modulus = BigUint::from_bytes_be(ek_cert_modulus);
    let exponent: BigUint = BigUint::from(RSA_PUBKEY_EXPONENT);

    // pub_key_cert has a different type from pub_key_cert_data, even though their type names
    // actually do coincide!
    let pub_key_cert = RsaPublicKey::new(modulus, exponent).map_err(|e| {
        CarbideError::AttestBindKeyError(format!("Could not create RsaPublicKey from EK Cert: {e}"))
    })?;
    // construct the Public structure and extract the PublicKeyRsa from it, which is really just the modulus
    let ek_pub = Public::unmarshall(ek_pub.as_slice())
        .map_err(|e| CarbideError::AttestBindKeyError(format!("Could not unmarshall EK: {e}")))?;

    let unique = match ek_pub {
        Public::Rsa { unique, .. } => unique,
        _ => {
            return Err(CarbideError::AttestBindKeyError(
                "EK Pub is not in RSA format".to_string(),
            ));
        }
    };

    // now, we construct the actual public key from the modulus and exponent
    let modulus = BigUint::from_bytes_be(unique.value());
    let exponent: BigUint = BigUint::from(RSA_PUBKEY_EXPONENT);

    let pub_key_ek = RsaPublicKey::new(modulus, exponent).map_err(|e| {
        CarbideError::AttestBindKeyError(format!(
            "Could not create RsaPublicKey from TPM's EK Pub: {e}"
        ))
    })?;

    Ok((pub_key_ek == pub_key_cert, pub_key_ek))
}

pub async fn has_passed_attestation<DB>(
    db: &mut DB,
    machine_id: &MachineId,
    _report_id: &MeasurementReportId,
) -> CarbideResult<bool>
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    let measuring_outcome = handle_measuring_state(
        &MeasuringState::WaitingForMeasurements,
        machine_id,
        db,
        true,
    )
    .await
    .map_err(|e| CarbideError::AttestQuoteError(e.to_string()))?;

    Ok(measuring_outcome == MeasuringOutcome::PassedOk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cred_secret_buffer_too_short_panics() {
        let creds = [12, 13, 15];
        let res = extract_cred_secret(&creds);

        match res {
            Ok(..) => panic!("Failed: Should have received an error"),
            Err(e) => assert_eq!(
                e.to_string(),
                "Attest Bind Key Error: Creds file is too short: 3 bytes"
            ),
        }
    }
}
