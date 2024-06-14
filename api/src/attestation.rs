/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::fs;
use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::str;
use tempdir::TempDir;

use tss_esapi::structures::Attest;
use tss_esapi::structures::AttestInfo;
use tss_esapi::structures::Public;
use tss_esapi::structures::Signature;
use tss_esapi::structures::Signature::RsaPss;
use tss_esapi::traits::UnMarshall;

use num_bigint_dig::BigUint;

use pkcs1::LineEnding;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::RsaPublicKey;
use sha2::Digest;

use byteorder::{BigEndian, ByteOrder};

use crate::CarbideError;
use crate::CarbideResult;

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
            (true, false) => Self::SignatureInvalid,
            (false, true) => Self::VerifyHashNoMatch,
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
            Err(CarbideError::AttestationVerifyQuoteError(
                "PCR signature invalid (see logs for full event log)".to_string(),
            ))
        }
        VerifyQuoteState::VerifyHashNoMatch => {
            tracing::warn!(
                "PCR hash mismatch (event log: {}",
                event_log_to_string(event_log)
            );
            Err(CarbideError::AttestationVerifyQuoteError(
                "PCR hash does not match (see logs for full event log)".to_string(),
            ))
        }
        VerifyQuoteState::CompleteFailure => {
            tracing::warn!(
                "PCR signature invalid and PCR hash mismatch (event log: {}",
                event_log_to_string(event_log)
            );
            Err(CarbideError::AttestationVerifyQuoteError(
                "PCR signature invalid (see logs for full event log)".to_string(),
            ))
        }
    }
}

pub fn cli_make_cred(
    ek_serialized: &Vec<u8>,
    ak_serialized: &Vec<u8>,
    session_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CarbideError> {
    // now construct the temp directory
    let tmp_dir = TempDir::new("make_cred").map_err(|e| {
        CarbideError::AttestationBindKeyError(format!("Could not create TempDir: {0}", e))
    })?;
    let tmp_dir_path = tmp_dir.path();

    // create a file to write the EK key to
    let ek_file_path = tmp_dir_path.join("ek.dat");
    let mut ek_file = File::create(ek_file_path.clone()).map_err(|e| {
        CarbideError::AttestationBindKeyError(format!("Could not create EK file: {0}", e))
    })?;

    // construct the Public structure and extract the PublicKeyRsa from it, which is really just the modulus
    let ek_pub = Public::unmarshall(ek_serialized.as_slice()).map_err(|e| {
        CarbideError::AttestationBindKeyError(format!("Could not unmarshall EK: {0}", e))
    })?;

    let unique = match ek_pub {
        Public::Rsa { unique, .. } => unique,
        _ => {
            println!("Not an RSA key");
            return Err(CarbideError::AttestationBindKeyError(
                "EK Pub is not in RSA format".to_string(),
            ));
        }
    };

    // now, we construct the actual public key from the modulus and exponent
    let modulus = BigUint::from_bytes_be(unique.value());
    let exponent: BigUint = BigUint::from(65537u32);

    let pub_key = RsaPublicKey::new(modulus, exponent).map_err(|e| {
        CarbideError::AttestationBindKeyError(format!("Could not create RsaPublicKey: {0}", e))
    })?;

    // serialize the public key to a PEM format and write it to the file
    let pem_pub_key = pub_key.to_pkcs1_pem(LineEnding::default()).map_err(|e| {
        CarbideError::AttestationBindKeyError(format!(
            "Could not convert EK RsaPublicKey to PEM format: {0}",
            e
        ))
    })?;

    ek_file.write_all(pem_pub_key.as_bytes()).map_err(|e| {
        CarbideError::AttestationBindKeyError(format!("Could not write EK Pub to PEM file: {0}", e))
    })?;

    // now write AK name to the file in hexadecimal format
    let ak_name_hex = hex::encode(ak_serialized);

    let session_key_path = tmp_dir_path.join("session_key.dat");
    let session_key_path_str =
        session_key_path
            .to_str()
            .ok_or(CarbideError::AttestationBindKeyError(
                "Could not join seession_key_path".to_string(),
            ))?;

    let mut session_key_file = File::create(session_key_path.clone()).map_err(|e| {
        CarbideError::AttestationBindKeyError(format!(
            "Could not create file for session key: {0}",
            e
        ))
    })?;
    session_key_file.write_all(session_key).map_err(|e| {
        CarbideError::AttestationBindKeyError(format!(
            "Could not write session key to file: {0}",
            e
        ))
    })?;

    // construct the command to execute make_credential
    let ek_file_path_str = ek_file_path
        .to_str()
        .ok_or(CarbideError::AttestationBindKeyError(
            "Could not convert ek_file_path to str".to_string(),
        ))?;

    let cred_out_path = tmp_dir_path.join("mkcred.out");
    let cred_out_path_str = cred_out_path
        .to_str()
        .ok_or(CarbideError::AttestationBindKeyError(
            "Could not join cred_out_path".to_string(),
        ))?;

    let cmd_str =
        format!("tpm2 makecredential -u {ek_file_path_str} -s {session_key_path_str} -n {ak_name_hex} -o {cred_out_path_str} -G rsa -V --tcti=none");

    tracing::debug!("make credential command is {}", cmd_str);
    // execute the makecredential command
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd_str)
        .output()
        .map_err(|e| {
            CarbideError::AttestationBindKeyError(format!(
                "Could not execute makecredential command: {0}",
                e
            ))
        })?;

    tracing::debug!(
        "make cred stdout output is {}",
        str::from_utf8(output.stdout.as_slice()).unwrap_or("<error: undisplayable output>")
    );
    tracing::debug!(
        "make cred stderr output is {}",
        str::from_utf8(output.stderr.as_slice()).unwrap_or("<error: undisplayable output>")
    );

    let creds = fs::read(cred_out_path).map_err(|e| {
        CarbideError::AttestationBindKeyError(format!("Could not reate creds file: {0}", e))
    })?;

    let (cred_blob, encr_secret) = extract_cred_secret(&creds);

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
            return Err(CarbideError::AttestationVerifyQuoteError(
                "AK Pub is not an RSA key".to_string(),
            ))
        }
    };

    // now, we construct the actual public key from the modulus and exponent
    let modulus = BigUint::from_bytes_be(unique.value());
    let exponent: BigUint = BigUint::from(65537u32);

    let pub_key = RsaPublicKey::new(modulus, exponent).map_err(|e| {
        CarbideError::AttestationVerifyQuoteError(format!("Could not create RsaPublicKey: {0}", e))
    })?;

    let rsa_signature = match signature {
        RsaPss(rsa_signature) => rsa_signature,
        _ => {
            return Err(CarbideError::AttestationVerifyQuoteError(
                "unknown signature type".to_string(),
            ))
        }
    };

    return match pub_key.verify(
        rsa::Pss::new::<sha2::Sha256>(),
        &attest_hash,
        rsa_signature.signature().value(),
    ) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    };
}

pub fn verify_pcr_hash(attest: &Attest, pcr_values: &[Vec<u8>]) -> CarbideResult<bool> {
    let attest_digest = match attest.attested() {
        AttestInfo::Quote { info } => info.pcr_digest(),
        _other => {
            return Err(CarbideError::AttestationVerifyQuoteError(
                "Incorrect Attestation Type".into(),
            ))
        }
    };

    let mut hasher = sha2::Sha256::new();

    pcr_values.iter().for_each(|buf| {
        hasher.update(buf);
    });

    let computed_pcr_hash = hasher.finalize();

    if attest_digest.value() == computed_pcr_hash.as_slice() {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn extract_cred_secret(creds: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let magic_header_offset: usize = 8; // 4 bytes for magic number and 4 bytes for version

    // get length for cred blob
    // read cred blob
    let cred_blob_offset: usize = 2;
    let secret_offset: usize = 2;

    let cred_blob_size_bytes =
        &creds[magic_header_offset..(magic_header_offset + cred_blob_offset)];
    let cred_blob_size = BigEndian::read_u16(cred_blob_size_bytes);

    let cred_blob_end_idx: usize =
        magic_header_offset + cred_blob_offset + usize::from(cred_blob_size);
    let cred_blob = Vec::from(&creds[magic_header_offset + cred_blob_offset..cred_blob_end_idx]);

    // read secret
    let secret = Vec::from(&creds[cred_blob_end_idx + secret_offset..]);

    (cred_blob, secret)
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

// test: verify_signature, verify_pcr_hash, extract_cred_secret
// cli_make_cred relies on tpm2_tools installed - maybe it can be tested also? can I make it conditional on tpm2_tools being present?
