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
                "PCR signature invalid and PCR hash mismatch (see logs for full event log)"
                    .to_string(),
            ))
        }
    }
}

pub fn cli_make_cred(
    ek_serialized: &Vec<u8>,
    ak_name_serialized: &Vec<u8>,
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
    let ak_name_hex = hex::encode(ak_name_serialized);

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
        CarbideError::AttestationBindKeyError(format!("Could not create creds file: {0}", e))
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

fn extract_cred_secret(creds: &[u8]) -> CarbideResult<(Vec<u8>, Vec<u8>)> {
    let magic_header_offset: usize = 8; // 4 bytes for magic number and 4 bytes for version

    // get length for cred blob
    // read cred blob
    let cred_blob_offset: usize = 2;
    let secret_offset: usize = 2;

    if creds.len() < magic_header_offset + cred_blob_offset {
        return Err(CarbideError::AttestationBindKeyError(format!(
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
        return Err(CarbideError::AttestationBindKeyError(format!(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CarbideError::AttestationBindKeyError;
    use tss_esapi::structures::EccPoint;
    use tss_esapi::traits::Marshall;

    // serialized version of the cryptographic name (i.e. some SHA) of the AK
    const AK_NAME: [u8; 34] = [
        0, 11, 156, 103, 195, 162, 106, 182, 77, 69, 39, 156, 55, 160, 196, 165, 213, 65, 105, 238,
        251, 75, 243, 144, 166, 24, 132, 177, 159, 77, 184, 23, 17, 253,
    ];

    // a credential
    const SESSION_KEY: [u8; 14] = [
        141, 70, 165, 215, 36, 253, 82, 215, 110, 6, 82, 11, 100, 242,
    ];

    #[test]
    fn test_cli_make_cred_corrupt_ek_pub_returns_error() {
        let ek_pub = [
            0, 44, 204, 141, 70, 165, 215, 36, 253, 82, 215, 110, 6, 82, 11, 100, 242, 161, 218,
            27, 51, 20, 105, 170, 0, 6, 0, 128, 0, 67, 0, 16, 8, 0, 0, 0, 0, 0, 1, 0, 161, 6, 212,
            135, 171, 109, 37, 41, 140, 162, 195, 208, 28, 179, 230, 10, 240, 68, 50, 63, 156, 87,
            145, 116, 187, 226, 155, 98, 39, 45, 151, 92, 237, 12, 163, 23, 222, 219, 192, 54, 202,
            86, 88, 126, 33, 221, 129, 226, 234, 88, 157, 181, 78, 232, 181, 248, 75, 150, 214, 90,
            154, 231, 177, 168, 97, 214, 69, 237, 147, 77, 89, 191, 188, 209, 36, 87, 92, 145, 236,
            231, 206, 100, 177, 159, 40, 65, 177, 177, 91, 116, 173, 114, 128, 82, 70, 2, 225, 214,
            11, 241, 253, 134, 12, 160, 205, 34, 148, 77, 77, 114, 165, 237, 25, 36, 65, 183, 193,
            35, 138, 64, 183, 59, 240, 142, 126, 67, 81, 15, 120, 9, 13, 94, 220, 12, 99, 225, 130,
            91, 81, 223, 183, 122, 0, 224, 243, 84, 239, 188, 147, 44, 149, 78, 90, 246, 180, 255,
            71, 44, 4, 20, 114, 46, 234, 213, 115, 123, 21, 3, 29, 161, 52, 203, 172, 186, 8, 84,
            2, 127, 252, 152, 219, 56, 144, 177, 9, 125, 234, 93, 78, 118, 126, 101, 38, 59, 174,
            103, 249, 86, 7, 2, 97, 246, 117, 79, 1, 222, 12, 64, 167, 15, 41, 67, 140, 66, 124,
            100, 236, 245, 2, 227, 26, 68, 132, 104, 156, 96, 53, 225, 169, 180, 84, 182, 67, 143,
            162, 63, 156, 13, 6, 118, 37, 35, 105, 163, 200, 56, 233, 254, 7, 165, 40, 33, 189,
            226, 206, 145,
        ];

        let res = cli_make_cred(
            ek_pub.to_vec().as_ref(),
            AK_NAME.to_vec().as_ref(),
            &SESSION_KEY,
        );

        match res {
            Ok(..) => {
                panic!("Failed: should have returned error");
            }
            Err(e) => match e {
                AttestationBindKeyError(d) => {
                    assert_eq!(d, "Could not unmarshall EK: response code not recognized")
                }
                _another_error => panic!("Failed: incorrect error type: {:?}", _another_error),
            },
        }
    }

    #[test]
    fn test_cli_make_cred_ek_pub_not_rsa_returns_error() {
        let ek_pub = get_ext_ecc_pub();

        let ek_pub_serialized = ek_pub.marshall().unwrap();

        let res = cli_make_cred(&ek_pub_serialized, AK_NAME.to_vec().as_ref(), &SESSION_KEY);

        match res {
            Ok(..) => {
                panic!("Failed: should have returned error");
            }
            Err(e) => match e {
                AttestationBindKeyError(d) => {
                    assert_eq!(d, "EK Pub is not in RSA format")
                }
                _another_error => panic!("Failed: incorrect error type: {:?}", _another_error),
            },
        }
    }

    #[test]
    fn test_cli_make_cred_invalid_modulus_returns_error() {
        use tss_esapi::structures::Public::Rsa;
        use tss_esapi::structures::PublicKeyRsa;

        let ek_pub = get_ext_rsa_pub();

        let (object_attributes, name_hashing_algo, auth_policy, params) = match ek_pub {
            Rsa {
                object_attributes,
                name_hashing_algorithm,
                auth_policy,
                parameters,
                ..
            } => (
                object_attributes,
                name_hashing_algorithm,
                auth_policy,
                parameters,
            ),
            _ => panic!("Incorrect key type"),
        };

        let ek_pub_copy = Rsa {
            object_attributes,
            name_hashing_algorithm: name_hashing_algo,
            auth_policy,
            parameters: params,
            unique: PublicKeyRsa::try_from([0, 34, 56].to_vec()).unwrap(), // injecting bad value
        };

        let ek_pub_serialized = ek_pub_copy.marshall().unwrap();

        let res = cli_make_cred(&ek_pub_serialized, AK_NAME.to_vec().as_ref(), &SESSION_KEY);

        match res {
            Ok(..) => {
                panic!("Failed: should have returned error");
            }
            Err(e) => match e {
                AttestationBindKeyError(d) => {
                    assert_eq!(d, "Could not create RsaPublicKey: invalid modulus")
                }
                _another_error => panic!("Failed: incorrect error type: {:?}", _another_error),
            },
        }
    }

    // apparently either GitLab pipelines don't have permissions to write to disk, or default location is not writable
    #[ignore]
    #[test]
    fn test_cli_make_cred_success_returns_cred_and_secret() {
        let ek_pub = get_ext_rsa_pub();

        let ek_pub_serialized = ek_pub.marshall().unwrap();

        let res = cli_make_cred(&ek_pub_serialized, AK_NAME.to_vec().as_ref(), &SESSION_KEY);

        match res {
            Ok((v1, v2)) => {
                assert_eq!(v1.len(), 50);
                assert_eq!(v2.len(), 256);
            }
            Err(_) => panic!("Failed: should have returned Ok"),
        }
    }

    use crate::CarbideError::AttestationVerifyQuoteError;

    const ATTEST_SERIALIZED: [u8; 129] = [
        255, 84, 67, 71, 128, 24, 0, 34, 0, 11, 131, 45, 55, 82, 140, 235, 232, 215, 180, 133, 115,
        220, 203, 79, 13, 153, 10, 168, 230, 203, 59, 199, 64, 128, 150, 218, 164, 66, 52, 72, 227,
        197, 0, 16, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        0, 0, 0, 1, 108, 44, 167, 86, 0, 0, 0, 63, 0, 0, 0, 0, 1, 0, 7, 0, 2, 0, 2, 0, 0, 0, 0, 0,
        1, 0, 11, 3, 255, 15, 0, 0, 32, 69, 159, 141, 33, 201, 110, 233, 102, 224, 171, 155, 67,
        115, 214, 128, 145, 55, 215, 242, 130, 251, 89, 92, 188, 251, 113, 20, 127, 251, 198, 74,
        188,
    ];
    const SIGNATURE_SERIALIZED: [u8; 262] = [
        0, 22, 0, 11, 1, 0, 171, 33, 190, 68, 89, 71, 190, 125, 172, 120, 100, 63, 101, 236, 168,
        171, 90, 209, 161, 89, 156, 193, 87, 74, 57, 203, 179, 84, 240, 213, 128, 158, 39, 132,
        212, 18, 25, 113, 53, 71, 255, 68, 15, 213, 40, 25, 118, 180, 156, 67, 63, 153, 150, 17,
        64, 74, 68, 242, 195, 11, 53, 92, 103, 222, 109, 66, 104, 115, 86, 243, 49, 31, 229, 160,
        71, 213, 45, 119, 126, 183, 106, 235, 224, 63, 132, 119, 208, 158, 236, 201, 147, 200, 70,
        166, 175, 20, 239, 145, 228, 215, 233, 184, 111, 54, 134, 133, 28, 171, 118, 94, 99, 43,
        194, 122, 19, 20, 107, 214, 203, 72, 16, 71, 16, 58, 116, 98, 64, 156, 197, 241, 184, 76,
        197, 198, 79, 15, 90, 157, 18, 234, 35, 241, 144, 136, 72, 69, 197, 232, 251, 251, 181,
        190, 64, 191, 130, 160, 76, 253, 179, 172, 12, 7, 213, 245, 140, 109, 97, 222, 164, 233,
        189, 166, 219, 218, 243, 72, 95, 124, 184, 71, 152, 109, 101, 47, 119, 117, 141, 1, 1, 108,
        148, 28, 69, 217, 177, 187, 153, 119, 216, 76, 44, 102, 249, 94, 56, 93, 108, 7, 229, 79,
        75, 47, 82, 82, 159, 202, 238, 240, 176, 99, 123, 61, 186, 28, 149, 166, 124, 62, 176, 84,
        197, 231, 222, 116, 40, 39, 68, 228, 210, 208, 152, 50, 240, 53, 223, 9, 213, 255, 190,
        231, 214, 11, 126, 155, 19, 190,
    ];
    const AK_PUB_SERIALIZED: [u8; 280] = [
        0, 1, 0, 11, 0, 5, 0, 114, 0, 0, 0, 16, 0, 22, 0, 11, 8, 0, 0, 0, 0, 0, 1, 0, 183, 98, 82,
        64, 227, 242, 101, 235, 94, 190, 115, 98, 139, 145, 176, 117, 64, 80, 27, 131, 8, 234, 223,
        32, 34, 225, 126, 76, 88, 171, 97, 120, 111, 22, 89, 174, 189, 113, 255, 8, 67, 184, 206,
        133, 82, 210, 227, 106, 176, 17, 105, 132, 103, 117, 61, 114, 235, 2, 183, 216, 246, 213,
        57, 111, 174, 139, 247, 70, 142, 225, 151, 15, 144, 249, 214, 149, 255, 45, 193, 0, 161,
        109, 251, 69, 246, 78, 116, 230, 2, 18, 229, 211, 74, 98, 18, 174, 104, 227, 162, 237, 72,
        207, 117, 130, 242, 149, 143, 46, 6, 25, 170, 234, 80, 199, 240, 7, 142, 92, 44, 55, 217,
        205, 139, 86, 8, 4, 140, 164, 223, 233, 109, 78, 188, 127, 130, 237, 39, 219, 189, 29, 47,
        111, 145, 114, 92, 32, 24, 186, 135, 193, 176, 52, 138, 18, 232, 54, 104, 56, 13, 219, 90,
        219, 94, 110, 246, 28, 224, 112, 222, 0, 166, 131, 21, 226, 52, 36, 236, 140, 235, 183,
        226, 80, 77, 58, 26, 218, 173, 223, 209, 111, 191, 126, 87, 215, 91, 93, 71, 246, 25, 190,
        91, 62, 244, 53, 61, 149, 148, 197, 219, 230, 18, 10, 206, 183, 208, 22, 106, 242, 174,
        182, 35, 206, 26, 208, 0, 39, 180, 241, 23, 129, 19, 218, 129, 59, 126, 25, 184, 252, 146,
        246, 248, 204, 177, 4, 42, 2, 198, 69, 50, 0, 243, 27, 42, 41, 68, 177,
    ];

    #[test]
    fn test_verify_signature_ak_pub_not_rsa_returns_error() {
        let ak_pub = get_ext_ecc_pub();

        let signature = Signature::unmarshall(&SIGNATURE_SERIALIZED).unwrap();

        let res = verify_signature(&ak_pub, &ATTEST_SERIALIZED.to_vec(), &signature);

        match res {
            Ok(..) => {
                panic!("Failed: should have returned error");
            }
            Err(e) => match e {
                AttestationVerifyQuoteError(d) => {
                    assert_eq!(d, "AK Pub is not an RSA key")
                }
                _another_error => panic!("Failed: incorrect error type: {:?}", _another_error),
            },
        }
    }

    #[test]
    fn test_verify_signature_ak_pub_invalid_modulus_returns_error() {
        use tss_esapi::structures::Public::Rsa;
        use tss_esapi::structures::PublicKeyRsa;

        let ak_pub = get_ext_rsa_pub();

        let (object_attributes, name_hashing_algo, auth_policy, params) = match ak_pub {
            Rsa {
                object_attributes,
                name_hashing_algorithm,
                auth_policy,
                parameters,
                ..
            } => (
                object_attributes,
                name_hashing_algorithm,
                auth_policy,
                parameters,
            ),
            _ => panic!("Incorrect key type"),
        };

        let ak_pub_copy = Rsa {
            object_attributes,
            name_hashing_algorithm: name_hashing_algo,
            auth_policy,
            parameters: params,
            unique: PublicKeyRsa::try_from([0, 34, 56].to_vec()).unwrap(), // injecting invalid value
        };

        let signature = Signature::unmarshall(&SIGNATURE_SERIALIZED).unwrap();

        let res = verify_signature(&ak_pub_copy, &ATTEST_SERIALIZED.to_vec(), &signature);

        match res {
            Ok(..) => {
                panic!("Failed: should have returned error");
            }
            Err(e) => match e {
                AttestationVerifyQuoteError(d) => {
                    assert_eq!(d, "Could not create RsaPublicKey: invalid modulus")
                }
                _another_error => panic!("Failed: incorrect error type: {:?}", _another_error),
            },
        }
    }

    #[test]
    fn test_verify_signature_invalid_signature_type_returns_error() {
        use tss_esapi::structures::Public as TssPublic;
        use tss_esapi::structures::Signature::RsaSsa;

        let ak_pub = TssPublic::unmarshall(AK_PUB_SERIALIZED.as_slice()).unwrap();

        let signature = Signature::unmarshall(&SIGNATURE_SERIALIZED).unwrap();

        let rsa_signature = match signature {
            RsaPss(rsa_signature) => rsa_signature,
            _ => panic!("Failed: Unexepected signature type in test"),
        };

        let signature = RsaSsa(rsa_signature);

        let res = verify_signature(&ak_pub, &ATTEST_SERIALIZED.to_vec(), &signature);

        match res {
            Ok(..) => {
                panic!("Failed: should have returned error");
            }
            Err(e) => match e {
                AttestationVerifyQuoteError(d) => {
                    assert_eq!(d, "unknown signature type")
                }
                _another_error => panic!("Failed: incorrect error type: {:?}", _another_error),
            },
        }
    }

    #[test]
    fn test_verify_signature_invalid_attestation_returns_false() {
        use tss_esapi::structures::Public as TssPublic;

        let bad_attest = [
            255, 84, 67, 53, 10, 168, 230, 203, 59, 199, 64, 128, 150, 218, 164, 66, 52, 72, 227,
            197, 0, 16, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 0, 0, 0, 1, 108, 44, 167, 86, 0, 0, 0, 63, 0, 0, 0, 0, 1, 0, 7, 0, 2, 0, 2, 0, 0,
            0, 0, 0, 1, 0, 11, 3, 255, 15, 0, 0, 32, 69, 159, 141, 33, 201, 110, 233, 102, 224,
            171, 155, 67, 115, 214, 128, 145, 55, 215, 242, 130, 251, 89, 92, 188, 251, 113, 20,
            127, 251, 198, 74, 188,
        ];

        let ak_pub = TssPublic::unmarshall(AK_PUB_SERIALIZED.as_slice()).unwrap();

        let signature = Signature::unmarshall(&SIGNATURE_SERIALIZED).unwrap();

        let res = verify_signature(&ak_pub, &bad_attest.to_vec(), &signature);

        match res {
            Ok(value) => assert!(!value),
            Err(_) => panic!("Failed: Should have returned Ok"),
        }
    }

    #[test]
    fn test_verify_signature_success_returns_true() {
        use tss_esapi::structures::Public as TssPublic;

        let ak_pub = TssPublic::unmarshall(AK_PUB_SERIALIZED.as_slice()).unwrap();

        let signature = Signature::unmarshall(&SIGNATURE_SERIALIZED).unwrap();

        let res = verify_signature(&ak_pub, &ATTEST_SERIALIZED.to_vec(), &signature);

        match res {
            Ok(value) => assert!(value),
            Err(_) => panic!("Failed: Should have returned Ok"),
        }
    }

    const PCR_VALUES: [[u8; 32]; 2] = [
        [
            164, 126, 4, 71, 192, 152, 159, 113, 199, 82, 135, 160, 29, 112, 174, 109, 44, 162, 41,
            122, 116, 248, 9, 60, 82, 184, 5, 170, 14, 216, 205, 85,
        ],
        [
            194, 184, 135, 178, 147, 136, 167, 102, 146, 89, 65, 45, 32, 200, 40, 3, 203, 165, 253,
            191, 25, 109, 184, 243, 196, 215, 170, 188, 187, 77, 188, 218,
        ],
    ];

    const ATTEST_SERIALIZED_SHORT: [u8; 129] = [
        255, 84, 67, 71, 128, 24, 0, 34, 0, 11, 44, 93, 55, 234, 83, 198, 195, 90, 85, 14, 189,
        234, 103, 243, 125, 164, 152, 193, 21, 104, 96, 147, 159, 210, 223, 11, 3, 238, 198, 190,
        62, 99, 0, 16, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 0, 0, 0, 1, 108, 214, 233, 61, 0, 0, 0, 63, 0, 0, 0, 0, 1, 0, 7, 0, 2, 0, 2, 0, 0, 0,
        0, 0, 1, 0, 11, 3, 3, 0, 0, 0, 32, 232, 82, 131, 35, 89, 74, 4, 241, 44, 187, 250, 255,
        208, 109, 234, 133, 170, 43, 173, 225, 98, 59, 24, 212, 29, 89, 0, 224, 217, 164, 190, 44,
    ];

    #[test]
    fn test_verify_pcr_hash_attest_not_match_returns_false() {
        let attest = Attest::unmarshall(&ATTEST_SERIALIZED_SHORT).unwrap();
        let mut pcr_values_copy = PCR_VALUES;

        pcr_values_copy[0][10] = 255;

        let res = verify_pcr_hash(
            &attest,
            &[pcr_values_copy[0].to_vec(), pcr_values_copy[1].to_vec()],
        );

        match res {
            Ok(value) => assert!(!value),
            Err(_) => panic!("Failed: Should have returned Ok"),
        }
    }

    #[test]
    fn test_verify_pcr_hash_success_returns_true() {
        let attest = Attest::unmarshall(&ATTEST_SERIALIZED_SHORT).unwrap();

        let res = verify_pcr_hash(&attest, &[PCR_VALUES[0].to_vec(), PCR_VALUES[1].to_vec()]);

        match res {
            Ok(value) => assert!(value),
            Err(_) => panic!("Failed: Should have returned Ok"),
        }
    }

    // test_verify_pcr_hash_invalid_quote_type_returns_error - currently impossible to do since Attest fields are private

    #[test]
    fn test_extract_cred_secret_buffer_too_short_panics() {
        let creds = [12, 13, 15];
        let res = extract_cred_secret(&creds);

        match res {
            Ok(..) => panic!("Failed: Should have received an error"),
            Err(e) => assert_eq!(
                e.to_string(),
                "Attestation Bind Key Error: Creds file is too short: 3 bytes"
            ),
        }
    }

    //------------------
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;

    fn get_ext_ecc_pub() -> Public {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::interface_types::algorithm::PublicAlgorithm;
        use tss_esapi::interface_types::ecc::EccCurve;
        use tss_esapi::structures::EccScheme;
        use tss_esapi::structures::KeyDerivationFunctionScheme;
        use tss_esapi::structures::PublicBuilder;
        use tss_esapi::structures::PublicEccParametersBuilder;

        let object_attributes = ObjectAttributesBuilder::new()
            .with_user_with_auth(true)
            .with_decrypt(false)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Failed to build object attributes");

        let ecc_parameters = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::Null)
            .with_curve(EccCurve::NistP256)
            .with_is_signing_key(false)
            .with_is_decryption_key(true)
            .with_restricted(false)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .build()
            .expect("Failed to build PublicEccParameters");
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_parameters)
            .with_ecc_unique_identifier(get_ecc_point())
            .build()
            .expect("Failed to build Public structure")
    }

    const EC_POINT: [u8; 65] = [
        0x04, 0x14, 0xd8, 0x59, 0xec, 0x31, 0xe5, 0x94, 0x0f, 0x2b, 0x3a, 0x08, 0x97, 0x64, 0xc4,
        0xfb, 0xa6, 0xcd, 0xaf, 0x0e, 0xa2, 0x44, 0x7f, 0x30, 0xcf, 0xe8, 0x2e, 0xe5, 0x1b, 0x47,
        0x70, 0x01, 0xc3, 0xd6, 0xb4, 0x69, 0x7e, 0xa1, 0xcf, 0x03, 0xdb, 0x05, 0x9c, 0x62, 0x3e,
        0xc6, 0x15, 0x4f, 0xed, 0xab, 0xa0, 0xa0, 0xab, 0x84, 0x2e, 0x67, 0x0c, 0x98, 0xc7, 0x1e,
        0xef, 0xd2, 0x51, 0x91, 0xce,
    ];

    fn get_ecc_point() -> EccPoint {
        use tss_esapi::structures::EccParameter;

        let x =
            EccParameter::try_from(&EC_POINT[1..33]).expect("Failed to construct x EccParameter");
        let y: EccParameter =
            EccParameter::try_from(&EC_POINT[33..]).expect("Failed to construct y EccParameter");
        EccPoint::new(x, y)
    }

    const RSA_KEY: [u8; 256] = [
        0xc9, 0x75, 0xf8, 0xb2, 0x30, 0xf4, 0x24, 0x6e, 0x95, 0xb1, 0x3c, 0x55, 0x0f, 0xe4, 0x48,
        0xe9, 0xac, 0x06, 0x1f, 0xa8, 0xbe, 0xa4, 0xd7, 0x1c, 0xa5, 0x5e, 0x2a, 0xbf, 0x60, 0xc2,
        0x98, 0x63, 0x6c, 0xb4, 0xe2, 0x61, 0x54, 0x31, 0xc3, 0x3e, 0x9d, 0x1a, 0x83, 0x84, 0x18,
        0x51, 0xe9, 0x8c, 0x24, 0xcf, 0xac, 0xc6, 0x0d, 0x26, 0x2c, 0x9f, 0x2b, 0xd5, 0x91, 0x98,
        0x89, 0xe3, 0x68, 0x97, 0x36, 0x02, 0xec, 0x16, 0x37, 0x24, 0x08, 0xb4, 0x77, 0xd1, 0x56,
        0x10, 0x3e, 0xf0, 0x64, 0xf6, 0x68, 0x50, 0x68, 0x31, 0xf8, 0x9b, 0x88, 0xf2, 0xc5, 0xfb,
        0xc9, 0x21, 0xd2, 0xdf, 0x93, 0x6f, 0x98, 0x94, 0x53, 0x68, 0xe5, 0x25, 0x8d, 0x8a, 0xf1,
        0xd7, 0x5b, 0xf3, 0xf9, 0xdf, 0x8c, 0x77, 0x24, 0x9e, 0x28, 0x09, 0x36, 0xf0, 0xa2, 0x93,
        0x17, 0xad, 0xbb, 0x1a, 0xd7, 0x6f, 0x25, 0x6b, 0x0c, 0xd3, 0x76, 0x7f, 0xcf, 0x3a, 0xe3,
        0x1a, 0x84, 0x57, 0x62, 0x71, 0x8a, 0x6a, 0x42, 0x94, 0x71, 0x21, 0x6a, 0x13, 0x73, 0x17,
        0x56, 0xa2, 0x38, 0xc1, 0x5e, 0x76, 0x0b, 0x67, 0x6b, 0x6e, 0xcd, 0xd3, 0xe2, 0x8a, 0x80,
        0x61, 0x6c, 0x1c, 0x60, 0x9d, 0x65, 0xbd, 0x5a, 0x4e, 0xeb, 0xa2, 0x06, 0xd6, 0xbe, 0xf5,
        0x49, 0xc1, 0x7d, 0xd9, 0x46, 0x3e, 0x9f, 0x2f, 0x92, 0xa4, 0x1a, 0x14, 0x2c, 0x1e, 0xb7,
        0x6d, 0x71, 0x29, 0x92, 0x43, 0x7b, 0x76, 0xa4, 0x8b, 0x33, 0xf3, 0xd0, 0xda, 0x7c, 0x7f,
        0x73, 0x50, 0xe2, 0xc5, 0x30, 0xad, 0x9e, 0x0f, 0x61, 0x73, 0xa0, 0xbb, 0x87, 0x1f, 0x0b,
        0x70, 0xa9, 0xa6, 0xaa, 0x31, 0x2d, 0x62, 0x2c, 0xaf, 0xea, 0x49, 0xb2, 0xce, 0x6c, 0x23,
        0x90, 0xdd, 0x29, 0x37, 0x67, 0xb1, 0xc9, 0x99, 0x3a, 0x3f, 0xa6, 0x69, 0xc9, 0x0d, 0x24,
        0x3f,
    ];

    pub fn get_ext_rsa_pub() -> Public {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::interface_types::algorithm::PublicAlgorithm;
        use tss_esapi::interface_types::algorithm::RsaSchemeAlgorithm;
        use tss_esapi::interface_types::key_bits::RsaKeyBits;
        use tss_esapi::structures::PublicBuilder;
        use tss_esapi::structures::PublicKeyRsa;
        use tss_esapi::structures::PublicRsaParametersBuilder;
        use tss_esapi::structures::RsaScheme;

        let object_attributes = ObjectAttributesBuilder::new()
            .with_user_with_auth(true)
            .with_decrypt(false)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Failed to build object attributes");

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new_unrestricted_signing_key(
                    RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                        .expect("Failed to create rsa scheme"),
                    RsaKeyBits::Rsa2048,
                    Default::default(), // Default exponent is 0 but TPM internally this is mapped to 65537
                )
                .build()
                .expect("Failed to create rsa parameters for public structure"),
            )
            .with_rsa_unique_identifier(
                PublicKeyRsa::try_from(&RSA_KEY[..])
                    .expect("Failed to create Public RSA key from buffer"),
            )
            .build()
            .expect("Failed to build Public structure")
    }

    // test_cli_make_cred
}
