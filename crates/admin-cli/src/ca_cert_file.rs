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

//! Loading and validating operator-supplied CA certificate files, shared by the
//! trust-store commands (`tpm-ca add`, `dpu-device-ca add`).
//!
//! Deliberately strict: the DER bytes returned here are stored verbatim as a
//! trust anchor, and the server-side verifiers reject certificates with
//! trailing bytes — so accepting sloppy input here would seed a root that can
//! never match ("garbage in the store" beats "garbage rejected at add time"
//! only until the first fleet-wide verification failure).

use std::fs::File;
use std::io::Read;
use std::path::Path;

use x509_parser::certificate::X509Certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::FromDer;
use x509_parser::validate::{Validator, VecLogger, X509StructureValidator};

use crate::errors::{CarbideCliError, CarbideCliResult};

/// Whether this path names a certificate file the trust-store commands accept
/// (by the file's own extension: `.pem`, `.cer`, or `.der`).
pub(crate) fn is_ca_cert_file(filepath: &Path) -> bool {
    filepath.is_file() && cert_format(filepath).is_some()
}

enum CertFormat {
    Pem,
    Der,
}

fn cert_format(filepath: &Path) -> Option<CertFormat> {
    let extension = filepath.extension()?.to_str()?;
    if extension.eq_ignore_ascii_case("pem") {
        Some(CertFormat::Pem)
    } else if extension.eq_ignore_ascii_case("cer") || extension.eq_ignore_ascii_case("der") {
        Some(CertFormat::Der)
    } else {
        None
    }
}

/// Reads a CA certificate file (PEM or DER, chosen by the file's own
/// extension), validates it, and returns its DER bytes ready for upload.
pub(crate) fn load_ca_cert_der(filepath: &Path) -> CarbideCliResult<Vec<u8>> {
    let display_path = filepath.to_string_lossy();

    let Some(format) = cert_format(filepath) else {
        return Err(CarbideCliError::GenericError(format!(
            "cannot determine the certificate format of {display_path}: expected a .pem, .cer, or .der extension"
        )));
    };

    let mut file_bytes: Vec<u8> = Vec::new();
    File::open(filepath)
        .and_then(|mut f| f.read_to_end(&mut file_bytes))
        .map_err(CarbideCliError::IOError)?;

    let der = match format {
        CertFormat::Pem => {
            let (rem, pem) = parse_x509_pem(&file_bytes).map_err(|e| {
                CarbideCliError::GenericError(format!(
                    "could not parse {display_path} as a PEM certificate: {e}"
                ))
            })?;
            if pem.label != "CERTIFICATE" {
                return Err(CarbideCliError::GenericError(format!(
                    "{display_path} contains a \"{}\" PEM block; expected a single CERTIFICATE block",
                    pem.label
                )));
            }
            // A trust anchor is a single certificate; silently uploading only
            // the first block of a bundle would seed something the operator
            // did not intend.
            if !rem.iter().all(u8::is_ascii_whitespace) {
                return Err(CarbideCliError::GenericError(format!(
                    "{display_path} contains additional data after the first CERTIFICATE block; \
                     supply exactly one certificate per file"
                )));
            }
            pem.contents
        }
        CertFormat::Der => file_bytes,
    };

    validate_ca_cert(&der, &display_path)?;
    Ok(der)
}

fn validate_ca_cert(ca_cert_bytes: &[u8], display_path: &str) -> CarbideCliResult<()> {
    let (rem, ca_cert) = X509Certificate::from_der(ca_cert_bytes).map_err(|e| {
        CarbideCliError::GenericError(format!(
            "could not parse {display_path} as an X.509 certificate: {e}"
        ))
    })?;
    // The stored bytes are hashed/compared verbatim by the verifiers, which
    // reject trailing bytes — a root seeded with them could never match.
    if !rem.is_empty() {
        return Err(CarbideCliError::GenericError(format!(
            "{display_path} has {} trailing byte(s) after the DER certificate; \
             re-export the certificate without extra data",
            rem.len()
        )));
    }

    let mut logger = VecLogger::default();
    if !X509StructureValidator.validate(&ca_cert, &mut logger) {
        return Err(CarbideCliError::GenericError(format!(
            "{display_path} is not a structurally valid X.509 certificate: {}",
            logger
                .errors()
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn cert_pem() -> (Vec<u8>, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.der().to_vec(), cert.pem())
    }

    fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ca-cert-file-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut f = File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    #[test]
    fn der_format_is_chosen_by_own_extension_even_with_pem_sibling() {
        let (der, pem) = cert_pem();
        // A sibling .pem must not change how the .der file is parsed.
        write_temp("cert-a.pem", pem.as_bytes());
        let der_path = write_temp("cert-a.der", &der);
        let loaded = load_ca_cert_der(&der_path).unwrap();
        assert_eq!(loaded, der);
    }

    #[test]
    fn unsupported_extension_is_rejected_with_actionable_error() {
        let (der, _) = cert_pem();
        let path = write_temp("cert-b.crt", &der);
        let err = load_ca_cert_der(&path).unwrap_err().to_string();
        assert!(err.contains(".pem, .cer, or .der"), "got: {err}");
    }

    #[test]
    fn trailing_der_bytes_are_rejected() {
        let (mut der, _) = cert_pem();
        der.push(0x00);
        let path = write_temp("cert-c.der", &der);
        let err = load_ca_cert_der(&path).unwrap_err().to_string();
        assert!(err.contains("trailing"), "got: {err}");
    }

    #[test]
    fn non_certificate_pem_label_is_rejected() {
        let path = write_temp(
            "cert-d.pem",
            b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        );
        let err = load_ca_cert_der(&path).unwrap_err().to_string();
        assert!(err.contains("CERTIFICATE"), "got: {err}");
    }

    #[test]
    fn pem_bundle_with_extra_blocks_is_rejected() {
        let (_, pem) = cert_pem();
        let bundle = format!("{pem}{pem}");
        let path = write_temp("cert-e.pem", bundle.as_bytes());
        let err = load_ca_cert_der(&path).unwrap_err().to_string();
        assert!(err.contains("additional data"), "got: {err}");
    }

    #[test]
    fn valid_pem_loads_and_matches_der() {
        let (der, pem) = cert_pem();
        let path = write_temp("cert-f.pem", pem.as_bytes());
        let loaded = load_ca_cert_der(&path).unwrap();
        assert_eq!(loaded, der);
    }
}
