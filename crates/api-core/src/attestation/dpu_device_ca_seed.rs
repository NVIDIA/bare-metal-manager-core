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

//! Startup seeding of trusted DPU device (BlueField IRoT) root CA certificates
//! from an operator-supplied directory (`[dpu_device_attestation] ca_cert_dir`).
//!
//! Each `.pem`/`.cer`/`.der` file in the directory is parsed to DER and inserted
//! into `dpu_device_ca_certs`. Seeding is idempotent — the insert is
//! `ON CONFLICT DO NOTHING`, so already-trusted roots are skipped — which lets
//! operators mount the roots (e.g. a Kubernetes Secret) and have them re-applied
//! on every deploy instead of running `nico-admin-cli dpu-device-ca add` by hand.
//!
//! A single malformed file is logged and skipped rather than failing startup: a
//! trust anchor that will not parse can never match a chain anyway, and crashing
//! the API over one bad file would take down the whole controller.

use std::path::Path;

use db::Transaction;
use sqlx::{Pool, Postgres};
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::FromDer;

use crate::CarbideResult;
use crate::attestation::extract_ca_fields;

/// Seeds every device CA certificate file under `dir` into `dpu_device_ca_certs`.
/// Skips (with a logged warning) any file that cannot be parsed as a single
/// trust anchor. A missing directory is a logged warning, not an error.
pub async fn seed_device_ca_certs_from_dir(
    db_pool: &Pool<Postgres>,
    dir: &Path,
) -> CarbideResult<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(
                "DPU device CA seed directory {} could not be read: {e}; skipping seeding",
                dir.display()
            );
            return Ok(());
        }
    };

    // Sort for deterministic seeding order (and stable logs) across runs.
    let mut paths: Vec<_> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| cert_der_extension(path).is_some())
        .collect();
    paths.sort();

    if paths.is_empty() {
        tracing::info!(
            "DPU device CA seed directory {} contains no .pem/.cer/.der files",
            dir.display()
        );
        return Ok(());
    }

    let mut seeded = 0usize;
    let mut already_trusted = 0usize;
    let mut skipped = 0usize;

    for path in paths {
        let der = match load_cert_der(&path) {
            Ok(der) => der,
            Err(e) => {
                tracing::error!("Skipping DPU device CA file {}: {e}", path.display());
                skipped += 1;
                continue;
            }
        };

        let (not_valid_before, not_valid_after, subject) = match extract_ca_fields(&der) {
            Ok(fields) => fields,
            Err(e) => {
                tracing::error!(
                    "Skipping DPU device CA file {}: could not extract CA fields: {e}",
                    path.display()
                );
                skipped += 1;
                continue;
            }
        };

        let mut txn = Transaction::begin(db_pool).await?;
        let inserted = db::attestation::dpu_device_ca_certs::insert(
            &mut txn,
            &not_valid_before,
            &not_valid_after,
            &der,
            subject.as_slice(),
        )
        .await?;
        txn.commit().await?;

        match inserted {
            Some(ca) => {
                tracing::info!(
                    "Seeded DPU device CA certificate from {} (id {})",
                    path.display(),
                    ca.id
                );
                seeded += 1;
            }
            None => already_trusted += 1,
        }
    }

    tracing::info!(
        "DPU device CA seeding from {} complete: {seeded} added, {already_trusted} already trusted, {skipped} skipped",
        dir.display()
    );
    Ok(())
}

/// Returns whether a path names a certificate file we seed, keyed on its own
/// extension (`.pem`, `.cer`, or `.der`), and whether it is PEM or DER.
fn cert_der_extension(path: &Path) -> Option<bool> {
    if !path.is_file() {
        return None;
    }
    let ext = path.extension()?.to_str()?;
    if ext.eq_ignore_ascii_case("pem") {
        Some(true)
    } else if ext.eq_ignore_ascii_case("cer") || ext.eq_ignore_ascii_case("der") {
        Some(false)
    } else {
        None
    }
}

/// Reads a certificate file (PEM or DER, by extension) and returns its DER
/// bytes. Strict — the same trailing-byte rejection the add handler and the
/// chain verifier apply, so a root that could never match is never seeded.
fn load_cert_der(path: &Path) -> Result<Vec<u8>, String> {
    let is_pem =
        cert_der_extension(path).ok_or_else(|| "unsupported certificate extension".to_string())?;
    let bytes = std::fs::read(path).map_err(|e| format!("could not read file: {e}"))?;

    let der = if is_pem {
        let (rem, pem) =
            parse_x509_pem(&bytes).map_err(|e| format!("could not parse PEM certificate: {e}"))?;
        if pem.label != "CERTIFICATE" {
            return Err(format!(
                "contains a \"{}\" PEM block; expected a single CERTIFICATE block",
                pem.label
            ));
        }
        // A trust anchor is one certificate; silently taking the first block of
        // a bundle would seed something the operator did not intend.
        if !rem.iter().all(u8::is_ascii_whitespace) {
            return Err(
                "contains data after the first CERTIFICATE block; supply exactly one certificate per file"
                    .to_string(),
            );
        }
        pem.contents
    } else {
        bytes
    };

    // Reject trailing bytes: the stored DER is hashed/compared verbatim by the
    // verifier, which rejects trailing data.
    let (rem, _) =
        X509Certificate::from_der(&der).map_err(|e| format!("invalid X.509 certificate: {e}"))?;
    if !rem.is_empty() {
        return Err(format!(
            "has {} trailing byte(s) after the DER certificate",
            rem.len()
        ));
    }

    Ok(der)
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
        let dir = std::env::temp_dir().join(format!("dpu-ca-seed-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    #[test]
    fn der_file_loads_verbatim() {
        let (der, _) = cert_pem();
        let path = write_temp("root.der", &der);
        assert_eq!(load_cert_der(&path).unwrap(), der);
    }

    #[test]
    fn cer_extension_is_treated_as_der() {
        let (der, _) = cert_pem();
        let path = write_temp("root.cer", &der);
        assert_eq!(load_cert_der(&path).unwrap(), der);
    }

    #[test]
    fn pem_file_loads_and_matches_der() {
        let (der, pem) = cert_pem();
        let path = write_temp("root.pem", pem.as_bytes());
        assert_eq!(load_cert_der(&path).unwrap(), der);
    }

    #[test]
    fn trailing_der_bytes_are_rejected() {
        let (mut der, _) = cert_pem();
        der.push(0x00);
        let path = write_temp("trailing.der", &der);
        let err = load_cert_der(&path).unwrap_err();
        assert!(err.contains("trailing"), "got: {err}");
    }

    #[test]
    fn non_certificate_pem_is_rejected() {
        let path = write_temp(
            "key.pem",
            b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        );
        let err = load_cert_der(&path).unwrap_err();
        assert!(err.contains("CERTIFICATE"), "got: {err}");
    }

    #[test]
    fn pem_bundle_is_rejected() {
        let (_, pem) = cert_pem();
        let path = write_temp("bundle.pem", format!("{pem}{pem}").as_bytes());
        let err = load_cert_der(&path).unwrap_err();
        assert!(
            err.contains("after the first CERTIFICATE block"),
            "got: {err}"
        );
    }

    #[test]
    fn unsupported_extension_is_not_a_cert_file() {
        let (der, _) = cert_pem();
        let path = write_temp("root.txt", &der);
        assert_eq!(cert_der_extension(&path), None);
    }
}
