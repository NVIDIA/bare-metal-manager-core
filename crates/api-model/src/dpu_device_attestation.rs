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

//! DPU device-identity verification.
//!
//! BlueField DPUs carry a factory-provisioned device-identity certificate (a
//! DICE-style IDevID) chaining to an NVIDIA device CA. carbide uses it as a
//! hardware root of trust for DPU identity — the DPU analog of the host TPM
//! EK-certificate path in api-core's `attestation::tpm_ca_cert`. Otherwise DPUs
//! skip attestation: `DiscoverMachine` derives a DPU's identity from
//! self-asserted DMI serials over an anonymous channel.
//!
//! The IRoT device-certificate chain is fetched **out-of-band** from the DPU
//! BMC over Redfish SPDM `ComponentIntegrity` and verified here against the
//! configured NVIDIA device roots via [`verify_device_cert_chain`]. A verified
//! chain yields a hardware-rooted [`MachineId`] (source
//! [`MachineIdSource::DpuDeviceCert`]); [`select_dpu_machine_id`] then applies
//! the [`DpuDeviceAttestationMode`] policy for a previously-unseen DPU
//! (backward compatibility for already-enrolled DPUs is handled by the
//! resolver's enrollment lookup *before* this policy runs).
//!
//! This module lives in api-model (rather than api-core) so both api-core and
//! the SPDM controller can run the same verification.

use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

/// A DPU whose device certificate verified to a trusted NVIDIA device CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDpuDevice {
    /// Hardware-rooted machine identity derived from the verified device cert.
    pub machine_id: MachineId,
    /// Human-readable device serial taken from the leaf certificate subject CN
    /// (for logs / operator display only — not the identity key).
    pub device_serial: String,
    /// sha256 of the verified leaf device certificate (DER), for the
    /// device-identity binding audit record.
    pub leaf_cert_sha256: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum DpuAttestError {
    #[error("device certificate chain was empty")]
    EmptyChain,
    #[error("could not parse certificate at chain index {index}: {source}")]
    ParseCert {
        index: usize,
        #[source]
        source: x509_parser::error::X509Error,
    },
    #[error("certificate at chain index {index} is not valid at {at}")]
    CertNotValid { index: usize, at: DateTime<Utc> },
    #[error("signature on certificate at chain index {index} did not verify: {source}")]
    ChainSignature {
        index: usize,
        #[source]
        source: x509_parser::error::X509Error,
    },
    #[error("device certificate does not chain to any trusted NVIDIA device CA")]
    NoTrustedRoot,
    #[error("device certificate subject has no common name to use as a serial")]
    MissingSerial,
    #[error("could not parse PEM certificate bundle: {0}")]
    Pem(String),
    #[error(
        "device identity is required (mode = required) but no verified device certificate was available"
    )]
    DeviceIdentityRequired,
    #[error("trailing bytes after certificate at chain index {index}")]
    TrailingBytes { index: usize },
    #[error(
        "issuer name of certificate at chain index {index} does not match the next certificate's subject"
    )]
    IssuerNameMismatch { index: usize },
    #[error("issuer certificate at chain index {index} is not a CA")]
    IssuerNotCa { index: usize },
}

/// Verifies a DPU device-identity **certificate chain** (no proof of
/// possession) and, on success, returns the hardware-rooted identity for the
/// DPU.
///
/// This is the entry point for the out-of-band (BMC / SPDM) path: carbide
/// fetches the `BlueField_DPU_IRoT` certificate chain from the DPU BMC over
/// Redfish and verifies it server-side — the DPU analog of host TPM EK-cert
/// verification.
///
/// `trusted_roots` are DER-encoded NVIDIA device root CA certificates. A root
/// that fails to parse is skipped (with a warning) rather than failing the
/// whole verification: roots are operator-seeded, and one malformed row must
/// not poison verification for every DPU in the fleet. `now` is the
/// verification time (injected for determinism; callers pass [`Utc::now`]).
///
/// Deliberately simple path build: validity windows, each issuer→subject link,
/// and that the top of the presented chain is signed by a trusted root. It does
/// **not** yet enforce name constraints, EKU, or revocation (TODOs for a
/// production implementation). Proof of possession is layered on separately by
/// the in-band path.
pub fn verify_device_cert_chain(
    device_cert_chain: &[Vec<u8>],
    trusted_roots: &[Vec<u8>],
    now: DateTime<Utc>,
) -> Result<VerifiedDpuDevice, DpuAttestError> {
    if device_cert_chain.is_empty() {
        return Err(DpuAttestError::EmptyChain);
    }

    // Parse the presented chain (leaf first), requiring each parse to consume
    // its entire input (see `parse_full_cert`).
    let chain: Vec<X509Certificate<'_>> = device_cert_chain
        .iter()
        .enumerate()
        .map(|(index, der)| parse_full_cert(der, index))
        .collect::<Result<_, _>>()?;

    // Trust anchors parse leniently: skip (don't propagate) a malformed row so
    // the remaining valid roots still work.
    let roots: Vec<X509Certificate<'_>> = trusted_roots
        .iter()
        .enumerate()
        .filter_map(|(index, der)| match parse_full_cert(der, index) {
            Ok(cert) => Some(cert),
            Err(e) => {
                tracing::warn!("skipping malformed trusted DPU device root CA (row {index}): {e}");
                None
            }
        })
        .collect();

    let now_ts = now.timestamp();

    // 1. Every certificate in the presented chain must be temporally valid.
    for (index, cert) in chain.iter().enumerate() {
        if !cert_valid_at(cert, now_ts) {
            return Err(DpuAttestError::CertNotValid { index, at: now });
        }
    }

    // 2. Verify each issuer→subject link inside the presented chain. The issuer
    //    must name-match the subject's issuer field, be a CA, and its key must
    //    have signed the subject. The CA check is what stops an end-entity (e.g.
    //    a genuine device leaf whose private key an attacker holds) from being
    //    smuggled in as an intermediate to mint a forged identity.
    for index in 0..chain.len().saturating_sub(1) {
        let subject = &chain[index];
        let issuer = &chain[index + 1];
        if subject.issuer().as_raw() != issuer.subject().as_raw() {
            return Err(DpuAttestError::IssuerNameMismatch { index });
        }
        if !issuer.is_ca() {
            return Err(DpuAttestError::IssuerNotCa { index: index + 1 });
        }
        subject
            .verify_signature(Some(issuer.public_key()))
            .map_err(|e| DpuAttestError::ChainSignature { index, source: e })?;
    }

    // 3. The top of the presented chain must be signed by a trusted root: a CA
    //    whose subject matches the top cert's issuer, valid at `now`, whose key
    //    verifies the top's signature. Try every matching root (not just the
    //    first) so multiple roots sharing a subject — e.g. during key rollover —
    //    are all considered.
    let top = chain.last().expect("non-empty chain checked above");
    let signed_by_trusted_root = roots.iter().any(|root| {
        root.subject().as_raw() == top.issuer().as_raw()
            && root.is_ca()
            && cert_valid_at(root, now_ts)
            && top.verify_signature(Some(root.public_key())).is_ok()
    });
    if !signed_by_trusted_root {
        return Err(DpuAttestError::NoTrustedRoot);
    }

    // 4. Derive the identity from the verified leaf. The serial (CN) is for
    //    display; the machine_id is rooted in the full leaf certificate bytes,
    //    mirroring how the host path hashes the TPM EK certificate.
    let leaf = &chain[0];
    let device_serial = leaf
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned)
        .ok_or(DpuAttestError::MissingSerial)?;

    let mut hasher = Sha256::new();
    hasher.update(&device_cert_chain[0]);
    let leaf_cert_sha256 = hasher.finalize().to_vec();

    Ok(VerifiedDpuDevice {
        machine_id: machine_id_from_device_cert(&device_cert_chain[0]),
        device_serial,
        leaf_cert_sha256,
    })
}

/// Splits a PEM bundle (concatenated `-----BEGIN CERTIFICATE-----` blocks) into
/// DER-encoded certificates, leaf first. Used to consume the PEM chain that the
/// SPDM/Redfish path stores for a DPU (`CaCertificate::certificate_string`).
pub fn pem_chain_to_der(pem: &str) -> Result<Vec<Vec<u8>>, DpuAttestError> {
    let mut ders = Vec::new();
    for block in x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()) {
        let block = block.map_err(|e| DpuAttestError::Pem(e.to_string()))?;
        ders.push(block.contents);
    }
    if ders.is_empty() {
        return Err(DpuAttestError::Pem(
            "no PEM certificate blocks found".to_string(),
        ));
    }
    Ok(ders)
}

/// Derives a stable, hardware-rooted DPU [`MachineId`] from the DER bytes of a
/// verified device certificate. Deterministic: the same device cert always
/// yields the same ID, so a DPU keeps its identity across re-discovery.
pub fn machine_id_from_device_cert(device_cert_der: &[u8]) -> MachineId {
    let mut hasher = Sha256::new();
    hasher.update(device_cert_der);
    MachineId::new(
        MachineIdSource::DpuDeviceCert,
        hasher.finalize().into(),
        MachineType::Dpu,
    )
}

/// Policy for how a DPU's device-identity certificate participates in
/// `machine_id` assignment. Configured via `[dpu_device_attestation] mode`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpuDeviceAttestationMode {
    /// Off: DPUs always use the legacy serial-derived id (current behavior).
    #[default]
    Disabled,
    /// Prefer the hardware-rooted id for a new DPU, but fall back to the legacy
    /// id when the device certificate is unavailable or fails verification.
    BestEffort,
    /// A new DPU must present a verifiable device identity; discovery fails
    /// (fail closed) when one is not available.
    Required,
}

/// Outcome of [`select_dpu_machine_id`] for a previously-unseen DPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpuIdentitySelection {
    /// The DPU presented a verified device attestation: adopt the
    /// hardware-rooted device-cert identity (callers record the binding).
    DeviceRooted(MachineId),
    /// Fall back to the legacy serial-derived id, exactly as before this
    /// feature. `None` when no legacy id could be derived either (missing
    /// serials) — the caller leaves the identity unassigned, as before.
    Legacy(Option<MachineId>),
}

/// Chooses a **previously-unseen** DPU's [`MachineId`] under the configured
/// [`DpuDeviceAttestationMode`].
///
/// Already-enrolled DPUs never reach this policy: the resolver first looks up
/// enrollment under both the legacy id and any previously adopted device-rooted
/// id (via the `dpu_device_cert_status` binding), and keeps the enrolled id in
/// every mode — so an upgrade re-keys nothing and a transient fetch failure
/// cannot flap an enrolled DPU's identity.
///
/// - `legacy_id` is the serial-derived id computed exactly as today
///   (`machine_id::from_hardware_info`), when one could be derived.
/// - `verified_device` is `Some` only when a device certificate was available
///   and passed verification.
///
/// `Disabled` always uses the legacy id; `BestEffort` uses the device-rooted id
/// when a verified cert is available and otherwise falls back to the legacy id;
/// `Required` uses the device-rooted id or fails with
/// [`DpuAttestError::DeviceIdentityRequired`]. The device-rooted id is
/// deterministic, so a new DPU's subsequent discoveries resolve the same id.
pub fn select_dpu_machine_id(
    mode: DpuDeviceAttestationMode,
    legacy_id: Option<MachineId>,
    verified_device: Option<&VerifiedDpuDevice>,
) -> Result<DpuIdentitySelection, DpuAttestError> {
    match (mode, verified_device) {
        (DpuDeviceAttestationMode::Disabled, _) => Ok(DpuIdentitySelection::Legacy(legacy_id)),
        (_, Some(device)) => Ok(DpuIdentitySelection::DeviceRooted(device.machine_id)),
        // New DPU with no verified device identity:
        (DpuDeviceAttestationMode::BestEffort, None) => Ok(DpuIdentitySelection::Legacy(legacy_id)),
        (DpuDeviceAttestationMode::Required, None) => Err(DpuAttestError::DeviceIdentityRequired),
    }
}

/// Parses one DER certificate, requiring the parser to consume the **entire**
/// input. Trailing bytes are rejected so attacker-appended data can't ride along
/// — in particular it can't perturb the certificate bytes that
/// [`machine_id_from_device_cert`] hashes into the identity.
fn parse_full_cert(der: &[u8], index: usize) -> Result<X509Certificate<'_>, DpuAttestError> {
    let (rest, cert) = X509Certificate::from_der(der).map_err(|e| DpuAttestError::ParseCert {
        index,
        source: e.into(),
    })?;
    if !rest.is_empty() {
        return Err(DpuAttestError::TrailingBytes { index });
    }
    Ok(cert)
}

/// Whether `cert` is within its validity window at the given unix timestamp.
fn cert_valid_at(cert: &X509Certificate<'_>, now_ts: i64) -> bool {
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    now_ts >= not_before && now_ts <= not_after
}

#[cfg(test)]
mod tests {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, date_time_ymd,
    };

    use super::*;

    /// A generated CA: its self-signed cert (DER + PEM) and the key pair to sign with.
    struct TestCa {
        cert_der: Vec<u8>,
        cert_pem: String,
        key: KeyPair,
        params: CertificateParams,
    }

    fn make_ca(common_name: &str) -> TestCa {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2034, 1, 1);
        let cert = params.self_signed(&key).expect("self-signed ca");
        TestCa {
            cert_der: cert.der().to_vec(),
            cert_pem: cert.pem(),
            key,
            params,
        }
    }

    /// A device (leaf) certificate signed by `ca`, in DER and PEM form.
    struct TestDevice {
        cert_der: Vec<u8>,
        cert_pem: String,
    }

    fn make_device(ca: &TestCa, serial: &str, not_after_ymd: (i32, u8, u8)) -> TestDevice {
        let key = KeyPair::generate().expect("device key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("device params");
        params.distinguished_name.push(DnType::CommonName, serial);
        params.not_before = date_time_ymd(2024, 1, 1);
        let (y, m, d) = not_after_ymd;
        params.not_after = date_time_ymd(y, m, d);
        let issuer = Issuer::from_params(&ca.params, &ca.key);
        let cert = params.signed_by(&key, &issuer).expect("sign device cert");
        TestDevice {
            cert_der: cert.der().to_vec(),
            cert_pem: cert.pem(),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(date_time_ymd(2026, 6, 25).unix_timestamp(), 0).unwrap()
    }

    #[test]
    fn expired_device_cert_is_rejected() {
        let ca = make_ca("NVIDIA BlueField Device CA");
        // not_after in the past relative to `now()`.
        let device = make_device(&ca, "MT2147XYZ005", (2025, 1, 1));
        let err = verify_device_cert_chain(&[device.cert_der], &[ca.cert_der], now()).unwrap_err();
        assert!(
            matches!(err, DpuAttestError::CertNotValid { index: 0, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn empty_chain_is_rejected() {
        let err = verify_device_cert_chain(&[], &[], now()).unwrap_err();
        assert!(matches!(err, DpuAttestError::EmptyChain), "got {err:?}");
    }

    #[test]
    fn two_devices_get_distinct_identities() {
        let ca = make_ca("NVIDIA BlueField Device CA");
        let a = machine_id_from_device_cert(&make_device(&ca, "serial-A", (2030, 1, 1)).cert_der);
        let b = machine_id_from_device_cert(&make_device(&ca, "serial-B", (2030, 1, 1)).cert_der);
        assert_ne!(a, b);
    }

    // --- chain-only (BMC / SPDM path) verification ---

    #[test]
    fn chain_only_verification_yields_identity_without_nonce() {
        let ca = make_ca("NVIDIA BlueField Device CA");
        let device = make_device(&ca, "MT-irot-001", (2030, 1, 1));

        let verified = verify_device_cert_chain(
            std::slice::from_ref(&device.cert_der),
            std::slice::from_ref(&ca.cert_der),
            now(),
        )
        .unwrap();

        assert_eq!(verified.device_serial, "MT-irot-001");
        assert_eq!(verified.machine_id.source(), MachineIdSource::DpuDeviceCert);
        // Same identity the in-band path would derive for this device.
        assert_eq!(
            verified.machine_id,
            machine_id_from_device_cert(&device.cert_der)
        );
    }

    #[test]
    fn chain_only_rejects_untrusted_root() {
        let real_ca = make_ca("NVIDIA BlueField Device CA");
        let rogue_ca = make_ca("Rogue CA");
        let device = make_device(&rogue_ca, "MT-irot-002", (2030, 1, 1));
        let err =
            verify_device_cert_chain(&[device.cert_der], &[real_ca.cert_der], now()).unwrap_err();
        assert!(matches!(err, DpuAttestError::NoTrustedRoot), "got {err:?}");
    }

    #[test]
    fn one_malformed_root_does_not_poison_verification() {
        // A trusted-root row with trailing bytes (e.g. an operator-seeded DER
        // file with a stray newline) is skipped, and a chain that verifies
        // against another (valid) root still verifies.
        let ca = make_ca("NVIDIA BlueField Device CA");
        let device = make_device(&ca, "MT-irot-poison", (2030, 1, 1));

        let mut malformed_root = ca.cert_der.clone();
        malformed_root.push(b'\n');

        let verified = verify_device_cert_chain(
            std::slice::from_ref(&device.cert_der),
            &[malformed_root, ca.cert_der],
            now(),
        )
        .unwrap();
        assert_eq!(verified.device_serial, "MT-irot-poison");
    }

    #[test]
    fn pem_path_verifies_chain_fetched_as_pem() {
        // Mirrors the SPDM/Redfish path: the chain and roots arrive as PEM.
        let ca = make_ca("NVIDIA BlueField Device CA");
        let device = make_device(&ca, "MT-irot-pem", (2030, 1, 1));

        let chain = pem_chain_to_der(&device.cert_pem).unwrap();
        let roots = pem_chain_to_der(&ca.cert_pem).unwrap();
        let verified = verify_device_cert_chain(&chain, &roots, now()).unwrap();
        assert_eq!(verified.device_serial, "MT-irot-pem");
        // PEM and DER entry points agree on the derived identity.
        assert_eq!(
            verified.machine_id,
            machine_id_from_device_cert(&device.cert_der)
        );
    }

    #[test]
    fn pem_parse_rejects_non_pem_input() {
        let err = pem_chain_to_der("not a pem bundle").unwrap_err();
        assert!(matches!(err, DpuAttestError::Pem(_)), "got {err:?}");
    }

    #[test]
    fn end_entity_cannot_act_as_intermediate() {
        // Attacker holds a genuine device leaf (signed by the trusted root) and
        // its key. They try to use it as an "intermediate" to sign a forged leaf
        // carrying a victim's serial. The chain must be rejected because the
        // device leaf is not a CA — otherwise one device could forge any identity.
        let ca = make_ca("NVIDIA BlueField Device CA");

        let attacker_key = KeyPair::generate().unwrap();
        let mut attacker_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        attacker_params
            .distinguished_name
            .push(DnType::CommonName, "attacker-device");
        attacker_params.not_before = date_time_ymd(2024, 1, 1);
        attacker_params.not_after = date_time_ymd(2030, 1, 1);
        // Default params are NOT a CA.
        let attacker_cert = attacker_params
            .signed_by(&attacker_key, &Issuer::from_params(&ca.params, &ca.key))
            .unwrap();

        let forged_key = KeyPair::generate().unwrap();
        let mut forged_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        forged_params
            .distinguished_name
            .push(DnType::CommonName, "victim-serial");
        forged_params.not_before = date_time_ymd(2024, 1, 1);
        forged_params.not_after = date_time_ymd(2030, 1, 1);
        let forged_cert = forged_params
            .signed_by(
                &forged_key,
                &Issuer::from_params(&attacker_params, &attacker_key),
            )
            .unwrap();

        let chain = vec![forged_cert.der().to_vec(), attacker_cert.der().to_vec()];
        let err = verify_device_cert_chain(&chain, &[ca.cert_der], now()).unwrap_err();
        assert!(
            matches!(err, DpuAttestError::IssuerNotCa { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn trailing_bytes_after_cert_are_rejected() {
        let ca = make_ca("NVIDIA BlueField Device CA");
        let device = make_device(&ca, "MT-trailing", (2030, 1, 1));
        let mut der = device.cert_der;
        der.push(0x00); // attacker-appended trailing byte
        let err = verify_device_cert_chain(&[der], &[ca.cert_der], now()).unwrap_err();
        assert!(
            matches!(err, DpuAttestError::TrailingBytes { index: 0 }),
            "got {err:?}"
        );
    }

    // --- identity-selection policy (previously-unseen DPUs only) ---

    fn legacy_id() -> MachineId {
        MachineId::new(
            MachineIdSource::ProductBoardChassisSerial,
            [7u8; 32],
            MachineType::Dpu,
        )
    }

    fn verified(serial: &str) -> VerifiedDpuDevice {
        let ca = make_ca("NVIDIA BlueField Device CA");
        let device = make_device(&ca, serial, (2030, 1, 1));
        let mut hasher = Sha256::new();
        hasher.update(&device.cert_der);
        VerifiedDpuDevice {
            machine_id: machine_id_from_device_cert(&device.cert_der),
            device_serial: serial.to_string(),
            leaf_cert_sha256: hasher.finalize().to_vec(),
        }
    }

    use DpuDeviceAttestationMode::{BestEffort, Disabled, Required};

    #[test]
    fn new_dpu_with_attestation_gets_device_rooted_id() {
        let device = verified("MT-brand-new");
        for mode in [BestEffort, Required] {
            let decision = select_dpu_machine_id(mode, Some(legacy_id()), Some(&device)).unwrap();
            assert_eq!(
                decision,
                DpuIdentitySelection::DeviceRooted(device.machine_id)
            );
        }
    }

    #[test]
    fn best_effort_falls_back_to_legacy_when_no_cert() {
        let decision = select_dpu_machine_id(BestEffort, Some(legacy_id()), None).unwrap();
        assert_eq!(decision, DpuIdentitySelection::Legacy(Some(legacy_id())));
    }

    #[test]
    fn required_fails_when_no_cert_for_new_dpu() {
        let err = select_dpu_machine_id(Required, Some(legacy_id()), None).unwrap_err();
        assert!(
            matches!(err, DpuAttestError::DeviceIdentityRequired),
            "got {err:?}"
        );
    }

    #[test]
    fn required_fails_when_no_cert_and_no_legacy_id() {
        // A DPU whose report has no serial-derived id at all must still fail
        // closed in required mode (it must not silently skip the policy).
        let err = select_dpu_machine_id(Required, None, None).unwrap_err();
        assert!(
            matches!(err, DpuAttestError::DeviceIdentityRequired),
            "got {err:?}"
        );
    }

    #[test]
    fn verified_cert_without_legacy_id_still_yields_device_rooted_id() {
        let device = verified("MT-no-serial");
        let decision = select_dpu_machine_id(BestEffort, None, Some(&device)).unwrap();
        assert_eq!(
            decision,
            DpuIdentitySelection::DeviceRooted(device.machine_id)
        );
    }

    #[test]
    fn disabled_always_uses_legacy_even_with_cert() {
        let device = verified("MT-disabled");
        let decision = select_dpu_machine_id(Disabled, Some(legacy_id()), Some(&device)).unwrap();
        assert_eq!(decision, DpuIdentitySelection::Legacy(Some(legacy_id())));
    }

    #[test]
    fn rediscovery_of_new_dpu_is_stable() {
        // A new DPU enrolled under its device-rooted id resolves to the same
        // deterministic id on every re-verification.
        let device = verified("MT-stable");
        let first = select_dpu_machine_id(BestEffort, Some(legacy_id()), Some(&device)).unwrap();
        let second = select_dpu_machine_id(BestEffort, Some(legacy_id()), Some(&device)).unwrap();
        assert_eq!(first, second);
        assert_eq!(first, DpuIdentitySelection::DeviceRooted(device.machine_id));
    }
}
