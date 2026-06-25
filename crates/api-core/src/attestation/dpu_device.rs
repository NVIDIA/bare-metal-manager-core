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

//! DPU device attestation (spike / design exploration).
//!
//! BlueField DPUs ship with a factory-provisioned **device identity
//! certificate** (a DICE-style IDevID) whose private key never leaves the
//! device and whose certificate chains to an NVIDIA device CA. This module is a
//! prototype of using that certificate as a *hardware root of trust* for DPU
//! bootstrap — the DPU equivalent of the host TPM EK-certificate path in
//! [`crate::attestation::tpm_ca_cert`].
//!
//! Today (see issue NVIDIA/infra-controller#355 discussion) DPUs **skip
//! attestation entirely**: `DiscoverMachine` derives a DPU's identity from
//! self-asserted DMI serials over an anonymous channel. This module shows what
//! it looks like to instead *prove* a DPU's identity:
//!
//! 1. The API issues a random `nonce` (challenge) during discovery.
//! 2. The DPU returns its device certificate chain plus an ECDSA signature over
//!    the nonce produced with the device private key.
//! 3. [`verify_dpu_device_attestation`] verifies the chain to a trusted NVIDIA
//!    device CA **and** the nonce signature (proof of possession), then derives
//!    a hardware-rooted [`MachineId`] from the verified leaf certificate.
//!
//! The resulting `MachineId` uses [`MachineIdSource::DpuDeviceCert`], so it is
//! distinguishable from the legacy self-asserted serial-derived IDs.
//!
//! Scope of this spike: the cryptographic core is real and unit-tested. The
//! gRPC message plumbing and the `DiscoverMachine` call site are sketched in the
//! crate review notes, not wired here, so the nonce-issuance/storage path (which
//! mirrors the host AK-challenge flow in `db::attestation::secret_ak_pub`) stays
//! out of this module.

use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Attestation material presented by a DPU during discovery. Field names mirror
/// the proposed `DpuDeviceAttestation` protobuf message (see review notes).
#[derive(Debug, Clone)]
pub struct DpuDeviceAttestation {
    /// DER-encoded certificate chain, leaf first: `[device_cert, intermediate…]`.
    /// The chain need not include the trust anchor; the anchor is supplied
    /// separately via [`verify_dpu_device_attestation`]'s `trusted_roots`.
    pub device_cert_chain: Vec<Vec<u8>>,
    /// The server-issued challenge the device signed. Echoing it back lets the
    /// server confirm freshness (anti-replay) without per-device state beyond
    /// the outstanding-nonce record.
    pub nonce: Vec<u8>,
    /// DER-encoded ECDSA (P-256) signature over `nonce`, produced with the
    /// device certificate's private key.
    pub nonce_signature: Vec<u8>,
}

/// A DPU whose device certificate verified to a trusted NVIDIA device CA and
/// which proved possession of the device key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDpuDevice {
    /// Hardware-rooted machine identity derived from the verified device cert.
    pub machine_id: MachineId,
    /// Human-readable device serial taken from the leaf certificate subject CN
    /// (for logs / operator display only — not the identity key).
    pub device_serial: String,
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
    #[error("device leaf public key is not a usable P-256 key: {0}")]
    BadDeviceKey(String),
    #[error("nonce signature is malformed: {0}")]
    MalformedSignature(String),
    #[error("nonce signature did not verify against the device key (proof of possession failed)")]
    ProofOfPossession,
    #[error("device certificate subject has no common name to use as a serial")]
    MissingSerial,
}

/// Verifies a DPU device attestation and, on success, returns the hardware-rooted
/// identity to use for the DPU.
///
/// `trusted_roots` are DER-encoded NVIDIA device root CA certificates (the
/// configured trust anchors). `now` is the verification time (injected for
/// determinism; callers pass [`Utc::now`]).
///
/// This performs a deliberately simple path build — it checks validity windows,
/// each issuer→subject signature link, that the top of the presented chain is
/// signed by a trusted root, and the nonce proof-of-possession. It does **not**
/// yet enforce name constraints, EKU, or revocation; those are noted as TODOs
/// for a production implementation.
pub fn verify_dpu_device_attestation(
    attestation: &DpuDeviceAttestation,
    trusted_roots: &[Vec<u8>],
    now: DateTime<Utc>,
) -> Result<VerifiedDpuDevice, DpuAttestError> {
    if attestation.device_cert_chain.is_empty() {
        return Err(DpuAttestError::EmptyChain);
    }

    // Parse the presented chain (leaf first) and the trust anchors.
    let chain: Vec<X509Certificate<'_>> = attestation
        .device_cert_chain
        .iter()
        .enumerate()
        .map(|(index, der)| {
            X509Certificate::from_der(der)
                .map(|(_rest, cert)| cert)
                .map_err(|e| DpuAttestError::ParseCert {
                    index,
                    source: e.into(),
                })
        })
        .collect::<Result<_, _>>()?;

    let roots: Vec<X509Certificate<'_>> = trusted_roots
        .iter()
        .enumerate()
        .map(|(index, der)| {
            X509Certificate::from_der(der)
                .map(|(_rest, cert)| cert)
                .map_err(|e| DpuAttestError::ParseCert {
                    index,
                    source: e.into(),
                })
        })
        .collect::<Result<_, _>>()?;

    let now_ts = now.timestamp();

    // 1. Every certificate in the presented chain must be temporally valid.
    for (index, cert) in chain.iter().enumerate() {
        if !cert_valid_at(cert, now_ts) {
            return Err(DpuAttestError::CertNotValid { index, at: now });
        }
    }

    // 2. Verify each issuer→subject link inside the presented chain.
    for index in 0..chain.len().saturating_sub(1) {
        let subject = &chain[index];
        let issuer = &chain[index + 1];
        subject
            .verify_signature(Some(issuer.public_key()))
            .map_err(|e| DpuAttestError::ChainSignature { index, source: e })?;
    }

    // 3. The top of the presented chain must be signed by a trusted root whose
    //    subject matches the top cert's issuer.
    let top = chain.last().expect("non-empty chain checked above");
    let top_index = chain.len() - 1;
    let root = roots
        .iter()
        .find(|root| root.subject().as_raw() == top.issuer().as_raw())
        .ok_or(DpuAttestError::NoTrustedRoot)?;
    if !cert_valid_at(root, now_ts) {
        return Err(DpuAttestError::NoTrustedRoot);
    }
    top.verify_signature(Some(root.public_key()))
        .map_err(|e| DpuAttestError::ChainSignature {
            index: top_index,
            source: e,
        })?;

    // 4. Proof of possession: the device must have signed the server's nonce
    //    with the private key matching the leaf certificate.
    let leaf = &chain[0];
    let leaf_point = leaf.public_key().subject_public_key.data.as_ref();
    let verifying_key = VerifyingKey::from_sec1_bytes(leaf_point)
        .map_err(|e| DpuAttestError::BadDeviceKey(e.to_string()))?;
    let signature = Signature::from_der(&attestation.nonce_signature)
        .map_err(|e| DpuAttestError::MalformedSignature(e.to_string()))?;
    verifying_key
        .verify(&attestation.nonce, &signature)
        .map_err(|_| DpuAttestError::ProofOfPossession)?;

    // 5. Derive the identity from the verified leaf. The serial (CN) is for
    //    display; the machine_id is rooted in the full leaf certificate bytes,
    //    mirroring how the host path hashes the TPM EK certificate.
    let device_serial = leaf
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned)
        .ok_or(DpuAttestError::MissingSerial)?;

    let machine_id = machine_id_from_device_cert(&attestation.device_cert_chain[0]);

    Ok(VerifiedDpuDevice {
        machine_id,
        device_serial,
    })
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

/// Outcome of choosing a DPU's [`MachineId`] during discovery under the
/// backward-compatibility policy (issue NVIDIA/infra-controller#355 epic):
/// an already-known DPU keeps the identity it was first enrolled with, and only
/// a brand-new DPU adopts the hardware-rooted device-cert identity.
///
/// The three variants are distinguished (rather than collapsed to a bare
/// `MachineId`) so the discovery handler can log *why* an id was chosen, which
/// matters while the fleet is mid-migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpuIdentity {
    /// The DPU is already known under its legacy (serial-derived) id; keep it so
    /// existing machine records, certs, and JWTs stay valid across the upgrade.
    ExistingLegacy(MachineId),
    /// A previously-unseen DPU that presented a verified device attestation:
    /// adopt the hardware-rooted device-cert identity.
    NewDeviceRooted(MachineId),
    /// A previously-unseen DPU with no (or unverified) device attestation: fall
    /// back to the legacy serial-derived id, exactly as before this feature.
    NewLegacy(MachineId),
}

impl DpuIdentity {
    /// The [`MachineId`] to actually use for this DPU.
    pub fn machine_id(&self) -> MachineId {
        match self {
            DpuIdentity::ExistingLegacy(id)
            | DpuIdentity::NewDeviceRooted(id)
            | DpuIdentity::NewLegacy(id) => *id,
        }
    }
}

/// Chooses a DPU's [`MachineId`] under the backward-compatibility policy.
///
/// - `legacy_id` is the serial-derived id computed exactly as today
///   (`machine_id::from_hardware_info`).
/// - `verified_device` is `Some` only when device attestation was supplied and
///   passed [`verify_dpu_device_attestation`]; the handler gates this on the
///   feature flag, so this function need not know about it.
/// - `legacy_machine_known` is whether a machine already exists under
///   `legacy_id` (the caller looks this up in the DB).
///
/// Existing DPUs (`legacy_machine_known == true`) always keep `legacy_id`, so an
/// upgrade re-keys nothing. Only a previously-unseen DPU that proves a device
/// identity adopts the device-rooted id. Because the device-rooted id is
/// deterministic and a new DPU is never stored under its `legacy_id`, that DPU's
/// *subsequent* discoveries resolve here too and keep the same device-rooted id.
pub fn select_dpu_machine_id(
    legacy_id: MachineId,
    verified_device: Option<&VerifiedDpuDevice>,
    legacy_machine_known: bool,
) -> DpuIdentity {
    if legacy_machine_known {
        // Backward compatible: a DPU we have already enrolled keeps its original
        // key regardless of whether it now also presents a device attestation.
        return DpuIdentity::ExistingLegacy(legacy_id);
    }
    match verified_device {
        Some(device) => DpuIdentity::NewDeviceRooted(device.machine_id),
        None => DpuIdentity::NewLegacy(legacy_id),
    }
}

/// Whether `cert` is within its validity window at the given unix timestamp.
fn cert_valid_at(cert: &X509Certificate<'_>, now_ts: i64) -> bool {
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    now_ts >= not_before && now_ts <= not_after
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, date_time_ymd,
    };

    use super::*;

    /// A generated CA: its self-signed cert (DER) and the key pair to sign with.
    struct TestCa {
        cert_der: Vec<u8>,
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
            key,
            params,
        }
    }

    /// A device (leaf) certificate signed by `ca`, plus its P-256 signing key.
    struct TestDevice {
        cert_der: Vec<u8>,
        signing_key: SigningKey,
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
        let signing_key =
            SigningKey::from_pkcs8_pem(&key.serialize_pem()).expect("device signing key");
        TestDevice {
            cert_der: cert.der().to_vec(),
            signing_key,
        }
    }

    fn sign_nonce(device: &TestDevice, nonce: &[u8]) -> Vec<u8> {
        let sig: Signature = device.signing_key.sign(nonce);
        sig.to_der().as_bytes().to_vec()
    }

    fn now() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(date_time_ymd(2026, 6, 25).unix_timestamp(), 0).unwrap()
    }

    #[test]
    fn valid_attestation_yields_hardware_rooted_dpu_identity() {
        let ca = make_ca("NVIDIA BlueField Device CA");
        let device = make_device(&ca, "MT2147XYZ001", (2030, 1, 1));
        let nonce = b"server-issued-nonce-123".to_vec();
        let attestation = DpuDeviceAttestation {
            device_cert_chain: vec![device.cert_der.clone()],
            nonce_signature: sign_nonce(&device, &nonce),
            nonce,
        };

        let verified =
            verify_dpu_device_attestation(&attestation, &[ca.cert_der.clone()], now()).unwrap();

        assert_eq!(verified.device_serial, "MT2147XYZ001");
        assert_eq!(verified.machine_id.machine_type(), MachineType::Dpu);
        assert_eq!(verified.machine_id.source(), MachineIdSource::DpuDeviceCert);
        // Identity is deterministic in the device cert.
        assert_eq!(
            verified.machine_id,
            machine_id_from_device_cert(&device.cert_der)
        );
    }

    #[test]
    fn untrusted_root_is_rejected() {
        let real_ca = make_ca("NVIDIA BlueField Device CA");
        let rogue_ca = make_ca("Totally Legit Device CA");
        let device = make_device(&rogue_ca, "MT2147XYZ002", (2030, 1, 1));
        let nonce = b"nonce".to_vec();
        let attestation = DpuDeviceAttestation {
            device_cert_chain: vec![device.cert_der.clone()],
            nonce_signature: sign_nonce(&device, &nonce),
            nonce,
        };

        // Only the real CA is trusted; the device was signed by the rogue CA.
        let err =
            verify_dpu_device_attestation(&attestation, &[real_ca.cert_der], now()).unwrap_err();
        assert!(matches!(err, DpuAttestError::NoTrustedRoot), "got {err:?}");
    }

    #[test]
    fn wrong_key_signature_fails_proof_of_possession() {
        let ca = make_ca("NVIDIA BlueField Device CA");
        let device = make_device(&ca, "MT2147XYZ003", (2030, 1, 1));
        // Sign the nonce with an unrelated key, not the device key.
        let attacker = make_device(&ca, "attacker", (2030, 1, 1));
        let nonce = b"nonce".to_vec();
        let attestation = DpuDeviceAttestation {
            device_cert_chain: vec![device.cert_der],
            nonce_signature: sign_nonce(&attacker, &nonce),
            nonce,
        };

        let err = verify_dpu_device_attestation(&attestation, &[ca.cert_der], now()).unwrap_err();
        assert!(
            matches!(err, DpuAttestError::ProofOfPossession),
            "got {err:?}"
        );
    }

    #[test]
    fn tampered_nonce_fails_proof_of_possession() {
        let ca = make_ca("NVIDIA BlueField Device CA");
        let device = make_device(&ca, "MT2147XYZ004", (2030, 1, 1));
        let signature = sign_nonce(&device, b"the-real-nonce");
        let attestation = DpuDeviceAttestation {
            device_cert_chain: vec![device.cert_der],
            nonce: b"a-different-nonce".to_vec(),
            nonce_signature: signature,
        };

        let err = verify_dpu_device_attestation(&attestation, &[ca.cert_der], now()).unwrap_err();
        assert!(
            matches!(err, DpuAttestError::ProofOfPossession),
            "got {err:?}"
        );
    }

    #[test]
    fn expired_device_cert_is_rejected() {
        let ca = make_ca("NVIDIA BlueField Device CA");
        // not_after in the past relative to `now()`.
        let device = make_device(&ca, "MT2147XYZ005", (2025, 1, 1));
        let nonce = b"nonce".to_vec();
        let attestation = DpuDeviceAttestation {
            device_cert_chain: vec![device.cert_der.clone()],
            nonce_signature: sign_nonce(&device, &nonce),
            nonce,
        };

        let err = verify_dpu_device_attestation(&attestation, &[ca.cert_der], now()).unwrap_err();
        assert!(
            matches!(err, DpuAttestError::CertNotValid { index: 0, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn empty_chain_is_rejected() {
        let attestation = DpuDeviceAttestation {
            device_cert_chain: vec![],
            nonce: b"nonce".to_vec(),
            nonce_signature: vec![],
        };
        let err = verify_dpu_device_attestation(&attestation, &[], now()).unwrap_err();
        assert!(matches!(err, DpuAttestError::EmptyChain), "got {err:?}");
    }

    #[test]
    fn two_devices_get_distinct_identities() {
        let ca = make_ca("NVIDIA BlueField Device CA");
        let a = machine_id_from_device_cert(&make_device(&ca, "serial-A", (2030, 1, 1)).cert_der);
        let b = machine_id_from_device_cert(&make_device(&ca, "serial-B", (2030, 1, 1)).cert_der);
        assert_ne!(a, b);
    }

    // --- backward-compatibility identity-selection policy ---

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
        VerifiedDpuDevice {
            machine_id: machine_id_from_device_cert(&device.cert_der),
            device_serial: serial.to_string(),
        }
    }

    #[test]
    fn existing_dpu_keeps_legacy_id_even_with_attestation() {
        let device = verified("MT-existing");
        // legacy_machine_known = true: this DPU is already enrolled.
        let decision = select_dpu_machine_id(legacy_id(), Some(&device), true);
        assert_eq!(decision, DpuIdentity::ExistingLegacy(legacy_id()));
        assert_eq!(decision.machine_id(), legacy_id());
    }

    #[test]
    fn new_dpu_with_attestation_gets_device_rooted_id() {
        let device = verified("MT-brand-new");
        let decision = select_dpu_machine_id(legacy_id(), Some(&device), false);
        assert_eq!(decision, DpuIdentity::NewDeviceRooted(device.machine_id));
        assert_eq!(
            decision.machine_id().source(),
            MachineIdSource::DpuDeviceCert
        );
    }

    #[test]
    fn new_dpu_without_attestation_falls_back_to_legacy() {
        let decision = select_dpu_machine_id(legacy_id(), None, false);
        assert_eq!(decision, DpuIdentity::NewLegacy(legacy_id()));
        assert_eq!(decision.machine_id(), legacy_id());
    }

    #[test]
    fn rediscovery_of_new_dpu_is_stable() {
        // A new DPU enrolled under its device-rooted id is never stored under its
        // legacy id, so on re-discovery legacy_machine_known stays false and it
        // resolves to the same device-rooted id again.
        let device = verified("MT-stable");
        let first = select_dpu_machine_id(legacy_id(), Some(&device), false);
        let second = select_dpu_machine_id(legacy_id(), Some(&device), false);
        assert_eq!(first, second);
        assert_eq!(first.machine_id(), device.machine_id);
    }
}
