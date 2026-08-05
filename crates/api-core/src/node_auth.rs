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

//! Node-auth: validation of self-signed bearer JWTs from Scout / DPU-agent
//! (issue NVIDIA/infra-controller#355, simple variant).
//!
//! Nodes sign short-lived ES256 JWTs with the private key of their EXISTING
//! mTLS client certificate and carry the certificate chain in the token's
//! `x5c` header. [`NodeJwtValidator`] verifies, in order:
//!
//! 1. the `x5c` chain against the same root CAs the TLS listener trusts for
//!    client certificates (chain of trust, validity window, client-auth EKU);
//! 2. the JWT signature against the verified leaf's public key (algorithm
//!    pinned to ES256 — the only key type Vault PKI issues to machines);
//! 3. the registered claims: `exp` (with a bounded lifetime), `aud`;
//! 4. the SPIFFE constraints on the leaf and that the token's `sub` matches
//!    the leaf's SPIFFE URI SAN — identity always derives from the verified
//!    certificate, never from an attacker-controlled claim.
//!
//! The resulting SPIFFE URI is mapped by the authn middleware through the
//! SAME `SpiffeContext` as mTLS client certs, so a JWT and a cert for the
//! same machine yield an identical principal and reuse the existing RBAC
//! unchanged. There is no server-side key material and no issuance path:
//! "public key exchange" is the existing certificate PKI.

use std::sync::{Arc, RwLock};

use carbide_authn::middleware::BearerTokenAuthenticator;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::Deserialize;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::cfg::file::NodeAuthConfig;

#[derive(Debug, thiserror::Error)]
pub enum NodeAuthError {
    #[error("could not read root CA file {path}: {error}")]
    RootCaRead { path: String, error: std::io::Error },
    #[error("root CA file {path} contains no usable trust anchors")]
    NoTrustAnchors { path: String },
    #[error("could not build certificate verifier: {0}")]
    Verifier(String),
}

/// Why a presented bearer token was rejected. Only ever logged at debug —
/// rejection simply means the request proceeds without a bearer principal.
#[derive(Debug, thiserror::Error)]
enum RejectReason {
    #[error("malformed JWT: {0}")]
    Malformed(jsonwebtoken::errors::Error),
    #[error("unexpected algorithm {0:?}; only ES256 is accepted")]
    Algorithm(Algorithm),
    #[error("no x5c certificate chain in the JWT header")]
    NoChain,
    #[error("x5c chain did not verify against the trusted roots: {0}")]
    Chain(rustls::Error),
    #[error("leaf certificate is not an EC (P-256) certificate")]
    NotEcCertificate,
    #[error("signature/claims validation failed: {0}")]
    Claims(jsonwebtoken::errors::Error),
    #[error("token lifetime exceeds the allowed maximum")]
    Lifetime,
    #[error("leaf certificate fails SPIFFE validation: {0}")]
    Spiffe(String),
    #[error("token `sub` does not match the certificate's SPIFFE URI")]
    SubjectMismatch,
    #[error("system clock is before the UNIX epoch")]
    Clock,
}

/// Registered claims checked on node tokens. `iat` is required so the bounded
/// lifetime check (`exp - iat`) cannot be dodged by omitting it.
#[derive(Debug, Deserialize)]
struct NodeClaims {
    sub: String,
    iat: u64,
    exp: u64,
}

/// Validates node-auth JWTs against the client-certificate PKI.
pub struct NodeJwtValidator {
    /// Kept so the trust anchors can be re-read when the bundle rotates.
    root_cafile_path: String,
    /// Swapped in place by [`NodeJwtValidator::refresh_roots`]. The validator
    /// is shared (the authn layer holds one `Arc` for the process lifetime),
    /// so the refresh has to be interior, not a rebuild of the whole struct.
    /// Held behind a lock rather than an `ArcSwap` because `arc-swap` cannot
    /// store an unsized `dyn ClientCertVerifier`; the guard is released before
    /// the (comparatively expensive) chain verification runs.
    cert_verifier: RwLock<Arc<dyn ClientCertVerifier>>,
    validation: Validation,
    max_token_ttl_sec: u64,
}

impl NodeJwtValidator {
    /// Builds a validator trusting the given root CA bundle — the same file
    /// the TLS listener uses to verify mTLS client certificates.
    pub fn from_root_ca_file(
        root_cafile_path: &str,
        cfg: &NodeAuthConfig,
    ) -> Result<Self, NodeAuthError> {
        let cert_verifier = Self::build_verifier(root_cafile_path)?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[&cfg.audience]);
        validation.set_required_spec_claims(&["exp", "sub", "aud", "iat"]);

        Ok(Self {
            root_cafile_path: root_cafile_path.to_string(),
            cert_verifier: RwLock::new(cert_verifier),
            validation,
            max_token_ttl_sec: u64::from(cfg.max_token_ttl_sec),
        })
    }

    /// Re-reads the root CA bundle from disk and swaps in a verifier built
    /// from it.
    ///
    /// The TLS listener reloads the same file every five minutes to pick up
    /// cert-manager rotations; without this the validator would keep its
    /// startup snapshot and start rejecting tokens whose `x5c` chains to the
    /// new CA — which, with `mtls_enabled = false`, locks nodes out until the
    /// API restarts. On error the existing verifier is left in place: a
    /// half-written or briefly unreadable bundle should not disarm node auth.
    pub fn refresh_roots(&self) -> Result<(), NodeAuthError> {
        let cert_verifier = Self::build_verifier(&self.root_cafile_path)?;
        *self
            .cert_verifier
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = cert_verifier;
        Ok(())
    }

    fn build_verifier(
        root_cafile_path: &str,
    ) -> Result<Arc<dyn ClientCertVerifier>, NodeAuthError> {
        let pem = std::fs::read(root_cafile_path).map_err(|error| NodeAuthError::RootCaRead {
            path: root_cafile_path.to_string(),
            error,
        })?;
        let mut roots = RootCertStore::empty();
        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(&pem[..]))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| NodeAuthError::Verifier(format!("root CA parse error: {e}")))?;
        let (added, _ignored) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(NodeAuthError::NoTrustAnchors {
                path: root_cafile_path.to_string(),
            });
        }

        WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .allow_unknown_revocation_status()
        .build()
        .map_err(|e| NodeAuthError::Verifier(e.to_string()))
    }

    fn validate(&self, token: &str) -> Result<String, RejectReason> {
        let header = decode_header(token).map_err(RejectReason::Malformed)?;
        if header.alg != Algorithm::ES256 {
            return Err(RejectReason::Algorithm(header.alg));
        }

        // 1. The certificate chain must verify against the trusted roots.
        let chain = header
            .x5c_der()
            .map_err(RejectReason::Malformed)?
            .filter(|chain| !chain.is_empty())
            .ok_or(RejectReason::NoChain)?;
        let leaf = CertificateDer::from(chain[0].clone());
        let intermediates: Vec<CertificateDer> = chain[1..]
            .iter()
            .map(|der| CertificateDer::from(der.clone()))
            .collect();
        let cert_verifier = self
            .cert_verifier
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        cert_verifier
            .verify_client_cert(&leaf, &intermediates, UnixTime::now())
            .map_err(RejectReason::Chain)?;

        // 2. The token must be signed by the verified leaf's key.
        let (_, x509) =
            X509Certificate::from_der(leaf.as_ref()).map_err(|_| RejectReason::NotEcCertificate)?;
        let decoding_key = DecodingKey::from_ec_der(&x509.public_key().subject_public_key.data);
        let claims = decode::<NodeClaims>(token, &decoding_key, &self.validation)
            .map_err(RejectReason::Claims)?
            .claims;

        // 3. Bounded lifetime: the client controls `exp`, so cap how far in
        //    the future it may reach. `jsonwebtoken` already rejected expired
        //    tokens above.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| RejectReason::Clock)?
            .as_secs();
        if claims.exp.saturating_sub(claims.iat) > self.max_token_ttl_sec
            || claims.exp > now + self.max_token_ttl_sec
        {
            return Err(RejectReason::Lifetime);
        }

        // 4. Identity comes from the verified certificate, with `sub` only
        //    cross-checked against it.
        let spiffe_id = carbide_authn::validate_x509_certificate(leaf.as_ref())
            .map_err(|e| RejectReason::Spiffe(e.to_string()))?;
        let spiffe_uri = spiffe_id.to_string();
        if claims.sub != spiffe_uri {
            return Err(RejectReason::SubjectMismatch);
        }
        Ok(spiffe_uri)
    }
}

impl BearerTokenAuthenticator for NodeJwtValidator {
    fn spiffe_id_from_bearer(&self, token: &str) -> Option<String> {
        match self.validate(token) {
            Ok(spiffe_uri) => Some(spiffe_uri),
            Err(reason) => {
                tracing::debug!(target: "node_auth", %reason, "node-auth: rejected bearer token");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rpc::node_jwt::NodeJwtMinter;

    use super::*;

    const TRUST_DOMAIN: &str = "forge.local";
    const MACHINE_PATH: &str = "/forge-system/machine/fm100xtest";

    struct TestPki {
        ca_pem: String,
        cert_pem: String,
        key_pem: String,
    }

    /// A CA plus a leaf it issued carrying the machine SPIFFE URI SAN —
    /// stand-ins for the Vault PKI root and a node's client certificate.
    fn test_pki(spiffe_path: &str) -> TestPki {
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test root");
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.clone().self_signed(&ca_key).expect("ca cert");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let mut leaf_params = rcgen::CertificateParams::default();
        leaf_params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(format!("spiffe://{TRUST_DOMAIN}{spiffe_path}"))
                .expect("uri"),
        )];
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert");

        TestPki {
            ca_pem: ca_cert.pem(),
            cert_pem: leaf_cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        }
    }

    fn write_temp(dir: &tempfile::TempDir, name: &str, contents: &str) -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("write");
        path.to_string_lossy().into_owned()
    }

    fn validator_for(dir: &tempfile::TempDir, ca_pem: &str) -> NodeJwtValidator {
        let ca_path = write_temp(dir, "ca.pem", ca_pem);
        NodeJwtValidator::from_root_ca_file(&ca_path, &NodeAuthConfig::default())
            .expect("validator builds")
    }

    fn mint_with(dir: &tempfile::TempDir, pki: &TestPki) -> String {
        let minter = NodeJwtMinter::new(
            write_temp(dir, "cert.pem", &pki.cert_pem),
            write_temp(dir, "key.pem", &pki.key_pem),
        );
        minter.current().expect("token minted")
    }

    /// `[node_auth] audience` is configurable, so a site that changes it must
    /// still work end to end: the minter has to stamp the configured value and
    /// the validator has to accept it (and nothing else).
    #[test]
    fn a_configured_audience_round_trips_and_excludes_the_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pki = test_pki(MACHINE_PATH);
        let ca_path = write_temp(&dir, "ca.pem", &pki.ca_pem);
        let cfg = NodeAuthConfig {
            audience: "carbide-api-eu".to_string(),
            ..NodeAuthConfig::default()
        };
        let validator =
            NodeJwtValidator::from_root_ca_file(&ca_path, &cfg).expect("validator builds");

        let cert_path = write_temp(&dir, "cert.pem", &pki.cert_pem);
        let key_path = write_temp(&dir, "key.pem", &pki.key_pem);

        let matching = NodeJwtMinter::with_audience(
            cert_path.clone(),
            key_path.clone(),
            "carbide-api-eu".to_string(),
        )
        .current()
        .expect("token minted");
        assert_eq!(
            validator.spiffe_id_from_bearer(&matching).as_deref(),
            Some(format!("spiffe://{TRUST_DOMAIN}{MACHINE_PATH}").as_str()),
            "a token minted for the configured audience must be accepted"
        );

        let default_aud = NodeJwtMinter::new(cert_path, key_path)
            .current()
            .expect("token minted");
        assert_eq!(
            validator.spiffe_id_from_bearer(&default_aud),
            None,
            "the default audience must not be accepted once one is configured"
        );
    }

    /// A rotated client-CA bundle has to be picked up without a restart: the
    /// TLS listener re-reads the same file every five minutes, and tokens
    /// chaining to the new CA must start verifying once it does.
    #[test]
    fn rotated_root_ca_is_honored_after_refresh() {
        let dir = tempfile::tempdir().expect("tempdir");
        let old_pki = test_pki(MACHINE_PATH);
        let ca_path = write_temp(&dir, "ca.pem", &old_pki.ca_pem);
        let validator = NodeJwtValidator::from_root_ca_file(&ca_path, &NodeAuthConfig::default())
            .expect("validator builds");

        // A second CA, as though cert-manager had rotated the bundle.
        let new_pki = test_pki(MACHINE_PATH);
        let new_dir = tempfile::tempdir().expect("tempdir");
        let token = mint_with(&new_dir, &new_pki);
        assert_eq!(
            validator.spiffe_id_from_bearer(&token),
            None,
            "a token from the not-yet-trusted CA must be rejected"
        );

        std::fs::write(&ca_path, &new_pki.ca_pem).expect("rotate the bundle on disk");
        validator.refresh_roots().expect("roots reload");

        assert_eq!(
            validator.spiffe_id_from_bearer(&token).as_deref(),
            Some(format!("spiffe://{TRUST_DOMAIN}{MACHINE_PATH}").as_str()),
            "after the refresh the rotated CA must be trusted"
        );
    }

    /// A bundle that cannot be read or parsed must not disarm bearer auth.
    #[test]
    fn a_broken_bundle_leaves_the_previous_roots_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pki = test_pki(MACHINE_PATH);
        let ca_path = write_temp(&dir, "ca.pem", &pki.ca_pem);
        let validator = NodeJwtValidator::from_root_ca_file(&ca_path, &NodeAuthConfig::default())
            .expect("validator builds");
        let token = mint_with(&dir, &pki);

        std::fs::write(&ca_path, "not a certificate").expect("truncate the bundle");
        validator
            .refresh_roots()
            .expect_err("a bundle with no trust anchors must not be accepted");

        assert_eq!(
            validator.spiffe_id_from_bearer(&token).as_deref(),
            Some(format!("spiffe://{TRUST_DOMAIN}{MACHINE_PATH}").as_str()),
            "the previous roots must still verify tokens"
        );
    }

    #[test]
    fn client_minted_token_round_trips_to_the_cert_spiffe_uri() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pki = test_pki(MACHINE_PATH);
        let validator = validator_for(&dir, &pki.ca_pem);

        let token = mint_with(&dir, &pki);
        assert_eq!(
            validator.spiffe_id_from_bearer(&token).as_deref(),
            Some(format!("spiffe://{TRUST_DOMAIN}{MACHINE_PATH}").as_str())
        );
    }

    #[test]
    fn token_from_an_untrusted_ca_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pki = test_pki(MACHINE_PATH);
        let other_pki = test_pki(MACHINE_PATH);
        // Validator trusts a DIFFERENT root than the one that issued the cert.
        let validator = validator_for(&dir, &other_pki.ca_pem);

        let token = mint_with(&dir, &pki);
        assert!(validator.spiffe_id_from_bearer(&token).is_none());
    }

    #[test]
    fn garbage_and_missing_chain_tokens_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pki = test_pki(MACHINE_PATH);
        let validator = validator_for(&dir, &pki.ca_pem);

        assert!(validator.spiffe_id_from_bearer("not.a.jwt").is_none());

        // Structurally valid ES256 JWT without an x5c header.
        let key = rcgen::KeyPair::generate().expect("key");
        let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(key.serialize_pem().as_bytes())
            .expect("encoding key");
        let claims = serde_json::json!({
            "sub": format!("spiffe://{TRUST_DOMAIN}{MACHINE_PATH}"),
            "aud": "nico-api", "iat": 0u64, "exp": u64::MAX / 2,
        });
        let no_chain = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::ES256),
            &claims,
            &encoding_key,
        )
        .expect("token");
        assert!(validator.spiffe_id_from_bearer(&no_chain).is_none());
    }

    #[test]
    fn overlong_lifetime_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pki = test_pki(MACHINE_PATH);
        let ca_path = write_temp(&dir, "ca.pem", &pki.ca_pem);
        // A validator whose lifetime cap is below what the client mints.
        let strict = NodeJwtValidator::from_root_ca_file(
            &ca_path,
            &NodeAuthConfig {
                max_token_ttl_sec: 1,
                ..NodeAuthConfig::default()
            },
        )
        .expect("validator builds");

        let token = mint_with(&dir, &pki);
        assert!(strict.spiffe_id_from_bearer(&token).is_none());
    }
}
