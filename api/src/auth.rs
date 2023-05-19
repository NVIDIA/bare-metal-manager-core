/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

mod casbin_engine;

// Principal: something like an account, service, address, or other
// identity that we can treat as the "subject" in a subject-action-object
// construction.
#[derive(Clone, Debug)]
pub enum Principal {
    CertificateIdentity(String),
    // JWT(Claims),
    // ClientAddress(IPAddr),

    // Anonymous is more like the absence of any principal, but it's convenient
    // to be able to represent it explicitly.
    Anonymous,
}

impl Principal {
    pub fn as_identifier(&self) -> String {
        match self {
            Principal::CertificateIdentity(identity) => format!("certificate-identity/{identity}"),
            Principal::Anonymous => "anonymous".into(),
        }
    }

    // Note: no certificate verification is performed here!
    pub fn try_from_client_certificate(
        certificate: &tokio_rustls::rustls::Certificate,
    ) -> Result<Principal, SpiffeError> {
        let der_bytes = &certificate.0;
        let spiffe_id = forge_spiffe::validate_x509_certificate(der_bytes.as_slice())?;
        // FIXME: we shouldn't be making a new one of these every time, better
        // to pass one in from somewhere so we can reuse it
        let context = forge_spiffe::ForgeSpiffeContext::new(
            spiffe::spiffe_id::TrustDomain::new("forge.local").unwrap(),
            String::from("/ns/forge-system/sa/"),
        );
        let service_id = context.extract_service_identifier(&spiffe_id)?;
        Ok(Principal::CertificateIdentity(service_id))
    }
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum SpiffeError {
    #[error("SPIFFE validation error: {0}")]
    Validation(#[from] forge_spiffe::SpiffeValidationError),

    #[error("Unrecognized SPIFFE ID: {0}")]
    Recognition(#[from] forge_spiffe::ForgeSpiffeContextError),
}

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Create,
    Read,
    Update,
    Delete,
}

impl Action {
    pub fn as_str(&self) -> &str {
        match self {
            Action::Create => "create",
            Action::Read => "read",
            Action::Update => "update",
            Action::Delete => "delete",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Object {
    Instance,
}

impl Object {
    pub fn as_str(&self) -> &str {
        match self {
            Object::Instance => "instance",
        }
    }
}

pub trait PrincipalExtractor {
    // Extract all useful principals from a request.
    fn principals(&self) -> Vec<Principal>;
}

impl<T> PrincipalExtractor for tonic::Request<T> {
    fn principals(&self) -> Vec<Principal> {
        let _certs = self.peer_certs();
        // TODO: extract 1 or more Principal::CertIdentity from certs
        Vec::default()
    }
}

// An Authorization is sort of like a ticket that says we're allowed to do the
// thing we're trying to do, and specifically which Principal was permitted to
// do it.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Authorization {
    principal: Principal,
    action: Action,
    object: Object,
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum AuthorizationError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

impl From<AuthorizationError> for tonic::Status {
    fn from(e: AuthorizationError) -> Self {
        tracing::info!("Request was denied: {e}");
        tonic::Status::permission_denied("Not authorized")
    }
}

// A PolicyEngine is anything that can enforce whether a request is allowed.
pub trait PolicyEngine {
    fn authorize(
        &self,
        principals: &[Principal],
        action: Action,
        object: Object,
    ) -> Result<Authorization, AuthorizationError>;
}

pub type PolicyEngineObject = (dyn PolicyEngine + Send + Sync);

#[derive(Clone)]
pub struct Authorizer {
    policy_engine: Arc<PolicyEngineObject>,
}

impl Authorizer {
    pub fn new(policy_engine: Arc<PolicyEngineObject>) -> Self {
        Self { policy_engine }
    }

    pub fn authorize<R: PrincipalExtractor>(
        &self,
        req: &R,
        action: Action,
        object: Object,
    ) -> Result<Authorization, AuthorizationError> {
        let principals = req.principals();
        let engine = self.policy_engine.clone();
        tracing::debug!(
            "Checking authorization with (object={object:?}, action={action:?}, \
            principals={principals:?})"
        );
        engine.authorize(&principals, action, object)
    }

    // TODO: config this out in release mode?
    fn enable_permissive(&mut self) {
        let inner_engine = self.policy_engine.clone();
        let permissive_engine: Arc<PolicyEngineObject> =
            Arc::new(PermissiveWrapper::new(inner_engine));
        self.policy_engine = permissive_engine;
    }

    pub async fn build_casbin(
        policy_path: &Path,
        permissive_mode: bool,
    ) -> Result<Self, AuthorizerError> {
        use casbin_engine::{CasbinEngine, ModelType};
        let engine = CasbinEngine::new(ModelType::BasicAcl, policy_path)
            .await
            .map_err(|e| AuthorizerError::InitializationError(e.to_string()))?;
        let engine_object: Arc<PolicyEngineObject> = Arc::new(engine);
        let mut authorizer = Self::new(engine_object);
        // TODO: config this out in release mode?
        if permissive_mode {
            authorizer.enable_permissive();
        }
        Ok(authorizer)
    }
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum AuthorizerError {
    #[error("Initialization error: {0}")]
    InitializationError(String),
}

struct PermissiveWrapper {
    inner: Arc<PolicyEngineObject>,
}

impl PermissiveWrapper {
    fn new(inner: Arc<PolicyEngineObject>) -> Self {
        Self { inner }
    }
}

impl PolicyEngine for PermissiveWrapper {
    fn authorize(
        &self,
        principals: &[Principal],
        action: Action,
        object: Object,
    ) -> Result<Authorization, AuthorizationError> {
        let result = self.inner.authorize(principals, action, object);
        result.or_else(|e| {
            tracing::warn!(
                "The policy engine denied this request, but \
                --auth-permissive-mode overrides it. The policy engine error \
                message follows:"
            );
            tracing::warn!("{e}");

            // FIXME: Strictly speaking, it's not true that Anonymous is
            // authorized to do this. Maybe define a different principal
            // to use here? "Development"?
            let authorization = Authorization {
                principal: Principal::Anonymous,
                action,
                object,
            };
            Ok(authorization)
        })
    }
}

pub struct NoopEngine {}

impl PolicyEngine for NoopEngine {
    fn authorize(
        &self,
        _principals: &[Principal],
        action: Action,
        object: Object,
    ) -> Result<Authorization, AuthorizationError> {
        // FIXME: same problem again as the PermissiveWrapper implementation.
        // Figure out a name for this use case, and use that instead.
        Ok(Authorization {
            principal: Principal::Anonymous,
            action,
            object,
        })
    }
}

pub mod forge_spiffe {
    use spiffe::spiffe_id::SpiffeId;
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

    // Validate an X.509 DER certificate against the SPIFFE requirements, and
    // return a SPIFFE ID.
    //
    // https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md#5-validation
    //
    // Note that this only implements the SPIFFE-specific validation steps. We
    // assume the X.509 certificate has already been validated to a trusted root.
    pub fn validate_x509_certificate(
        der_certificate: &[u8],
    ) -> Result<SpiffeId, SpiffeValidationError> {
        use SpiffeValidationError::ValidationError;

        let (_remainder, x509_cert) = X509Certificate::from_der(der_certificate)
            .map_err(|e| ValidationError(format!("X.509 parse error: {e}")))?;

        // Verify that this is a leaf certificate (i.e. it is not a CA certificate)
        let is_ca_cert = match x509_cert.basic_constraints() {
            Ok(None) => Ok(false),
            Ok(Some(basic_constraints)) => Ok(basic_constraints.value.ca),
            Err(_) => Err(ValidationError(
                "More than one X.509 Basic Constraints extension was found".into(),
            )),
        }?;
        if is_ca_cert {
            return Err(ValidationError(
                "The X.509 certificate must be a leaf certificate (it must \
                not have CA=true in the Basic Constraints extension)"
                    .into(),
            ));
        };

        // Verify that keyCertSign and cRLSign are not set in the Key Usage
        // extension (if any).
        if let Some(key_usage) = x509_cert.key_usage().map_err(|_e| {
            ValidationError("More than one X.509 Key Usage extension was found".into())
        })? {
            if key_usage.value.key_cert_sign() {
                return Err(ValidationError(
                    "keyCertSign must not be set in the X.509 Key Usage extension".into(),
                ));
            }
            if key_usage.value.crl_sign() {
                return Err(ValidationError(
                    "cRLSign must not be set in the X.509 Key Usage extension".into(),
                ));
            }
        };

        let subj_alt_name = x509_cert.subject_alternative_name().map_err(|_e| {
            ValidationError("Multiple X.509 Subject Alternative Name extensions found".into())
        })?;
        let subj_alt_name = subj_alt_name.ok_or_else(|| {
            ValidationError("No X.509 Subject Alternative Name extension found".into())
        })?;

        // Verify there is exactly one SAN URI
        let uris = subj_alt_name
            .value
            .general_names
            .iter()
            .cloned()
            .filter_map(|n| match n {
                GeneralName::URI(uri) => Some(uri),
                _ => None,
            })
            .collect::<Vec<_>>();
        let uri = match (uris.len(), uris.first()) {
            (1, Some(uri)) => Ok(uri),
            (n, _) => Err(ValidationError(format!(
                "The X.509 Subject Alternative Name extension must contain exactly \
                1 URI (found {n})"
            ))),
        }?;

        let spiffe_id = SpiffeId::new(uri)
            .map_err(|e| ValidationError(format!("Couldn't parse SPIFFE ID: {e}")))?;
        Ok(spiffe_id)
    }

    #[derive(thiserror::Error, Debug, Clone)]
    pub enum SpiffeValidationError {
        #[error("SPIFFE validation error: {0}")]
        ValidationError(String),
    }

    pub struct ForgeSpiffeContext {
        trust_domain: spiffe::spiffe_id::TrustDomain,
        service_base_path: String,
    }

    impl ForgeSpiffeContext {
        pub fn new(
            trust_domain: spiffe::spiffe_id::TrustDomain,
            service_base_path: String,
        ) -> Self {
            ForgeSpiffeContext {
                trust_domain,
                service_base_path,
            }
        }

        pub fn extract_service_identifier(
            &self,
            spiffe_id: &SpiffeId,
        ) -> Result<String, ForgeSpiffeContextError> {
            use ForgeSpiffeContextError::*;

            if !spiffe_id.is_member_of(&self.trust_domain) {
                let id_trust_domain = spiffe_id.trust_domain().id_string();
                let expected_trust_domain = self.trust_domain.id_string();
                return Err(ContextError(format!(
                    "Found a trust domain {id_trust_domain} which is not a \
                    member of the configured trust domain \
                    {expected_trust_domain}"
                )));
            };
            let spiffe_id_path = spiffe_id.path();
            let service_base_path = self.service_base_path.as_str();
            let path_remainder = spiffe_id_path.strip_prefix(service_base_path);
            match path_remainder {
                Some(identifier) if !identifier.is_empty() => Ok(identifier.into()),
                Some(_empty) => Err(ContextError(
                    "The service identifier was empty after removing the base prefix".into(),
                )),
                None => Err(ContextError(format!(
                    "The SPIFFE ID path \"{spiffe_id_path}\" does not begin \
                        with the expected prefix \"{service_base_path}\""
                ))),
            }
        }
    }

    #[derive(thiserror::Error, Debug, Clone)]
    pub enum ForgeSpiffeContextError {
        #[error("{0}")]
        ContextError(String),
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CarbideAuthClaims {
    aud: String,
    iss: String,
    sub: String,
    privilege: Option<String>,
    vpc: Option<String>,
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum AuthError {
    #[error("JWT decode error {0}")]
    JWTDecodeError(jsonwebtoken::errors::Error),

    #[error("JWT-related placeholder error")]
    JWTFixmeError,

    #[error("Unknown signer key and algorithm pair")]
    UnrecognizedSigSpec,
}

pub mod jwt {
    use std::collections::HashMap;

    use jsonwebtoken::{decode, decode_header, Validation};
    pub use jsonwebtoken::{Algorithm, DecodingKey};

    use super::{AuthError, CarbideAuthClaims};

    #[derive(Clone)]
    pub struct TokenValidator {
        validators: HashMap<TokenSigSpec, DecoderSpec>,
    }

    impl TokenValidator {
        pub fn new() -> Self {
            let validators = HashMap::new();
            Self { validators }
        }

        pub fn _add_key(
            &mut self,
            algorithm: Algorithm,
            key_spec: KeySpec,
            decoding_key: DecodingKey,
        ) {
            let sig_spec = TokenSigSpec {
                algorithm,
                key_spec,
            };
            let verification_spec = DecoderSpec {
                decoding_key,
                validation: Validation::new(algorithm),
            };
            _ = self.validators.insert(sig_spec, verification_spec);
        }

        pub fn validate(&self, token: &str) -> Result<CarbideAuthClaims, AuthError> {
            let header = decode_header(token).map_err(AuthError::JWTDecodeError)?;
            let algorithm = header.alg;
            let key_id = header.kid.ok_or(AuthError::JWTFixmeError)?;
            let token_sig_spec = TokenSigSpec {
                algorithm,
                key_spec: KeySpec::KeyID(key_id),
            };
            let decoder_spec = self
                .validators
                .get(&token_sig_spec)
                .ok_or(AuthError::UnrecognizedSigSpec)?;

            let decoded = decode::<CarbideAuthClaims>(
                token,
                &decoder_spec.decoding_key,
                &decoder_spec.validation,
            )
            .map_err(AuthError::JWTDecodeError)?;

            // big time FIXME: We aren't validating the iss/sub/aud fields,
            // since at the time of this writing there isn't anything specified
            // or agreed upon for what they should be. -db

            Ok(decoded.claims)
        }
    }

    impl Default for TokenValidator {
        fn default() -> Self {
            TokenValidator::new()
        }
    }

    #[derive(Clone, Eq, PartialEq, Hash)]
    pub struct TokenSigSpec {
        algorithm: Algorithm,
        key_spec: KeySpec,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Hash)]
    pub enum KeySpec {
        KeyID(String),
    }

    #[derive(Clone)]
    pub struct DecoderSpec {
        decoding_key: DecodingKey,
        validation: Validation,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_initialize() {
            let v = TokenValidator::new();
            assert!(matches!(v, TokenValidator { .. }));
        }

        #[test]
        fn test_parse_invalid() {
            let v = TokenValidator::new();
            let result = v.validate("this is not even a JWT");
            assert!(matches!(result, Err(AuthError::JWTDecodeError(_))));
            let result = v.validate("bleep.bloop.blup");
            assert!(matches!(result, Err(AuthError::JWTDecodeError(_))));
        }

        #[test]
        fn test_decode() {
            // base64 encoding of "this is not a very good secret"
            let b64_key = "dGhpcyBpcyBub3QgYSB2ZXJ5IGdvb2Qgc2VjcmV0";
            let decode_key = DecodingKey::from_base64_secret(b64_key).unwrap();

            let mut v = TokenValidator::new();
            v._add_key(
                Algorithm::HS256,
                KeySpec::KeyID("testing-kid".into()),
                decode_key,
            );

            // This JWT was made with the following Python (using PyJWT):
            // jwt.encode(
            //     dict(
            //         iss='test issuer',
            //         aud='test audience',
            //         sub='test subject',
            //         exp=int((datetime.datetime.utcnow() + datetime.timedelta(days = 365 * 10)).timestamp()),
            //     ),
            //     'this is not a very good secret',
            //     headers=dict(kid='testing-kid')
            // )
            let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Rpbmcta2lkIn0.eyJpc3MiOiJ0ZXN0IGlzc3VlciIsImF1ZCI6InRlc3QgYXVkaWVuY2UiLCJzdWIiOiJ0ZXN0IHN1YmplY3QiLCJleHAiOjE5NzA3NjE1NDN9.wyGCEyEdWO47p60jgX_ITp27UPO8WEVC1LtlPNnNDw8";

            let claims = v.validate(jwt).unwrap();
            assert!(matches!(claims, CarbideAuthClaims { .. }));
            assert_eq!(
                claims,
                CarbideAuthClaims {
                    iss: "test issuer".into(),
                    aud: "test audience".into(),
                    sub: "test subject".into(),
                    privilege: None,
                    vpc: None,
                }
            );
        }
    }
}
