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
use crate::{
    CarbideError,
    cfg::file::{AllowedCertCriteria, CertComponent},
};
use asn1_rs::PrintableString;
use middleware::CertDescriptionMiddleware;
use oid_registry::Oid;
use rustls_pki_types::CertificateDer;
use std::path::Path;
use std::sync::Arc;
use x509_parser::prelude::{FromDer, X509Certificate, X509Name};

mod casbin_engine;
pub mod internal_rbac_rules;
pub mod middleware;
pub mod spiffe_id; // public for doctests

// Various properties of a user gleaned from the presented certificate
#[derive(Clone, Debug, PartialEq)]
pub struct ExternalUserInfo {
    // Organization of the user, currently unused except for reporting
    pub org: Option<String>,
    // Group of the user, which determines their permissions
    pub group: String,
    // Name of the user, used as identifier in applying redfish changes.
    pub user: Option<String>,
}

impl ExternalUserInfo {
    fn new(org: Option<String>, group: String, user: Option<String>) -> Self {
        Self { org, group, user }
    }
}

// Principal: something like an account, service, address, or other
// identity that we can treat as the "subject" in a subject-action-object
// construction.
#[derive(Clone, Debug, PartialEq)]
pub enum Principal {
    // A SPIFFE ID after the trust domain and base path have been removed.
    SpiffeServiceIdentifier(String),
    SpiffeMachineIdentifier(String),

    // Certficate based authentication from outside of the cluster
    ExternalUser(ExternalUserInfo),

    // Any certificate that was trusted by the TLS acceptor. This is a superset
    // of what gets mapped into the SPIFFE or nvinit principals, so any request
    // with one of those will also have one of these (but not necessarily the
    // other way around).
    TrustedCertificate,

    // JWT(Claims),
    // ClientAddress(IPAddr),

    // Anonymous is more like the absence of any principal, but it's convenient
    // to be able to represent it explicitly.
    Anonymous,
}

impl Principal {
    pub fn as_identifier(&self) -> String {
        match self {
            Principal::SpiffeServiceIdentifier(identifier) => {
                format!("spiffe-service-id/{identifier}")
            }
            Principal::SpiffeMachineIdentifier(_identifier) => {
                // We don't care so much about the specific machine id, but we
                // do want to grant permissions to machines as a class.
                "spiffe-machine-id".into()
            }
            Principal::ExternalUser(info) => {
                format!("external-role/{}", info.group)
            }
            Principal::TrustedCertificate => "trusted-certificate".into(),
            Principal::Anonymous => "anonymous".into(),
        }
    }

    // Note: no certificate verification is performed here!
    pub fn try_from_client_certificate(
        certificate: &CertificateDer,
        auth_context: &CertDescriptionMiddleware,
    ) -> Result<Principal, SpiffeError> {
        match forge_spiffe::validate_x509_certificate(certificate.as_ref()) {
            Ok(spiffe_id) => {
                let service_id = auth_context
                    .spiffe_context
                    .extract_service_identifier(&spiffe_id)?;
                Ok(match service_id {
                    forge_spiffe::SpiffeIdClass::Service(service_id) => {
                        Principal::SpiffeServiceIdentifier(service_id)
                    }
                    forge_spiffe::SpiffeIdClass::Machine(machine_id) => {
                        Principal::SpiffeMachineIdentifier(machine_id)
                    }
                })
            }
            Err(e) => {
                // nvinit certs do not include a SPIFFE ID, check if we might be one of them
                if let Some(external_cert) = try_external_cert(certificate.as_ref(), auth_context) {
                    return Ok(external_cert);
                }
                Err(SpiffeError::Validation(e))
            }
        }
    }

    pub fn is_proper_subset_of(&self, other: &Self) -> bool {
        match other {
            Principal::SpiffeServiceIdentifier(id_other) => match self {
                Principal::SpiffeServiceIdentifier(id_self) => id_self == id_other,
                _ => false,
            },
            Principal::SpiffeMachineIdentifier(_) => {
                matches!(self, Principal::SpiffeMachineIdentifier(_))
            }
            Principal::ExternalUser(_) => {
                matches!(self, Principal::ExternalUser(_))
            }
            Principal::TrustedCertificate => {
                matches!(self, Principal::TrustedCertificate)
            }
            Principal::Anonymous => true,
        }
    }

    pub fn from_web_cookie(user: String, group: String) -> Self {
        Principal::ExternalUser(ExternalUserInfo::new(None, group, Some(user)))
    }
}

// try_external_cert will return a Pricipal::ExternalUser if this looks like some external cert
fn try_external_cert(
    der_certificate: &[u8],
    auth_context: &CertDescriptionMiddleware,
) -> Option<Principal> {
    if let Ok((_remainder, x509_cert)) = X509Certificate::from_der(der_certificate) {
        // Looks through the issuer releative distinguished names for a CN matching what we expect for nvinit certs.
        // Other options may be available in the future, but just this for now.
        for rdn in x509_cert.issuer().iter() {
            if let Some(value) = rdn
                .iter()
                .filter(|attribute| attribute.attr_type() == &oid_registry::OID_X509_COMMON_NAME) // CN=  see https://www.rfc-editor.org/rfc/rfc4519.html
                .filter_map(|attribute| attribute.attr_value().as_printablestring().ok())
                .find(|value| {
                    value.string().as_str() == "pki-k8s-usercert-ca.ngc.nvidia.com"
                        || value.string().as_str() == "NVIDIA Forge Root Certificate Authority 2022"
                })
            {
                if value.string().as_str() == "pki-k8s-usercert-ca.ngc.nvidia.com" {
                    // This CN is what we expect from nvinit certs
                    return Some(Principal::ExternalUser(nvinit_cert_values(
                        x509_cert.subject(),
                    )));
                }
            }
        }

        if let Some(allowed_certs) = &auth_context.extra_allowed_certs {
            return site_allowed_cert(&x509_cert, allowed_certs);
        }
    }
    None
}

// nvinit_cert_values parses the information from an nvinit cert
fn nvinit_cert_values(subject: &X509Name) -> ExternalUserInfo {
    let mut org = None;
    let mut group = "".to_string();
    let mut user = None;

    for rdn in subject.iter() {
        for attribute in rdn.iter() {
            match attribute.attr_type() {
                x if x == &oid_registry::OID_X509_ORGANIZATION_NAME => {
                    if let Ok(value) = attribute.attr_value().as_printablestring() {
                        org = Some(value.string());
                    }
                }
                x if x == &oid_registry::OID_X509_ORGANIZATIONAL_UNIT => {
                    if let Ok(value) = attribute.attr_value().as_printablestring() {
                        group = value.string();
                    }
                }
                x if x == &oid_registry::OID_X509_COMMON_NAME => {
                    if let Ok(value) = attribute.attr_value().as_printablestring() {
                        user = Some(value.string());
                    }
                }
                _ => {}
            };
        }
    }

    ExternalUserInfo::new(org, group, user)
}

// Finds the CertComponent for the given ASN1 OID, given that this is coming from the issuer.
fn cert_component_from_oid_issuer(oid: Oid) -> Option<CertComponent> {
    // Lack of implementation in oid_registry means we can't use match here
    if oid == oid_registry::OID_X509_ORGANIZATION_NAME {
        Some(CertComponent::IssuerO)
    } else if oid == oid_registry::OID_X509_ORGANIZATIONAL_UNIT {
        Some(CertComponent::IssuerOU)
    } else if oid == oid_registry::OID_X509_COMMON_NAME {
        Some(CertComponent::IssuerCN)
    } else {
        None
    }
}

// Finds the CertComponent for the given ASN1 OID, given that this is coming from the subject.
fn cert_component_from_oid_subject(oid: Oid) -> Option<CertComponent> {
    // Lack of implementation in oid_registry means we can't use match here
    if oid == oid_registry::OID_X509_ORGANIZATION_NAME {
        Some(CertComponent::SubjectO)
    } else if oid == oid_registry::OID_X509_ORGANIZATIONAL_UNIT {
        Some(CertComponent::SubjectOU)
    } else if oid == oid_registry::OID_X509_COMMON_NAME {
        Some(CertComponent::SubjectCN)
    } else {
        None
    }
}

// Checks if the given non-nvinit cert is an acceptable forge-admin-cli user based on per site criteria
pub fn site_allowed_cert(
    cert: &X509Certificate,
    criteria: &AllowedCertCriteria,
) -> Option<Principal> {
    for rdn in cert.issuer().iter() {
        if rdn.iter().any(|attribute| {
            if let Some(component) = cert_component_from_oid_issuer(attribute.attr_type().clone()) {
                if let Some(required_value) = criteria.required_equals.get(&component) {
                    attribute
                        .attr_value()
                        .as_printablestring()
                        .ok()
                        .unwrap_or(PrintableString::new(""))
                        .string()
                        != required_value.clone()
                } else {
                    false
                }
            } else {
                false
            }
        }) {
            // Something didn't match
            return None;
        }
    }
    let mut group = "".to_string();
    let mut username_from_cert = None;
    for rdn in cert.subject().iter() {
        if rdn.iter().any(|attribute| {
            if let Some(component) = cert_component_from_oid_subject(attribute.attr_type().clone())
            {
                if criteria.group_from == Some(component.clone()) {
                    group = attribute
                        .attr_value()
                        .as_printablestring()
                        .ok()
                        .unwrap_or(PrintableString::new(""))
                        .string();
                }
                if criteria.username_from == Some(component.clone()) {
                    username_from_cert = Some(
                        attribute
                            .attr_value()
                            .as_printablestring()
                            .ok()
                            .unwrap_or(PrintableString::new(""))
                            .string(),
                    );
                }
                if let Some(required_value) = criteria.required_equals.get(&component) {
                    attribute
                        .attr_value()
                        .as_printablestring()
                        .ok()
                        .unwrap_or(PrintableString::new(""))
                        .string()
                        != required_value.clone()
                } else {
                    false
                }
            } else {
                false
            }
        }) {
            // Something didn't match
            return None;
        }
    }
    if criteria.username_from.is_some() && username_from_cert.is_some() {
        Some(Principal::ExternalUser(ExternalUserInfo {
            org: None,
            group,
            user: username_from_cert,
        }))
    } else if let Some(username) = &criteria.username {
        Some(Principal::ExternalUser(ExternalUserInfo {
            org: None,
            group,
            user: Some(username.clone()),
        }))
    } else {
        Some(Principal::ExternalUser(ExternalUserInfo {
            org: None,
            group,
            user: None,
        }))
    }
}

// This is added to the extensions of a request. The authentication (authn)
// middleware populates the `principals` field, and the authorization (authz)
// middleware sets the `authorization` field.
#[derive(Clone)]
pub struct AuthContext {
    pub principals: Vec<Principal>,
    pub authorization: Option<Authorization>,
}

impl AuthContext {
    pub fn get_spiffe_machine_id(&self) -> Option<&str> {
        self.principals.iter().find_map(|p| match p {
            Principal::SpiffeMachineIdentifier(identifier) => Some(identifier.as_str()),
            _ => None,
        })
    }

    pub fn get_external_user_info(&self) -> Option<&ExternalUserInfo> {
        self.principals.iter().find_map(|p| match p {
            Principal::ExternalUser(external_user_info)
                if external_user_info
                    .user
                    .as_ref()
                    .is_some_and(|u| !u.is_empty()) =>
            {
                Some(external_user_info)
            }
            _ => None,
        })
    }
}

impl Default for AuthContext {
    fn default() -> Self {
        // We'll probably only ever see 1-2 principals associated with a request.
        let principals = Vec::with_capacity(4);
        let authorization = None;
        AuthContext {
            principals,
            authorization,
        }
    }
}

pub fn external_user_info<T>(
    request: &tonic::Request<T>,
) -> Result<ExternalUserInfo, CarbideError> {
    if let Some(external_user_info) = request
        .extensions()
        .get::<AuthContext>()
        .and_then(|auth_context| auth_context.get_external_user_info())
    {
        Ok(external_user_info.clone())
    } else {
        Err(CarbideError::ClientCertificateMissingInformation(
            "external user info".to_string(),
        ))
    }
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum SpiffeError {
    #[error("SPIFFE validation error: {0}")]
    Validation(#[from] forge_spiffe::SpiffeValidationError),

    #[error("Unrecognized SPIFFE ID: {0}")]
    Recognition(#[from] forge_spiffe::ForgeSpiffeContextError),
}

// This is a "predicate" in the grammar sense of the word, so it's some sort of
// action that may or may not specify an object it's acting on.
#[derive(Clone, Debug)]
pub enum Predicate {
    // A call to a Forge-owned gRPC method. The string is the gRPC method name,
    // relative to the Forge service that contains it (i.e. without any slash
    // delimiters).
    ForgeCall(String),
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

impl PrincipalExtractor for &[Principal] {
    fn principals(&self) -> Vec<Principal> {
        self.to_vec()
    }
}

// An Authorization is sort of like a ticket that says we're allowed to do the
// thing we're trying to do, and specifically which Principal was permitted to
// do it.
#[derive(Clone, Debug)]
pub struct Authorization {
    _principal: Principal, // Currently unused
    _predicate: Predicate, // Currently unused
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum AuthorizationError {
    #[error("Unauthorized: CasbinEngine: all auth principals denied by enforcer")]
    Unauthorized,
}

impl From<AuthorizationError> for tonic::Status {
    fn from(e: AuthorizationError) -> Self {
        tracing::info!(error = %e, "Request denied");
        tonic::Status::permission_denied("Not authorized")
    }
}

// A PolicyEngine is anything that can enforce whether a request is allowed.
pub trait PolicyEngine {
    fn authorize(
        &self,
        principals: &[Principal],
        predicate: Predicate,
    ) -> Result<Authorization, AuthorizationError>;
}

pub type PolicyEngineObject = (dyn PolicyEngine + Send + Sync);

#[derive(Clone)]
pub struct CasbinAuthorizer {
    policy_engine: Arc<PolicyEngineObject>,
}

impl CasbinAuthorizer {
    pub fn new(policy_engine: Arc<PolicyEngineObject>) -> Self {
        Self { policy_engine }
    }

    pub fn authorize<R: PrincipalExtractor>(
        &self,
        req: &R,
        predicate: Predicate,
    ) -> Result<Authorization, AuthorizationError> {
        let mut principals = req.principals();

        // We will also explicitly check anonymous to make the policy easier
        // to express.
        principals.push(Principal::Anonymous);

        let engine = self.policy_engine.clone();
        tracing::debug!(?principals, ?predicate, "Checking authorization");
        engine.authorize(&principals, predicate)
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
    ) -> Result<Self, CasbinAuthorizerError> {
        use casbin_engine::{CasbinEngine, ModelType};
        let engine = CasbinEngine::new(ModelType::Rbac, policy_path)
            .await
            .map_err(|e| CasbinAuthorizerError::InitializationError(e.to_string()))?;
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
pub enum CasbinAuthorizerError {
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
        predicate: Predicate,
    ) -> Result<Authorization, AuthorizationError> {
        let result = self.inner.authorize(principals, predicate.clone());
        result.or_else(|e| {
            tracing::warn!(
                ?principals,
                ?predicate,
                error = %e,
                "The policy engine denied this request, but \
                --auth-permissive-mode overrides it."
            );

            // FIXME: Strictly speaking, it's not true that Anonymous is
            // authorized to do this. Maybe define a different principal
            // to use here? "Development"?
            let authorization = Authorization {
                _principal: Principal::Anonymous,
                _predicate: predicate,
            };
            Ok(authorization)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eyre::Context;
    use std::collections::HashMap;
    use std::io::BufRead;

    struct ClientCertTable {
        cert: String,
        desired: Principal,
    }

    // The certs here alone aren't enough to use for authentication, it's the key that would be needed for that; thus
    // they are safe to check in.

    // Generation example: root@machine-a-tron-696cd47455-ngb7l:/var/run/secrets/spiffe.io# od -t u1 tls.crt | sed -e 's/^[^ ]* *//g' -e 's/ *//' -e 's/  */,/g' -e 's/$/,/'

    static CLIENT_CERT_DHCP: &[u8] = &[
        45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45,
        45, 45, 45, 45, 10, 77, 73, 73, 67, 69, 122, 67, 67, 65, 98, 113, 103, 65, 119, 73, 66, 65,
        103, 73, 85, 84, 67, 101, 55, 112, 90, 80, 74, 111, 47, 51, 117, 122, 69, 51, 99, 104, 52,
        110, 78, 50, 111, 103, 74, 104, 105, 77, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106,
        48, 69, 65, 119, 73, 119, 10, 70, 68, 69, 83, 77, 66, 65, 71, 65, 49, 85, 69, 65, 120, 77,
        74, 99, 50, 108, 48, 90, 83, 49, 121, 98, 50, 57, 48, 77, 66, 52, 88, 68, 84, 73, 48, 77,
        84, 65, 120, 78, 68, 73, 119, 77, 122, 81, 49, 79, 86, 111, 88, 68, 84, 73, 48, 77, 84, 69,
        120, 77, 122, 73, 119, 10, 77, 122, 85, 121, 79, 86, 111, 119, 65, 68, 66, 50, 77, 66, 65,
        71, 66, 121, 113, 71, 83, 77, 52, 57, 65, 103, 69, 71, 66, 83, 117, 66, 66, 65, 65, 105,
        65, 50, 73, 65, 66, 73, 102, 89, 55, 98, 71, 56, 86, 105, 72, 79, 122, 70, 104, 49, 53, 68,
        49, 121, 73, 48, 49, 116, 10, 111, 47, 102, 117, 76, 47, 55, 70, 90, 70, 113, 57, 101, 117,
        81, 82, 115, 71, 75, 118, 50, 102, 100, 75, 87, 53, 122, 73, 114, 69, 81, 80, 54, 118, 111,
        52, 74, 69, 100, 76, 53, 48, 113, 103, 67, 86, 57, 84, 76, 75, 43, 65, 75, 70, 43, 115, 50,
        49, 50, 97, 48, 106, 79, 100, 10, 102, 104, 118, 116, 56, 98, 78, 119, 47, 72, 107, 113,
        103, 102, 109, 81, 100, 75, 97, 87, 107, 88, 116, 118, 115, 84, 107, 86, 120, 84, 112, 108,
        101, 53, 54, 47, 56, 118, 50, 82, 43, 113, 79, 66, 52, 68, 67, 66, 51, 84, 65, 79, 66, 103,
        78, 86, 72, 81, 56, 66, 65, 102, 56, 69, 10, 66, 65, 77, 67, 65, 54, 103, 119, 72, 81, 89,
        68, 86, 82, 48, 108, 66, 66, 89, 119, 70, 65, 89, 73, 75, 119, 89, 66, 66, 81, 85, 72, 65,
        119, 69, 71, 67, 67, 115, 71, 65, 81, 85, 70, 66, 119, 77, 67, 77, 66, 48, 71, 65, 49, 85,
        100, 68, 103, 81, 87, 66, 66, 81, 80, 10, 117, 80, 43, 48, 110, 108, 80, 82, 77, 49, 43,
        121, 47, 71, 69, 51, 65, 97, 119, 122, 71, 75, 85, 111, 106, 68, 65, 102, 66, 103, 78, 86,
        72, 83, 77, 69, 71, 68, 65, 87, 103, 66, 84, 50, 118, 49, 43, 80, 57, 119, 106, 111, 120,
        97, 55, 112, 100, 71, 65, 100, 51, 97, 118, 84, 10, 75, 68, 70, 81, 83, 68, 66, 115, 66,
        103, 78, 86, 72, 82, 69, 66, 65, 102, 56, 69, 89, 106, 66, 103, 103, 105, 116, 106, 89, 88,
        74, 105, 97, 87, 82, 108, 76, 87, 82, 111, 89, 51, 65, 117, 90, 109, 57, 121, 90, 50, 85,
        116, 99, 51, 108, 122, 100, 71, 86, 116, 76, 110, 78, 50, 10, 89, 121, 53, 106, 98, 72, 86,
        122, 100, 71, 86, 121, 76, 109, 120, 118, 89, 50, 70, 115, 104, 106, 70, 122, 99, 71, 108,
        109, 90, 109, 85, 54, 76, 121, 57, 109, 98, 51, 74, 110, 90, 83, 53, 115, 98, 50, 78, 104,
        98, 67, 57, 109, 98, 51, 74, 110, 90, 83, 49, 122, 101, 88, 78, 48, 10, 90, 87, 48, 118,
        99, 50, 69, 118, 89, 50, 70, 121, 89, 109, 108, 107, 90, 83, 49, 107, 97, 71, 78, 119, 77,
        65, 111, 71, 67, 67, 113, 71, 83, 77, 52, 57, 66, 65, 77, 67, 65, 48, 99, 65, 77, 69, 81,
        67, 73, 72, 68, 50, 74, 54, 113, 76, 67, 47, 75, 72, 57, 51, 98, 104, 10, 109, 122, 70, 89,
        48, 97, 74, 122, 78, 52, 65, 70, 69, 74, 102, 73, 117, 76, 85, 82, 48, 90, 112, 84, 77,
        102, 108, 43, 65, 105, 66, 69, 100, 90, 72, 50, 117, 110, 117, 110, 47, 54, 49, 83, 65, 82,
        87, 83, 122, 113, 118, 82, 81, 79, 55, 110, 56, 102, 102, 69, 108, 99, 78, 71, 10, 78, 74,
        89, 112, 76, 51, 87, 118, 68, 81, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69,
        82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45,
    ];

    static CLIENT_CERT_NVINIT: &[u8] = &[
        45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45,
        45, 45, 45, 45, 10, 77, 73, 73, 69, 70, 122, 67, 67, 65, 118, 43, 103, 65, 119, 73, 66, 65,
        103, 73, 85, 65, 116, 79, 84, 122, 77, 52, 47, 118, 50, 50, 83, 74, 55, 112, 119, 84, 90,
        70, 51, 76, 90, 108, 43, 71, 122, 85, 119, 68, 81, 89, 74, 75, 111, 90, 73, 104, 118, 99,
        78, 65, 81, 69, 76, 10, 66, 81, 65, 119, 76, 84, 69, 114, 77, 67, 107, 71, 65, 49, 85, 69,
        65, 120, 77, 105, 99, 71, 116, 112, 76, 87, 115, 52, 99, 121, 49, 49, 99, 50, 86, 121, 89,
        50, 86, 121, 100, 67, 49, 106, 89, 83, 53, 117, 90, 50, 77, 117, 98, 110, 90, 112, 90, 71,
        108, 104, 76, 109, 78, 118, 10, 98, 84, 65, 101, 70, 119, 48, 121, 78, 68, 69, 119, 77, 84,
        89, 120, 79, 68, 77, 122, 77, 106, 66, 97, 70, 119, 48, 121, 78, 68, 69, 119, 77, 84, 89,
        120, 79, 68, 77, 52, 78, 84, 66, 97, 77, 69, 77, 120, 69, 106, 65, 81, 66, 103, 78, 86, 66,
        65, 111, 84, 67, 85, 53, 72, 10, 81, 121, 66, 71, 98, 51, 74, 110, 90, 84, 69, 98, 77, 66,
        107, 71, 65, 49, 85, 69, 67, 120, 77, 83, 99, 51, 100, 117, 90, 50, 77, 116, 90, 109, 57,
        121, 90, 50, 85, 116, 89, 87, 82, 116, 97, 87, 53, 122, 77, 82, 65, 119, 68, 103, 89, 68,
        86, 81, 81, 68, 69, 119, 100, 107, 10, 90, 71, 86, 113, 98, 50, 53, 110, 77, 73, 73, 66,
        73, 106, 65, 78, 66, 103, 107, 113, 104, 107, 105, 71, 57, 119, 48, 66, 65, 81, 69, 70, 65,
        65, 79, 67, 65, 81, 56, 65, 77, 73, 73, 66, 67, 103, 75, 67, 65, 81, 69, 65, 55, 83, 69,
        57, 86, 97, 102, 51, 89, 69, 114, 52, 10, 108, 66, 55, 67, 53, 78, 73, 101, 50, 68, 52,
        116, 90, 73, 51, 72, 43, 71, 103, 121, 112, 118, 90, 47, 108, 101, 84, 71, 70, 57, 83, 78,
        66, 43, 119, 50, 50, 83, 89, 117, 51, 74, 89, 117, 100, 101, 83, 121, 71, 90, 85, 48, 55,
        47, 88, 116, 81, 50, 71, 57, 68, 53, 73, 102, 10, 66, 113, 73, 73, 106, 97, 113, 75, 102,
        89, 114, 56, 80, 104, 53, 67, 53, 89, 80, 110, 84, 117, 112, 86, 49, 50, 57, 85, 121, 53,
        86, 53, 118, 84, 110, 56, 56, 71, 118, 98, 56, 106, 121, 103, 112, 90, 55, 90, 71, 78, 84,
        106, 85, 115, 107, 85, 103, 103, 55, 73, 75, 81, 78, 65, 10, 97, 83, 80, 101, 88, 103, 88,
        76, 113, 52, 118, 106, 87, 121, 98, 116, 101, 71, 81, 121, 74, 78, 110, 50, 97, 104, 88,
        53, 111, 117, 53, 77, 70, 67, 104, 116, 47, 102, 67, 43, 86, 114, 100, 84, 74, 51, 112,
        110, 76, 70, 49, 89, 90, 72, 52, 75, 65, 104, 82, 80, 107, 77, 83, 65, 10, 67, 56, 101, 54,
        56, 101, 99, 106, 112, 48, 116, 43, 83, 113, 113, 120, 88, 103, 121, 103, 118, 57, 120, 90,
        109, 79, 68, 51, 100, 54, 109, 98, 79, 120, 71, 72, 117, 71, 68, 83, 56, 114, 88, 73, 78,
        105, 74, 70, 43, 90, 122, 98, 68, 85, 109, 82, 88, 97, 84, 66, 54, 120, 83, 103, 10, 67,
        109, 47, 112, 53, 51, 109, 118, 72, 53, 89, 97, 73, 108, 43, 112, 57, 85, 100, 84, 118, 99,
        85, 51, 77, 73, 121, 116, 120, 105, 50, 76, 72, 121, 90, 70, 117, 67, 98, 104, 75, 111,
        116, 88, 86, 118, 69, 81, 116, 113, 74, 72, 73, 113, 116, 49, 66, 122, 50, 103, 57, 97,
        107, 84, 10, 89, 115, 51, 119, 119, 49, 89, 112, 119, 119, 73, 68, 65, 81, 65, 66, 111, 52,
        73, 66, 70, 122, 67, 67, 65, 82, 77, 119, 68, 103, 89, 68, 86, 82, 48, 80, 65, 81, 72, 47,
        66, 65, 81, 68, 65, 103, 79, 111, 77, 66, 77, 71, 65, 49, 85, 100, 74, 81, 81, 77, 77, 65,
        111, 71, 10, 67, 67, 115, 71, 65, 81, 85, 70, 66, 119, 77, 67, 77, 66, 48, 71, 65, 49, 85,
        100, 68, 103, 81, 87, 66, 66, 81, 89, 65, 55, 79, 81, 106, 67, 100, 117, 78, 115, 85, 108,
        79, 114, 104, 73, 73, 80, 49, 76, 110, 80, 87, 73, 122, 68, 65, 102, 66, 103, 78, 86, 72,
        83, 77, 69, 10, 71, 68, 65, 87, 103, 66, 84, 77, 111, 66, 119, 113, 119, 81, 51, 66, 109,
        81, 117, 111, 83, 57, 67, 78, 73, 107, 113, 99, 120, 107, 52, 110, 70, 122, 66, 81, 66,
        103, 103, 114, 66, 103, 69, 70, 66, 81, 99, 66, 65, 81, 82, 69, 77, 69, 73, 119, 81, 65,
        89, 73, 75, 119, 89, 66, 10, 66, 81, 85, 72, 77, 65, 75, 71, 78, 71, 104, 48, 100, 72, 66,
        122, 79, 105, 56, 118, 99, 72, 74, 118, 90, 67, 53, 50, 89, 88, 86, 115, 100, 67, 53, 117,
        100, 109, 108, 107, 97, 87, 69, 117, 89, 50, 57, 116, 76, 51, 89, 120, 76, 51, 66, 114, 97,
        83, 49, 114, 79, 72, 77, 116, 10, 100, 88, 78, 108, 99, 109, 78, 108, 99, 110, 81, 118, 89,
        50, 69, 119, 69, 103, 89, 68, 86, 82, 48, 82, 66, 65, 115, 119, 67, 89, 73, 72, 90, 71, 82,
        108, 97, 109, 57, 117, 90, 122, 66, 71, 66, 103, 78, 86, 72, 82, 56, 69, 80, 122, 65, 57,
        77, 68, 117, 103, 79, 97, 65, 51, 10, 104, 106, 86, 111, 100, 72, 82, 119, 99, 122, 111,
        118, 76, 51, 66, 121, 98, 50, 81, 117, 100, 109, 70, 49, 98, 72, 81, 117, 98, 110, 90, 112,
        90, 71, 108, 104, 76, 109, 78, 118, 98, 83, 57, 50, 77, 83, 57, 119, 97, 50, 107, 116, 97,
        122, 104, 122, 76, 88, 86, 122, 90, 88, 74, 106, 10, 90, 88, 74, 48, 76, 50, 78, 121, 98,
        68, 65, 78, 66, 103, 107, 113, 104, 107, 105, 71, 57, 119, 48, 66, 65, 81, 115, 70, 65, 65,
        79, 67, 65, 81, 69, 65, 97, 120, 55, 118, 76, 119, 102, 81, 43, 48, 118, 66, 43, 77, 99,
        104, 100, 122, 119, 71, 89, 103, 78, 81, 119, 100, 43, 101, 10, 89, 111, 57, 74, 79, 43,
        52, 107, 101, 87, 43, 79, 50, 119, 69, 51, 54, 88, 88, 99, 115, 110, 115, 79, 115, 65, 88,
        103, 48, 109, 75, 78, 70, 53, 82, 109, 70, 72, 89, 81, 118, 55, 98, 120, 118, 43, 100, 81,
        90, 78, 100, 110, 118, 74, 72, 122, 57, 48, 90, 106, 97, 119, 82, 67, 10, 49, 119, 69, 85,
        49, 116, 116, 66, 115, 74, 101, 56, 107, 52, 54, 68, 119, 120, 101, 120, 78, 100, 100, 100,
        71, 102, 105, 109, 122, 56, 77, 65, 73, 71, 101, 53, 115, 87, 51, 105, 67, 107, 106, 109,
        102, 65, 122, 89, 111, 88, 50, 114, 87, 68, 119, 78, 53, 80, 65, 103, 54, 77, 65, 51, 10,
        119, 67, 76, 112, 80, 122, 121, 101, 103, 66, 88, 116, 104, 90, 83, 115, 82, 50, 117, 100,
        52, 73, 78, 120, 114, 87, 88, 104, 113, 81, 50, 102, 103, 103, 49, 51, 48, 110, 76, 114,
        122, 110, 111, 85, 55, 78, 108, 68, 51, 100, 115, 54, 47, 85, 57, 50, 114, 98, 121, 118,
        50, 102, 99, 81, 10, 112, 77, 101, 76, 120, 49, 82, 109, 56, 50, 88, 82, 89, 71, 107, 119,
        72, 107, 49, 119, 66, 65, 82, 111, 67, 66, 119, 82, 83, 122, 101, 117, 105, 71, 117, 103,
        73, 99, 43, 81, 72, 104, 48, 68, 120, 118, 77, 74, 99, 99, 116, 68, 74, 50, 48, 68, 52,
        106, 53, 52, 48, 105, 72, 71, 10, 112, 48, 99, 71, 114, 65, 114, 97, 73, 110, 101, 90, 112,
        113, 52, 47, 98, 77, 112, 108, 51, 56, 102, 122, 111, 117, 85, 108, 105, 72, 47, 66, 74,
        70, 80, 106, 88, 47, 103, 53, 121, 70, 81, 84, 106, 47, 67, 113, 47, 70, 89, 122, 102, 87,
        121, 65, 122, 65, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69, 82, 84, 73, 70,
        73, 67, 65, 84, 69, 45, 45, 45, 45, 45,
    ];

    static CLIENT_CERT_MACHINEATRON: &[u8] = &[
        45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45,
        45, 45, 45, 45, 10, 77, 73, 73, 67, 69, 122, 67, 67, 65, 98, 109, 103, 65, 119, 73, 66, 65,
        103, 73, 85, 83, 65, 99, 54, 51, 100, 65, 86, 55, 83, 98, 104, 84, 82, 86, 90, 54, 82, 67,
        77, 86, 73, 50, 99, 85, 55, 56, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69,
        65, 119, 73, 119, 10, 70, 68, 69, 83, 77, 66, 65, 71, 65, 49, 85, 69, 65, 120, 77, 74, 99,
        50, 108, 48, 90, 83, 49, 121, 98, 50, 57, 48, 77, 66, 52, 88, 68, 84, 73, 48, 77, 84, 65,
        121, 79, 84, 73, 119, 78, 84, 107, 49, 78, 49, 111, 88, 68, 84, 73, 48, 77, 84, 69, 121,
        79, 68, 73, 120, 10, 77, 68, 65, 121, 78, 49, 111, 119, 65, 68, 66, 50, 77, 66, 65, 71, 66,
        121, 113, 71, 83, 77, 52, 57, 65, 103, 69, 71, 66, 83, 117, 66, 66, 65, 65, 105, 65, 50,
        73, 65, 66, 74, 116, 105, 114, 120, 52, 88, 112, 112, 97, 66, 105, 105, 51, 43, 53, 53, 80,
        68, 52, 52, 108, 108, 10, 56, 67, 72, 115, 114, 75, 113, 85, 80, 103, 108, 43, 113, 121,
        119, 112, 110, 88, 49, 99, 112, 100, 53, 119, 101, 88, 97, 76, 51, 105, 50, 72, 107, 78,
        103, 53, 106, 86, 65, 113, 108, 106, 73, 87, 112, 105, 80, 118, 102, 84, 121, 112, 112, 86,
        72, 108, 100, 117, 118, 55, 114, 120, 102, 116, 10, 74, 113, 57, 115, 111, 86, 65, 120,
        105, 54, 57, 81, 67, 78, 79, 86, 53, 115, 104, 50, 66, 43, 81, 57, 75, 97, 52, 100, 113,
        103, 108, 97, 71, 79, 54, 69, 72, 111, 116, 102, 119, 75, 79, 66, 51, 122, 67, 66, 51, 68,
        65, 79, 66, 103, 78, 86, 72, 81, 56, 66, 65, 102, 56, 69, 10, 66, 65, 77, 67, 65, 54, 103,
        119, 72, 81, 89, 68, 86, 82, 48, 108, 66, 66, 89, 119, 70, 65, 89, 73, 75, 119, 89, 66, 66,
        81, 85, 72, 65, 119, 69, 71, 67, 67, 115, 71, 65, 81, 85, 70, 66, 119, 77, 67, 77, 66, 48,
        71, 65, 49, 85, 100, 68, 103, 81, 87, 66, 66, 84, 70, 10, 106, 90, 105, 75, 102, 66, 65,
        107, 114, 121, 113, 71, 43, 109, 105, 71, 57, 48, 107, 56, 48, 120, 55, 65, 52, 106, 65,
        102, 66, 103, 78, 86, 72, 83, 77, 69, 71, 68, 65, 87, 103, 66, 84, 50, 118, 49, 43, 80, 57,
        119, 106, 111, 120, 97, 55, 112, 100, 71, 65, 100, 51, 97, 118, 84, 10, 75, 68, 70, 81, 83,
        68, 66, 114, 66, 103, 78, 86, 72, 82, 69, 66, 65, 102, 56, 69, 89, 84, 66, 102, 103, 105,
        49, 116, 89, 87, 78, 111, 97, 87, 53, 108, 76, 87, 69, 116, 100, 72, 74, 118, 98, 105, 53,
        109, 98, 51, 74, 110, 90, 83, 49, 122, 101, 88, 78, 48, 90, 87, 48, 117, 10, 99, 51, 90,
        106, 76, 109, 78, 115, 100, 88, 78, 48, 90, 88, 73, 117, 98, 71, 57, 106, 89, 87, 121, 71,
        76, 110, 78, 119, 97, 87, 90, 109, 90, 84, 111, 118, 76, 50, 90, 118, 99, 109, 100, 108,
        76, 109, 120, 118, 89, 50, 70, 115, 76, 50, 82, 108, 90, 109, 70, 49, 98, 72, 81, 118, 10,
        99, 50, 69, 118, 98, 87, 70, 106, 97, 71, 108, 117, 90, 83, 49, 104, 76, 88, 82, 121, 98,
        50, 52, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 73, 68, 83, 65,
        65, 119, 82, 81, 73, 103, 66, 54, 115, 80, 111, 48, 121, 56, 106, 98, 56, 87, 118, 114, 87,
        103, 10, 49, 98, 89, 43, 57, 74, 77, 80, 104, 100, 90, 108, 103, 87, 98, 106, 120, 76, 99,
        65, 65, 121, 120, 118, 122, 100, 111, 67, 73, 81, 67, 47, 47, 71, 65, 106, 97, 52, 99, 110,
        106, 67, 103, 111, 53, 71, 80, 113, 110, 118, 79, 87, 54, 80, 57, 83, 115, 89, 109, 50,
        106, 72, 81, 55, 10, 50, 79, 105, 98, 51, 82, 86, 80, 102, 81, 61, 61, 10, 45, 45, 45, 45,
        45, 69, 78, 68, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10,
    ];

    static CLIENT_CERT_SITEAGENT: &[u8] = &[
        45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45,
        45, 45, 45, 45, 10, 77, 73, 73, 67, 88, 84, 67, 67, 65, 103, 79, 103, 65, 119, 73, 66, 65,
        103, 73, 85, 97, 53, 112, 77, 75, 56, 74, 110, 89, 86, 48, 83, 49, 105, 85, 100, 84, 70,
        57, 73, 102, 43, 74, 54, 43, 74, 89, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48,
        69, 65, 119, 73, 119, 10, 85, 68, 69, 98, 77, 66, 107, 71, 65, 49, 85, 69, 67, 104, 77, 83,
        84, 108, 90, 74, 82, 69, 108, 66, 73, 69, 78, 118, 99, 110, 66, 118, 99, 109, 70, 48, 97,
        87, 57, 117, 77, 84, 69, 119, 76, 119, 89, 68, 86, 81, 81, 68, 69, 121, 104, 79, 86, 107,
        108, 69, 83, 85, 69, 103, 10, 82, 109, 57, 121, 90, 50, 85, 103, 83, 87, 53, 48, 90, 88,
        74, 116, 90, 87, 82, 112, 89, 88, 82, 108, 73, 69, 78, 66, 73, 68, 73, 119, 77, 106, 77,
        103, 76, 83, 66, 107, 90, 88, 89, 122, 77, 66, 52, 88, 68, 84, 73, 48, 77, 84, 65, 121, 79,
        84, 69, 48, 77, 122, 69, 121, 10, 78, 108, 111, 88, 68, 84, 73, 48, 77, 84, 69, 121, 79,
        68, 69, 48, 77, 122, 69, 49, 78, 108, 111, 119, 65, 68, 66, 50, 77, 66, 65, 71, 66, 121,
        113, 71, 83, 77, 52, 57, 65, 103, 69, 71, 66, 83, 117, 66, 66, 65, 65, 105, 65, 50, 73, 65,
        66, 75, 72, 105, 110, 70, 66, 84, 10, 70, 87, 102, 68, 47, 68, 112, 67, 57, 53, 48, 70, 57,
        115, 74, 78, 81, 48, 48, 66, 50, 84, 100, 78, 120, 109, 66, 82, 110, 73, 76, 90, 57, 122,
        79, 47, 73, 66, 114, 118, 48, 66, 86, 49, 101, 79, 81, 77, 71, 103, 115, 57, 88, 115, 101,
        50, 89, 90, 51, 78, 101, 51, 67, 50, 10, 107, 103, 89, 121, 68, 121, 81, 66, 117, 118, 43,
        77, 97, 82, 74, 56, 70, 121, 50, 90, 84, 116, 57, 67, 48, 103, 55, 119, 106, 102, 74, 50,
        50, 68, 78, 55, 54, 115, 97, 86, 113, 72, 50, 55, 81, 50, 73, 57, 67, 48, 101, 102, 118,
        100, 54, 57, 99, 97, 79, 66, 55, 84, 67, 66, 10, 54, 106, 65, 79, 66, 103, 78, 86, 72, 81,
        56, 66, 65, 102, 56, 69, 66, 65, 77, 67, 65, 54, 103, 119, 72, 81, 89, 68, 86, 82, 48, 108,
        66, 66, 89, 119, 70, 65, 89, 73, 75, 119, 89, 66, 66, 81, 85, 72, 65, 119, 69, 71, 67, 67,
        115, 71, 65, 81, 85, 70, 66, 119, 77, 67, 10, 77, 66, 48, 71, 65, 49, 85, 100, 68, 103, 81,
        87, 66, 66, 83, 119, 50, 78, 121, 85, 106, 85, 73, 97, 55, 116, 79, 66, 117, 87, 76, 70,
        120, 104, 99, 111, 52, 85, 116, 50, 75, 68, 65, 102, 66, 103, 78, 86, 72, 83, 77, 69, 71,
        68, 65, 87, 103, 66, 84, 101, 107, 75, 111, 118, 10, 103, 84, 81, 67, 121, 110, 57, 116,
        100, 120, 73, 122, 66, 121, 70, 107, 89, 54, 111, 100, 116, 68, 66, 53, 66, 103, 78, 86,
        72, 82, 69, 66, 65, 102, 56, 69, 98, 122, 66, 116, 103, 105, 120, 108, 98, 71, 86, 114,
        100, 72, 74, 104, 76, 109, 86, 115, 90, 87, 116, 48, 99, 109, 69, 116, 10, 99, 50, 108, 48,
        90, 83, 49, 104, 90, 50, 86, 117, 100, 67, 53, 122, 100, 109, 77, 117, 89, 50, 120, 49, 99,
        51, 82, 108, 99, 105, 53, 115, 98, 50, 78, 104, 98, 73, 89, 57, 99, 51, 66, 112, 90, 109,
        90, 108, 79, 105, 56, 118, 90, 109, 57, 121, 90, 50, 85, 117, 98, 71, 57, 106, 10, 89, 87,
        119, 118, 90, 87, 120, 108, 97, 51, 82, 121, 89, 83, 49, 122, 97, 88, 82, 108, 76, 87, 70,
        110, 90, 87, 53, 48, 76, 51, 78, 104, 76, 50, 86, 115, 90, 87, 116, 48, 99, 109, 69, 116,
        99, 50, 108, 48, 90, 83, 49, 104, 90, 50, 86, 117, 100, 68, 65, 75, 66, 103, 103, 113, 10,
        104, 107, 106, 79, 80, 81, 81, 68, 65, 103, 78, 73, 65, 68, 66, 70, 65, 105, 66, 43, 98,
        89, 118, 54, 115, 114, 52, 79, 97, 98, 87, 118, 69, 81, 119, 86, 100, 78, 71, 103, 83, 88,
        110, 111, 114, 105, 118, 119, 82, 121, 89, 85, 74, 110, 43, 69, 75, 117, 57, 79, 104, 103,
        73, 104, 10, 65, 78, 112, 50, 83, 87, 81, 73, 53, 122, 68, 98, 109, 69, 80, 81, 73, 113,
        65, 122, 86, 102, 72, 103, 65, 107, 54, 104, 112, 54, 112, 83, 87, 118, 100, 82, 79, 82,
        75, 51, 121, 110, 105, 87, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69, 82, 84, 73, 70,
        73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67,
        69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 77, 73, 73, 67, 78, 122,
        67, 67, 65, 98, 121, 103, 65, 119, 73, 66, 65, 103, 73, 85, 81, 76, 73, 49, 106, 113, 109,
        99, 81, 43, 115, 104, 65, 78, 106, 67, 81, 106, 117, 56, 76, 50, 78, 119, 114, 103, 77,
        119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 77, 119, 10, 89, 84, 69,
        76, 77, 65, 107, 71, 65, 49, 85, 69, 66, 104, 77, 67, 86, 86, 77, 120, 71, 122, 65, 90, 66,
        103, 78, 86, 66, 65, 111, 84, 69, 107, 53, 87, 83, 85, 82, 74, 81, 83, 66, 68, 98, 51, 74,
        119, 98, 51, 74, 104, 100, 71, 108, 118, 98, 106, 69, 49, 77, 68, 77, 71, 10, 65, 49, 85,
        69, 65, 120, 77, 115, 84, 108, 90, 74, 82, 69, 108, 66, 73, 69, 90, 118, 99, 109, 100, 108,
        73, 70, 74, 118, 98, 51, 81, 103, 81, 50, 86, 121, 100, 71, 108, 109, 97, 87, 78, 104, 100,
        71, 85, 103, 81, 88, 86, 48, 97, 71, 57, 121, 97, 88, 82, 53, 73, 68, 73, 119, 10, 77, 106,
        73, 119, 72, 104, 99, 78, 77, 106, 81, 119, 78, 106, 65, 120, 77, 84, 77, 48, 78, 122, 81,
        53, 87, 104, 99, 78, 77, 106, 99, 119, 78, 106, 65, 120, 77, 84, 77, 48, 79, 68, 69, 53,
        87, 106, 66, 81, 77, 82, 115, 119, 71, 81, 89, 68, 86, 81, 81, 75, 69, 120, 74, 79, 10, 86,
        107, 108, 69, 83, 85, 69, 103, 81, 50, 57, 121, 99, 71, 57, 121, 89, 88, 82, 112, 98, 50,
        52, 120, 77, 84, 65, 118, 66, 103, 78, 86, 66, 65, 77, 84, 75, 69, 53, 87, 83, 85, 82, 74,
        81, 83, 66, 71, 98, 51, 74, 110, 90, 83, 66, 74, 98, 110, 82, 108, 99, 109, 49, 108, 10,
        90, 71, 108, 104, 100, 71, 85, 103, 81, 48, 69, 103, 77, 106, 65, 121, 77, 121, 65, 116,
        73, 71, 82, 108, 100, 106, 77, 119, 87, 84, 65, 84, 66, 103, 99, 113, 104, 107, 106, 79,
        80, 81, 73, 66, 66, 103, 103, 113, 104, 107, 106, 79, 80, 81, 77, 66, 66, 119, 78, 67, 65,
        65, 83, 65, 10, 57, 80, 84, 71, 82, 47, 74, 100, 65, 88, 82, 85, 50, 83, 88, 78, 82, 89,
        77, 118, 65, 80, 67, 121, 119, 83, 79, 65, 108, 121, 99, 65, 112, 53, 80, 50, 119, 70, 89,
        52, 82, 67, 65, 84, 103, 70, 117, 51, 52, 109, 77, 104, 75, 74, 117, 67, 82, 77, 56, 50,
        118, 67, 103, 78, 10, 101, 84, 122, 51, 82, 80, 66, 116, 79, 105, 81, 97, 86, 56, 102, 118,
        52, 75, 54, 99, 111, 50, 77, 119, 89, 84, 65, 79, 66, 103, 78, 86, 72, 81, 56, 66, 65, 102,
        56, 69, 66, 65, 77, 67, 65, 81, 89, 119, 68, 119, 89, 68, 86, 82, 48, 84, 65, 81, 72, 47,
        66, 65, 85, 119, 10, 65, 119, 69, 66, 47, 122, 65, 100, 66, 103, 78, 86, 72, 81, 52, 69,
        70, 103, 81, 85, 51, 112, 67, 113, 76, 52, 69, 48, 65, 115, 112, 47, 98, 88, 99, 83, 77,
        119, 99, 104, 90, 71, 79, 113, 72, 98, 81, 119, 72, 119, 89, 68, 86, 82, 48, 106, 66, 66,
        103, 119, 70, 111, 65, 85, 10, 106, 65, 117, 54, 97, 71, 53, 85, 108, 73, 109, 115, 78, 77,
        57, 116, 85, 102, 109, 48, 105, 111, 48, 87, 48, 66, 115, 119, 67, 103, 89, 73, 75, 111,
        90, 73, 122, 106, 48, 69, 65, 119, 77, 68, 97, 81, 65, 119, 90, 103, 73, 120, 65, 74, 67,
        120, 43, 53, 90, 120, 48, 54, 121, 85, 10, 72, 113, 104, 70, 97, 43, 111, 99, 67, 53, 109,
        85, 54, 101, 99, 89, 118, 116, 89, 113, 69, 100, 120, 48, 100, 80, 103, 52, 97, 85, 86, 89,
        105, 119, 87, 112, 115, 109, 75, 79, 70, 87, 122, 48, 49, 89, 76, 83, 117, 105, 108, 122,
        86, 103, 73, 120, 65, 75, 114, 102, 100, 116, 72, 111, 10, 54, 98, 99, 98, 73, 108, 55, 50,
        77, 121, 116, 105, 76, 99, 48, 108, 54, 76, 78, 117, 50, 117, 52, 90, 71, 76, 117, 76, 56,
        52, 85, 117, 109, 90, 71, 119, 100, 48, 87, 100, 99, 89, 101, 51, 75, 67, 79, 68, 54, 99,
        88, 90, 57, 81, 108, 55, 55, 119, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69,
        82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10,
    ];

    static CLIENT_CERT_CI: &[u8] = &[
        45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45,
        45, 45, 45, 45, 10, 77, 73, 73, 67, 99, 84, 67, 67, 65, 102, 101, 103, 65, 119, 73, 66, 65,
        103, 73, 85, 65, 53, 118, 50, 103, 120, 110, 84, 102, 107, 114, 122, 53, 104, 100, 52, 104,
        74, 109, 76, 74, 111, 81, 53, 106, 107, 111, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122,
        106, 48, 69, 65, 119, 77, 119, 10, 89, 84, 69, 76, 77, 65, 107, 71, 65, 49, 85, 69, 66,
        104, 77, 67, 86, 86, 77, 120, 71, 122, 65, 90, 66, 103, 78, 86, 66, 65, 111, 84, 69, 107,
        53, 87, 83, 85, 82, 74, 81, 83, 66, 68, 98, 51, 74, 119, 98, 51, 74, 104, 100, 71, 108,
        118, 98, 106, 69, 49, 77, 68, 77, 71, 10, 65, 49, 85, 69, 65, 120, 77, 115, 84, 108, 90,
        74, 82, 69, 108, 66, 73, 69, 90, 118, 99, 109, 100, 108, 73, 70, 74, 118, 98, 51, 81, 103,
        81, 50, 86, 121, 100, 71, 108, 109, 97, 87, 78, 104, 100, 71, 85, 103, 81, 88, 86, 48, 97,
        71, 57, 121, 97, 88, 82, 53, 73, 68, 73, 119, 10, 77, 106, 73, 119, 72, 104, 99, 78, 77,
        106, 81, 120, 77, 84, 73, 50, 77, 84, 81, 48, 77, 68, 73, 120, 87, 104, 99, 78, 77, 106,
        81, 120, 77, 84, 73, 50, 77, 106, 65, 48, 77, 68, 85, 120, 87, 106, 65, 54, 77, 82, 89,
        119, 70, 65, 89, 68, 86, 81, 81, 76, 69, 119, 49, 106, 10, 89, 88, 74, 105, 97, 87, 82,
        108, 76, 87, 78, 112, 76, 50, 78, 107, 77, 83, 65, 119, 72, 103, 89, 68, 86, 81, 81, 68,
        69, 120, 100, 104, 99, 71, 107, 116, 90, 71, 86, 50, 78, 67, 53, 109, 99, 109, 99, 117, 98,
        110, 90, 112, 90, 71, 108, 104, 76, 109, 78, 118, 98, 84, 66, 50, 10, 77, 66, 65, 71, 66,
        121, 113, 71, 83, 77, 52, 57, 65, 103, 69, 71, 66, 83, 117, 66, 66, 65, 65, 105, 65, 50,
        73, 65, 66, 68, 86, 109, 65, 80, 57, 71, 50, 84, 67, 43, 76, 108, 116, 98, 49, 103, 65, 72,
        54, 81, 111, 71, 71, 99, 110, 88, 79, 54, 103, 102, 74, 70, 122, 76, 10, 47, 69, 47, 99,
        104, 74, 57, 116, 67, 113, 52, 52, 75, 50, 87, 77, 113, 90, 99, 115, 67, 111, 117, 69, 80,
        57, 103, 108, 113, 89, 111, 105, 52, 98, 118, 50, 78, 111, 102, 52, 75, 66, 111, 120, 118,
        53, 83, 117, 109, 109, 68, 84, 48, 72, 109, 84, 112, 88, 54, 76, 57, 47, 79, 74, 10, 112,
        77, 70, 110, 80, 105, 121, 76, 109, 52, 43, 121, 98, 49, 48, 102, 116, 75, 67, 43, 67, 103,
        69, 120, 81, 80, 122, 48, 102, 113, 79, 66, 108, 106, 67, 66, 107, 122, 65, 79, 66, 103,
        78, 86, 72, 81, 56, 66, 65, 102, 56, 69, 66, 65, 77, 67, 65, 54, 103, 119, 72, 81, 89, 68,
        10, 86, 82, 48, 108, 66, 66, 89, 119, 70, 65, 89, 73, 75, 119, 89, 66, 66, 81, 85, 72, 65,
        119, 69, 71, 67, 67, 115, 71, 65, 81, 85, 70, 66, 119, 77, 67, 77, 66, 48, 71, 65, 49, 85,
        100, 68, 103, 81, 87, 66, 66, 84, 52, 101, 78, 89, 81, 54, 78, 102, 82, 97, 89, 67, 55, 10,
        121, 99, 121, 112, 48, 86, 111, 106, 119, 99, 72, 47, 66, 68, 65, 102, 66, 103, 78, 86, 72,
        83, 77, 69, 71, 68, 65, 87, 103, 66, 83, 77, 67, 55, 112, 111, 98, 108, 83, 85, 105, 97,
        119, 48, 122, 50, 49, 82, 43, 98, 83, 75, 106, 82, 98, 81, 71, 122, 65, 105, 66, 103, 78,
        86, 10, 72, 82, 69, 69, 71, 122, 65, 90, 103, 104, 100, 104, 99, 71, 107, 116, 90, 71, 86,
        50, 78, 67, 53, 109, 99, 109, 99, 117, 98, 110, 90, 112, 90, 71, 108, 104, 76, 109, 78,
        118, 98, 84, 65, 75, 66, 103, 103, 113, 104, 107, 106, 79, 80, 81, 81, 68, 65, 119, 78,
        111, 65, 68, 66, 108, 10, 65, 106, 65, 83, 86, 103, 47, 80, 116, 82, 66, 120, 87, 90, 117,
        75, 104, 121, 104, 83, 54, 102, 110, 48, 120, 90, 87, 115, 51, 111, 89, 117, 116, 57, 86,
        99, 108, 65, 71, 114, 54, 67, 101, 82, 105, 115, 88, 97, 107, 51, 73, 90, 90, 115, 67, 100,
        54, 104, 109, 47, 56, 83, 75, 57, 10, 99, 89, 115, 67, 77, 81, 68, 76, 98, 115, 79, 118,
        82, 48, 76, 52, 101, 101, 84, 98, 97, 115, 81, 122, 85, 47, 103, 79, 122, 47, 119, 98, 78,
        85, 68, 68, 81, 71, 86, 105, 109, 51, 86, 53, 118, 90, 109, 107, 103, 82, 104, 122, 43,
        102, 57, 75, 101, 68, 112, 72, 77, 119, 49, 97, 10, 113, 90, 89, 89, 71, 108, 52, 61, 10,
        45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45,
        45, 45, 10,
    ];

    #[test]
    fn test_try_from_client_certificates() -> Result<(), eyre::Error> {
        // Because we are not actually validating these certs, it doesn't matter if they expire
        let mut table = vec![
            // Cert used by carbide-dhcp in local dev
            ClientCertTable {
                cert: std::str::from_utf8(CLIENT_CERT_DHCP).unwrap().to_string(),
                desired: Principal::SpiffeServiceIdentifier("carbide-dhcp".to_string()),
            },
            // nvinit cert (expired, of course)
            ClientCertTable {
                cert: std::str::from_utf8(CLIENT_CERT_NVINIT).unwrap().to_string(),
                desired: Principal::ExternalUser(ExternalUserInfo::new(
                    Some("NGC Forge".to_string()),
                    "swngc-forge-admins".to_string(),
                    Some("ddejong".to_string()),
                )),
            },
            // Machine-a-tron cert (Has "default" instead of "forge-system")
            ClientCertTable {
                cert: std::str::from_utf8(CLIENT_CERT_MACHINEATRON)
                    .unwrap()
                    .to_string(),
                desired: Principal::SpiffeServiceIdentifier("machine-a-tron".to_string()),
            },
            // Site agent cert (Simply different)
            ClientCertTable {
                cert: std::str::from_utf8(CLIENT_CERT_SITEAGENT)
                    .unwrap()
                    .to_string(),
                desired: Principal::SpiffeServiceIdentifier("elektra-site-agent".to_string()),
            },
            // Cert that gets used in CI/CD testing
            ClientCertTable {
                cert: std::str::from_utf8(CLIENT_CERT_CI).unwrap().to_string(),
                desired: Principal::ExternalUser(ExternalUserInfo::new(
                    None,
                    "carbide-ci/cd".to_string(),
                    Some("api-dev4.frg.nvidia.com".to_string()),
                )),
            },
        ];
        if let Some(extra) = extra_test_cert() {
            // Pull in an additional cert that would be a security problem to check in
            println!("Extra test cert: {:?}", extra.desired);
            table.push(extra);
        }
        let context = CertDescriptionMiddleware::new(Some(AllowedCertCriteria {
            required_equals: HashMap::from([
                (CertComponent::IssuerO, "NVIDIA Corporation".to_string()),
                (
                    CertComponent::IssuerCN,
                    "NVIDIA Forge Root Certificate Authority 2022".to_string(),
                ),
            ]),
            group_from: Some(CertComponent::SubjectOU),
            username_from: Some(CertComponent::SubjectCN),
            username: None,
        }));

        for test in table {
            let clone = test.cert.clone();
            let certs =
                rustls_pemfile::certs(&mut clone.as_bytes()).collect::<Result<Vec<_>, _>>()?;
            let certificate = certs.first().unwrap();
            assert_eq!(
                Principal::try_from_client_certificate(certificate, &context)
                    .wrap_err(format!("Bad certificate {}", test.cert))?,
                test.desired
            );
        }
        Ok(())
    }

    fn extra_test_cert() -> Option<ClientCertTable> {
        let cert = std::fs::read_to_string("/tmp/extra_test_cert.crt").ok()?;
        let principal_file = std::fs::File::open("/tmp/extra_test_cert.principal").ok()?;
        let mut principal_file = std::io::BufReader::new(principal_file);
        let mut line = String::new();
        principal_file.read_line(&mut line).ok()?;
        match line.as_str() {
            "SpiffeServiceIdentifier\n" => {
                let mut line = String::new();
                principal_file.read_line(&mut line).ok()?;
                if let Some(stripped) = line.strip_suffix("\n") {
                    line = stripped.to_string();
                }
                Some(ClientCertTable {
                    cert,
                    desired: Principal::SpiffeServiceIdentifier(line),
                })
            }
            _ => None,
        }
    }
}

pub mod forge_spiffe {
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

    use super::spiffe_id;

    // Validate an X.509 DER certificate against the SPIFFE requirements, and
    // return a SPIFFE ID.
    //
    // https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md#5-validation
    //
    // Note that this only implements the SPIFFE-specific validation steps. We
    // assume the X.509 certificate has already been validated to a trusted root.
    pub fn validate_x509_certificate(
        der_certificate: &[u8],
    ) -> Result<spiffe_id::SpiffeId, SpiffeValidationError> {
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

        let spiffe_id = spiffe_id::SpiffeId::new(uri)
            .map_err(|e| ValidationError(format!("Couldn't parse SPIFFE ID: {e}")))?;
        Ok(spiffe_id)
    }

    #[derive(thiserror::Error, Debug, Clone)]
    pub enum SpiffeValidationError {
        #[error("SPIFFE validation error: {0}")]
        ValidationError(String),
    }

    #[derive(Debug)]
    pub enum SpiffeIdClass {
        Service(String),
        Machine(String),
    }

    impl SpiffeIdClass {
        fn identifier(&self) -> &str {
            let identifier = match self {
                SpiffeIdClass::Service(identifier) => identifier,
                SpiffeIdClass::Machine(identifier) => identifier,
            };
            identifier.as_str()
        }
    }

    pub struct ForgeSpiffeContext {
        trust_domain: spiffe_id::TrustDomain,
        service_base_paths: Vec<String>,
        machine_base_path: String,
    }

    impl ForgeSpiffeContext {
        pub fn extract_service_identifier(
            &self,
            spiffe_id: &spiffe_id::SpiffeId,
        ) -> Result<SpiffeIdClass, ForgeSpiffeContextError> {
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
            let maybe_service = self
                .service_base_paths
                .iter()
                .find_map(|service_base_path| {
                    spiffe_id_path
                        .strip_prefix(service_base_path.as_str())
                        .map(|i| SpiffeIdClass::Service(i.into()))
                });
            let maybe_machine = spiffe_id_path
                .strip_prefix(self.machine_base_path.as_str())
                .map(|i| SpiffeIdClass::Machine(i.into()));
            let maybe_identifier = maybe_service.or(maybe_machine);
            match maybe_identifier {
                Some(identifier) if !identifier.identifier().is_empty() => Ok(identifier),
                Some(_empty_identifier) => Err(ContextError(
                    "The service identifier was empty after removing the base prefix".into(),
                )),
                None => Err(ContextError(format!(
                    "The SPIFFE ID path \"{spiffe_id_path}\" does not begin \
                        with a recognized prefix (one of {:?} or {})",
                    self.service_base_paths, self.machine_base_path,
                ))),
            }
        }
    }

    impl Default for ForgeSpiffeContext {
        fn default() -> Self {
            let trust_domain = spiffe_id::TrustDomain::new("forge.local").unwrap();
            let service_base_paths = vec![
                String::from("/forge-system/sa/"),
                String::from("/default/sa/"),
                String::from("/elektra-site-agent/sa/"),
            ];
            let machine_base_path = String::from("/forge-system/machine/");
            ForgeSpiffeContext {
                trust_domain,
                service_base_paths,
                machine_base_path,
            }
        }
    }

    #[derive(thiserror::Error, Debug, Clone)]
    pub enum ForgeSpiffeContextError {
        #[error("{0}")]
        ContextError(String),
    }
}
