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
use std::path::Path;
use std::sync::Arc;

use asn1_rs::PrintableString;
use middleware::CertDescriptionMiddleware;
use oid_registry::Oid;
use rustls_pki_types::CertificateDer;
use x509_parser::prelude::{FromDer, X509Certificate, X509Name};

use crate::CarbideError;
use crate::cfg::file::{AllowedCertCriteria, CertComponent};

mod casbin_engine;
pub mod internal_rbac_rules;
pub mod middleware;
pub mod spiffe_id; // public for doctests
mod test_certs;

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

    // Certificate based authentication from outside of the cluster
    ExternalUser(ExternalUserInfo),

    // Any certificate that was trusted by the TLS acceptor. This is a superset
    // of what gets mapped into the SPIFFE or external principals, so any request
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
                // external certs do not include a SPIFFE ID, check if we might be one of them
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
        // Looks through the issuer relative distinguished names for a CN matching what we expect for external certs.
        // Other options may be available in the future, but just this for now.
        for rdn in x509_cert.issuer().iter() {
            if rdn
                .iter()
                .filter(|attribute| attribute.attr_type() == &oid_registry::OID_X509_COMMON_NAME) // CN=  see https://www.rfc-editor.org/rfc/rfc4519.html
                .filter_map(|attribute| attribute.attr_value().as_printablestring().ok())
                .any(|value| {
                    auth_context
                        .spiffe_context
                        .additional_issuer_cns
                        .contains(value.as_ref())
                })
            {
                // This CN is what we expect from external certs
                return Some(Principal::ExternalUser(parse_org_group_user_from_subject(
                    x509_cert.subject(),
                )));
            }
        }

        if let Some(allowed_certs) = &auth_context.extra_allowed_certs {
            return site_allowed_cert(&x509_cert, allowed_certs);
        }
    }
    None
}

// Get the O=, OU=, and CN= values from a certificate subject
fn parse_org_group_user_from_subject(subject: &X509Name) -> ExternalUserInfo {
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

// Checks if the given cert is an acceptable carbide-admin-cli user based on per site criteria
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

    pub fn get_external_user_name(&self) -> Option<&str> {
        self.principals.iter().find_map(|p| match p {
            Principal::ExternalUser(external_user_info) => external_user_info
                .user
                .as_ref()
                .filter(|x| !x.is_empty())
                .map(|x| x.as_str()),
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

pub type PolicyEngineObject = dyn PolicyEngine + Send + Sync;

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
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::io::BufRead;

    use eyre::Context;

    use super::*;
    use crate::auth::forge_spiffe::ForgeSpiffeContext;

    struct ClientCertTable {
        cert: Cow<'static, str>,
        desired: Principal,
    }

    #[test]
    fn test_try_from_client_certificates() -> Result<(), eyre::Error> {
        use super::test_certs::*;

        let mut table = vec![
            // Cert used by carbide-dhcp in local dev
            ClientCertTable {
                cert: CLIENT_CERT_DHCP.into(),
                desired: Principal::SpiffeServiceIdentifier("carbide-dhcp".to_string()),
            },
            // external cert (expired, of course)
            ClientCertTable {
                cert: CLIENT_CERT_EXTERNAL.into(),
                desired: Principal::ExternalUser(ExternalUserInfo::new(
                    Some("ExampleCo".to_string()),
                    "admins".to_string(),
                    Some("testuser".to_string()),
                )),
            },
            ClientCertTable {
                cert: CLIENT_CERT_MACHINEATRON.into(),
                desired: Principal::SpiffeServiceIdentifier("machine-a-tron".to_string()),
            },
            // Other app cert (signed by intermediate CA)
            ClientCertTable {
                cert: CLIENT_CERT_OTHER_APP.into(),
                desired: Principal::SpiffeServiceIdentifier("other-app".to_string()),
            },
            // Cert that gets used in CI/CD testing
            ClientCertTable {
                cert: CLIENT_CERT_CI.into(),
                desired: Principal::ExternalUser(ExternalUserInfo::new(
                    None,
                    "generic ci/cd".to_string(),
                    Some("ci-host.example.com".to_string()),
                )),
            },
        ];
        if let Some(extra) = extra_test_cert() {
            // Pull in an additional cert that would be a security problem to check in
            println!("Extra test cert: {:?}", extra.desired);
            table.push(extra);
        }
        let context = CertDescriptionMiddleware::new(
            Some(AllowedCertCriteria {
                required_equals: HashMap::from([
                    (CertComponent::IssuerO, "ExampleCo".to_string()),
                    (
                        CertComponent::IssuerCN,
                        "Example Root Certificate Authority".to_string(),
                    ),
                ]),
                group_from: Some(CertComponent::SubjectOU),
                username_from: Some(CertComponent::SubjectCN),
                username: None,
            }),
            ForgeSpiffeContext {
                trust_domain: spiffe_id::TrustDomain::new("example.test").unwrap(),
                service_base_paths: vec![
                    String::from("/carbide-system/sa/"),
                    String::from("/default/sa/"),
                    String::from("/other-namespace/sa/"),
                ],
                machine_base_path: String::from("/carbide-system/machine/"),
                additional_issuer_cns: ["usercert-ca.example.com".to_string()].into(),
            },
        );

        for test in table {
            let certs =
                rustls_pemfile::certs(&mut test.cert.as_bytes()).collect::<Result<Vec<_>, _>>()?;
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
                    cert: cert.into(),
                    desired: Principal::SpiffeServiceIdentifier(line),
                })
            }
            _ => None,
        }
    }
}

pub mod forge_spiffe {
    use std::collections::HashSet;

    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

    use super::spiffe_id;
    use crate::auth::spiffe_id::{SpiffeIdError, TrustDomain};
    use crate::cfg;
    use crate::cfg::file::TrustConfig;

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
        pub trust_domain: spiffe_id::TrustDomain,
        pub service_base_paths: Vec<String>,
        pub machine_base_path: String,
        pub additional_issuer_cns: HashSet<String>,
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

    impl TryFrom<cfg::file::TrustConfig> for ForgeSpiffeContext {
        type Error = SpiffeIdError;

        fn try_from(value: TrustConfig) -> Result<Self, Self::Error> {
            Ok(ForgeSpiffeContext {
                trust_domain: TrustDomain::new(&value.spiffe_trust_domain)?,
                service_base_paths: value.spiffe_service_base_paths,
                machine_base_path: value.spiffe_machine_base_path,
                additional_issuer_cns: value.additional_issuer_cns.into_iter().collect(),
            })
        }
    }

    #[derive(thiserror::Error, Debug, Clone)]
    pub enum ForgeSpiffeContextError {
        #[error("{0}")]
        ContextError(String),
    }
}
