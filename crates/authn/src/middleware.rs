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
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::Request;
use tonic::transport::CertificateDer;
use tower::{Layer, Service};
use x509_parser::asn1_rs::{Oid, PrintableString};
use x509_parser::oid_registry;
use x509_parser::prelude::{FromDer, X509Certificate, X509Name};

use crate::config::{AllowedCertCriteria, CertComponent};
use crate::{SpiffeContext, SpiffeError};

// A middleware layer to deal with per-request authentication.
// This might mean extracting a service identifier from a SPIFFE x509
// certificate (in which case most of the heavy lifting has already been done by
// the TLS verifier), validating a JWT, validating a TPM signature, or any other
// similar mechanism.
//
// This middleware is not expected to enforce anything on its own, so anything
// that an access control policy might need to do its work should be passed
// along in the request extensions.
#[derive(Clone)]
pub struct CertDescriptionMiddleware<AZ: Authorization> {
    pub spiffe_context: Arc<SpiffeContext>,
    pub extra_allowed_certs: Option<AllowedCertCriteria>,
    _authorization: std::marker::PhantomData<AZ>,
}

impl<AZ: Authorization> CertDescriptionMiddleware<AZ> {
    pub fn new(
        extra_allowed_certs: Option<AllowedCertCriteria>,
        spiffe_context: SpiffeContext,
    ) -> Self {
        CertDescriptionMiddleware {
            spiffe_context: Arc::new(spiffe_context),
            extra_allowed_certs,
            _authorization: std::marker::PhantomData,
        }
    }
}

impl<S, AZ: Authorization> Layer<S> for CertDescriptionMiddleware<AZ> {
    type Service = CertDescriptionService<S, AZ>;

    fn layer(&self, inner: S) -> Self::Service {
        CertDescriptionService {
            inner,
            authorization_context: Arc::new(self.clone()),
        }
    }
}

#[derive(Clone)]
pub struct CertDescriptionService<S, AZ: Authorization> {
    inner: S,
    authorization_context: Arc<CertDescriptionMiddleware<AZ>>,
}

// This is added to the extensions of a request. The authentication (authn)
// middleware populates the `principals` field, and the authorization (authz)
// middleware sets the `authorization` field.
#[derive(Clone)]
pub struct AuthContext<AZ: Authorization> {
    pub principals: Vec<Principal>,
    pub authorization: Option<AZ>,
}

/// Clients may want to include Authorization information (distinct from "authentication" which this
/// crate provides) in the AuthContext. This trait allows clients to tag a type as containing
/// Authorization info, so that it can work as the generic type for AuthContext<T>.
pub trait Authorization: Clone + Send + Sync + 'static {}

pub type NoAuthorization = ();
impl Authorization for NoAuthorization {}

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
    pub fn new(org: Option<String>, group: String, user: Option<String>) -> Self {
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
    pub fn try_from_client_certificate<AZ: Authorization>(
        certificate: &CertificateDer,
        auth_context: &CertDescriptionMiddleware<AZ>,
    ) -> Result<Principal, SpiffeError> {
        match crate::validate_x509_certificate(certificate.as_ref()) {
            Ok(spiffe_id) => {
                let service_id = auth_context
                    .spiffe_context
                    .extract_service_identifier(&spiffe_id)?;
                Ok(match service_id {
                    crate::SpiffeIdClass::Service(service_id) => {
                        Principal::SpiffeServiceIdentifier(service_id)
                    }
                    crate::SpiffeIdClass::Machine(machine_id) => {
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
fn try_external_cert<AZ: Authorization>(
    der_certificate: &[u8],
    auth_context: &CertDescriptionMiddleware<AZ>,
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

// Checks if the given cert is an acceptable user based on per site criteria
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

impl<T: Authorization> AuthContext<T> {
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

impl<T: Authorization> Default for AuthContext<T> {
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

// This is used as an extension to requests for anything that is an attribute of
// the connection the request came in on, as opposed to the HTTP request itself.
// Note that if you're trying to retrieve it, it's probably inside an Arc in the
// extensions typemap, so .get::<Arc<ConnectionAttributes>>() is what you want.
pub struct ConnectionAttributes {
    pub peer_address: SocketAddr,
    pub peer_certificates: Vec<CertificateDer<'static>>,
}

impl<S, B, AZ> Service<Request<B>> for CertDescriptionService<S, AZ>
where
    B: tonic::codegen::Body,
    S: Service<Request<B>>,
    AZ: Authorization,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        if let Some(_req_auth_header) = request.headers().get(hyper::header::AUTHORIZATION) {
            // If we want to extract additional principals from the request's
            // Authorization header, we can do it here.
        }
        let extensions = request.extensions_mut();
        let mut auth_context = AuthContext::<AZ>::default();
        if let Some(conn_attrs) = extensions.get::<Arc<ConnectionAttributes>>() {
            let peer_certs = &conn_attrs.peer_certificates;
            let peer_cert_principals = peer_certs.iter().filter_map(|cert| {
                match Principal::try_from_client_certificate(cert, &self.authorization_context) {
                    Ok(x) => Some(x),
                    Err(e) => {
                        tracing::debug!(
                            "Saw bad certificate from {:?}: {e}",
                            conn_attrs.peer_address,
                        );
                        None
                    }
                }
            });
            auth_context.principals.extend(peer_cert_principals);
            // Regardless of whether we were able to get a specific Principal
            // flavor out of the certificate, having a trusted certificate
            // presented by the client is worth recording on its own.
            if !peer_certs.is_empty() {
                auth_context.principals.push(Principal::TrustedCertificate);
            }
        } else {
            tracing::warn!("No ConnectionAttributes in request extensions!");
        }

        extensions.insert(auth_context);
        self.inner.call(request)
    }
}
