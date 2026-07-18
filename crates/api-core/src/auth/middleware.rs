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
use std::sync::Arc;

use carbide_authn::middleware::{ConnectionAttributes, Principal};
use futures_util::future::BoxFuture;
use hyper::{Request, Response, StatusCode};
use tonic::service::AxumBody;
use tower_http::auth::AsyncAuthorizeRequest;

use crate::auth::internal_rbac_rules::InternalRBACRules;
use crate::auth::{AuthContext, CasbinAuthorizer, Predicate};

/// A caller was denied by an authorizer -- the canonical security signal.
/// The denial rate is the alert; `authorizer` names the engine that denied
/// and `principal_class` the strongest identity the caller presented. The
/// denied method, principals, and client address ride the log line. (The
/// method is deliberately NOT a metric label: the path segment is
/// caller-supplied, so it would mint unbounded series. A per-method label
/// needs a real method registry to bucket against.)
#[derive(carbide_instrument::Event)]
#[event(
    event_name = "authorization_denied",
    metric_name = "carbide_auth_denied_total",
    component = "nico-api",
    log = info,
    metric = counter,
    message = "Denied a call to Forge method",
    describe = "Number of Forge calls denied by the authorizer"
)]
struct AuthorizationDenied {
    #[label]
    principal_class: PrincipalClass,
    #[label]
    authorizer: Authorizer,
    #[context]
    method: String,
    #[context]
    principals: String,
    #[context]
    client_address: String,
    #[context]
    reason: String,
}

/// The strongest kind of identity among a request's principals, as the
/// bounded `principal_class` label on [`AuthorizationDenied`]. Variants are
/// declared weakest-first so the derived `Ord` is the precedence order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, carbide_instrument::LabelValue)]
enum PrincipalClass {
    Anonymous,
    TrustedCertificate,
    SpiffeMachine,
    SpiffeService,
    ExternalUser,
}

impl PrincipalClass {
    fn classify(principals: &[Principal]) -> Self {
        principals
            .iter()
            .map(|principal| match principal {
                Principal::ExternalUser(_) => PrincipalClass::ExternalUser,
                Principal::SpiffeServiceIdentifier(_) => PrincipalClass::SpiffeService,
                Principal::SpiffeMachineIdentifier(_) => PrincipalClass::SpiffeMachine,
                Principal::TrustedCertificate => PrincipalClass::TrustedCertificate,
                Principal::Anonymous => PrincipalClass::Anonymous,
            })
            .max()
            // A request that presented no principals at all is anonymous.
            .unwrap_or(PrincipalClass::Anonymous)
    }
}

/// Which authorization engine denied the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, carbide_instrument::LabelValue)]
enum Authorizer {
    Casbin,
    InternalRbac,
}

/// The peer address of the connection a request arrived on, as recorded by
/// the authentication middleware; `None` for a request that never passed
/// through it (misordered layers, in-process tests).
fn peer_address<B>(request: &Request<B>) -> Option<std::net::SocketAddr> {
    request
        .extensions()
        .get::<Arc<ConnectionAttributes>>()
        .map(|conn_attrs| conn_attrs.peer_address)
}

/// The denial log's rendering of [`peer_address`]: allocated only when a
/// request is actually denied.
fn client_address(peer_address: Option<std::net::SocketAddr>) -> String {
    peer_address
        .map(|address| address.to_string())
        .unwrap_or_else(|| "<Unable to determine client address>".to_string())
}

// An authorization handler to plug into tower_http::auth::AsyncAuthorizeRequest.
// According to the docs for AsyncAuthorizeRequest, we're _supposed_ to use the
// HTTP Authorization header to perform our custom logic, but as far as I can
// tell from the implementation in the code, we are free to do it however we
// like without violating any contracts.
#[derive(Clone)]
pub struct CasbinHandler {
    authorizer: Arc<CasbinAuthorizer>,
}

impl CasbinHandler {
    pub fn new(authorizer: Arc<CasbinAuthorizer>) -> Self {
        CasbinHandler { authorizer }
    }
}

impl<B> AsyncAuthorizeRequest<B> for CasbinHandler
where
    B: Send + Sync + 'static,
{
    type RequestBody = B;
    type ResponseBody = AxumBody;
    type Future = BoxFuture<'static, Result<Request<B>, Response<Self::ResponseBody>>>;

    fn authorize(&mut self, mut request: Request<B>) -> Self::Future {
        let authorizer = self.authorizer.clone();
        Box::pin(async move {
            use RequestClass::*;
            let request_permitted = match RequestClass::from(&request) {
                // Forge-owned endpoints must go through access control.
                ForgeMethod(method_name) => {
                    // Read before AuthContext borrows the extensions mutably;
                    // the denial emit below needs it. Copy, not a String: the
                    // allowed path -- almost every request -- never formats it.
                    let peer_address = peer_address(&request);
                    let req_auth_context = request
                        .extensions_mut()
                        .get_mut::<AuthContext>()
                        .ok_or_else(|| {
                            tracing::warn!(
                                "CasbinHandler::authorize() found a request with \
                                no AuthContext in its extensions. This may mean \
                                the authentication middleware didn't run \
                                successfully, or the middleware layers are \
                                nested in the wrong order."
                            );
                            empty_response_with_status(StatusCode::INTERNAL_SERVER_ERROR)
                        })?;

                    let principals = req_auth_context.principals.as_slice();
                    let predicate = Predicate::ForgeCall(method_name.clone());
                    match authorizer.authorize(&principals, predicate) {
                        Ok(authorization) => {
                            if let Some(Principal::ExternalUser(info)) = principals
                                .iter()
                                .find(|x| matches!(x, Principal::ExternalUser(_)))
                            {
                                // Inject the User ID as attribute into the current span.
                                // The name of the field matches OTEL semantic conventions
                                tracing::Span::current().record(
                                    "user.id",
                                    info.user.as_deref().unwrap_or("nameless user"),
                                );
                            }
                            req_auth_context.authorization = Some(authorization);
                            true
                        }
                        Err(e) => {
                            carbide_instrument::emit(AuthorizationDenied {
                                principal_class: PrincipalClass::classify(principals),
                                authorizer: Authorizer::Casbin,
                                method: method_name,
                                // audit_identity() keeps each principal's concrete
                                // identity (which machine was denied) while keeping
                                // ExternalUserInfo payloads out of the log line.
                                principals: principals
                                    .iter()
                                    .map(Principal::audit_identity)
                                    .collect::<Vec<_>>()
                                    .join(","),
                                client_address: client_address(peer_address),
                                reason: e.to_string(),
                            });
                            false
                        }
                    }
                }

                // Anyone can talk to the reflection service.
                GrpcReflection => true,

                // XXX: Should we do something different here? It might just
                // be a malformed request, but could also be a bug in the
                // RequestClass implementation.
                // At a minimum, anything in the web UI hits this, so we will need to handle those correctly before
                // returning errors for this.
                Unrecognized => {
                    let request_path = request.uri().path();
                    tracing::debug!(request_path, "No authorization policy matched this request");
                    true
                }
            };

            match request_permitted {
                true => Ok(request),
                false => Err(empty_response_with_status(StatusCode::FORBIDDEN)),
            }
        })
    }
}

// We use this to classify requests for readability inside the authorization
// middleware.
enum RequestClass {
    ForgeMethod(String),
    GrpcReflection,
    Unrecognized,
}

impl<B> From<&Request<B>> for RequestClass {
    fn from(request: &Request<B>) -> Self {
        use RequestClass::*;

        let endpoint_path = request.uri().path();
        let endpoint_path = match endpoint_path.strip_prefix('/') {
            Some(relative_path) => relative_path,
            None => return Unrecognized,
        };

        if let Some((service_name, method_name)) = endpoint_path.split_once('/') {
            match (service_name, method_name) {
                ("forge.Forge", m) => ForgeMethod(m.into()),
                (s, "ServerReflectionInfo") if s.ends_with(".ServerReflection") => GrpcReflection,
                _ => Unrecognized,
            }
        } else {
            Unrecognized
        }
    }
}

fn empty_response_with_status(status: StatusCode) -> Response<AxumBody> {
    Response::builder()
        .status(status)
        .body(AxumBody::default())
        .unwrap()
}

#[derive(Clone)]
pub struct InternalRBACHandler {}

impl InternalRBACHandler {
    pub fn new() -> Self {
        Self {}
    }
}
impl Default for InternalRBACHandler {
    fn default() -> Self {
        Self::new()
    }
}
impl<B> AsyncAuthorizeRequest<B> for InternalRBACHandler
where
    B: Send + Sync + 'static,
{
    type RequestBody = B;
    type ResponseBody = AxumBody;
    type Future = BoxFuture<'static, Result<Request<B>, Response<Self::ResponseBody>>>;

    fn authorize(&mut self, request: Request<B>) -> Self::Future {
        Box::pin(async move {
            let request_permitted = match RequestClass::from(&request) {
                // Forge-owned endpoints must go through access control.
                RequestClass::ForgeMethod(method_name) => {
                    let req_auth_context =
                        request.extensions().get::<AuthContext>().ok_or_else(|| {
                            tracing::warn!(
                                "InternalRBACHandler::authorize() found a request with \
                                no AuthContext in its extensions. This may mean \
                                the authentication middleware didn't run \
                                successfully, or the middleware layers are \
                                nested in the wrong order."
                            );
                            empty_response_with_status(StatusCode::INTERNAL_SERVER_ERROR)
                        })?;
                    let principals = &req_auth_context.principals;

                    let allowed = InternalRBACRules::allowed_from_static(&method_name, principals);

                    if !allowed {
                        carbide_instrument::emit(AuthorizationDenied {
                            principal_class: PrincipalClass::classify(principals),
                            authorizer: Authorizer::InternalRbac,
                            method: method_name,
                            principals: principals
                                .iter()
                                .map(Principal::audit_identity)
                                .collect::<Vec<_>>()
                                .join(","),
                            client_address: client_address(peer_address(&request)),
                            reason: "no internal RBAC rule permits these principals".to_string(),
                        });
                    }
                    allowed
                }

                _ => {
                    // We don't do anything for other types.
                    true
                }
            };

            match request_permitted {
                true => Ok(request),
                false => Err(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(AxumBody::default())
                    .unwrap()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use carbide_authn::middleware::ExternalUserInfo;
    use carbide_instrument::testing::{CapturedLog, MetricsCapture, capture_logs};
    use carbide_test_support::{Check, check_values};
    use futures_util::FutureExt as _;

    use super::*;
    use crate::auth::{Authorization, AuthorizationError, PolicyEngine};

    /// Denies everything, standing in for a Casbin policy with no matching rule.
    struct DenyAll;

    impl PolicyEngine for DenyAll {
        fn authorize(
            &self,
            _principals: &[Principal],
            _predicate: Predicate,
        ) -> Result<Authorization, AuthorizationError> {
            Err(AuthorizationError::Unauthorized)
        }
    }

    /// A Forge-method request presenting `principals`, arriving from
    /// `peer_address` per the connection middleware's attributes.
    fn forge_request(uri: &str, principals: Vec<Principal>, peer_address: &str) -> Request<()> {
        let mut request = Request::builder().uri(uri).body(()).expect("request");
        request.extensions_mut().insert(AuthContext {
            principals,
            authorization: None,
        });
        request
            .extensions_mut()
            .insert(Arc::new(ConnectionAttributes {
                peer_address: peer_address.parse().expect("socket address"),
                peer_certificates: Vec::new(),
            }));
        request
    }

    fn field<'a>(log: &'a CapturedLog, name: &str) -> Option<&'a str> {
        log.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The denial branch is a contract: one emit writes the log line (method,
    /// principals, client address, reason) AND moves carbide_auth_denied_total
    /// under the caller's principal class, and the caller gets 403.
    #[test]
    fn denied_forge_call_logs_and_counts() {
        let metrics = MetricsCapture::start();
        let mut handler = CasbinHandler::new(Arc::new(CasbinAuthorizer::new(Arc::new(DenyAll))));

        let logs = capture_logs(|| {
            let request = forge_request(
                "/forge.Forge/PowerControl",
                vec![Principal::TrustedCertificate],
                "203.0.113.9:52011",
            );

            let result = handler
                .authorize(request)
                .now_or_never()
                .expect("the authorization future has no awaits");
            let response = result.expect_err("DenyAll must reject the call");
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        });

        let denial = logs
            .iter()
            .find(|log| log.message == "Denied a call to Forge method")
            .expect("the denial log line");
        assert_eq!(
            field(denial, "principal_class"),
            Some("trusted_certificate")
        );
        assert_eq!(field(denial, "authorizer"), Some("casbin"));
        assert_eq!(field(denial, "method"), Some("PowerControl"));
        assert_eq!(field(denial, "principals"), Some("trusted-certificate"));
        assert_eq!(field(denial, "client_address"), Some("203.0.113.9:52011"));
        assert_eq!(
            field(denial, "reason").expect("reason field"),
            AuthorizationError::Unauthorized.to_string()
        );

        assert_eq!(
            metrics.counter_delta(
                "carbide_auth_denied_total",
                &[
                    ("principal_class", "trusted_certificate"),
                    ("authorizer", "casbin"),
                ],
            ),
            1.0
        );
    }

    /// The internal RBAC denial path emits the same event as the Casbin path,
    /// distinguished by the authorizer label, and the caller gets 403.
    #[test]
    fn denied_internal_rbac_call_logs_and_counts() {
        let metrics = MetricsCapture::start();
        let mut handler = InternalRBACHandler::new();

        let logs = capture_logs(|| {
            // MachineSetup permits only the admin CLI, never a bare trusted
            // certificate.
            let request = forge_request(
                "/forge.Forge/MachineSetup",
                vec![Principal::TrustedCertificate],
                "198.51.100.4:40000",
            );

            let result = handler
                .authorize(request)
                .now_or_never()
                .expect("the authorization future has no awaits");
            let response = result.expect_err("the internal RBAC rules must reject the call");
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        });

        let denial = logs
            .iter()
            .find(|log| log.message == "Denied a call to Forge method")
            .expect("the denial log line");
        assert_eq!(
            field(denial, "principal_class"),
            Some("trusted_certificate")
        );
        assert_eq!(field(denial, "authorizer"), Some("internal_rbac"));
        assert_eq!(field(denial, "method"), Some("MachineSetup"));
        assert_eq!(field(denial, "principals"), Some("trusted-certificate"));
        assert_eq!(field(denial, "client_address"), Some("198.51.100.4:40000"));

        assert_eq!(
            metrics.counter_delta(
                "carbide_auth_denied_total",
                &[
                    ("principal_class", "trusted_certificate"),
                    ("authorizer", "internal_rbac"),
                ],
            ),
            1.0
        );
    }

    /// principal_class is the strongest identity present; an empty principal
    /// set is anonymous.
    #[test]
    fn principal_class_is_the_strongest_principal() {
        let spiffe_service = || Principal::SpiffeServiceIdentifier("machine-a-tron".to_string());
        let spiffe_machine = || Principal::SpiffeMachineIdentifier("fm100".to_string());
        let external_user =
            || Principal::ExternalUser(ExternalUserInfo::new(None, "admins".to_string(), None));

        check_values(
            [
                Check {
                    scenario: "no principals at all",
                    input: vec![],
                    expect: PrincipalClass::Anonymous,
                },
                Check {
                    scenario: "an explicit anonymous principal",
                    input: vec![Principal::Anonymous],
                    expect: PrincipalClass::Anonymous,
                },
                Check {
                    scenario: "a trusted certificate outranks anonymous",
                    input: vec![Principal::Anonymous, Principal::TrustedCertificate],
                    expect: PrincipalClass::TrustedCertificate,
                },
                Check {
                    scenario: "a machine identity outranks its trusted certificate",
                    input: vec![spiffe_machine(), Principal::TrustedCertificate],
                    expect: PrincipalClass::SpiffeMachine,
                },
                Check {
                    scenario: "a service identity outranks a machine identity",
                    input: vec![
                        Principal::TrustedCertificate,
                        spiffe_machine(),
                        spiffe_service(),
                    ],
                    expect: PrincipalClass::SpiffeService,
                },
                Check {
                    scenario: "an external user outranks everything",
                    input: vec![
                        spiffe_service(),
                        external_user(),
                        Principal::TrustedCertificate,
                    ],
                    expect: PrincipalClass::ExternalUser,
                },
            ],
            |principals| PrincipalClass::classify(&principals),
        );
    }
}
