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

use futures_util::future::BoxFuture;
use hyper::{Request, Response, StatusCode};
use tonic::service::AxumBody;
use tower::{Layer, Service};
use tower_http::auth::AsyncAuthorizeRequest;

use crate::auth::forge_spiffe::ForgeSpiffeContext;
use crate::auth::internal_rbac_rules::InternalRBACRules;
use crate::auth::{AuthContext, CasbinAuthorizer, Predicate, Principal};
use crate::cfg::file::AllowedCertCriteria;
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
pub struct CertDescriptionMiddleware {
    pub spiffe_context: Arc<ForgeSpiffeContext>,
    pub extra_allowed_certs: Option<AllowedCertCriteria>,
}

impl CertDescriptionMiddleware {
    pub fn new(
        extra_allowed_certs: Option<AllowedCertCriteria>,
        spiffe_context: ForgeSpiffeContext,
    ) -> Self {
        CertDescriptionMiddleware {
            spiffe_context: Arc::new(spiffe_context),
            extra_allowed_certs,
        }
    }
}

impl<S> Layer<S> for CertDescriptionMiddleware {
    type Service = CertDescriptionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CertDescriptionService {
            inner,
            authorization_context: Arc::new(self.clone()),
        }
    }
}

#[derive(Clone)]
pub struct CertDescriptionService<S> {
    inner: S,
    authorization_context: Arc<CertDescriptionMiddleware>,
}

impl<S, B> Service<Request<B>> for CertDescriptionService<S>
where
    B: tonic::codegen::Body,
    S: Service<Request<B>>,
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
        let mut auth_context = AuthContext::default();
        if let Some(conn_attrs) = extensions.get::<Arc<crate::listener::ConnectionAttributes>>() {
            let peer_certs = conn_attrs.peer_certificates();
            let peer_cert_principals = peer_certs.iter().filter_map(|cert| {
                match Principal::try_from_client_certificate(cert, &self.authorization_context) {
                    Ok(x) => Some(x),
                    Err(e) => {
                        tracing::debug!(
                            "Saw bad certificate from {:?}: {e}",
                            conn_attrs.peer_address()
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
                            tracing::info!(
                                method_name,
                                ?principals,
                                "Denied a call to Forge method because of authorizer result '{e}'"
                            );
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

    fn authorize(&mut self, mut request: Request<B>) -> Self::Future {
        Box::pin(async move {
            let request_permitted = match RequestClass::from(&request) {
                // Forge-owned endpoints must go through access control.
                RequestClass::ForgeMethod(method_name) => {
                    let extensions = request.extensions_mut();
                    let req_auth_context = extensions.get::<AuthContext>().ok_or_else(|| {
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
                        let client_address = if let Some(conn_attrs) =
                            extensions.get::<Arc<crate::listener::ConnectionAttributes>>()
                        {
                            conn_attrs.peer_address().to_string()
                        } else {
                            "<Unable to determine client address>".to_string()
                        };
                        tracing::info!(
                            "Request denied: {client_address} {method_name} {principals:?}",
                        );
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
