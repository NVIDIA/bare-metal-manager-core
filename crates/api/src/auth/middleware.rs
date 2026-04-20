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

use carbide_authn::middleware::Principal;
use futures_util::future::BoxFuture;
use hyper::{Request, Response, StatusCode};
use tonic::service::AxumBody;
use tower_http::auth::AsyncAuthorizeRequest;

use crate::auth::internal_rbac_rules::InternalRBACRules;
use crate::auth::{AuthContext, CasbinAuthorizer, Predicate};

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
                            extensions.get::<Arc<carbide_authn::middleware::ConnectionAttributes>>()
                        {
                            conn_attrs.peer_address.to_string()
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
