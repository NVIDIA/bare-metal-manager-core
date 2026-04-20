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

use carbide_authn::middleware::{ExternalUserInfo, Principal};

use crate::CarbideError;

mod casbin_engine;
pub mod internal_rbac_rules;
pub mod middleware;
pub mod mqtt_auth;
mod test_certs;

pub type AuthContext = carbide_authn::middleware::AuthContext<Authorization>;

// An Authorization is sort of like a ticket that says we're allowed to do the
// thing we're trying to do, and specifically which Principal was permitted to
// do it.
#[derive(Clone, Debug)]
pub struct Authorization {
    _principal: Principal, // Currently unused
    _predicate: Predicate, // Currently unused
}

impl carbide_authn::middleware::Authorization for Authorization {}

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

    use carbide_authn::SpiffeContext;
    use carbide_authn::config::{AllowedCertCriteria, CertComponent};
    use carbide_authn::middleware::CertDescriptionMiddleware;
    use carbide_authn::spiffe_id::TrustDomain;
    use eyre::Context;

    use super::*;

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
        let context: CertDescriptionMiddleware<Authorization> = CertDescriptionMiddleware::new(
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
            SpiffeContext {
                trust_domain: TrustDomain::new("example.test").unwrap(),
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
