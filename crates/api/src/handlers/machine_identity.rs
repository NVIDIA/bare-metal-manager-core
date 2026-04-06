/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use it except in compliance with the License.
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

//! gRPC handlers for machine identity: JWT-SVID signing, JWKS, and OpenID discovery.
//! PEM/JWK encoding helpers live in `crate::machine_identity`; persisted config in `tenant_identity_config`.

use std::convert::TryFrom;

use ::rpc::forge::{
    self as rpc, Jwks, JwksKind, JwksRequest, MachineIdentityResponse, OpenIdConfigRequest,
    OpenIdConfiguration,
};
use db::{WithTransaction, tenant, tenant_identity_config};
use model::tenant::{InvalidTenantOrg, TenantIdentityConfig, TenantOrganizationId};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::auth::AuthContext;

/// Shared gate for APIs that require site `[machine_identity].enabled` (identity admin + discovery).
pub(crate) fn require_machine_identity_site_enabled(api: &Api) -> Result<(), Status> {
    if !api.runtime_config.machine_identity.enabled {
        return Err(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config".to_string(),
        )
        .into());
    }
    Ok(())
}

fn jwks_uri_for_issuer(issuer: &str) -> String {
    let base = issuer.trim_end_matches('/');
    format!("{base}/.well-known/jwks.json")
}

fn spiffe_jwks_uri_for_issuer(issuer: &str) -> String {
    let base = issuer.trim_end_matches('/');
    format!("{base}/.well-known/spiffe/jwks.json")
}

async fn load_enabled_identity_for_well_known(
    api: &Api,
    org_id: &TenantOrganizationId,
) -> Result<TenantIdentityConfig, Status> {
    let org_id_str = org_id.as_str().to_string();
    let (cfg, _tenant) = api
        .database_connection
        .with_txn(|txn| {
            let org_id = org_id.clone();
            Box::pin(async move {
                let cfg = tenant_identity_config::find(&org_id, txn).await?;
                let tenant = tenant::find(org_id.as_str(), false, txn).await?;
                Ok::<_, db::DatabaseError>((cfg, tenant))
            })
        })
        .await??;
    let cfg = match cfg {
        Some(c) if c.enabled => c,
        _ => {
            return Err(CarbideError::NotFoundError {
                kind: "tenant_identity_config",
                id: org_id_str,
            }
            .into());
        }
    };
    Ok(cfg)
}

/// Handles the SignMachineIdentity gRPC call: validates the request, extracts
/// machine identity from the client certificate, and returns a JWT-SVID response.
///
/// The machine_id is taken from the client's mTLS certificate SPIFFE ID.
/// Actual signing and key loading are implemented in `crate::machine_identity`.
#[allow(dead_code, clippy::unused_async)]
pub(crate) async fn sign_machine_identity(
    api: &Api,
    request: Request<rpc::MachineIdentityRequest>,
) -> Result<Response<MachineIdentityResponse>, Status> {
    log_request_data(&request);

    if !api.runtime_config.machine_identity.enabled {
        return Err(CarbideError::UnavailableError(
            "Machine identity is disabled in site config".into(),
        )
        .into());
    }

    let auth_context = request
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| Status::unauthenticated("No authentication context found"))?;

    let machine_id_str = auth_context
        .get_spiffe_machine_id()
        .ok_or_else(|| Status::unauthenticated("No machine identity in client certificate"))?;

    tracing::info!(machine_id = %machine_id_str, "Processing machine identity request");

    let _machine_id: carbide_uuid::machine::MachineId = machine_id_str
        .parse()
        .map_err(|e| CarbideError::InvalidArgument(format!("Invalid machine ID format: {}", e)))?;

    let req = request.get_ref();
    let _audience = &req.audience; // TODO: Use audience in JWT claims

    // TODO: Implement the full JWT-SVID signing flow:
    // 1. Validate the machine exists and is authorized
    // 2. Retrieve the tenant's encrypted signing key from the database
    // 3. Decrypt the signing key using the master key from Vault KV
    // 4. Generate JWT-SVID with SPIFFE ID (spiffe://<trust-domain>/machine/<machine-id>)
    // 5. Sign the JWT with the tenant's private key
    // 6. Optionally call Exchange Token Service for token exchange

    // TODO: Call into crate::machine_identity for key loading and signing once implemented
    let response = MachineIdentityResponse {
        access_token: String::new(), // TODO: Generate actual JWT-SVID
        issued_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: "3600".to_string(), // 1 hour default
    };

    Ok(Response::new(response))
}

/// Public JWKS for JWT verification (intended for unauthenticated callers via REST gateway).
pub(crate) async fn get_jwks(
    api: &Api,
    request: Request<JwksRequest>,
) -> Result<Response<Jwks>, Status> {
    log_request_data(&request);
    require_machine_identity_site_enabled(api)?;

    let req = request.into_inner();
    let org_raw = req.organization_id.trim();
    if org_raw.is_empty() {
        return Err(
            CarbideError::InvalidArgument("organization_id is required".to_string()).into(),
        );
    }
    let org_id: TenantOrganizationId = org_raw
        .parse()
        .map_err(|e: InvalidTenantOrg| CarbideError::InvalidArgument(e.to_string()))?;

    let jwks_kind = match req.kind {
        None => JwksKind::Unspecified,
        Some(raw) => JwksKind::try_from(raw).map_err(|_| {
            CarbideError::InvalidArgument(format!("invalid JwksRequest.kind enum value: {raw}"))
        })?,
    };

    let jwk_key_use = match jwks_kind {
        JwksKind::Unspecified | JwksKind::Oidc => {
            crate::machine_identity::JwkPublicKeyUse::OidcSignature
        }
        JwksKind::Spiffe => crate::machine_identity::JwkPublicKeyUse::SpiffeJwtSvid,
    };

    let cfg = load_enabled_identity_for_well_known(api, &org_id).await?;

    if cfg.signing_key_public.trim().is_empty() || cfg.key_id.trim().is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "tenant_identity_config",
            id: org_id.as_str().to_string(),
        }
        .into());
    }

    let jwk = crate::machine_identity::public_pem_to_jwk_value(
        &cfg.signing_key_public,
        &cfg.key_id,
        &cfg.algorithm,
        jwk_key_use,
    )
    .map_err(|e| CarbideError::InvalidArgument(e.to_string()))?;
    let jwks = crate::machine_identity::jwks_document_string(&jwk)
        .map_err(|e| CarbideError::InvalidArgument(e.to_string()))?;

    Ok(Response::new(Jwks { jwks }))
}

/// OpenID Provider–shaped metadata (issuer, JWKS URIs). Signing algorithms come from GetJWKS `jwks` (`keys[].alg`).
pub(crate) async fn get_open_id_configuration(
    api: &Api,
    request: Request<OpenIdConfigRequest>,
) -> Result<Response<OpenIdConfiguration>, Status> {
    log_request_data(&request);
    require_machine_identity_site_enabled(api)?;

    let req = request.into_inner();
    let org_raw = req.organization_id.trim();
    if org_raw.is_empty() {
        return Err(
            CarbideError::InvalidArgument("organization_id is required".to_string()).into(),
        );
    }
    let org_id: TenantOrganizationId = org_raw
        .parse()
        .map_err(|e: InvalidTenantOrg| CarbideError::InvalidArgument(e.to_string()))?;

    let cfg = load_enabled_identity_for_well_known(api, &org_id).await?;

    if cfg.issuer.trim().is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "tenant_identity_config",
            id: org_id.as_str().to_string(),
        }
        .into());
    }

    Ok(Response::new(OpenIdConfiguration {
        issuer: cfg.issuer.clone(),
        jwks_uri: jwks_uri_for_issuer(&cfg.issuer),
        spiffe_jwks_uri: spiffe_jwks_uri_for_issuer(&cfg.issuer),
        response_types_supported: vec!["token".into()],
        subject_types_supported: vec!["public".into()],
        id_token_signing_alg_values_supported: vec![],
    }))
}
