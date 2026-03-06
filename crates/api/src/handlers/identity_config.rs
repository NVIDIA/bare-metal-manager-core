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

//! gRPC handlers for tenant_identity_config table.
//! Identity config: issuer, audiences, TTL, signing key (Get/Set/Delete).
//! Token delegation: token exchange config for external IdP (Get/Set/Delete).

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use ::rpc::forge::{
    GetIdentityConfigRequest, GetTokenDelegationRequest, IdentityConfigRequest,
    IdentityConfigResponse, TokenDelegationRequest, TokenDelegationResponse,
};
use ::rpc::Timestamp;
use db::tenant;
use db::tenant_identity_config;
use db::WithTransaction;
use prost_types::value::Kind;
use prost_types::{Struct, Value};
use tonic::{Request, Response, Status};

use crate::api::{log_request_data, Api};
use crate::auth::AuthContext;

// --- Token delegation: Struct/JSON conversion and secret hashing ---

/// Secret keys -> API response hash key. Hash is computed on cleartext only.
/// - client_secret: from API request (cleartext)
/// - encrypted_client_secret: from DB (decrypt first when encryption is enabled)
const SECRET_TO_HASH_KEY: &[(&str, &str)] = &[
    ("client_secret", "client_secret_hash"),
    ("encrypted_client_secret", "client_secret_hash"),
];

/// Secret keys to omit from response without adding a hash (key_id identifies private_key).
const SECRET_KEYS_TO_OMIT: &[&str] = &["private_key", "encrypted_private_key"];

/// Number of hex chars to show (8 chars = 4 bytes of SHA256).
const HASH_PREFIX_HEX_LEN: usize = 8;

/// API key -> DB key. encrypted_* are DB-only, never in API.
const API_TO_DB_SECRET_KEY: &[(&str, &str)] = &[
    ("client_secret", "encrypted_client_secret"),
    ("private_key", "encrypted_private_key"),
];

/// Transforms API request keys to DB keys before persisting.
fn api_config_to_db(config: &serde_json::Value) -> serde_json::Value {
    let obj = match config {
        serde_json::Value::Object(o) => o,
        _ => return config.clone(),
    };
    let out: serde_json::Map<String, serde_json::Value> = obj
        .iter()
        .map(|(k, v)| {
            let key_lower = k.to_lowercase();
            let db_key = API_TO_DB_SECRET_KEY
                .iter()
                .find(|(api, _)| key_lower == *api)
                .map(|(_, db)| db.to_string())
                .unwrap_or_else(|| k.clone());
            (db_key, api_config_to_db(v))
        })
        .collect();
    serde_json::Value::Object(out)
}

fn struct_to_json(pb: &Struct) -> serde_json::Value {
    let obj: serde_json::Map<String, serde_json::Value> = pb
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), value_to_json(v)))
        .collect();
    serde_json::Value::Object(obj)
}

fn value_to_json(pb: &Value) -> serde_json::Value {
    match &pb.kind {
        Some(Kind::NullValue(_)) => serde_json::Value::Null,
        Some(Kind::NumberValue(n)) => serde_json::Value::Number(
            serde_json::Number::from_f64(*n).unwrap_or(serde_json::Number::from(0)),
        ),
        Some(Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(Kind::StructValue(s)) => struct_to_json(s),
        Some(Kind::ListValue(l)) => {
            let arr: Vec<serde_json::Value> = l.values.iter().map(value_to_json).collect();
            serde_json::Value::Array(arr)
        }
        None => serde_json::Value::Null,
    }
}

fn json_to_struct(json: &serde_json::Value) -> Option<Struct> {
    let obj = json.as_object()?;
    let fields: BTreeMap<String, Value> = obj
        .iter()
        .filter_map(|(k, v)| Some((k.clone(), json_to_value(v)?)))
        .collect();
    Some(Struct { fields })
}

fn json_to_value(json: &serde_json::Value) -> Option<Value> {
    Some(Value {
        kind: Some(match json {
            serde_json::Value::Null => Kind::NullValue(0),
            serde_json::Value::Number(n) => Kind::NumberValue(n.as_f64()?),
            serde_json::Value::String(s) => Kind::StringValue(s.clone()),
            serde_json::Value::Bool(b) => Kind::BoolValue(*b),
            serde_json::Value::Array(a) => {
                let values: Vec<Value> = a.iter().filter_map(json_to_value).collect();
                Kind::ListValue(prost_types::ListValue { values })
            }
            serde_json::Value::Object(o) => {
                let fields: BTreeMap<String, Value> = o
                    .iter()
                    .filter_map(|(k, v)| Some((k.clone(), json_to_value(v)?)))
                    .collect();
                Kind::StructValue(Struct { fields })
            }
        }),
    })
}

/// Builds response auth_method_config: omits secrets, adds *_hash fields with sha256: prefix.
/// Hash is always computed on cleartext: SHA256(client_secret) on PUT, or SHA256(decrypt(encrypted_*)) on GET.
/// TODO: when encryption is enabled, decrypt encrypted_* before hashing on the read path.
fn build_response_auth_config(config: &serde_json::Value) -> serde_json::Value {
    let obj = match config {
        serde_json::Value::Object(o) => o,
        _ => return config.clone(),
    };
    let mut out: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    let mut hash_keys_added: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (k, v) in obj.iter() {
        let key_lower = k.to_lowercase();
        let omit_only = SECRET_KEYS_TO_OMIT
            .iter()
            .any(|secret| key_lower.contains(&secret.to_lowercase()));
        if omit_only {
            // omit the secret key (key_id identifies private_key)
            continue;
        }
        let secret_entry = SECRET_TO_HASH_KEY
            .iter()
            .find(|(secret, _)| key_lower.contains(&secret.to_lowercase()));

        if let Some((_, hash_key)) = secret_entry {
            if let Some(s) = v.as_str() {
                if !hash_keys_added.contains(*hash_key) {
                    let hash = Sha256::digest(s.as_bytes());
                    let byte_len = (HASH_PREFIX_HEX_LEN / 2).min(hash.len());
                    let prefix = hex::encode(&hash[..byte_len]);
                    out.insert(
                        hash_key.to_string(),
                        serde_json::Value::String(format!("sha256:{prefix}")),
                    );
                    hash_keys_added.insert((*hash_key).to_string());
                }
            }
            // omit the secret key
        } else {
            out.insert(k.clone(), build_response_auth_config(v));
        }
    }
    serde_json::Value::Object(out)
}

// --- Identity configuration handlers ---

/// Handles GetIdentityConfiguration: fetches per-org identity config.
pub(crate) async fn get_identity_configuration(
    api: &Api,
    request: Request<GetIdentityConfigRequest>,
) -> Result<Response<IdentityConfigResponse>, Status> {
    log_request_data(&request);

    request
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| Status::unauthenticated("No authentication context found"))?;

    if !api.runtime_config.machine_identity.enabled {
        return Err(Status::unavailable(
            "Machine identity must be enabled in site config",
        ));
    }

    let req = request.into_inner();
    let org_id = req.org_id.trim();
    if org_id.is_empty() {
        return Err(Status::invalid_argument("org_id is required"));
    }

    let cfg = api
        .database_connection
        .with_txn(|txn| Box::pin(async move { tenant_identity_config::find(org_id, txn).await }))
        .await??;

    let cfg = match cfg {
        Some(c) => c,
        None => return Err(Status::not_found("Identity config not found for org")),
    };

    let allowed_audiences: Vec<String> =
        serde_json::from_value(cfg.allowed_audiences.clone()).unwrap_or_default();

    Ok(Response::new(IdentityConfigResponse {
        org_id: cfg.organization_id,
        enabled: cfg.enabled,
        issuer: cfg.issuer,
        default_audience: cfg.default_audience,
        allowed_audiences,
        token_ttl: cfg.token_ttl as u32,
        subject_domain: cfg.subject_domain_prefix,
        created_at: Some(Timestamp::from(cfg.created_at)),
        updated_at: Some(Timestamp::from(cfg.updated_at)),
        key_id: cfg.key_id,
    }))
}

/// Handles DeleteIdentityConfiguration: removes per-org identity config.
pub(crate) async fn delete_identity_configuration(
    api: &Api,
    request: Request<GetIdentityConfigRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    request
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| Status::unauthenticated("No authentication context found"))?;

    if !api.runtime_config.machine_identity.enabled {
        return Err(Status::unavailable(
            "Machine identity must be enabled in site config",
        ));
    }

    let req = request.into_inner();
    let org_id = req.org_id.trim();
    if org_id.is_empty() {
        return Err(Status::invalid_argument("org_id is required"));
    }

    let deleted = api
        .database_connection
        .with_txn(|txn| Box::pin(async move { tenant_identity_config::delete(org_id, txn).await }))
        .await??;

    if !deleted {
        return Err(Status::not_found("Identity config not found for org"));
    }

    Ok(Response::new(()))
}

/// Handles SetIdentityConfiguration: upserts per-org identity config into tenant_identity_config.
/// Requires auth. Tenant must exist. Key generation is placeholder until Vault integration.
pub(crate) async fn set_identity_configuration(
    api: &Api,
    request: Request<IdentityConfigRequest>,
) -> Result<Response<IdentityConfigResponse>, Status> {
    log_request_data(&request);

    request
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| Status::unauthenticated("No authentication context found"))?;

    if !api.runtime_config.machine_identity.enabled {
        return Err(Status::unavailable(
            "Machine identity must be enabled in site config before setting identity configuration",
        ));
    }

    let req = request.into_inner();
    let org_id = req.org_id.trim();
    if org_id.is_empty() {
        return Err(Status::invalid_argument("org_id is required"));
    }
    if req.issuer.is_empty() {
        return Err(Status::invalid_argument("issuer is required"));
    }
    if req.default_audience.is_empty() {
        return Err(Status::invalid_argument("default_audience is required"));
    }
    if req.subject_domain.is_empty() {
        return Err(Status::invalid_argument("subject_domain is required"));
    }
    let mi = &api.runtime_config.machine_identity;
    if req.token_ttl == 0 {
        return Err(Status::invalid_argument(format!(
            "token_ttl is required (must be between {} and {} seconds)",
            mi.token_ttl_min, mi.token_ttl_max
        )));
    }

    let allowed: Vec<String> = req.allowed_audiences.into_iter().collect();
    let token_ttl = req.token_ttl;
    if token_ttl < mi.token_ttl_min || token_ttl > mi.token_ttl_max {
        return Err(Status::invalid_argument(format!(
            "token_ttl must be between {} and {} seconds",
            mi.token_ttl_min, mi.token_ttl_max
        )));
    }
    let algorithm = mi.algorithm.as_str();
    let master_key_id = "placeholder-master-key";

    let cfg = api
        .database_connection
        .with_txn(|txn| {
            Box::pin(async move {
                let tenant_exists = tenant::find(org_id, false, txn).await?;
                if tenant_exists.is_none() {
                    return Err(db::DatabaseError::NotFoundError {
                        kind: "Tenant",
                        id: org_id.to_string(),
                    });
                }
                tenant_identity_config::set(
                    org_id,
                    &req.issuer,
                    &req.default_audience,
                    &allowed,
                    token_ttl,
                    &req.subject_domain,
                    req.enabled,
                    req.rotate_key,
                    algorithm,
                    master_key_id,
                    txn,
                )
                .await
            })
        })
        .await??;

    let allowed_audiences: Vec<String> =
        serde_json::from_value(cfg.allowed_audiences.clone()).unwrap_or_default();

    Ok(Response::new(IdentityConfigResponse {
        org_id: cfg.organization_id,
        enabled: cfg.enabled,
        issuer: cfg.issuer,
        default_audience: cfg.default_audience,
        allowed_audiences,
        token_ttl: cfg.token_ttl as u32,
        subject_domain: cfg.subject_domain_prefix,
        created_at: Some(Timestamp::from(cfg.created_at)),
        updated_at: Some(Timestamp::from(cfg.updated_at)),
        key_id: cfg.key_id,
    }))
}

// --- Token delegation handlers ---

pub(crate) async fn get_token_delegation(
    api: &Api,
    request: Request<GetTokenDelegationRequest>,
) -> Result<Response<TokenDelegationResponse>, Status> {
    log_request_data(&request);

    request
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| Status::unauthenticated("No authentication context found"))?;

    if !api.runtime_config.machine_identity.enabled {
        return Err(Status::unavailable(
            "Machine identity must be enabled in site config",
        ));
    }

    let req = request.into_inner();
    let org_id = req.org_id.trim();
    if org_id.is_empty() {
        return Err(Status::invalid_argument("org_id is required"));
    }

    let cfg = api
        .database_connection
        .with_txn(|txn| Box::pin(async move { tenant_identity_config::find(org_id, txn).await }))
        .await??;

    let cfg = match cfg {
        Some(c) => c,
        None => return Err(Status::not_found("Identity config not found for org")),
    };

    let auth_method_config = cfg
        .encrypted_auth_method_config
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    let (token_endpoint, auth_method) = match (&cfg.token_endpoint, &cfg.auth_method) {
        (Some(te), Some(am)) => (te.clone(), am.clone()),
        _ => return Err(Status::not_found("Token delegation not configured for org")),
    };

    let redacted = build_response_auth_config(&auth_method_config);
    let pb_struct = json_to_struct(&redacted).unwrap_or_default();

    let created_at = cfg
        .token_delegation_created_at
        .map(Timestamp::from)
        .or_else(|| Some(Timestamp::from(cfg.updated_at)));

    Ok(Response::new(TokenDelegationResponse {
        org_id: cfg.organization_id,
        token_endpoint,
        auth_method,
        auth_method_config: Some(pb_struct),
        subject_token_audience: cfg.subject_token_audience.unwrap_or_default(),
        created_at,
        updated_at: Some(Timestamp::from(cfg.updated_at)),
    }))
}

pub(crate) async fn set_token_delegation(
    api: &Api,
    request: Request<TokenDelegationRequest>,
) -> Result<Response<TokenDelegationResponse>, Status> {
    log_request_data(&request);

    request
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| Status::unauthenticated("No authentication context found"))?;

    if !api.runtime_config.machine_identity.enabled {
        return Err(Status::unavailable(
            "Machine identity must be enabled in site config",
        ));
    }

    let req = request.into_inner();
    let org_id = req.org_id.trim();
    if org_id.is_empty() {
        return Err(Status::invalid_argument("org_id is required"));
    }
    if req.token_endpoint.is_empty() {
        return Err(Status::invalid_argument("token_endpoint is required"));
    }
    if req.auth_method.is_empty() {
        return Err(Status::invalid_argument("auth_method is required"));
    }
    let auth_method_config = req
        .auth_method_config
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("auth_method_config is required"))?;

    let config_json = api_config_to_db(&struct_to_json(auth_method_config));
    let config_str = serde_json::to_string(&config_json).unwrap_or_else(|_| "{}".to_string());

    let cfg = api
        .database_connection
        .with_txn(|txn| {
            Box::pin(async move {
                let tenant_exists = tenant::find(org_id, false, txn).await?;
                if tenant_exists.is_none() {
                    return Err(db::DatabaseError::NotFoundError {
                        kind: "Tenant",
                        id: org_id.to_string(),
                    });
                }
                tenant_identity_config::set_token_delegation(
                    org_id,
                    &req.token_endpoint,
                    &req.auth_method,
                    &config_str,
                    if req.subject_token_audience.is_empty() {
                        None
                    } else {
                        Some(req.subject_token_audience.as_str())
                    },
                    txn,
                )
                .await
            })
        })
        .await??;

    // Use request config for hash: client_secret is cleartext before we store as encrypted_client_secret.
    let config_for_response = struct_to_json(auth_method_config);
    let redacted = build_response_auth_config(&config_for_response);
    let pb_struct = json_to_struct(&redacted).unwrap_or_default();

    let created_at = cfg
        .token_delegation_created_at
        .map(Timestamp::from)
        .or_else(|| Some(Timestamp::from(cfg.updated_at)));

    Ok(Response::new(TokenDelegationResponse {
        org_id: cfg.organization_id,
        token_endpoint: cfg.token_endpoint.unwrap_or_default(),
        auth_method: cfg.auth_method.unwrap_or_default(),
        auth_method_config: Some(pb_struct),
        subject_token_audience: cfg.subject_token_audience.unwrap_or_default(),
        created_at,
        updated_at: Some(Timestamp::from(cfg.updated_at)),
    }))
}

pub(crate) async fn delete_token_delegation(
    api: &Api,
    request: Request<GetTokenDelegationRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    request
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| Status::unauthenticated("No authentication context found"))?;

    if !api.runtime_config.machine_identity.enabled {
        return Err(Status::unavailable(
            "Machine identity must be enabled in site config",
        ));
    }

    let req = request.into_inner();
    let org_id = req.org_id.trim();
    if org_id.is_empty() {
        return Err(Status::invalid_argument("org_id is required"));
    }

    api.database_connection
        .with_txn(|txn| {
            Box::pin(async move {
                tenant_identity_config::delete_token_delegation(org_id, txn).await
            })
        })
        .await??;

    Ok(Response::new(()))
}
