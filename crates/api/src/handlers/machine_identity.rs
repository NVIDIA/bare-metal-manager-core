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

//! gRPC handler for machine identity (JWT-SVID SignMachineIdentity).
//! Business logic lives in the `crate::machine_identity` module.

use ::rpc::forge::{self as rpc, MachineIdentityResponse};
use tonic::{Request, Response, Status};

use crate::api::{Api, log_request_data};
use crate::auth::AuthContext;

/// Handles the SignMachineIdentity gRPC call: validates the request, extracts
/// machine identity from the client certificate, and returns a JWT-SVID response.
///
/// The machine_id is taken from the client's mTLS certificate SPIFFE ID.
/// Actual signing and key loading are implemented in `crate::machine_identity`.
#[allow(dead_code, clippy::unused_async)]
pub(crate) async fn sign_machine_identity(
    _api: &Api,
    request: Request<rpc::MachineIdentityRequest>,
) -> Result<Response<MachineIdentityResponse>, Status> {
    log_request_data(&request);

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
        .map_err(|e| Status::invalid_argument(format!("Invalid machine ID format: {}", e)))?;

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
