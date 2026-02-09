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
use ::rpc::forge as rpc;
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialProvider, Credentials,
};
use sqlx::PgPool;

use crate::CarbideError;
use crate::api::{Api, TransactionVending, log_request_data};
use crate::handlers::bmc_endpoint_explorer::validate_and_complete_bmc_endpoint_request;

pub(crate) async fn get(
    api: &Api,
    request: tonic::Request<rpc::BmcMetaDataGetRequest>,
) -> Result<tonic::Response<rpc::BmcMetaDataGetResponse>, tonic::Status> {
    log_request_data(&request);
    let request = request.into_inner();

    let response = get_inner(
        request,
        &api.database_connection,
        api.credential_provider.as_ref(),
    )
    .await?;

    Ok(response.into())
}

/// This is a separate function so it can be called from redfish_apply_action to build a custom BMC
/// client.
pub(crate) async fn get_inner(
    request: rpc::BmcMetaDataGetRequest,
    pool: &PgPool,
    credential_provider: &dyn CredentialProvider,
) -> Result<rpc::BmcMetaDataGetResponse, CarbideError> {
    let mut txn = pool.txn_begin().await?;
    let (bmc_endpoint_request, _) = validate_and_complete_bmc_endpoint_request(
        &mut txn,
        request.bmc_endpoint_request,
        request.machine_id,
    )
    .await?;
    txn.commit().await?;

    let Some(bmc_mac_address) = bmc_endpoint_request.mac_address else {
        return Err(CarbideError::NotFoundError {
            kind: "bmc_metadata",
            id: format!(
                "MachineId: {}, IP: {}",
                request
                    .machine_id
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                bmc_endpoint_request.ip_address
            ),
        });
    };

    let bmc_mac_address: mac_address::MacAddress = match bmc_mac_address.parse() {
        Ok(m) => m,
        Err(_) => {
            let e = format!(
                "The MAC address {bmc_mac_address} resolved for MachineId {}, IP {} is not valid",
                request
                    .machine_id
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                bmc_endpoint_request.ip_address
            );
            tracing::error!(e);
            return Err(CarbideError::internal(e));
        }
    };

    let credentials = credential_provider
        .get_credentials(&CredentialKey::BmcCredentials {
            credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
        })
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?
        .ok_or_else(|| CarbideError::internal("missing credentials".to_string()))?;

    let (username, password) = match credentials {
        Credentials::UsernamePassword { username, password } => (username, password),
    };

    Ok(rpc::BmcMetaDataGetResponse {
        ip: bmc_endpoint_request.ip_address,
        port: None,
        ssh_port: None,
        ipmi_port: None,
        mac: bmc_mac_address.to_string(),
        user: username,
        password,
    })
}
