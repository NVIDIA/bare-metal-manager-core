/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
