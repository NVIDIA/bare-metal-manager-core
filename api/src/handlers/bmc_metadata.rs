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
use db::DatabaseError;
use forge_secrets::credentials::{BmcCredentialType, CredentialKey, Credentials};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

pub(crate) async fn get(
    api: &Api,
    request: tonic::Request<rpc::BmcMetaDataGetRequest>,
) -> Result<tonic::Response<rpc::BmcMetaDataGetResponse>, tonic::Status> {
    log_request_data(&request);
    let request = request.into_inner();

    const DB_TXN_NAME: &str = "get_bmc_meta_data";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let (bmc_endpoint_request, _) = crate::api::validate_and_complete_bmc_endpoint_request(
        &mut txn,
        request.bmc_endpoint_request,
        request.machine_id,
    )
    .await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

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
        }
        .into());
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
            return Err(CarbideError::internal(e).into());
        }
    };

    let credentials = api
        .credential_provider
        .get_credentials(CredentialKey::BmcCredentials {
            credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
        })
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?
        .ok_or_else(|| CarbideError::internal("missing credentials".to_string()))?;

    let (username, password) = match credentials {
        Credentials::UsernamePassword { username, password } => (username, password),
    };

    Ok(tonic::Response::new(rpc::BmcMetaDataGetResponse {
        ip: bmc_endpoint_request.ip_address,
        port: None,
        ssh_port: None,
        ipmi_port: None,
        mac: bmc_mac_address.to_string(),
        user: username,
        password,
    }))
}
