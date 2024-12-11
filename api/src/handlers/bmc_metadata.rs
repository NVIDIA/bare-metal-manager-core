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
use forge_secrets::credentials::{BmcCredentialType, CredentialKey, Credentials};
use mac_address::MacAddress;

use crate::api::{log_machine_id, log_request_data, Api};
use crate::db::bmc_metadata::BmcMetaDataUpdateRequest;
use crate::db::DatabaseError;
use crate::CarbideError;

async fn get_bmc_credentials(
    api: &Api,
    bmc_mac_address: MacAddress,
) -> Result<(String, String), eyre::Report> {
    let credentials = api
        .credential_provider
        .get_credentials(CredentialKey::BmcCredentials {
            credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
        })
        .await?;

    let (username, password) = match credentials {
        Credentials::UsernamePassword { username, password } => (username, password),
    };

    Ok((username, password))
}

pub(crate) async fn get(
    api: &Api,
    request: tonic::Request<rpc::BmcMetaDataGetRequest>,
) -> Result<tonic::Response<rpc::BmcMetaDataGetResponse>, tonic::Status> {
    log_request_data(&request);
    let request = request.into_inner();

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_bmc_meta_data",
            e,
        ))
    })?;

    let bmc_endpoint_request = crate::api::validate_and_complete_bmc_endpoint_request(
        &mut txn,
        request.bmc_endpoint_request,
        request.machine_id.clone().map(|id| id.id),
    )
    .await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit get_bmc_meta_data",
            e,
        ))
    })?;

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

    let (username, password) = get_bmc_credentials(api, bmc_mac_address)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    Ok(tonic::Response::new(rpc::BmcMetaDataGetResponse {
        ip: bmc_endpoint_request.ip_address,
        port: None,
        mac: bmc_mac_address.to_string(),
        user: username,
        password,
    }))
}

pub(crate) async fn update(
    api: &Api,
    request: tonic::Request<rpc::BmcMetaDataUpdateRequest>,
) -> Result<tonic::Response<rpc::BmcMetaDataUpdateResponse>, tonic::Status> {
    let Some(bmc_info) = request.get_ref().bmc_info.clone() else {
        return Err(CarbideError::InvalidArgument("Missing BMC Information".to_owned()).into());
    };

    // Note: Be *careful* when logging this request: do not log the password!
    tracing::Span::current().record(
        "request",
        format!(
            "BmcMetadataUpdateRequest machine_id: {:?} ip: {:?} request_type: {:?}",
            request.get_ref().machine_id,
            bmc_info.ip,
            request.get_ref().request_type
        ),
    );

    let request = request.into_inner();
    let mut update_request = BmcMetaDataUpdateRequest::try_from(request.clone())?;
    log_machine_id(&update_request.machine_id);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_bmc_meta_data",
            e,
        ))
    })?;

    update_request
        .update_bmc_meta_data(&mut txn)
        .await
        .map(tonic::Response::new)?;

    // Update the actual credentials in Vault
    // We now only use a single path
    let key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: update_request.bmc_metadata.bmc_info.mac.unwrap(),
        },
    };

    for data in request.data.iter() {
        api.credential_provider
            .set_credentials(
                key.clone(),
                Credentials::UsernamePassword {
                    username: data.user.clone(),
                    password: data.password.clone(),
                },
            )
            .await
            .map_err(|err| {
                CarbideError::internal(format!("Error setting credential for BMC: {:?}", err))
            })?;
    }

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit update_bmc_meta_data",
            e,
        ))
    })?;

    Ok(tonic::Response::new(rpc::BmcMetaDataUpdateResponse {}))
}
