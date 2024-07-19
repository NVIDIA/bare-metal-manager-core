use forge_secrets::credentials::{BmcCredentialType, CredentialKey, Credentials};
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
use mac_address::MacAddress;

use crate::api::{log_machine_id, log_request_data, Api};
use crate::db::bmc_metadata::{BmcMetaDataGetRequest, BmcMetaDataUpdateRequest};
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
    let request = BmcMetaDataGetRequest::try_from(request.into_inner())?;
    log_machine_id(&request.machine_id);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_bmc_meta_data",
            e,
        ))
    })?;

    let mut bmc_info = request.get_bmc_meta_data(&mut txn).await?;
    // this will handle the legacy case, for hosts that were ingested without having the MAC address set
    // although we will call enrich everytime, the DB update will only be done once.
    // it is better to call enrich here rather than in db::get_bmc_information, becuase we can guarantee that txn.commit is called
    // TODO (spyda): remove this once we've handled all the legacy hosts
    bmc_info
        .enrich_mac_address(
            "get_bmc_meta_data".to_string(),
            &mut txn,
            &request.machine_id,
            true,
        )
        .await?;

    match bmc_info.bmc_info.mac {
        Some(mac) => {
            let bmc_mac_address = mac.parse::<MacAddress>().map_err(CarbideError::from)?;
            let (username, password) = get_bmc_credentials(api, bmc_mac_address)
                .await
                .map_err(|e| CarbideError::GenericError(e.to_string()))?;

            txn.commit().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "commit get_bmc_meta_data",
                    e,
                ))
            })?;

            Ok(tonic::Response::new(rpc::BmcMetaDataGetResponse {
                ip: bmc_info.bmc_info.ip.unwrap_or_default(),
                port: bmc_info.bmc_info.port.map(|p| p as u32),
                mac,
                user: username,
                password,
            }))
        }
        None => Err(CarbideError::GenericError(format!(
            "could not retrieve BMC mac address for machine {}: {:#?}",
            request.machine_id, bmc_info
        ))
        .into()),
    }
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

    let mut request = BmcMetaDataUpdateRequest::try_from(request.into_inner())?;
    log_machine_id(&request.machine_id);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_bmc_meta_data",
            e,
        ))
    })?;

    request
        .update_bmc_meta_data(&mut txn)
        .await
        .map(tonic::Response::new)?;

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
