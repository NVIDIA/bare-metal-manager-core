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
use sqlx::{Postgres, Transaction};
use tonic::Status;

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::db::DatabaseError;
use crate::db::expected_machine::ExpectedMachine;
use crate::model::metadata::Metadata;

pub(crate) async fn get(
    api: &Api,
    request: tonic::Request<rpc::ExpectedMachineRequest>,
) -> Result<tonic::Response<rpc::ExpectedMachine>, tonic::Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_expected_machine",
            e,
        ))
    })?;

    let request = request.into_inner();

    let parsed_mac: MacAddress = request
        .bmc_mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;

    match ExpectedMachine::find_by_bmc_mac_address(&mut txn, parsed_mac)
        .await
        .map_err(CarbideError::from)?
    {
        Some(expected_machine) => {
            if expected_machine.bmc_mac_address != parsed_mac {
                return Err(Status::invalid_argument(format!(
                    "find_by_bmc_mac_address returned {expected_machine:#?} which differs from the queried mac address {parsed_mac}"
                )));
            }

            Ok(tonic::Response::new(expected_machine.into()))
        }
        None => Err(CarbideError::NotFoundError {
            kind: "expected_machine",
            id: parsed_mac.to_string(),
        }
        .into()),
    }
}

pub(crate) async fn add(
    api: &Api,
    request: tonic::Request<rpc::ExpectedMachine>,
) -> Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    if utils::has_duplicates(&request.fallback_dpu_serial_numbers) {
        return Err(
            CarbideError::InvalidArgument("duplicate dpu serial number found".to_string()).into(),
        );
    }
    let parsed_mac: MacAddress = request
        .bmc_mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;

    let metadata = metadata_from_request(request.metadata)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin add_expected_machines",
            e,
        ))
    })?;

    ExpectedMachine::create(
        &mut txn,
        parsed_mac,
        request.bmc_username,
        request.bmc_password,
        request.chassis_serial_number,
        request.fallback_dpu_serial_numbers,
        metadata,
        request.sku_id,
    )
    .await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit add_expected_machines",
            e,
        ))
    })?;

    Ok(tonic::Response::new(()))
}

pub(crate) async fn delete(
    api: &Api,
    request: tonic::Request<rpc::ExpectedMachineRequest>,
) -> Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);

    // We parse the MAC in order to detect formatting errors before
    // handing it off to the database
    let parsed_mac: MacAddress = request
        .into_inner()
        .bmc_mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin delete_expected_machines",
            e,
        ))
    })?;

    ExpectedMachine::delete(parsed_mac, &mut txn).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit delete_expected_machines",
            e,
        ))
    })?;

    Ok(tonic::Response::new(()))
}

pub(crate) async fn update(
    api: &Api,
    request: tonic::Request<rpc::ExpectedMachine>,
) -> Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    if utils::has_duplicates(&request.fallback_dpu_serial_numbers) {
        return Err(
            CarbideError::InvalidArgument("duplicate dpu serial number found".to_string()).into(),
        );
    }
    let parsed_mac: MacAddress = request
        .bmc_mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;

    let metadata = metadata_from_request(request.metadata)?;

    let mut expected_machine = ExpectedMachine {
        bmc_mac_address: parsed_mac,
        bmc_username: request.bmc_username.clone(),
        serial_number: request.chassis_serial_number.clone(),
        bmc_password: request.bmc_password.clone(),
        fallback_dpu_serial_numbers: request.fallback_dpu_serial_numbers.clone(),
        metadata: metadata.clone(),
        sku_id: request.sku_id.clone(),
    };

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_expected_machine",
            e,
        ))
    })?;

    expected_machine
        .update(
            &mut txn,
            request.bmc_username,
            request.bmc_password,
            request.chassis_serial_number,
            request.fallback_dpu_serial_numbers,
            metadata,
            request.sku_id,
        )
        .await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit update_expected_machine",
            e,
        ))
    })?;

    Ok(tonic::Response::new(()))
}

pub(crate) async fn replace_all(
    api: &Api,
    request: tonic::Request<rpc::ExpectedMachineList>,
) -> Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);
    let request = request.into_inner();

    let mut txn: Transaction<'_, Postgres> =
        api.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin replace_all_expected_machines",
                e,
            ))
        })?;

    ExpectedMachine::clear(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit replace_all_expected_machines",
            e,
        ))
    })?;

    for expected_machine in request.expected_machines {
        add(api, tonic::Request::new(expected_machine)).await?;
    }
    Ok(tonic::Response::new(()))
}

pub(crate) async fn get_all(
    api: &Api,
    request: tonic::Request<()>,
) -> Result<tonic::Response<rpc::ExpectedMachineList>, tonic::Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_all_expected_machines",
            e,
        ))
    })?;

    let expected_machine_list: Vec<ExpectedMachine> = ExpectedMachine::find_all(&mut txn).await?;

    Ok(tonic::Response::new(rpc::ExpectedMachineList {
        expected_machines: expected_machine_list.into_iter().map(Into::into).collect(),
    }))
}

pub(crate) async fn get_linked(
    api: &Api,
    request: tonic::Request<()>,
) -> Result<tonic::Response<rpc::LinkedExpectedMachineList>, tonic::Status> {
    log_request_data(&request);
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "begin get_linked", e))
    })?;

    let out = ExpectedMachine::find_all_linked(&mut txn).await?;
    let list = rpc::LinkedExpectedMachineList {
        expected_machines: out.into_iter().map(|m| m.into()).collect(),
    };
    Ok(tonic::Response::new(list))
}

pub(crate) async fn delete_all(
    api: &Api,
    request: tonic::Request<()>,
) -> Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);

    let mut txn: Transaction<'_, Postgres> =
        api.database_connection.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin delete_all_expected_machines",
                e,
            ))
        })?;

    ExpectedMachine::clear(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit delete_all_expected_machines",
            e,
        ))
    })?;

    Ok(tonic::Response::new(()))
}

// Utility method called by `explore`. Not a grpc handler.
pub(crate) async fn query(
    api: &Api,
    mac: MacAddress,
) -> Result<Option<ExpectedMachine>, CarbideError> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_many_by_bmc_mac_address",
            e,
        ))
    })?;

    let mut expected = ExpectedMachine::find_many_by_bmc_mac_address(&mut txn, &[mac]).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit find_many_by_bmc_mac_address",
            e,
        ))
    })?;

    Ok(expected.remove(&mac))
}

/// If Metadata is retrieved as part of the ExpectedMachine creation, validate and use the Metadata
/// Otherwise assume empty Metadata
fn metadata_from_request(
    opt_metadata: Option<::rpc::forge::Metadata>,
) -> Result<Metadata, CarbideError> {
    Ok(match opt_metadata {
        None => Metadata {
            name: "".to_string(),
            description: "".to_string(),
            labels: Default::default(),
        },
        Some(m) => {
            // Note that this is unvalidated Metadata. It can contain non-ASCII names
            // and
            let m: Metadata = m.try_into().map_err(CarbideError::from)?;
            m.validate(false).map_err(CarbideError::from)?;
            m
        }
    })
}
