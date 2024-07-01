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

use crate::api::{log_request_data, Api};
use crate::db::expected_machine::ExpectedMachine;
use crate::db::DatabaseError;
use crate::CarbideError;

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

    match ExpectedMachine::find_by_bmc_mac_address(&mut txn, parsed_mac).await? {
        Some(expected_machine) => {
            if expected_machine.bmc_mac_address != parsed_mac {
                return Err(Status::invalid_argument(format!(
                    "find_by_bmc_mac_address returned {expected_machine:#?} which differs from the queried mac address {parsed_mac}")));
            }

            let rpc_expected_machine = rpc::ExpectedMachine {
                bmc_mac_address: expected_machine.bmc_mac_address.to_string(),
                bmc_username: expected_machine.bmc_username,
                bmc_password: expected_machine.bmc_password,
                chassis_serial_number: expected_machine.serial_number,
            };

            Ok(tonic::Response::new(rpc_expected_machine))
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

    let parsed_mac: MacAddress = request
        .bmc_mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;

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

    let rpc_expected_machine = get(api, request).await?.into_inner();

    let parsed_mac: MacAddress = rpc_expected_machine
        .bmc_mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;

    let expected_machine = ExpectedMachine {
        bmc_mac_address: parsed_mac,
        bmc_username: rpc_expected_machine.bmc_username,
        serial_number: rpc_expected_machine.chassis_serial_number,
        bmc_password: rpc_expected_machine.bmc_password,
    };

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin delete_expected_machines",
            e,
        ))
    })?;

    expected_machine
        .delete(&mut txn)
        .await
        .map_err(CarbideError::from)?;

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

    let parsed_mac: MacAddress = request
        .bmc_mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;

    let mut expected_machine = ExpectedMachine {
        bmc_mac_address: parsed_mac,
        bmc_username: request.bmc_username.clone(),
        serial_number: request.chassis_serial_number,
        bmc_password: request.bmc_password.clone(),
    };

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_bmc_credentials",
            e,
        ))
    })?;

    expected_machine
        .update_bmc_credentials(&mut txn, request.bmc_username, request.bmc_password)
        .await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit update_bmc_credentials",
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

    let expected_machine_list: Vec<ExpectedMachine> = ExpectedMachine::find_all(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    Ok(tonic::Response::new(rpc::ExpectedMachineList {
        expected_machines: expected_machine_list
            .into_iter()
            .map(|machine| rpc::ExpectedMachine {
                bmc_mac_address: machine.bmc_mac_address.to_string(),
                bmc_username: machine.bmc_username,
                bmc_password: machine.bmc_password,
                chassis_serial_number: machine.serial_number,
            })
            .collect(),
    }))
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
