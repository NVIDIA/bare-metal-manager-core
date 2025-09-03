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
use lazy_static::lazy_static;
use mac_address::MacAddress;
use regex::Regex;
use sqlx::{Postgres, Transaction};
use tonic::Status;

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::db::DatabaseError;
use crate::db::expected_machine::ExpectedMachine;
use crate::db::expected_machine::ExpectedMachineData;

lazy_static! {
    // Verify what serial is alphanumeric string with, allows dashes '-' and underscores '_'
    static ref CHASSIS_SERIAL_REGEX: Regex = Regex::new(r"^[A-Za-z0-9_-]{4,64}$").unwrap();
}

pub(crate) async fn get(
    api: &Api,
    request: tonic::Request<rpc::ExpectedMachineRequest>,
) -> Result<tonic::Response<rpc::ExpectedMachine>, tonic::Status> {
    log_request_data(&request);

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin("get_expected_machine", e))?;

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

    if !CHASSIS_SERIAL_REGEX.is_match(&request.chassis_serial_number) {
        return Err(CarbideError::InvalidArgument(format!(
            "chassis serial is not formatted properly {}",
            request.chassis_serial_number
        ))
        .into());
    }

    let parsed_mac: MacAddress = request
        .bmc_mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;

    let db_data = request.try_into()?;

    const DB_TXN_NAME: &str = "add_expected_machines";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| CarbideError::from(DatabaseError::txn_begin(DB_TXN_NAME, e)))?;

    ExpectedMachine::create(&mut txn, parsed_mac, db_data).await?;

    txn.commit()
        .await
        .map_err(|e| CarbideError::from(DatabaseError::txn_commit(DB_TXN_NAME, e)))?;

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

    const DB_TXN_NAME: &str = "delete_expected_machines";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    ExpectedMachine::delete(parsed_mac, &mut txn).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

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

    let data: ExpectedMachineData = request.try_into()?;

    let mut expected_machine = ExpectedMachine {
        bmc_mac_address: parsed_mac,
        data: data.clone(),
    };

    const DB_TXN_NAME: &str = "update_expected_machine";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    expected_machine.update(&mut txn, data).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(tonic::Response::new(()))
}

pub(crate) async fn replace_all(
    api: &Api,
    request: tonic::Request<rpc::ExpectedMachineList>,
) -> Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);
    let request = request.into_inner();

    const DB_TXN_NAME: &str = "replace_all_expected_machines";
    let mut txn: Transaction<'_, Postgres> = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    ExpectedMachine::clear(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

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

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin("get_all_expected_machines", e))?;

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
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin("get_linked", e))?;

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

    const DB_TXN_NAME: &str = "delete_all_expected_machines";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    ExpectedMachine::clear(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(tonic::Response::new(()))
}

// Utility method called by `explore`. Not a grpc handler.
pub(crate) async fn query(
    api: &Api,
    mac: MacAddress,
) -> Result<Option<ExpectedMachine>, CarbideError> {
    const DB_TXN_NAME: &str = "find_many_by_bmc_mac_address";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let mut expected = ExpectedMachine::find_many_by_bmc_mac_address(&mut txn, &[mac]).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(expected.remove(&mac))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chassis_serial_regex() {
        assert!(CHASSIS_SERIAL_REGEX.is_match("ABC123"));
        assert!(CHASSIS_SERIAL_REGEX.is_match("ABC-123"));
        assert!(CHASSIS_SERIAL_REGEX.is_match("ABC_123"));
        assert!(CHASSIS_SERIAL_REGEX.is_match("DELL-R740-12345"));
        assert!(CHASSIS_SERIAL_REGEX.is_match("A495122X5503847"));

        assert!(!CHASSIS_SERIAL_REGEX.is_match("ABC"));
        assert!(!CHASSIS_SERIAL_REGEX.is_match("ABC 123"));
        assert!(!CHASSIS_SERIAL_REGEX.is_match("A495122X5503847\r"));
        assert!(!CHASSIS_SERIAL_REGEX.is_match("ABC.123"));

        let too_long = "A".repeat(65);
        assert!(!CHASSIS_SERIAL_REGEX.is_match(&too_long));
    }
}
