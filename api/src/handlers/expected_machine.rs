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
use lazy_static::lazy_static;
use mac_address::MacAddress;
use model::expected_machine::{ExpectedMachine, ExpectedMachineData};
use regex::Regex;
use sqlx::{Postgres, Transaction};
use tonic::Status;
use uuid::Uuid;

use crate::CarbideError;
use crate::api::{Api, log_request_data};

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

    // If id was provided, fetch by id; else fetch by MAC
    if let Some(uuid_val) = request.id.clone() {
        let id = Uuid::parse_str(&uuid_val.value).map_err(|_| {
            CarbideError::InvalidArgument("invalid expected_machine id".to_string())
        })?;
        let maybe: Option<ExpectedMachine> = db::expected_machine::find_by_id(&mut txn, id).await?;
        return match maybe {
            Some(expected_machine) => Ok(tonic::Response::new(expected_machine.into())),
            None => Err(CarbideError::NotFoundError {
                kind: "expected_machine",
                id: uuid_val.value,
            }
            .into()),
        };
    }

    let parsed_mac: MacAddress = request
        .bmc_mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;

    match db::expected_machine::find_by_bmc_mac_address(&mut txn, parsed_mac).await? {
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

    let mut db_data: ExpectedMachineData = request.try_into()?;
    // Ensure an id is always supplied by the server if the client omitted it
    if db_data.override_id.is_none() {
        db_data.override_id = Some(Uuid::new_v4());
    }

    const DB_TXN_NAME: &str = "add_expected_machines";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    db::expected_machine::create(&mut txn, parsed_mac, db_data).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(tonic::Response::new(()))
}

pub(crate) async fn delete(
    api: &Api,
    request: tonic::Request<rpc::ExpectedMachineRequest>,
) -> Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();

    const DB_TXN_NAME: &str = "delete_expected_machines";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    if let Some(uuid_val) = request.id.clone() {
        let id = Uuid::parse_str(&uuid_val.value).map_err(|_| {
            CarbideError::InvalidArgument("invalid expected_machine id".to_string())
        })?;
        db::expected_machine::delete_by_id(id, &mut txn).await?;
    } else {
        // We parse the MAC in order to detect formatting errors before handing it off to the database
        let parsed_mac: MacAddress = request
            .bmc_mac_address
            .parse::<MacAddress>()
            .map_err(CarbideError::from)?;
        db::expected_machine::delete(parsed_mac, &mut txn).await?;
    }

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
    // Save fields needed later before moving `request` into data conversion
    let request_id = request.id.clone();
    let request_mac = request.bmc_mac_address.clone();
    let data: ExpectedMachineData = request.try_into()?;

    const DB_TXN_NAME: &str = "update_expected_machine";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    if let Some(uuid_val) = request_id.clone() {
        let id = Uuid::parse_str(&uuid_val.value).map_err(|_| {
            CarbideError::InvalidArgument("invalid expected_machine id".to_string())
        })?;
        db::expected_machine::update_by_id(&mut txn, id, data).await?;
    } else {
        let parsed_mac: MacAddress = request_mac
            .parse::<MacAddress>()
            .map_err(CarbideError::from)?;
        let mut expected_machine = ExpectedMachine {
            id: Some(Uuid::new_v4()),
            bmc_mac_address: parsed_mac,
            data: data.clone(),
        };
        db::expected_machine::update(&mut expected_machine, &mut txn, data).await?;
    }

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

    db::expected_machine::clear(&mut txn).await?;

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

    let expected_machine_list: Vec<ExpectedMachine> =
        db::expected_machine::find_all(&mut txn).await?;

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

    let out = db::expected_machine::find_all_linked(&mut txn).await?;
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

    db::expected_machine::clear(&mut txn).await?;

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

    let mut expected = db::expected_machine::find_many_by_bmc_mac_address(&mut txn, &[mac]).await?;

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
