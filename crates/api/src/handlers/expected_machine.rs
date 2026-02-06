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
use carbide_uuid::rack::RackId;
use db::{WithTransaction, rack as db_rack};
use futures_util::FutureExt;
use lazy_static::lazy_static;
use mac_address::MacAddress;
use model::expected_machine::{ExpectedMachine, ExpectedMachineData};
use regex::Regex;
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

    let mut txn = api.txn_begin().await?;

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

    let result = match db::expected_machine::find_by_bmc_mac_address(&mut txn, parsed_mac).await? {
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
    };

    txn.rollback().await?;

    result
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

    let request_rack_id = request.rack_id;
    let mut db_data: ExpectedMachineData = request.try_into()?;
    // Ensure an id is always supplied by the server if the client omitted it
    if db_data.override_id.is_none() {
        db_data.override_id = Some(Uuid::new_v4());
    }

    let mut txn = api.txn_begin().await?;

    db::expected_machine::create(&mut txn, parsed_mac, db_data).await?;

    if let Some(rack_id) = request_rack_id {
        match db_rack::get(&mut txn, rack_id).await {
            Ok(rack) => {
                let mut config = rack.config.clone();
                if !config.expected_compute_trays.contains(&parsed_mac) {
                    config.expected_compute_trays.push(parsed_mac);
                    db_rack::update(&mut txn, rack_id, &config)
                        .await
                        .map_err(CarbideError::from)?;
                }
            }
            Err(_) => {
                let expected_compute_trays = vec![parsed_mac];
                let _rack =
                    db_rack::create(&mut txn, rack_id, expected_compute_trays, vec![], vec![])
                        .await
                        .map_err(CarbideError::from)?;
            }
        }
    }

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

pub(crate) async fn delete(
    api: &Api,
    request: tonic::Request<rpc::ExpectedMachineRequest>,
) -> Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();

    let mut txn = api.txn_begin().await?;

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

    txn.commit().await?;

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
    let request_rack_id = request.rack_id;
    let data: ExpectedMachineData = request.try_into()?;

    let mut txn = api.txn_begin().await?;

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

        // TODO(chet): This should also go into the `update_by_id` flow,
        // but the fact `parsed_mac` is only in this flow makes me think
        // there might not be a parsed MAC to work with in the `update_by_id`
        // flow. That said, the backing queries could be changed to return
        // the bmc_mac_address in both cases, which would then let this
        // work for both cases.
        if let Some(rack_id) = request_rack_id {
            match db_rack::get(&mut txn, rack_id).await {
                Ok(rack) => {
                    let mut config = rack.config.clone();
                    if !config.expected_compute_trays.contains(&parsed_mac) {
                        config.expected_compute_trays.push(parsed_mac);
                        db_rack::update(&mut txn, rack_id, &config)
                            .await
                            .map_err(CarbideError::from)?;
                    }
                }
                Err(_) => {
                    let expected_compute_trays = vec![parsed_mac];
                    let _rack =
                        db_rack::create(&mut txn, rack_id, expected_compute_trays, vec![], vec![])
                            .await
                            .map_err(CarbideError::from)?;
                }
            }
        }
    }

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

pub(crate) async fn replace_all(
    api: &Api,
    request: tonic::Request<rpc::ExpectedMachineList>,
) -> Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);
    let request = request.into_inner();

    let mut txn = api.txn_begin().await?;

    db::expected_machine::clear(&mut txn).await?;

    txn.commit().await?;

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

    let expected_machine_list: Vec<ExpectedMachine> = api
        .with_txn(|txn| db::expected_machine::find_all(txn).boxed())
        .await??;

    Ok(tonic::Response::new(rpc::ExpectedMachineList {
        expected_machines: expected_machine_list.into_iter().map(Into::into).collect(),
    }))
}

pub(crate) async fn get_linked(
    api: &Api,
    request: tonic::Request<()>,
) -> Result<tonic::Response<rpc::LinkedExpectedMachineList>, tonic::Status> {
    log_request_data(&request);

    let out = api
        .with_txn(|txn| db::expected_machine::find_all_linked(txn).boxed())
        .await??;
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

    let mut txn = api.txn_begin().await?;

    db::expected_machine::clear(&mut txn).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

/// Helper function to sanitize expected machine and return parsed IDs (ID+MAC)
fn sanitize_expected_machine_and_get_ids(
    _api: &Api,
    request: rpc::ExpectedMachine,
    _is_update: bool,
) -> Result<(Uuid, MacAddress), CarbideError> {
    // Validate id is present
    let id = match &request.id {
        Some(uuid_val) => Uuid::parse_str(&uuid_val.value).map_err(|_| {
            CarbideError::InvalidArgument("invalid expected_machine id".to_string())
        })?,
        None => {
            return Err(CarbideError::InvalidArgument(
                "id is mandatory for batch operations".to_string(),
            ));
        }
    };

    // Validate bmc_mac_address is present and parseable
    if request.bmc_mac_address.is_empty() {
        return Err(CarbideError::InvalidArgument(
            "bmc_mac_address is mandatory".to_string(),
        ));
    }

    let parsed_mac: MacAddress = request
        .bmc_mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;

    // Validate duplicates in fallback DPU serial numbers
    if utils::has_duplicates(&request.fallback_dpu_serial_numbers) {
        return Err(CarbideError::InvalidArgument(
            "duplicate dpu serial number found".to_string(),
        ));
    }

    // Validate chassis serial format
    if !CHASSIS_SERIAL_REGEX.is_match(&request.chassis_serial_number) {
        return Err(CarbideError::InvalidArgument(format!(
            "chassis serial is not formatted properly {}",
            request.chassis_serial_number
        )));
    }

    Ok((id, parsed_mac))
}

/// Helper function to process rack association
async fn process_rack_association(
    txn: &mut sqlx::PgConnection,
    rack_id: RackId,
    parsed_mac: MacAddress,
) -> Result<(), CarbideError> {
    match db_rack::get(txn, rack_id).await {
        Ok(rack) => {
            let mut config = rack.config.clone();
            if !config.expected_compute_trays.contains(&parsed_mac) {
                config.expected_compute_trays.push(parsed_mac);
                db_rack::update(txn, rack_id, &config)
                    .await
                    .map_err(CarbideError::from)?;
            }
        }
        Err(_) => {
            let expected_compute_trays = vec![parsed_mac];
            let _rack = db_rack::create(txn, rack_id, expected_compute_trays, vec![], vec![])
                .await
                .map_err(CarbideError::from)?;
        }
    }
    Ok(())
}

/// Helper function to create a single expected machine within a transaction
async fn create_expected_machine(
    txn: &mut sqlx::PgConnection,
    machine: rpc::ExpectedMachine,
    id: Uuid,
    parsed_mac: MacAddress,
) -> Result<(), CarbideError> {
    let request_rack_id = machine.rack_id;
    let mut db_data: ExpectedMachineData = machine.try_into()?;
    db_data.override_id = Some(id);

    db::expected_machine::create(txn, parsed_mac, db_data).await?;

    // Handle rack association
    if let Some(rack_id) = request_rack_id {
        process_rack_association(txn, rack_id, parsed_mac).await?;
    }

    Ok(())
}

/// Helper function to update a single expected machine within a transaction
async fn update_expected_machine(
    txn: &mut sqlx::PgConnection,
    machine: rpc::ExpectedMachine,
    id: Uuid,
    parsed_mac: MacAddress,
) -> Result<(), CarbideError> {
    let request_rack_id = machine.rack_id;
    let data: ExpectedMachineData = machine.try_into()?;

    db::expected_machine::update_by_id(txn, id, data).await?;

    // Handle rack association
    if let Some(rack_id) = request_rack_id {
        process_rack_association(txn, rack_id, parsed_mac).await?;
    }

    Ok(())
}

#[derive(Copy, Clone)]
enum BatchOperation {
    Create,
    Update,
}

impl BatchOperation {
    fn is_update(&self) -> bool {
        matches!(self, BatchOperation::Update)
    }
}

fn build_success_result(machine: rpc::ExpectedMachine) -> rpc::ExpectedMachineOperationResult {
    // Ensure the id is set in the returned machine payload.
    let id = machine
        .id
        .as_ref()
        .and_then(|u| Uuid::parse_str(&u.value).ok());

    rpc::ExpectedMachineOperationResult {
        id: id.map(|value| ::rpc::common::Uuid {
            value: value.to_string(),
        }),
        success: true,
        error_message: None,
        expected_machine: Some(machine),
    }
}

fn build_failure_result(id: Uuid, error_message: String) -> rpc::ExpectedMachineOperationResult {
    rpc::ExpectedMachineOperationResult {
        id: Some(::rpc::common::Uuid {
            value: id.to_string(),
        }),
        success: false,
        error_message: Some(error_message),
        expected_machine: None,
    }
}

async fn apply_operation(
    op: BatchOperation,
    txn: &mut sqlx::PgConnection,
    machine: rpc::ExpectedMachine,
    id: Uuid,
    parsed_mac: MacAddress,
) -> Result<(), CarbideError> {
    match op {
        BatchOperation::Create => create_expected_machine(txn, machine, id, parsed_mac).await,
        BatchOperation::Update => update_expected_machine(txn, machine, id, parsed_mac).await,
    }
}

async fn process_batch_operations(
    api: &Api,
    machines: Vec<rpc::ExpectedMachine>,
    accept_partial: bool,
    op: BatchOperation,
) -> Result<Vec<rpc::ExpectedMachineOperationResult>, CarbideError> {
    let mut results = Vec::new();

    if accept_partial {
        let mut txn: Option<db::Transaction<'_>> = None;

        for machine in machines {
            debug_assert!(txn.is_none());
            let request_id = machine
                .id
                .as_ref()
                .and_then(|u| Uuid::parse_str(&u.value).ok())
                .unwrap_or_else(Uuid::nil);

            let (id, parsed_mac) =
                match sanitize_expected_machine_and_get_ids(api, machine.clone(), op.is_update()) {
                    Ok(ids) => ids,
                    Err(e) => {
                        results.push(build_failure_result(
                            request_id,
                            format!("Validation failed: {}", e),
                        ));
                        continue;
                    }
                };

            let mut machine_for_result = machine.clone();
            machine_for_result.id = Some(::rpc::common::Uuid {
                value: id.to_string(),
            });

            txn = match api.txn_begin().await {
                Ok(txn) => Some(txn),
                Err(e) => {
                    results.push(build_failure_result(
                        id,
                        format!("Failed to begin transaction: {}", e),
                    ));
                    continue;
                }
            };

            let mut txn = txn
                .take()
                .expect("transaction should be present when beginning per-machine work");

            match apply_operation(op, txn.as_pgconn(), machine, id, parsed_mac).await {
                Ok(_) => match txn.commit().await {
                    Ok(_) => results.push(build_success_result(machine_for_result)),
                    Err(e) => {
                        results.push(build_failure_result(id, format!("Failed to commit: {}", e)))
                    }
                },
                Err(e) => {
                    let _ = txn.rollback().await;
                    results.push(build_failure_result(id, format!("Operation failed: {}", e)));
                }
            }
        }

        return Ok(results);
    }

    let mut prepared = Vec::with_capacity(machines.len());
    for machine in machines {
        let (id, parsed_mac) =
            sanitize_expected_machine_and_get_ids(api, machine.clone(), op.is_update())?;
        prepared.push((machine, id, parsed_mac));
    }

    let mut txn = api.txn_begin().await?;

    for (machine, id, parsed_mac) in prepared {
        let mut machine_for_result = machine.clone();
        machine_for_result.id = Some(::rpc::common::Uuid {
            value: id.to_string(),
        });

        if let Err(e) = apply_operation(op, txn.as_pgconn(), machine, id, parsed_mac).await {
            let _ = txn.rollback().await;
            return Err(e);
        }
        results.push(build_success_result(machine_for_result));
    }

    txn.commit().await?;

    Ok(results)
}

pub(crate) async fn create_expected_machines(
    api: &Api,
    request: tonic::Request<rpc::BatchExpectedMachineOperationRequest>,
) -> Result<tonic::Response<rpc::BatchExpectedMachineOperationResponse>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let accept_partial = request.accept_partial_results;
    let machines = request
        .expected_machines
        .ok_or_else(|| CarbideError::InvalidArgument("expected_machines is required".to_string()))?
        .expected_machines;

    let results =
        process_batch_operations(api, machines, accept_partial, BatchOperation::Create).await?;

    Ok(tonic::Response::new(
        rpc::BatchExpectedMachineOperationResponse { results },
    ))
}

pub(crate) async fn update_expected_machines(
    api: &Api,
    request: tonic::Request<rpc::BatchExpectedMachineOperationRequest>,
) -> Result<tonic::Response<rpc::BatchExpectedMachineOperationResponse>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let accept_partial = request.accept_partial_results;
    let machines = request
        .expected_machines
        .ok_or_else(|| CarbideError::InvalidArgument("expected_machines is required".to_string()))?
        .expected_machines;

    let results =
        process_batch_operations(api, machines, accept_partial, BatchOperation::Update).await?;

    Ok(tonic::Response::new(
        rpc::BatchExpectedMachineOperationResponse { results },
    ))
}

// Utility method called by `explore`. Not a grpc handler.
pub(crate) async fn query(
    api: &Api,
    mac: MacAddress,
) -> Result<Option<ExpectedMachine>, CarbideError> {
    let mut txn = api.txn_begin().await?;

    let mut expected = db::expected_machine::find_many_by_bmc_mac_address(&mut txn, &[mac]).await?;

    txn.commit().await?;

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
