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
use lazy_static::lazy_static;
use mac_address::MacAddress;
use model::expected_machine::{
    ExpectedHostNic, ExpectedMachine, ExpectedMachineData, ExpectedMachineRequest,
};
use regex::Regex;
use uuid::Uuid;

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::handlers::machine_interface_address::{
    preallocate_machine_interface, update_preallocated_machine_interface,
};

lazy_static! {
    // Verify what serial is alphanumeric string with, allows dashes '-' and underscores '_'
    static ref CHASSIS_SERIAL_REGEX: Regex = Regex::new(r"^[A-Za-z0-9_-]{4,64}$").unwrap();
}

/// Returns one expected machine by database id or BMC MAC (from `ExpectedMachineRequest`).
pub(crate) async fn get(
    api: &Api,
    request: tonic::Request<rpc::ExpectedMachineRequest>,
) -> Result<tonic::Response<rpc::ExpectedMachine>, tonic::Status> {
    log_request_data(&request);

    let req: ExpectedMachineRequest = request
        .into_inner()
        .try_into()
        .map_err(|e| CarbideError::InvalidArgument(format!("{}", e)))?;

    let target_id = req
        .id
        .map(|u| u.to_string())
        .or(req.bmc_mac_address.map(|m| m.to_string()))
        .unwrap_or_default();

    let expected_machine = db::expected_machine::find(&api.database_connection, &req)
        .await
        .map_err(CarbideError::from)?
        .ok_or(CarbideError::NotFoundError {
            kind: "expected_machine",
            id: target_id,
        })?;

    let response = rpc::ExpectedMachine::from(expected_machine);
    Ok(tonic::Response::new(response))
}

/// Adds an expected machine. When `bmc_ip_address` is present, pre-allocates a `machine_interface`
/// for that BMC MAC and IP (shared helper with expected switches / power shelves) so discovery can
/// proceed without waiting on DHCP.
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

    let id = request
        .id
        .as_ref()
        .map(|u| {
            Uuid::parse_str(&u.value).map_err(|_| {
                CarbideError::InvalidArgument("invalid expected_machine id".to_string())
            })
        })
        .transpose()?;
    let db_data: ExpectedMachineData = request.try_into()?;

    let machine = ExpectedMachine {
        id,
        bmc_mac_address: parsed_mac,
        data: db_data,
    };

    validate_at_most_one_primary_host_nic(&machine.data.host_nics)?;

    let mut txn = api.txn_begin().await?;

    // Pre-allocate BMC interface if bmc_ip_address is set.
    if let Some(bmc_ip) = machine.data.bmc_ip_address {
        preallocate_machine_interface(&mut txn, machine.bmc_mac_address, bmc_ip).await?;
    }

    // Pre-allocate machine interfaces for host NICs with fixed IPs.
    for nic in &machine.data.host_nics {
        if let Some(ref ip_str) = nic.fixed_ip {
            let ip: std::net::IpAddr = ip_str.parse().map_err(|_| {
                CarbideError::InvalidArgument(format!("invalid fixed_ip: {ip_str}"))
            })?;
            preallocate_machine_interface(&mut txn, nic.mac_address, ip).await?;
        }
    }

    db::expected_machine::create(&mut txn, machine).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

/// Deletes an expected machine by id or BMC MAC.
pub(crate) async fn delete(
    api: &Api,
    request: tonic::Request<rpc::ExpectedMachineRequest>,
) -> Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);

    let req: ExpectedMachineRequest = request
        .into_inner()
        .try_into()
        .map_err(|e| CarbideError::InvalidArgument(format!("{}", e)))?;

    let mut txn = api.txn_begin().await?;

    db::expected_machine::delete(&mut txn, &req)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

/// Updates an expected machine row and, when `bmc_ip_address` is set, reconciles the pre-allocated
/// `machine_interface` via [`update_preallocated_machine_interface`] (no-op for interfaces that
/// already have addresses—operators use `machine-interfaces assign-address` for those).
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
    let id = request
        .id
        .as_ref()
        .map(|u| {
            Uuid::parse_str(&u.value).map_err(|_| {
                CarbideError::InvalidArgument("invalid expected_machine id".to_string())
            })
        })
        .transpose()?;
    let parsed_mac: MacAddress = request
        .bmc_mac_address
        .parse::<MacAddress>()
        .map_err(CarbideError::from)?;
    let data: ExpectedMachineData = request.try_into()?;

    let machine = ExpectedMachine {
        id,
        bmc_mac_address: parsed_mac,
        data,
    };

    validate_at_most_one_primary_host_nic(&machine.data.host_nics)?;

    let mut txn = api.txn_begin().await?;

    // Update BMC interface if bmc_ip_address is set.
    if let Some(bmc_ip) = machine.data.bmc_ip_address {
        update_preallocated_machine_interface(&mut txn, machine.bmc_mac_address, bmc_ip).await?;
    }

    // Update/create machine interfaces for host NICs with fixed IPs.
    for nic in &machine.data.host_nics {
        if let Some(ref ip_str) = nic.fixed_ip {
            let ip: std::net::IpAddr = ip_str.parse().map_err(|_| {
                CarbideError::InvalidArgument(format!("invalid fixed_ip: {ip_str}"))
            })?;
            update_preallocated_machine_interface(&mut txn, nic.mac_address, ip).await?;
        }
    }

    db::expected_machine::update(&mut txn, &machine)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

/// Clears all expected machines, then creates each entry via [`add`]. Optional `bmc_ip_address` on
/// each RPC message runs the same `machine_interface` pre-allocation as a single create.
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

/// Lists all expected machines (includes configured `bmc_ip_address` when set).
pub(crate) async fn get_all(
    api: &Api,
    request: tonic::Request<()>,
) -> Result<tonic::Response<rpc::ExpectedMachineList>, tonic::Status> {
    log_request_data(&request);

    let expected_machine_list: Vec<ExpectedMachine> =
        db::expected_machine::find_all(&api.database_connection).await?;

    Ok(tonic::Response::new(rpc::ExpectedMachineList {
        expected_machines: expected_machine_list.into_iter().map(Into::into).collect(),
    }))
}

/// Lists expected machines joined to explored interfaces / machines (linkage view).
pub(crate) async fn get_linked(
    api: &Api,
    request: tonic::Request<()>,
) -> Result<tonic::Response<rpc::LinkedExpectedMachineList>, tonic::Status> {
    log_request_data(&request);

    let out = db::expected_machine::find_all_linked(&api.database_connection).await?;
    let list = rpc::LinkedExpectedMachineList {
        expected_machines: out.into_iter().map(|m| m.into()).collect(),
    };
    Ok(tonic::Response::new(list))
}

/// Lists host BMC endpoints that Site Explorer has explored but whose MAC is
/// not listed in any of `expected_machines`, `expected_power_shelf`, or
/// `expected_switch`. DPUs, power shelves, and switches are filtered out so the
/// response only contains actual host BMCs.
///
/// An entry with a non-null `machine_id` is an orphan: the host was ingested
/// before its `expected_machines` row was removed.
pub(crate) async fn get_all_unexpected_machines(
    api: &Api,
    request: tonic::Request<()>,
) -> Result<tonic::Response<rpc::UnexpectedMachineList>, tonic::Status> {
    log_request_data(&request);

    let out = db::expected_machine::find_all_unexpected(&api.database_connection).await?;
    let list = rpc::UnexpectedMachineList {
        unexpected_machines: out.into_iter().map(Into::into).collect(),
    };
    Ok(tonic::Response::new(list))
}

/// Deletes every expected machine row.
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

/// Rejects an ExpectedMachine payload that declares more than one host NIC
/// with `primary: true`, returning an InvalidArgument if found.
fn validate_at_most_one_primary_host_nic(
    host_nics: &[ExpectedHostNic],
) -> Result<(), CarbideError> {
    let primaries: Vec<_> = host_nics
        .iter()
        .filter(|n| n.primary == Some(true))
        .map(|n| n.mac_address.to_string())
        .collect();
    if primaries.len() > 1 {
        return Err(CarbideError::InvalidArgument(format!(
            "at most one host_nic may be flagged primary=true, got {}: {}",
            primaries.len(),
            primaries.join(", ")
        )));
    }
    Ok(())
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

/// Creates one expected machine inside an existing transaction (batch API). Applies the same static
/// BMC pre-allocation rules as [`add`].
async fn create_expected_machine(
    txn: &mut sqlx::PgConnection,
    machine: rpc::ExpectedMachine,
    id: Uuid,
    parsed_mac: MacAddress,
) -> Result<(), CarbideError> {
    let db_data: ExpectedMachineData = machine.try_into()?;

    let expected_machine = ExpectedMachine {
        id: Some(id),
        bmc_mac_address: parsed_mac,
        data: db_data,
    };

    if let Some(bmc_ip) = expected_machine.data.bmc_ip_address {
        preallocate_machine_interface(txn, expected_machine.bmc_mac_address, bmc_ip).await?;
    }

    db::expected_machine::create(txn, expected_machine).await?;

    Ok(())
}

/// Updates one expected machine inside an existing transaction (batch API). Applies the same
/// static BMC reconciliation as [`update`].
async fn update_expected_machine(
    txn: &mut sqlx::PgConnection,
    machine: rpc::ExpectedMachine,
    id: Uuid,
    parsed_mac: MacAddress,
) -> Result<(), CarbideError> {
    let data: ExpectedMachineData = machine.try_into()?;

    let expected_machine = ExpectedMachine {
        id: Some(id),
        bmc_mac_address: parsed_mac,
        data,
    };

    if let Some(bmc_ip) = expected_machine.data.bmc_ip_address {
        update_preallocated_machine_interface(txn, expected_machine.bmc_mac_address, bmc_ip)
            .await?;
    }

    db::expected_machine::update(txn, &expected_machine).await?;

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
        for machine in machines {
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

            let mut txn = match api.txn_begin().await {
                Ok(txn) => txn,
                Err(e) => {
                    results.push(build_failure_result(
                        id,
                        format!("Failed to begin transaction: {}", e),
                    ));
                    continue;
                }
            };

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

/// Batch-create expected machines. Static BMC IP handling matches single [`add`] for each row.
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

/// Batch-update expected machines. Static BMC IP handling matches single [`update`] for each row.
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
