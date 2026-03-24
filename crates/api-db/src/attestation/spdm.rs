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

use carbide_uuid::machine::MachineId;
use itertools::Itertools;
use libredfish::model::component_integrity::{CaCertificate, Evidence};
use model::attestation::spdm::{
    SpdmAttestationState, SpdmDeviceAttestation, SpdmDeviceAttestationDetails,
    SpdmMachineDeviceMetadata, SpdmObjectId,
};
use model::controller_outcome::PersistentStateHandlerOutcome;
use sqlx::{PgConnection, Row};

use crate::{DatabaseError, DatabaseResult};

pub async fn insert_device_attestations(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    devices: Vec<SpdmDeviceAttestation>,
) -> DatabaseResult<u64> {
    let query = "DELETE FROM spdm_machine_devices_attestation WHERE machine_id=$1";
    sqlx::query(query)
        .bind(machine_id)
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    let device_ids = devices.iter().map(|x| &x.device_id).collect_vec();
    let nonces = devices.iter().map(|x| x.nonce).collect_vec();
    let states = devices
        .iter()
        .map(|x| sqlx::types::Json(&x.state))
        .collect_vec();
    let state_versions = devices
        .iter()
        .map(|x| x.state_version.to_string())
        .collect_vec();
    let ca_certificate_links = devices.iter().map(|x| &x.ca_certificate_link).collect_vec();
    let evidence_targets = devices.iter().map(|x| &x.evidence_target).collect_vec();
    let started_at_timestamps = devices.iter().map(|x| &x.started_at).collect_vec();

    let query = r#"INSERT INTO spdm_machine_devices_attestation (machine_id, device_id, nonce, state, state_version, ca_certificate_link, evidence_target, started_at)
        SELECT 
            $1 as machine_id, device_id, nonce, state, state_version, ca_certificate_link, evidence_target, started_at
        FROM 
            UNNEST($2::TEXT[], $3::uuid[], $4::JSONB[], $5::TEXT[], $6::TEXT[], $7::TEXT[], $8::timestamptz[])
            AS t(device_id, nonce, state, state_version, ca_certificate_link, evidence_target, started_at)
        "#;
    let res = sqlx::query(query)
        .bind(machine_id)
        .bind(device_ids)
        .bind(nonces)
        .bind(states)
        .bind(state_versions)
        .bind(ca_certificate_links)
        .bind(evidence_targets)
        .bind(started_at_timestamps)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(res.rows_affected())
}

pub async fn cancel_machine_attestation(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> DatabaseResult<()> {
    let current_time = chrono::Utc::now();
    let query = r#"UPDATE spdm_machine_devices_attestation
        SET cancelled_at = $2
        WHERE machine_id = $1
        "#;
    let _ = sqlx::query(query)
        .bind(machine_id)
        .bind(current_time)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn set_completed_at(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    device_id: &str,
) -> DatabaseResult<()> {
    let current_time = chrono::Utc::now();
    let query = r#"UPDATE spdm_machine_devices_attestation
        SET completed_at = $3
        WHERE machine_id = $1 and device_id = $2
        "#;
    let _rows_affected = sqlx::query(query)
        .bind(machine_id)
        .bind(device_id)
        .bind(current_time)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?
        .rows_affected();

    Ok(())
}

pub async fn update_metadata(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    device_id: &str,
    metadata: &SpdmMachineDeviceMetadata,
) -> DatabaseResult<()> {
    let query = r#"UPDATE spdm_machine_devices_attestation
        SET metadata = $3
        WHERE machine_id = $1 AND device_id = $2"#;
    sqlx::query(query)
        .bind(machine_id)
        .bind(device_id)
        .bind(sqlx::types::Json(metadata))
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?
        .rows_affected();

    Ok(())
}

pub async fn update_certificate(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    device_id: &str,
    certificate: &CaCertificate,
) -> DatabaseResult<()> {
    let query = r#"UPDATE spdm_machine_devices_attestation
        SET ca_certificate = $3
        WHERE machine_id = $1 AND device_id = $2"#;
    sqlx::query(query)
        .bind(machine_id)
        .bind(device_id)
        .bind(sqlx::types::Json(certificate))
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?
        .rows_affected();

    Ok(())
}

pub async fn update_evidence(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    device_id: &str,
    evidence: &Evidence,
) -> DatabaseResult<()> {
    let query = r#"UPDATE spdm_machine_devices_attestation
        SET evidence = $3
        WHERE machine_id = $1 AND device_id = $2"#;
    sqlx::query(query)
        .bind(machine_id)
        .bind(device_id)
        .bind(sqlx::types::Json(evidence))
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?
        .rows_affected();

    Ok(())
}

/// returns all device attestations that are not completed
pub async fn find_machine_ids_for_attestation(
    txn: &mut PgConnection,
) -> Result<Vec<SpdmObjectId>, DatabaseError> {
    let query = r#"
        SELECT
            machine_id, device_id
        FROM spdm_machine_devices_attestation
        WHERE
            completed_at is NULL
    "#;

    let object_ids: Vec<SpdmObjectId> = sqlx::query_as(query)
        .fetch_all(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(object_ids)
}

pub async fn get_attestation_status_for_machine_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> Result<rpc::forge::SpdmAttestationStatus, DatabaseError> {
    // get states for all devices under attestation for a given
    // machine
    let query = r#"
        SELECT
            state
        FROM
            spdm_machine_devices_attestation
        WHERE
            machine_id = $1
    "#;

    let attestation_status_rows = sqlx::query(query)
        .bind(machine_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    // if all passed - PASSED
    // if all cancelled - CANCELLED
    // if any failed && none not in progress - FAILED
    // else - IN PROGRESS

    // define masks
    const PASSED_MASK: u8 = 0b0000_0001;
    const CANCELLELD_MASK: u8 = 0b0000_0010;
    const FAILED_MASK: u8 = 0b0000_0100;
    const INPROGRESS_MASK: u8 = 0b0000_1000;

    // this is a bitfield to keep track occurrences
    // of values
    let mut flags: u8 = 0;

    for pg_row in attestation_status_rows {
        let state_json: sqlx::types::Json<SpdmAttestationState> =
            pg_row
                .try_get("state")
                .map_err(|e| DatabaseError::Internal {
                    message: format!("Could not get SpdmAttestationState from DB record: {}", e),
                })?;
        let state = state_json.0;
        match state {
            SpdmAttestationState::Passed => {
                flags |= PASSED_MASK;
            }
            SpdmAttestationState::Cancelled => {
                flags |= CANCELLELD_MASK;
            }
            SpdmAttestationState::Failed { .. } => {
                flags |= FAILED_MASK;
            }
            _ => {
                flags |= INPROGRESS_MASK;
            }
        }
    }

    // some failed and none in progress
    if FAILED_MASK & flags != 0 && INPROGRESS_MASK & flags == 0 {
        return Ok(rpc::forge::SpdmAttestationStatus::SpdmAttFailed);
    }
    match flags {
        PASSED_MASK => Ok(rpc::forge::SpdmAttestationStatus::SpdmAttPassed),
        CANCELLELD_MASK => Ok(rpc::forge::SpdmAttestationStatus::SpdmAttCancelled),
        _ => Ok(rpc::forge::SpdmAttestationStatus::SpdmAttInProgress),
    }
}

pub async fn get_attestations_for_machine_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> Result<Vec<SpdmDeviceAttestationDetails>, DatabaseError> {
    let query = r#"
        SELECT machine_id, device_id, ca_certificate, state, metadata, evidence, started_at, cancelled_at, completed_at
        FROM spdm_machine_devices_attestation
        WHERE machine_id = $1
    "#;

    let attestation_details: Vec<SpdmDeviceAttestationDetails> = sqlx::query_as(query)
        .bind(machine_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(attestation_details)
}

/// this loads a device attestation from the DB
pub async fn load_snapshot_for_machine_and_device_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    device_id: &String,
) -> Result<SpdmDeviceAttestation, DatabaseError> {
    let query = r#"
        SELECT
            mda.*,
            to_jsonb(mt.topology->'bmc_info') AS bmc_info
        FROM spdm_machine_devices_attestation AS mda
        JOIN machine_topologies AS mt
            ON mt.machine_id = mda.machine_id
        WHERE mda.machine_id = $1
            AND mda.device_id  = $2;
    "#;

    let res: SpdmDeviceAttestation = sqlx::query_as(query)
        .bind(machine_id)
        .bind(device_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(res)
}

pub async fn list_machine_ids(txn: &mut PgConnection) -> Result<Vec<MachineId>, DatabaseError> {
    let query = r#"
        SELECT DISTINCT
            machine_id
        FROM 
            spdm_machine_devices_attestation
        WHERE
            completed_at is NULL
    "#;

    let res: Vec<MachineId> = sqlx::query_as(query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(res)
}

pub async fn persist_outcome(
    txn: &mut PgConnection,
    object_id: &SpdmObjectId,
    outcome: PersistentStateHandlerOutcome,
) -> Result<(), DatabaseError> {
    let query_device = r#"
        UPDATE 
            spdm_machine_devices_attestation
        SET state_outcome = $1
        WHERE machine_id = $2 AND device_id = $3
    "#;

    sqlx::query(query_device)
        .bind(sqlx::types::Json(outcome))
        .bind(object_id.0)
        .bind(object_id.1.clone())
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query_device, e))?
        .rows_affected();

    Ok(())
}

/// stores the controller state inside device attestation
/// if the state has changed, the ConfigVersion is incremented
pub async fn persist_controller_state(
    txn: &mut PgConnection,
    object_id: &SpdmObjectId,
    new_state: &SpdmAttestationState,
) -> Result<(), DatabaseError> {
    // fetch the existing device attestation to access its ConfigVersion
    let device_attestation =
        load_snapshot_for_machine_and_device_id(txn, &object_id.0, &object_id.1).await?;

    // increment ConfigVersion if the state has changed
    let new_version = if &device_attestation.state != new_state {
        device_attestation.state_version.increment()
    } else {
        device_attestation.state_version
    };

    let query = r#"
            UPDATE 
                spdm_machine_devices_attestation
            SET state= $1, state_version=$2
            WHERE machine_id = $3 AND device_id = $4
        "#;
    let _rows_affected = sqlx::query(query)
        .bind(sqlx::types::Json(new_state))
        .bind(new_version)
        .bind(object_id.0)
        .bind(object_id.1.clone())
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?
        .rows_affected();

    update_history(txn, object_id, new_state).await
}

async fn update_history(
    txn: &mut PgConnection,
    object_id: &SpdmObjectId,
    state_snapshot: &SpdmAttestationState,
) -> Result<(), DatabaseError> {
    let query = r#"INSERT INTO spdm_device_attestation_history (machine_id, device_id, updated_at, state_snapshot)
    VALUES($1, $2, now(),  $3)
    "#;

    sqlx::query(query)
        .bind(object_id.0)
        .bind(object_id.1.clone())
        .bind(sqlx::types::Json(state_snapshot))
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}
