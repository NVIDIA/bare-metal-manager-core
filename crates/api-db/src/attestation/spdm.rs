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
use config_version::ConfigVersion;
use itertools::Itertools;
use libredfish::model::component_integrity::{CaCertificate, Evidence};
use model::attestation::spdm::{
    AttestationState, SpdmAttestationStatus, SpdmMachineAttestation, SpdmMachineDetails,
    SpdmMachineDeviceAttestation, SpdmMachineDeviceMetadata, SpdmMachineSnapshot,
    SpdmMachineStateSnapshot, SpdmObjectId, SpdmObjectId_,
};
use model::controller_outcome::PersistentStateHandlerOutcome;
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult};

pub async fn insert_or_update_machine_attestation_request(
    txn: &mut PgConnection,
    attestation_request: &SpdmMachineAttestation,
) -> DatabaseResult<()> {
    let query = r#"INSERT INTO spdm_machine_attestation (machine_id, requested_at, state, state_version)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (machine_id) DO UPDATE SET
            requested_at = $2,
            state = $3,
            state_version = $4
        RETURNING *"#;
    let _res: SpdmMachineAttestation = sqlx::query_as(query)
        .bind(attestation_request.machine_id)
        .bind(attestation_request.requested_at)
        .bind(sqlx::types::Json(&attestation_request.state))
        .bind(attestation_request.state_version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn insert_devices(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    devices: Vec<SpdmMachineDeviceAttestation>,
) -> DatabaseResult<()> {
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

    let query = r#"INSERT INTO spdm_machine_devices_attestation (machine_id, device_id, nonce, state, state_version, ca_certificate_link, evidence_target)
        SELECT 
            $1 as machine_id, device_id, nonce, state, state_version, ca_certificate_link, evidence_target 
        FROM 
            UNNEST($2::TEXT[], $3::uuid[], $4::JSONB[], $5::TEXT[], $6::TEXT[], $7::TEXT[])
            AS t(device_id, nonce, state, state_version, ca_certificate_link, evidence_target)
        "#;
    sqlx::query(query)
        .bind(machine_id)
        .bind(device_ids)
        .bind(nonces)
        .bind(states)
        .bind(state_versions)
        .bind(ca_certificate_links)
        .bind(evidence_targets)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn cancel_machine_attestation(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> DatabaseResult<()> {
    let current_time = chrono::Utc::now();
    let query = r#"UPDATE spdm_machine_attestation
        SET canceled_at = $2
        WHERE machine_id = $1
        RETURNING *"#;
    let _res: SpdmMachineAttestation = sqlx::query_as(query)
        .bind(machine_id)
        .bind(current_time)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

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
        WHERE machine_id = $1 AND device_id = $2
        RETURNING *"#;
    let _res: SpdmMachineDeviceAttestation = sqlx::query_as(query)
        .bind(machine_id)
        .bind(device_id)
        .bind(sqlx::types::Json(metadata))
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

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
        WHERE machine_id = $1 AND device_id = $2
        RETURNING *"#;
    let _res: SpdmMachineDeviceAttestation = sqlx::query_as(query)
        .bind(machine_id)
        .bind(device_id)
        .bind(sqlx::types::Json(certificate))
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

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
        WHERE machine_id = $1 AND device_id = $2
        RETURNING *"#;
    let _res: SpdmMachineDeviceAttestation = sqlx::query_as(query)
        .bind(machine_id)
        .bind(device_id)
        .bind(sqlx::types::Json(evidence))
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn update_started_time(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> DatabaseResult<()> {
    let current_time = chrono::Utc::now();
    let query = r#"UPDATE spdm_machine_attestation
        SET started_at = $2
        WHERE machine_id = $1
        RETURNING *"#;
    let _res: SpdmMachineAttestation = sqlx::query_as(query)
        .bind(machine_id)
        .bind(current_time)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn update_attestation_status(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    status: &SpdmAttestationStatus,
) -> DatabaseResult<()> {
    let query = r#"UPDATE spdm_machine_attestation
        SET attestation_status = $2
        WHERE machine_id = $1
        RETURNING *"#;
    let _res: SpdmMachineAttestation = sqlx::query_as(query)
        .bind(machine_id)
        .bind(status)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

// This function has to find two sets of ids,
// 1. The machine_ids for which the attestation has to be started. Here device_ids will be None.
//      a. machine_ids where status is `not-started`.
//      b. machine_ids where cancellation is not triggered.
//      c. machine_ids where device/component fetching is pending.
// 2. The (machine_ids, device_ids) pair for which:
//      a. machine_ids not in above group (to leave devices for which re-attestation is triggered)
//      b. Attestation is not yet completed. (machine.status != completed)
//      c. Cancellation request is not received.
pub async fn find_machine_ids_for_attestation(
    txn: &mut PgConnection,
) -> Result<Vec<SpdmObjectId>, DatabaseError> {
    let state = AttestationState::FetchAttestationTargetsAndUpdateDb;
    let query = r#"
        SELECT 
            m.machine_id
        FROM spdm_machine_attestation AS m
        WHERE
            (
                m.requested_at > m.started_at 
                OR
                m.attestation_status = 'not_started'
                OR
                m.state = $1
            ) 
            AND 
            (   
                m.canceled_at is NULL 
                OR 
                m.requested_at > m.canceled_at
            )
    "#;

    // ids for which attestation has to be (re)started.
    let res: Vec<MachineId> = sqlx::query_as(query)
        .bind(sqlx::types::Json(state))
        .fetch_all(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    let query = r#"
        SELECT 
            md.machine_id, md.device_id 
        FROM 
            spdm_machine_devices_attestation AS md
        LEFT JOIN spdm_machine_attestation m ON m.machine_id=md.machine_id
        WHERE
            md.machine_id NOT IN (SELECT unnest($1::text[]))
            AND
            m.attestation_status != 'completed'
            AND
            (
                m.canceled_at is NULL 
                OR 
                m.requested_at > m.canceled_at
            )
    "#;

    let devices: Vec<SpdmObjectId_> = sqlx::query_as(query)
        .bind(&res)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    // collect the data
    let res = res.into_iter().map(|x| SpdmObjectId(x, None));
    let object_ids = devices
        .into_iter()
        .map(|x| SpdmObjectId(x.machine_id, Some(x.device_id)))
        .chain(res)
        .collect_vec();

    Ok(object_ids)
}

pub async fn load_snapshot_for_machine_with_no_device(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> Result<SpdmMachineSnapshot, DatabaseError> {
    let query = r#"
        SELECT
  null AS device,
  '{}'::jsonb AS devices_state,

  (
    SELECT row_to_json(m.*)
    FROM spdm_machine_attestation m
    WHERE m.machine_id = $1
  ) AS machine,

  (
    SELECT to_jsonb(mt.topology->'bmc_info') as bmc_info
    FROM machine_topologies mt WHERE mt.machine_id = $1
  ) AS bmc_info
    "#;

    let res: SpdmMachineSnapshot = sqlx::query_as(query)
        .bind(machine_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(res)
}

pub async fn load_snapshot_for_machine_and_device_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    device_id: &String,
) -> Result<SpdmMachineSnapshot, DatabaseError> {
    let query = r#"
        SELECT
  (
    SELECT to_jsonb(d.*)
    FROM spdm_machine_devices_attestation d
    WHERE d.machine_id = $1 AND d.device_id = $2
  ) AS device,

  (
    SELECT row_to_json(m.*)
    FROM spdm_machine_attestation m
    WHERE m.machine_id = $1
  ) AS machine,

  (
    SELECT jsonb_object_agg(d2.device_id, d2.state)
    FROM spdm_machine_devices_attestation d2
    WHERE d2.machine_id = $1
  ) AS devices_state,

  (
    SELECT to_jsonb(mt.topology->'bmc_info') as bmc_info
    FROM machine_topologies mt WHERE mt.machine_id = $1
  ) AS bmc_info
    "#;

    let res: SpdmMachineSnapshot = sqlx::query_as(query)
        .bind(machine_id)
        .bind(device_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(res)
}

pub async fn load_details_for_machine_ids(
    txn: &mut PgConnection,
    machine_ids: &[MachineId],
) -> Result<Vec<SpdmMachineDetails>, DatabaseError> {
    let query = r#"
        SELECT 
            to_jsonb(m) as machine,
            COALESCE(d.devices, '[]'::jsonb) as devices,
            to_jsonb(mt.topology->'bmc_info') as bmc_info
        FROM spdm_machine_attestation AS m
        LEFT JOIN LATERAL (
            SELECT jsonb_agg(to_jsonb(d) ORDER BY d.device_id) AS devices
            FROM spdm_machine_devices_attestation AS d
            WHERE d.machine_id = m.machine_id
        ) AS d ON TRUE
        LEFT JOIN machine_topologies mt ON mt.machine_id = m.machine_id
        WHERE
            m.machine_id = ANY($1)
    "#;

    sqlx::query_as(query)
        .bind(machine_ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find_machine_ids(txn: &mut PgConnection) -> Result<Vec<MachineId>, DatabaseError> {
    let query = r#"
        SELECT 
            machine_id
        FROM 
            spdm_machine_attestation
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
    let query_machine = r#"
        UPDATE 
            spdm_machine_attestation
        SET state_outcome = $1
        WHERE machine_id = $2
        RETURNING *
    "#;

    let query_device = r#"
        UPDATE 
            spdm_machine_devices_attestation
        SET state_outcome = $1
        WHERE machine_id = $2 AND device_id = $3
        RETURNING *
    "#;

    if let Some(device_id) = &object_id.1 {
        let _res: SpdmMachineDeviceAttestation = sqlx::query_as(query_device)
            .bind(sqlx::types::Json(outcome))
            .bind(object_id.0)
            .bind(device_id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query_device, e))?;
    } else {
        let _res: SpdmMachineAttestation = sqlx::query_as(query_machine)
            .bind(sqlx::types::Json(outcome))
            .bind(object_id.0)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query_machine, e))?;
    }

    Ok(())
}

pub async fn persist_controller_state(
    txn: &mut PgConnection,
    object_id: &SpdmObjectId,
    new_state: &SpdmMachineStateSnapshot,
) -> Result<(), DatabaseError> {
    // This is a major state change. This means sync state is achieved if devices exist.
    // Update machine state as well all devices state.
    if new_state.update_machine_version {
        let new_version = new_state.machine_version.increment();
        let query = r#"
            UPDATE 
                spdm_machine_attestation
            SET state= $1, state_version = $2
            WHERE machine_id = $3 AND state_version=$4
            RETURNING *
        "#;

        let result = sqlx::query(query)
            .bind(sqlx::types::Json(&new_state.machine_state))
            .bind(new_version)
            .bind(object_id.0)
            .bind(new_state.machine_version)
            .execute(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        // Check if the update actually affected any rows (optimistic lock check)
        // If 0 rows were affected, another device already performed this transition
        if result.rows_affected() == 0 {
            // This is not an error - just skip device updates and history recording
            // The other device that won the race will handle updating devices and history
            return Ok(());
        }

        // Sync state is achieved, update all devices state .
        if new_state.update_device_version {
            let query = r#"
                UPDATE 
                    spdm_machine_devices_attestation
                SET state= $1, state_version=$2
                WHERE machine_id = $3 AND device_id = $4
                RETURNING *
            "#;

            // Not the initial phase. Devices to be updated.
            if !new_state.devices_state.is_empty() {
                let details = load_details_for_machine_ids(&mut *txn, &[object_id.0]).await?;
                let Some(details) = details.first() else {
                    return Err(DatabaseError::GenericErrorFromReport(eyre::eyre!(
                        "no device info is found."
                    )));
                };

                for (device_id, state) in &new_state.devices_state {
                    let current_version = details.devices.iter().find_map(|x| {
                        if &x.device_id == device_id {
                            Some(x.state_version)
                        } else {
                            None
                        }
                    });

                    let new_version = if let Some(current_version) = current_version {
                        current_version.increment()
                    } else {
                        ConfigVersion::initial() // It should never happen.
                    };

                    let _res: SpdmMachineDeviceAttestation = sqlx::query_as(query)
                        .bind(sqlx::types::Json(state))
                        .bind(new_version)
                        .bind(object_id.0)
                        .bind(device_id)
                        .fetch_one(&mut *txn)
                        .await
                        .map_err(|e| DatabaseError::query(query, e))?;
                }
            }
        }
    } else if new_state.update_device_version {
        // Update device state only for the given device
        let Some(device_version) = &new_state.device_version else {
            return Err(DatabaseError::GenericErrorFromReport(eyre::eyre!(
                "device version not found."
            )));
        };

        let Some(device_state) = &new_state.device_state else {
            return Err(DatabaseError::GenericErrorFromReport(eyre::eyre!(
                "device state not found."
            )));
        };

        let Some(device_id) = &object_id.1 else {
            return Err(DatabaseError::GenericErrorFromReport(eyre::eyre!(
                "device id not found."
            )));
        };

        let new_version = device_version.increment();
        let query = r#"
                UPDATE 
                    spdm_machine_devices_attestation
                SET state= $1, state_version=$2
                WHERE machine_id = $3 AND device_id = $4
                RETURNING *
            "#;
        let _res: SpdmMachineDeviceAttestation = sqlx::query_as(query)
            .bind(sqlx::types::Json(device_state))
            .bind(new_version)
            .bind(object_id.0)
            .bind(device_id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;
    }

    update_history(txn, object_id, new_state).await
}

pub async fn update_history(
    txn: &mut PgConnection,
    object_id: &SpdmObjectId,
    state_snapshot: &SpdmMachineStateSnapshot,
) -> Result<(), DatabaseError> {
    let query = r#"INSERT INTO spdm_machine_attestation_history (machine_id, updated_at, state_snapshot)
    VALUES($1, now(),  $2)
    "#;

    let mut state_snapshot = state_snapshot.clone();

    // force update correct state for the device_id.
    // This is not updated by state handler if only device state has to be updated.
    if let Some(device_id) = object_id.1.clone()
        && state_snapshot.update_device_version
        && let Some(device_state) = state_snapshot.device_state.clone()
    {
        state_snapshot.devices_state.insert(device_id, device_state);
    }

    sqlx::query(query)
        .bind(object_id.0)
        .bind(sqlx::types::Json(state_snapshot))
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}
