/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_uuid::machine::MachineId;
use model::attestation::spdm::{
    SpdmMachineAttestation, SpdmMachineDeviceAttestation, SpdmMachineSnapshot,
};
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult};

pub async fn insert_or_update_machine_attestation_request(
    txn: &mut PgConnection,
    attestation_request: &SpdmMachineAttestation,
) -> DatabaseResult<()> {
    let query = r#"INSERT INTO spdm_machine_attestation (machine_id, requested_at, state, state_version)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (machine_id) DO UPDATE SET
            requested_at = $2
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

pub async fn insert_device(
    txn: &mut PgConnection,
    device: &SpdmMachineDeviceAttestation,
) -> DatabaseResult<()> {
    let query = r#"INSERT INTO spdm_machine_devices_attestation (machine_id, device_id, nonce, state)
        VALUES ($1, $2, $3, $4)
        RETURNING *"#;
    let _res: SpdmMachineDeviceAttestation = sqlx::query_as(query)
        .bind(device.machine_id)
        .bind(&device.device_id)
        .bind(device.nonce)
        .bind(sqlx::types::Json(&device.state))
        .fetch_one(txn)
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

pub async fn load_snapshots_for_attestation(
    txn: &mut PgConnection,
) -> Result<Vec<SpdmMachineSnapshot>, DatabaseError> {
    let query = r#"
        SELECT 
            to_jsonb(m) as machine,
            COALESCE(d.devices, '[]'::jsonb) as devices
        FROM spdm_machine_attestation AS m
        LEFT JOIN LATERAL (
            SELECT jsonb_agg(to_jsonb(d) ORDER BY d.device_id) AS devices
            FROM spdm_machine_devices_attestation AS d
            WHERE d.machine_id = m.machine_id
        ) AS d ON TRUE
        WHERE
            (
                m.requested_at > m.started_at 
                OR
                m.attestation_status = 'not_started'
                OR
                m.attestation_status = 'started') 
            AND 
            (   
                m.canceled_at is NULL 
                OR 
                m.requested_at > m.requested_at
            )
    "#;

    let res: Vec<SpdmMachineSnapshot> = sqlx::query_as(query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(res)
}

pub async fn load_snapshot_for_machine_ids(
    txn: &mut PgConnection,
    machine_ids: &[MachineId],
) -> Result<Vec<SpdmMachineSnapshot>, DatabaseError> {
    let query = r#"
        SELECT 
            to_jsonb(m) as machine,
            COALESCE(d.devices, '[]'::jsonb) as devices
        FROM spdm_machine_attestation AS m
        LEFT JOIN LATERAL (
            SELECT jsonb_agg(to_jsonb(d) ORDER BY d.device_id) AS devices
            FROM spdm_machine_devices_attestation AS d
            WHERE d.machine_id = m.machine_id
        ) AS d ON TRUE
        WHERE
            m.machine_id = ANY($1)
    "#;

    let res: Vec<SpdmMachineSnapshot> = sqlx::query_as(query)
        .bind(machine_ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(res)
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
