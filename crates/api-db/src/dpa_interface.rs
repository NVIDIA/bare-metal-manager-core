/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashSet;
use std::net::IpAddr;

use carbide_uuid::dpa_interface::{DpaInterfaceId, NULL_DPA_INTERFACE_ID};
use carbide_uuid::machine::MachineId;
use config_version::ConfigVersion;
use eyre::eyre;
use mac_address::MacAddress;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::dpa_interface::{
    DpaInterface, DpaInterfaceControllerState, DpaInterfaceNetworkConfig,
    DpaInterfaceNetworkStatusObservation, NewDpaInterface,
};
use model::machine::LoadSnapshotOptions;
use sqlx::PgConnection;

use super::{DatabaseError, dpa_interface_state_history};
use crate::managed_host;

pub async fn persist(
    value: NewDpaInterface,
    txn: &mut PgConnection,
) -> Result<DpaInterface, DatabaseError> {
    let network_config_version = ConfigVersion::initial();
    let network_config = DpaInterfaceNetworkConfig::default();
    let state_version = ConfigVersion::initial();
    let state = DpaInterfaceControllerState::Provisioning;

    let query = "INSERT INTO dpa_interfaces (machine_id, mac_address, network_config_version, network_config, controller_state_version, controller_state, device_type, pci_name)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING row_to_json(dpa_interfaces.*)";

    sqlx::query_as(query)
        .bind(value.machine_id.to_string())
        .bind(value.mac_address)
        .bind(network_config_version)
        .bind(sqlx::types::Json(&network_config))
        .bind(state_version)
        .bind(sqlx::types::Json(&state))
        .bind(value.device_type)
        .bind(value.pci_name)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn update_network_observation(
    value: &DpaInterface,
    txn: &mut PgConnection,
    observation: &DpaInterfaceNetworkStatusObservation,
) -> Result<DpaInterfaceId, DatabaseError> {
    let query =
        "UPDATE dpa_interfaces SET network_status_observation = $1::json WHERE id = $2::uuid AND
                (
                    (network_status_observation->>'observed_at' IS NULL)
                    OR ((network_status_observation->>'observed_at')::timestamp <= $3::timestamp)
                ) RETURNING id";

    sqlx::query_as(query)
        .bind(sqlx::types::Json(&observation))
        .bind(value.id.to_string())
        .bind(observation.observed_at)
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

// Update the last_hb_time field with the current timestamp for the given DPA interface
// and return the DPA Interface ID
pub async fn update_last_hb_time(
    value: &DpaInterface,
    txn: &mut PgConnection,
) -> Result<DpaInterfaceId, DatabaseError> {
    let query = "UPDATE dpa_interfaces SET last_hb_time = NOW() WHERE id = $1::uuid
                RETURNING id";

    sqlx::query_as(query)
        .bind(value.id)
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

// Update the underlay or the overlay ip address of the given DPA interface object
pub async fn update_ip(
    value: DpaInterface,
    underlay: bool,
    txn: &mut PgConnection,
) -> Result<DpaInterfaceId, DatabaseError> {
    let mut builder = sqlx::QueryBuilder::new("Update dpa_interfaces SET ");

    if underlay {
        builder.push(" underlay_ip=");
        builder.push_bind(value.underlay_ip.unwrap());
    } else {
        builder.push(" overlay_ip=");
        builder.push_bind(value.overlay_ip.unwrap());
    }

    builder.push(" WHERE id=");
    builder.push_bind(value.id);

    builder.push(" RETURNING id");

    builder
        .build_query_as()
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(builder.sql(), e))
}

pub async fn find_ids(txn: &mut PgConnection) -> Result<Vec<DpaInterfaceId>, DatabaseError> {
    let query = "SELECT id from dpa_interfaces WHERE deleted is NULL";

    let results: Vec<DpaInterfaceId> = {
        sqlx::query_as(query)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?
    };

    Ok(results)
}

// Given an IP address, find and return the DPA interface that has the given IP
// as its underlay or overlay IP address.
pub async fn find_by_ip(
    txn: &mut PgConnection,
    ipaddr: IpAddr,
) -> Result<Vec<DpaInterface>, DatabaseError> {
    let query = "SELECT row_to_json(m.*) from (select * from dpa_interfaces
        WHERE deleted is NULL AND underlay_ip = $1 or overlay_ip = $2) m";

    let results: Vec<DpaInterface> = {
        sqlx::query_as(query)
            .bind(ipaddr)
            .bind(ipaddr)
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?
    };

    Ok(results)
}

// Find a DPA Interface given its mac address. When we receive messages from the MQTT broker,
// the topic contains the mac address, and we look up the interface based on that mac address.
pub async fn find_by_mac_addr(
    txn: &mut PgConnection,
    maddr: &MacAddress,
) -> Result<Vec<DpaInterface>, DatabaseError> {
    let query = "SELECT row_to_json(m.*) from (select * from dpa_interfaces WHERE deleted is NULL AND mac_address = $1) m";

    let results: Vec<DpaInterface> = {
        sqlx::query_as(query)
            .bind(maddr)
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?
    };

    Ok(results)
}

pub async fn update_card_state(
    txn: &mut PgConnection,
    value: DpaInterface,
) -> Result<DpaInterfaceId, DatabaseError> {
    let query = "UPDATE dpa_interfaces SET card_state = $1::json WHERE id = $2::uuid 
                RETURNING id";

    sqlx::query_as(query)
        .bind(sqlx::types::Json(&value.card_state))
        .bind(value.id.to_string())
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

// Used by the machine statemachine controller to find all DPAs associated with a given machine
pub async fn find_by_machine_id(
    txn: &mut PgConnection,
    mid: &MachineId,
) -> Result<Vec<DpaInterface>, DatabaseError> {
    let query = "SELECT row_to_json(m.*) from (select * from dpa_interfaces WHERE deleted is NULL AND machine_id = $1) m";
    let results: Vec<DpaInterface> = {
        sqlx::query_as(query)
            .bind(mid)
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?
    };

    Ok(results)
}

pub async fn find_by_ids(
    txn: &mut PgConnection,
    dpa_ids: &[DpaInterfaceId],
    include_history: bool,
) -> Result<Vec<DpaInterface>, DatabaseError> {
    let mut builder = if include_history {
        sqlx::QueryBuilder::new("select row_to_json(m.*) from
                (SELECT si.*, COALESCE(history_agg.json, '[]'::json) AS history FROM dpa_interfaces si
                LEFT JOIN LATERAL (
                SELECT h.interface_id, json_agg(json_build_object('interface_id', h.interface_id, 'state', h.state::text, 'state_version', h.state_version,
                'timestamp', h.timestamp)) AS json FROM dpa_interface_state_history h WHERE h.interface_id = si.id GROUP BY h.interface_id ) AS history_agg ON true
                WHERE deleted is NULL")
    } else {
        sqlx::QueryBuilder::new(
            "SELECT row_to_json(m.*) from (select * from dpa_interfaces WHERE deleted is NULL",
        )
    };

    builder.push(" AND id = ANY(");
    builder.push_bind(dpa_ids);
    builder.push(")) m");

    builder
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|err: sqlx::Error| DatabaseError::query(builder.sql(), err))
}

// Given a DPA Interface ID, return a vector of the DPA Interface structures
// of all the DPAs in the same host machine.
pub async fn get_dpas_in_machine(
    txn: &mut PgConnection,
    id: DpaInterfaceId,
) -> Result<Vec<DpaInterface>, DatabaseError> {
    // let query = "SELECT * row_to_json(m.*) from (select * from dpa_interfaces e
    // deleted is NULL AND machine_id = (SELECT machine_id from dpa_interfaces WHERE id = $1)) m";
    let query = "SELECT row_to_json(m)
                        FROM dpa_interfaces m
                        JOIN dpa_interfaces d ON d.id = $1
                        WHERE m.deleted IS NULL
                        AND m.machine_id = d.machine_id";

    let results: Vec<DpaInterface> = {
        sqlx::query_as(query)
            .bind(id)
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?
    };

    Ok(results)
}

// Return true if all the dpas in the same machine as the given dpa (self) are in the
// same state. Return false otherwise.
// Use this in places where we need to move the DPAs in lockstep (i.e. all the DPAs have
// to be in the same state before we move to the next state).
pub async fn all_dpa_states_in_sync(
    value: &DpaInterface,
    txn: &mut PgConnection,
) -> Result<bool, DatabaseError> {
    let dpas_vec = get_dpas_in_machine(txn, value.id).await?;

    for dpa in &dpas_vec {
        if dpa.controller_state.value != value.controller_state.value {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Updates the dpa interface state that is owned by the state controller
/// under the premise that the current controller state version didn't change.
///
/// Returns `true` if the state could be updated, and `false` if the object
/// either doesn't exist anymore or is at a different version.
pub async fn try_update_controller_state(
    txn: &mut PgConnection,
    id: DpaInterfaceId,
    expected_version: ConfigVersion,
    new_state: &DpaInterfaceControllerState,
) -> Result<bool, DatabaseError> {
    let next_version = expected_version.increment();

    let query = "UPDATE dpa_interfaces SET controller_state_version=$1, controller_state=$2::json where id=$3::uuid AND controller_state_version=$4 returning id";
    let query_result: Result<DpaInterfaceId, _> = sqlx::query_as(query)
        .bind(next_version)
        .bind(sqlx::types::Json(new_state))
        .bind(id)
        .bind(expected_version)
        .fetch_one(&mut *txn)
        .await;

    match query_result {
        Ok(_segment_id) => {
            dpa_interface_state_history::persist(&mut *txn, id, new_state, next_version).await?;
            Ok(true)
        }
        Err(sqlx::Error::RowNotFound) => Ok(false),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

pub async fn update_controller_state_outcome(
    txn: &mut PgConnection,
    id: DpaInterfaceId,
    outcome: PersistentStateHandlerOutcome,
) -> Result<(), DatabaseError> {
    let query = "UPDATE dpa_interfaces SET controller_state_outcome=$1::json WHERE id=$2";
    sqlx::query(query)
        .bind(sqlx::types::Json(outcome))
        .bind(id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn delete(value: DpaInterface, txn: &mut PgConnection) -> Result<(), DatabaseError> {
    let query = "delete from dpa_interface_state_history where interface_id=$1";
    sqlx::query(query)
        .bind(value.id)
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    let query = "delete from dpa_interfaces where id=$1";
    sqlx::query(query)
        .bind(value.id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
        .map(|_| ())
}

// get_dpa_vni figures out the VNI to be used for this DPA interface
// when we are transitioning to ASSIGNED state. This happens when we are
// moving from Ready to WaitingForSetVNI or when we are still in WaitingForSetVNI
// states.
//
// Given the DPA Interface, we know its associated machine ID. From that, we need
// to find the VPC the machine belongs to. From the VPC, we can find the DPA VNI
// allocated for that VPC.
pub async fn get_dpa_vni(
    state: &mut DpaInterface,
    txn: &mut PgConnection,
) -> Result<i32, eyre::Report> {
    let machine_id = state.machine_id;

    let maybe_snapshot =
        managed_host::load_snapshot(txn, &machine_id, LoadSnapshotOptions::default()).await?;

    let snapshot = match maybe_snapshot {
        Some(sn) => sn,
        None => return Err(eyre!("machine {machine_id} snapshot found".to_string())),
    };

    let instance = match snapshot.instance {
        Some(inst) => inst,
        None => {
            return Err(eyre!("Expected an instance and found none"));
        }
    };

    let interfaces = &instance.config.network.interfaces;
    let Some(network_segment_id) = interfaces[0].network_segment_id else {
        // Network segment allocation is done before persisting record in db. So if still
        // network segment is empty, return error.
        return Err(eyre!("Expected Network Segment"));
    };

    let vpc = crate::vpc::find_by_segment(txn, network_segment_id).await?;

    match vpc.dpa_vni {
        Some(vni) => {
            if vni == 0 {
                tracing::warn!("Did not expect DPA VNI to be zero");
            }
            Ok(vni)
        }
        None => Err(eyre!("Expected VNI. Found none")),
    }
}

pub async fn is_machine_dpa_capable(
    txn: &mut PgConnection,
    machine_id: MachineId,
) -> Result<bool, DatabaseError> {
    let result = batch_is_machine_dpa_capable(txn, &[machine_id]).await?;
    Ok(result.contains(&machine_id))
}

/// Batch check which machines are DPA capable.
/// Returns a HashSet of machine IDs that have DPA interfaces.
pub async fn batch_is_machine_dpa_capable(
    txn: &mut PgConnection,
    machine_ids: &[MachineId],
) -> Result<HashSet<MachineId>, DatabaseError> {
    if machine_ids.is_empty() {
        return Ok(HashSet::new());
    }

    let query = "SELECT DISTINCT machine_id FROM dpa_interfaces
                 WHERE deleted IS NULL AND machine_id = ANY($1)";

    let rows: Vec<(String,)> = sqlx::query_as(query)
        .bind(
            machine_ids
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>(),
        )
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(rows
        .into_iter()
        .filter_map(|(id,)| id.parse::<MachineId>().ok())
        .collect())
}

/// Updates the desired network configuration for a host
pub async fn try_update_network_config(
    txn: &mut PgConnection,
    interface_id: &DpaInterfaceId,
    expected_version: ConfigVersion,
    new_state: &DpaInterfaceNetworkConfig,
) -> Result<DpaInterfaceId, DatabaseError> {
    let next_version = expected_version.increment();

    let query = "UPDATE dpa_interfaces SET network_config_version=$1, network_config=$2::json
            WHERE id=$3::uuid AND network_config_version=$4
            RETURNING id";
    let query_result: Result<DpaInterfaceId, _> = sqlx::query_as(query)
        .bind(next_version)
        .bind(sqlx::types::Json(new_state))
        .bind(interface_id)
        .bind(expected_version)
        .fetch_one(txn)
        .await;

    match query_result {
        Ok(interface_id) => Ok(interface_id),
        Err(sqlx::Error::RowNotFound) => Ok(NULL_DPA_INTERFACE_ID),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use carbide_uuid::machine::MachineId;
    use mac_address::MacAddress;
    use model::dpa_interface::NewDpaInterface;
    use model::machine::ManagedHostState;
    use model::metadata::Metadata;

    use crate::machine;

    #[crate::sqlx_test]
    async fn test_find_interfaces(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await.unwrap();

        let id =
            MachineId::from_str("fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30")?;

        machine::create(
            &mut txn,
            None,
            &id,
            ManagedHostState::Ready,
            &Metadata::default(),
            None,
            true,
            2,
        )
        .await?;

        let new_intf = NewDpaInterface {
            mac_address: MacAddress::from_str("00:11:22:33:44:55")?,
            machine_id: id,
            device_type: "Bluefield 3".to_string(),
            pci_name: "5e:00.0".to_string(),
        };

        let intf = crate::dpa_interface::persist(new_intf, &mut txn).await?;

        let ids = crate::dpa_interface::find_ids(&mut txn).await?;

        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], intf.id);

        let db_intf = crate::dpa_interface::find_by_ids(&mut txn, &[ids[0]], false).await?;

        assert_eq!(db_intf.len(), 1);
        assert_eq!(db_intf[0].id, intf.id);

        Ok(())
    }
}
