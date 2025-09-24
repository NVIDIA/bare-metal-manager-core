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

use forge_uuid::machine::MachineId;

use super::DatabaseError;
use crate::CarbideError;
use crate::db::managed_host;
use crate::db::vpc::Vpc;
use crate::model::controller_outcome::PersistentStateHandlerOutcome;
use crate::{
    db::dpa_interface_state_history::DpaInterfaceStateHistory,
    model::dpa_interface::{
        DpaInterfaceControllerState, DpaInterfaceNetworkConfig,
        DpaInterfaceNetworkStatusObservation,
    },
};
use chrono::prelude::*;
use config_version::ConfigVersion;
use config_version::Versioned;
use eyre::eyre;
use forge_uuid::dpa_interface::{DpaInterfaceId, NULL_DPA_INTERFACE_ID};
use itertools::Itertools;
use mac_address::MacAddress;
use managed_host::LoadSnapshotOptions;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgConnection, Row};
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct DpaInterface {
    pub id: DpaInterfaceId,
    pub machine_id: MachineId,

    pub mac_address: MacAddress,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,

    pub controller_state: Versioned<DpaInterfaceControllerState>,

    // Last time we issued a heartbeat command to the DPA
    pub last_hb_time: DateTime<Utc>,

    /// The result of the last attempt to change state
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,

    pub network_config: Versioned<DpaInterfaceNetworkConfig>,
    pub network_status_observation: Option<DpaInterfaceNetworkStatusObservation>,

    pub history: Vec<DpaInterfaceStateHistory>,
}

#[derive(Serialize, Deserialize)]
pub struct DpaInterfaceSnapshotPgJson {
    id: DpaInterfaceId,
    machine_id: MachineId,
    mac_address: MacAddress,
    created: DateTime<Utc>,
    updated: DateTime<Utc>,
    deleted: Option<DateTime<Utc>>,
    last_hb_time: DateTime<Utc>,
    controller_state: DpaInterfaceControllerState,
    controller_state_version: String,
    controller_state_outcome: Option<PersistentStateHandlerOutcome>,
    network_config: DpaInterfaceNetworkConfig,
    network_config_version: String,
    network_status_observation: Option<DpaInterfaceNetworkStatusObservation>,
    #[serde(default)]
    history: Vec<DpaInterfaceStateHistory>,
}

impl TryFrom<DpaInterfaceSnapshotPgJson> for DpaInterface {
    type Error = sqlx::Error;

    fn try_from(value: DpaInterfaceSnapshotPgJson) -> sqlx::Result<Self> {
        Ok(Self {
            id: value.id,
            machine_id: value.machine_id,
            mac_address: value.mac_address,
            created: value.created,
            updated: value.updated,
            deleted: value.deleted,
            last_hb_time: value.last_hb_time,
            controller_state: Versioned {
                value: value.controller_state,
                version: value.controller_state_version.parse().map_err(|e| {
                    sqlx::error::Error::ColumnDecode {
                        index: "controller_state_version".to_string(),
                        source: Box::new(e),
                    }
                })?,
            },
            controller_state_outcome: value.controller_state_outcome,
            network_config: Versioned {
                value: value.network_config,
                version: value.network_config_version.parse().map_err(|e| {
                    sqlx::error::Error::ColumnDecode {
                        index: "network_config_version".to_string(),
                        source: Box::new(e),
                    }
                })?,
            },
            network_status_observation: value.network_status_observation,
            history: value.history,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NewDpaInterface {
    pub machine_id: MachineId,
    pub mac_address: MacAddress,
}

impl TryFrom<rpc::forge::DpaInterfaceCreationRequest> for NewDpaInterface {
    type Error = CarbideError;

    fn try_from(value: rpc::forge::DpaInterfaceCreationRequest) -> Result<Self, Self::Error> {
        let machine_id = value
            .machine_id
            .ok_or(CarbideError::MissingArgument("id"))?;
        let mac_address = MacAddress::from_str(&value.mac_addr)?;
        Ok(NewDpaInterface {
            machine_id,
            mac_address,
        })
    }
}

impl NewDpaInterface {
    pub async fn persist(&self, txn: &mut PgConnection) -> Result<DpaInterface, DatabaseError> {
        let network_config_version = ConfigVersion::initial();
        let network_config = DpaInterfaceNetworkConfig::default();
        let state_version = ConfigVersion::initial();
        let state = DpaInterfaceControllerState::Provisioning;

        let query = "INSERT INTO dpa_interfaces (machine_id, mac_address, network_config_version, network_config, controller_state_version, controller_state)
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING row_to_json(dpa_interfaces.*)";

        sqlx::query_as(query)
            .bind(self.machine_id.to_string())
            .bind(self.mac_address)
            .bind(network_config_version)
            .bind(sqlx::types::Json(&network_config))
            .bind(state_version)
            .bind(sqlx::types::Json(&state))
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }
}

impl DpaInterface {
    pub fn use_admin_network(&self) -> bool {
        self.network_config.use_admin_network.unwrap_or(true)
    }

    pub async fn update_network_observation(
        &mut self,
        txn: &mut PgConnection,
        observation: &DpaInterfaceNetworkStatusObservation,
    ) -> Result<DpaInterfaceId, DatabaseError> {
        let query = "UPDATE dpa_interfaces SET network_status_observation = $1::json WHERE id = $2::uuid AND
                (
                    (network_status_observation->>'observed_at' IS NULL)
                    OR ((network_status_observation->>'observed_at')::timestamp <= $3::timestamp)
                ) RETURNING id";

        sqlx::query_as(query)
            .bind(sqlx::types::Json(&observation))
            .bind(self.id.to_string())
            .bind(observation.observed_at)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }

    // Update the last_hb_time field with the current timestamp for the given DPA interface
    // and return the DPA Interface ID
    pub async fn update_last_hb_time(
        &mut self,
        txn: &mut PgConnection,
    ) -> Result<DpaInterfaceId, DatabaseError> {
        let query = "UPDATE dpa_interfaces SET last_hb_time = NOW() WHERE id = $1::uuid
                RETURNING id";

        sqlx::query_as(query)
            .bind(self.id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }

    pub fn managed_host_network_config_version_synced(&self) -> bool {
        let dpa_expected_version = self.network_config.version;
        let dpa_observation = self.network_status_observation.as_ref();

        let dpa_observed_version: ConfigVersion = match dpa_observation {
            Some(network_status) => match network_status.network_config_version {
                Some(version) => version,
                None => return false,
            },
            None => return false,
        };

        dpa_expected_version == dpa_observed_version
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
                DpaInterfaceStateHistory::persist(&mut *txn, id, new_state, next_version).await?;
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

    pub async fn delete(&self, txn: &mut PgConnection) -> Result<(), DatabaseError> {
        let query = "delete from dpa_interface_state_history where interface_id=$1";
        sqlx::query(query)
            .bind(self.id)
            .execute(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        let query = "delete from dpa_interfaces where id=$1";
        sqlx::query(query)
            .bind(self.id)
            .execute(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
            .map(|_| ())
    }
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

    let vpc = Vpc::find_by_segment(txn, network_segment_id).await?;

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

impl<'r> FromRow<'r, PgRow> for DpaInterface {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let json: serde_json::value::Value = row.try_get(0)?;
        DpaInterfaceSnapshotPgJson::deserialize(json)
            .map_err(|err| sqlx::Error::Decode(err.into()))?
            .try_into()
    }
}

pub async fn is_machine_dpa_capable(
    txn: &mut PgConnection,
    machine_id: MachineId,
) -> Result<bool, DatabaseError> {
    let query = "SELECT COUNT(*) from dpa_interfaces where deleted is NULL and machine_id = $1";

    let (ifc_count,): (i64,) = sqlx::query_as(query)
        .bind(machine_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(ifc_count != 0)
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
        .bind(interface_id.to_string())
        .bind(expected_version)
        .fetch_one(txn)
        .await;

    match query_result {
        Ok(interface_id) => Ok(interface_id),
        Err(sqlx::Error::RowNotFound) => Ok(NULL_DPA_INTERFACE_ID),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

impl From<DpaInterface> for rpc::forge::DpaInterface {
    fn from(src: DpaInterface) -> Self {
        let (controller_state, controller_state_version) = src.controller_state.take();
        let (network_config, network_config_version) = src.network_config.take();

        let outcome = match src.controller_state_outcome {
            Some(psho) => psho.to_string(),
            None => "None".to_string(),
        };

        let network_status_observation = match src.network_status_observation {
            Some(nso) => nso.to_string(),
            None => "None".to_string(),
        };

        let history: Vec<rpc::forge::DpaInterfaceStateHistory> = src
            .history
            .into_iter()
            .sorted_by(
                | s1: &crate::db::dpa_interface_state_history::DpaInterfaceStateHistory,
                  s2: &crate::db::dpa_interface_state_history::DpaInterfaceStateHistory | {
                    Ord::cmp(&s1.state_version.timestamp(), &s2.state_version.timestamp())
                  },
            )
            .map(Into::into)
            .collect();

        rpc::forge::DpaInterface {
            id: Some(src.id),
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
            last_hb_time: Some(src.last_hb_time.into()),
            mac_addr: src.mac_address.to_string(),
            machine_id: Some(src.machine_id),
            controller_state: controller_state.to_string(),
            controller_state_version: controller_state_version.to_string(),
            network_config: network_config.to_string(),
            network_config_version: network_config_version.to_string(),
            controller_state_outcome: outcome,
            network_status_observation,
            history,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::db::machine;
    use crate::{
        db::dpa_interface::NewDpaInterface,
        model::{machine::ManagedHostState, metadata::Metadata},
    };
    use forge_uuid::machine::MachineId;
    use mac_address::MacAddress;
    use std::str::FromStr;

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
        )
        .await?;

        let new_intf = NewDpaInterface {
            mac_address: MacAddress::from_str("00:11:22:33:44:55")?,
            machine_id: id,
        };

        let intf = new_intf.persist(&mut txn).await?;

        let ids = crate::db::dpa_interface::DpaInterface::find_ids(&mut txn).await?;

        assert!(ids.len() == 1);
        assert!(ids[0] == intf.id);

        let db_intf =
            crate::db::dpa_interface::DpaInterface::find_by_ids(&mut txn, &[ids[0]], false).await?;

        assert!(db_intf.len() == 1);
        assert!(db_intf[0].id == intf.id);

        Ok(())
    }
}
