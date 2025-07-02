/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use forge_uuid::machine::MachineId;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection, Row, postgres::PgRow};

use crate::db::DatabaseError;

/// Representing DPU state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "host_power_state_t")]
pub enum PowerState {
    On,
    Off,
}

/// Represents the power management options for a specific host, including
/// details about the last fetched power information, the desired power state,
/// and the status of triggering power-on operations.
/// Carbide will poll for the actual power state of the machine, once in a 5 mins.
/// `next_try_at` will be now()+5 mins if power state is On. If machine is Off, next_try will be
/// now()+2 mins, if desired state is On. If machine remains off for 2 cycles (2+2 mins), carbide
/// would take the next decision.
/// If power manager tried to power on the host, wait until DPUs are up or wait_expiry_time is
/// expired (which is around 15 mins). If DPUs come up by this time, reboot the host, else ignore
/// the handling and move to the state handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerOptions {
    pub host_id: MachineId,
    last_fetched_updated_at: DateTime<Utc>,
    last_fetched_next_try_at: DateTime<Utc>,
    last_fetched_power_state: PowerState,
    /// Once counter is incremented >= 2, the machine will be assumed off.
    /// This is needed to avoid power off done by state machine for the recovery mechanism.
    last_fetched_off_counter: i32,
    pub desired_power_state_version: ConfigVersion,
    /// Tenant/SRE can set the desired power option.
    /// If there is some operation is being performed on any host, make the desired state
    /// off. Carbide won't try to turn on the machine and process any event in state machine.
    /// If desired state is On and machines state is Off, carbide will try to turn-on the machine.
    pub desired_power_state: PowerState,
    /// In the case if state machine decides to power on the host, state machine must wait until
    /// the DPUs come up and again reboot the host to force it to boot via pxe.
    wait_until_time_before_performing_next_power_action: DateTime<Utc>,
    // If tried_triggering_on_at is some and last_fetched.power_state is not On and
    // tried_triggering_on_at < last_fetched.updated_at, try powering on again.
    // Reset it when host's power state is detected as On.
    tried_triggering_on_at: Option<DateTime<Utc>>,
    // Increment it every time you try to power-on the host.
    // Reset it when host's power state is detected as On.
    tried_triggering_on_counter: i32,
}

impl<'r> FromRow<'r, PgRow> for PowerOptions {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let host_id: MachineId = row.try_get("host_id")?;
        let last_fetched_updated_at = row.try_get("last_fetched_updated_at")?;
        let last_fetched_next_try_at = row.try_get("last_fetched_next_try_at")?;
        let last_fetched_power_state = row.try_get("last_fetched_power_state")?;
        let last_fetched_off_counter = row.try_get("last_fetched_off_counter")?;
        let desired_state_version: String = row.try_get("desired_power_state_version")?;
        let desired_power_state_version =
            desired_state_version
                .parse()
                .map_err(|e| sqlx::error::Error::ColumnDecode {
                    index: "version".to_string(),
                    source: Box::new(e),
                })?;
        let desired_power_state = row.try_get("desired_power_state")?;
        let wait_until_time_before_performing_next_power_action =
            row.try_get("wait_until_time_before_performing_next_power_action")?;
        let tried_triggering_on_at: Option<DateTime<Utc>> =
            row.try_get("tried_triggering_on_at").ok();
        let tried_triggering_on_counter = row.try_get("tried_triggering_on_counter")?;

        Ok(Self {
            host_id,
            last_fetched_updated_at,
            last_fetched_next_try_at,
            last_fetched_power_state,
            last_fetched_off_counter,
            desired_power_state_version,
            desired_power_state,
            wait_until_time_before_performing_next_power_action,
            tried_triggering_on_at,
            tried_triggering_on_counter,
        })
    }
}

impl From<::rpc::forge::PowerState> for PowerState {
    fn from(value: ::rpc::forge::PowerState) -> Self {
        match value {
            rpc::forge::PowerState::On => PowerState::On,
            rpc::forge::PowerState::Off => PowerState::Off,
        }
    }
}

impl From<PowerState> for ::rpc::forge::PowerState {
    fn from(value: PowerState) -> Self {
        match value {
            PowerState::Off => ::rpc::forge::PowerState::Off,
            PowerState::On => ::rpc::forge::PowerState::On,
        }
    }
}

impl From<PowerOptions> for ::rpc::forge::PowerOptions {
    fn from(value: PowerOptions) -> Self {
        Self {
            desired_state: rpc::forge::PowerState::from(value.desired_power_state) as i32,
            desired_state_updated_at: Some(value.desired_power_state_version.timestamp().into()),
            actual_state: rpc::forge::PowerState::from(value.last_fetched_power_state) as i32,
            actual_state_updated_at: Some(value.last_fetched_updated_at.into()),
            host_id: Some(rpc::common::MachineId {
                id: value.host_id.to_string(),
            }),
            desired_power_state_version: value.desired_power_state_version.to_string(),
        }
    }
}

impl PowerOptions {
    /// Create a power option entry for a host into db.
    pub async fn create(
        host_id: &MachineId,
        txn: &mut PgConnection,
    ) -> Result<Self, DatabaseError> {
        let query = "INSERT INTO power_options ( host_id ) VALUES ($1) RETURNING *";

        let options = sqlx::query_as(query)
            .bind(host_id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(options)
    }

    pub async fn update_desired_state(
        host_id: &MachineId,
        power_state: PowerState,
        current_version: &ConfigVersion,
        txn: &mut PgConnection,
    ) -> Result<Self, DatabaseError> {
        let query = "UPDATE power_options SET desired_power_state=$1, desired_power_state_version=$2 WHERE host_id=$3 RETURNING *";

        let config_version = current_version.increment();

        let updated_value = sqlx::query_as(query)
            .bind(power_state)
            .bind(config_version)
            .bind(host_id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(updated_value)
    }

    pub async fn get_all(txn: &mut PgConnection) -> Result<Vec<PowerOptions>, DatabaseError> {
        let query = "SELECT * FROM power_options";

        let all_options = sqlx::query_as(query)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(all_options)
    }

    pub async fn get_by_ids(
        machine_ids: &[MachineId],
        txn: &mut PgConnection,
    ) -> Result<Vec<PowerOptions>, DatabaseError> {
        let query = "SELECT * FROM power_options WHERE host_id = ANY($1)";

        let all_options = sqlx::query_as(query)
            .bind(machine_ids)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(all_options)
    }
}
