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
use sqlx::{FromRow, PgConnection, Row, postgres::PgRow};

use crate::{
    db::DatabaseError,
    model::power_manager::{PowerOptions, PowerState},
};

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

    pub async fn persist(
        options: &PowerOptions,
        txn: &mut PgConnection,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE power_options SET 
                                    last_fetched_updated_at=$1, last_fetched_next_try_at=$2,
                                    last_fetched_power_state=$3, last_fetched_off_counter=$4,
                                    wait_until_time_before_performing_next_power_action=$5,
                                    tried_triggering_on_at=$6, tried_triggering_on_counter=$7
                                WHERE host_id=$8";

        sqlx::query(query)
            .bind(options.last_fetched_updated_at)
            .bind(options.last_fetched_next_try_at)
            .bind(options.last_fetched_power_state)
            .bind(options.last_fetched_off_counter)
            .bind(options.wait_until_time_before_performing_next_power_action)
            .bind(options.tried_triggering_on_at)
            .bind(options.tried_triggering_on_counter)
            .bind(options.host_id)
            .execute(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }
}
