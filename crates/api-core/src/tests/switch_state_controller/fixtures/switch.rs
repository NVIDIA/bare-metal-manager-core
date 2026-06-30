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

use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use db::switch as db_switch;
use model::switch::{ConfigureCertificateState, ConfiguringState, SwitchControllerState};
use sqlx::PgConnection;

/// Helper function to set switch controller state directly in database
pub async fn set_switch_controller_state(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
    state: SwitchControllerState,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE switches SET controller_state = $1 WHERE id = $2")
        .bind(serde_json::to_value(state).unwrap())
        .bind(switch_id)
        .execute(txn)
        .await?;

    Ok(())
}

pub async fn set_switch_rack_id(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
    rack_id: &RackId,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE switches SET rack_id = $1 WHERE id = $2")
        .bind(rack_id)
        .bind(switch_id)
        .execute(txn)
        .await?;
    Ok(())
}

pub async fn transition_switch_controller_state(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
    new_state: SwitchControllerState,
) -> Result<(), Box<dyn std::error::Error>> {
    let switch = db_switch::find_by_id(txn, switch_id)
        .await?
        .expect("switch should exist");
    db_switch::try_update_controller_state(
        txn,
        *switch_id,
        switch.controller_state.version,
        switch.controller_state.version.increment(),
        &new_state,
    )
    .await?;
    Ok(())
}

pub fn configure_certificate_start_state() -> SwitchControllerState {
    SwitchControllerState::Configuring {
        config_state: ConfiguringState::ConfigureCertificate {
            configure_certificate: ConfigureCertificateState::Start,
        },
    }
}

pub fn configure_certificate_wait_state(job_id: &str) -> SwitchControllerState {
    SwitchControllerState::Configuring {
        config_state: ConfiguringState::ConfigureCertificate {
            configure_certificate: ConfigureCertificateState::WaitForComplete {
                job_id: job_id.to_string(),
            },
        },
    }
}

/// Helper function to mark switch as deleted
pub async fn mark_switch_as_deleted(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE switches SET deleted = NOW() WHERE id = $1")
        .bind(switch_id)
        .execute(txn)
        .await?;

    Ok(())
}
