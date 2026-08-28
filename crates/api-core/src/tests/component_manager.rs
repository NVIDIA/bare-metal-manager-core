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

use std::collections::HashMap;

use carbide_uuid::switch::SwitchId;
use model::rack::{MaintenanceActivity, RackFirmwareUpgradeState, RackFirmwareUpgradeStatus};
use model::switch::{NewSwitch, SwitchConfig};
use rpc::forge as rpc;
use tonic::Request;

use crate::test_support::builder::TestApiBuilder;
use crate::tests::common::api_fixtures::create_test_env;

#[crate::sqlx_test]
async fn switch_firmware_status_uses_only_current_cycle_persistence(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let switch_ids = (0..3)
        .map(|_| SwitchId::from(uuid::Uuid::new_v4()))
        .collect::<Vec<_>>();
    let firmware_activity = MaintenanceActivity::FirmwareUpgrade {
        firmware_version: Some("firmware-object-json".into()),
        components: vec![],
        force_update: false,
    };

    let mut txn = pool.begin().await?;
    for (index, switch_id) in switch_ids.iter().enumerate() {
        db::switch::create(
            txn.as_mut(),
            &NewSwitch {
                id: *switch_id,
                config: SwitchConfig {
                    name: format!("firmware-status-switch-{index}"),
                    enable_nmxc: false,
                    fabric_manager_config: None,
                },
                bmc_mac_address: None,
                metadata: None,
                rack_id: None,
                slot_number: None,
                tray_index: None,
            },
        )
        .await?;
        db::switch::set_switch_reprovisioning_requested(
            txn.as_mut(),
            *switch_id,
            "rack-test",
            vec![firmware_activity.clone()],
        )
        .await?;
    }

    let switches = db::switch::find_by(
        txn.as_mut(),
        db::ObjectColumnFilter::List(db::switch::IdColumn, &switch_ids),
    )
    .await?;
    let requested_at_by_id = switches
        .into_iter()
        .map(|switch| {
            let requested_at = switch
                .switch_reprovisioning_requested
                .expect("test request must be persisted")
                .requested_at;
            (switch.id, requested_at)
        })
        .collect::<HashMap<_, _>>();

    let stale_requested_at = requested_at_by_id[&switch_ids[0]];
    db::switch::update_firmware_upgrade_status(
        txn.as_mut(),
        switch_ids[0],
        Some(&RackFirmwareUpgradeStatus {
            task_id: "stale-task".into(),
            status: RackFirmwareUpgradeState::Completed,
            started_at: Some(stale_requested_at - chrono::Duration::minutes(2)),
            ended_at: Some(stale_requested_at - chrono::Duration::minutes(1)),
        }),
    )
    .await?;

    let current_requested_at = requested_at_by_id[&switch_ids[1]];
    db::switch::update_firmware_upgrade_status(
        txn.as_mut(),
        switch_ids[1],
        Some(&RackFirmwareUpgradeStatus {
            task_id: "current-task".into(),
            status: RackFirmwareUpgradeState::Failed {
                cause: "current backend failure".into(),
            },
            started_at: Some(current_requested_at),
            ended_at: Some(current_requested_at),
        }),
    )
    .await?;
    txn.commit().await?;

    // Deliberately omit Component Manager: every switch has an active persisted
    // request, so status selection must be fully answerable from the database.
    let api = TestApiBuilder::new(
        pool,
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
    )
    .build();
    let response = crate::handlers::component_manager::get_component_firmware_status(
        &api,
        Request::new(rpc::GetComponentFirmwareStatusRequest {
            target: Some(
                rpc::get_component_firmware_status_request::Target::SwitchIds(rpc::SwitchIdList {
                    ids: switch_ids.clone(),
                }),
            ),
        }),
    )
    .await?
    .into_inner();
    let status_by_id = response
        .statuses
        .into_iter()
        .map(|status| {
            let component_id = status
                .result
                .as_ref()
                .expect("every firmware status must carry a result")
                .component_id
                .clone()
                .expect("a switch-id target always reports the component id");
            (component_id, status)
        })
        .collect::<HashMap<_, _>>();

    assert_eq!(
        status_by_id[&switch_ids[0].to_string()].state,
        rpc::FirmwareUpdateState::FwStateQueued as i32,
        "a stale terminal result must not complete the new request"
    );
    let current = &status_by_id[&switch_ids[1].to_string()];
    assert_eq!(
        current.state,
        rpc::FirmwareUpdateState::FwStateFailed as i32
    );
    assert_eq!(
        current
            .result
            .as_ref()
            .expect("current status must carry a result")
            .error,
        "current backend failure"
    );
    assert_eq!(
        status_by_id[&switch_ids[2].to_string()].state,
        rpc::FirmwareUpdateState::FwStateQueued as i32,
        "an accepted request without a persisted device result is still queued"
    );

    for switch_id in &switch_ids {
        assert_eq!(
            status_by_id[&switch_id.to_string()].target_version,
            "firmware-object-json",
            "the active request supplies the target version the backend never persists"
        );
    }

    Ok(())
}
