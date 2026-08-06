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

use std::sync::Arc;
use std::time::Duration;

use carbide_credential_rotation::RotationGate;
use carbide_power_shelf_controller::context::PowerShelfStateHandlerServices;
use carbide_power_shelf_controller::handler::PowerShelfStateHandler;
use carbide_power_shelf_controller::io::PowerShelfStateControllerIO;
use carbide_uuid::machine::MachineInterfaceId;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::power_shelf::PowerShelfId;
use mac_address::MacAddress;
use model::allocation_type::AllocationType;
use model::bmc_suppression::BmcSuppressionSubsystem;
use model::power_shelf::{
    PowerShelf, PowerShelfControllerState, PowerShelfVerifyingDhcpReleaseState,
};
use rpc::forge::forge_server::Forge;
use state_controller::config::IterationConfig;
use state_controller::controller::StateController;
use tokio_util::sync::CancellationToken;
use tonic::{Code, Request};

use super::fixtures::power_shelf::set_power_shelf_controller_state;
use crate::tests::common;
use crate::tests::common::api_fixtures::{TestEnv, create_test_env};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn services(env: &TestEnv, pool: &sqlx::PgPool) -> PowerShelfStateHandlerServices {
    PowerShelfStateHandlerServices {
        db_pool: pool.clone(),
        component_manager: None,
        credential_manager: env.test_credential_manager.clone(),
        per_object_metrics_registry: env.per_object_metrics_registry(),
        rack_firmware_reprovisioning_enabled: false,
        redfish_client_pool: env.redfish_sim.clone(),
        bmc_rotation_gate: RotationGate::new_for_family(
            db::credential_rotation::CredentialRotationType::Bmc,
        ),
        bmc_rotation_enabled: false,
    }
}

async fn seed_pmc_endpoint(
    pool: &sqlx::PgPool,
    power_shelf_id: PowerShelfId,
) -> TestResult<MacAddress> {
    let mut txn = pool.begin().await?;
    let segment_id: NetworkSegmentId = sqlx::query_scalar(
        "INSERT INTO network_segments (name, version, network_segment_type)
         VALUES ($1, 'V1-T0', 'tenant') RETURNING id",
    )
    .bind(format!("decommission-pmc-{power_shelf_id}"))
    .fetch_one(txn.as_mut())
    .await?;
    let pmc_mac: MacAddress = "02:00:00:00:0d:01".parse()?;
    let interface_id: MachineInterfaceId = sqlx::query_scalar(
        "INSERT INTO machine_interfaces
             (power_shelf_id, association_type, segment_id, mac_address,
              primary_interface, hostname, interface_type)
         VALUES ($1, 'PowerShelf', $2, $3, false, 'pmc', 'Bmc')
         RETURNING id",
    )
    .bind(power_shelf_id)
    .bind(segment_id)
    .bind(pmc_mac)
    .fetch_one(txn.as_mut())
    .await?;
    db::machine_interface_address::insert(
        txn.as_mut(),
        interface_id,
        "10.30.40.60".parse()?,
        AllocationType::Dhcp,
    )
    .await?;
    txn.commit().await?;
    Ok(pmc_mac)
}

async fn load_power_shelf(pool: &sqlx::PgPool, id: PowerShelfId) -> TestResult<PowerShelf> {
    let mut conn = pool.acquire().await?;
    Ok(db::power_shelf::find_by_id(&mut conn, &id)
        .await?
        .expect("power shelf should exist"))
}

#[crate::sqlx_test]
async fn decommission_requires_ready_power_shelf(pool: sqlx::PgPool) -> TestResult {
    let env = create_test_env(pool).await;
    let power_shelf_id = common::api_fixtures::site_explorer::new_power_shelf(
        &env,
        Some("Decommission precondition".to_string()),
        None,
        None,
        None,
    )
    .await?;

    let error = env
        .api
        .decommission_power_shelf(Request::new(power_shelf_id))
        .await
        .expect_err("an initializing power shelf must be rejected");
    assert_eq!(error.code(), Code::FailedPrecondition);

    let error = env
        .api
        .delete_decommissioned_power_shelf(Request::new(power_shelf_id))
        .await
        .expect_err("an initializing power shelf must not be permanently deleted");
    assert_eq!(error.code(), Code::FailedPrecondition);
    Ok(())
}

#[crate::sqlx_test]
async fn managed_power_shelf_reaches_decommissioned_after_dhcp_release(
    pool: sqlx::PgPool,
) -> TestResult {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id = common::api_fixtures::site_explorer::new_power_shelf(
        &env,
        Some("Decommission workflow".to_string()),
        None,
        None,
        None,
    )
    .await?;
    let pmc_mac = seed_pmc_endpoint(&pool, power_shelf_id).await?;
    let mut txn = pool.begin().await?;
    set_power_shelf_controller_state(
        txn.as_mut(),
        &power_shelf_id,
        PowerShelfControllerState::Ready,
    )
    .await?;
    txn.commit().await?;

    env.api
        .decommission_power_shelf(Request::new(power_shelf_id))
        .await?;

    let mut controller = StateController::<PowerShelfStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: Duration::from_millis(50),
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(services(&env, &pool).into())
        .state_handler(Arc::new(PowerShelfStateHandler::default()))
        .build_for_manual_iterations(CancellationToken::new())?;

    controller.run_single_iteration().await;
    assert_eq!(
        load_power_shelf(&pool, power_shelf_id)
            .await?
            .controller_state
            .value,
        PowerShelfControllerState::Preparing
    );
    controller.run_single_iteration().await;
    assert!(
        db::bmc_suppression::find(&pool, pmc_mac, BmcSuppressionSubsystem::SiteExplorer)
            .await?
            .is_some()
    );

    let mut txn = pool.begin().await?;
    db::bmc_suppression::acknowledge_unacknowledged(
        txn.as_mut(),
        &[pmc_mac],
        BmcSuppressionSubsystem::SiteExplorer,
    )
    .await?;
    txn.commit().await?;
    controller.run_single_iteration().await;
    assert_eq!(
        load_power_shelf(&pool, power_shelf_id)
            .await?
            .controller_state
            .value,
        PowerShelfControllerState::VerifyingDhcpRelease {
            verifying_state: PowerShelfVerifyingDhcpReleaseState::FactoryResetBmc,
        }
    );

    controller.run_single_iteration().await;
    assert_eq!(
        load_power_shelf(&pool, power_shelf_id)
            .await?
            .controller_state
            .value,
        PowerShelfControllerState::VerifyingDhcpRelease {
            verifying_state: PowerShelfVerifyingDhcpReleaseState::WaitingForBmcDhcpAcknowledgement,
        }
    );
    assert!(
        db::bmc_suppression::find(&pool, pmc_mac, BmcSuppressionSubsystem::Dhcp)
            .await?
            .is_some()
    );

    let mut txn = pool.begin().await?;
    db::bmc_suppression::acknowledge_unacknowledged(
        txn.as_mut(),
        &[pmc_mac],
        BmcSuppressionSubsystem::Dhcp,
    )
    .await?;
    txn.commit().await?;
    controller.run_single_iteration().await;

    let power_shelf = load_power_shelf(&pool, power_shelf_id).await?;
    assert_eq!(
        power_shelf.controller_state.value,
        PowerShelfControllerState::Decommissioned
    );
    assert!(!power_shelf.decommission_requested);

    env.api
        .delete_decommissioned_power_shelf(Request::new(power_shelf_id))
        .await?;
    let mut conn = pool.acquire().await?;
    assert!(
        db::power_shelf::find_by_id(conn.as_mut(), &power_shelf_id)
            .await?
            .is_none()
    );
    assert!(
        db::machine_interface::find_ids_by_power_shelf_id(conn.as_mut(), &power_shelf_id)
            .await?
            .is_empty()
    );
    assert!(
        db::bmc_suppression::find(&pool, pmc_mac, BmcSuppressionSubsystem::SiteExplorer)
            .await?
            .is_none()
    );
    assert!(
        db::bmc_suppression::find(&pool, pmc_mac, BmcSuppressionSubsystem::Dhcp)
            .await?
            .is_none()
    );
    Ok(())
}
