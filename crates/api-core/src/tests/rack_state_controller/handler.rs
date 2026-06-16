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

use carbide_rack_controller::context::RackStateHandlerContextObjects;
use carbide_rack_controller::handler::RackStateHandler;
use carbide_rack_controller::maintenance::apply_nvos_job_status_response;
use carbide_rack_controller::metrics::RackMetrics;
use carbide_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialReader, Credentials,
};
use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
use carbide_uuid::rack::{RackId, RackProfileId};
use carbide_uuid::switch::SwitchId;
use db::db_read::DbReader;
use db::{
    ObjectColumnFilter, expected_rack as db_expected_rack, rack as db_rack, switch as db_switch,
};
use librms::protos::rack_manager as rms;
use model::expected_machine::ExpectedMachineData;
use model::expected_rack::ExpectedRack;
use model::rack::{
    ConfigureNmxClusterState, FirmwareUpgradeDeviceStatus, FirmwareUpgradeJob,
    FirmwareUpgradeState, MaintenanceActivity, MaintenanceScope, NvosUpdateState,
    NvosUpdateSwitchStatus, Rack, RackConfig, RackFirmwareUpgradeState, RackMaintenanceState,
    RackPowerState, RackState, RackValidationState,
};
use model::rack_type::{
    RackCapabilitiesSet, RackCapabilityCompute, RackCapabilityPowerShelf, RackCapabilitySwitch,
    RackHardwareClass, RackHardwareTopology, RackHardwareType, RackProductFamily, RackProfile,
    RackProfileConfig,
};
use model::switch::{NewSwitch, SwitchConfig};
use model::test_support::ManagedHostConfig;
use state_controller::db_write_batch::DbWriteBatch;
use state_controller::state_handler::{StateHandler, StateHandlerContext, StateHandlerOutcome};
use tonic::Request;

use crate::test_support::fixture_config::{FixtureDefault as _, ManagedHostConfigExt as _};
use crate::tests::common::api_fixtures::site_explorer::{create_expected_switches, new_host};
use crate::tests::common::api_fixtures::{
    TestEnv, TestEnvOverrides, create_test_env_with_overrides, get_config,
};

fn test_capabilities() -> RackCapabilitiesSet {
    RackCapabilitiesSet {
        compute: RackCapabilityCompute {
            name: None,
            count: 2,
            vendor: Some("NVIDIA".to_string()),
            slot_ids: None,
        },
        switch: RackCapabilitySwitch {
            name: None,
            count: 1,
            vendor: Some("NVIDIA".to_string()),
            slot_ids: None,
        },
        power_shelf: RackCapabilityPowerShelf {
            name: None,
            count: 1,
            vendor: Some("LiteOn".to_string()),
            slot_ids: None,
        },
    }
}

fn simple_capabilities() -> RackCapabilitiesSet {
    RackCapabilitiesSet {
        compute: RackCapabilityCompute {
            name: None,
            count: 2,
            vendor: Some("NVIDIA".to_string()),
            slot_ids: None,
        },
        switch: RackCapabilitySwitch {
            name: None,
            count: 0,
            vendor: Some("NVIDIA".to_string()),
            slot_ids: None,
        },
        power_shelf: RackCapabilityPowerShelf {
            name: None,
            count: 0,
            vendor: Some("LiteOn".to_string()),
            slot_ids: None,
        },
    }
}

fn single_capabilities() -> RackCapabilitiesSet {
    RackCapabilitiesSet {
        compute: RackCapabilityCompute {
            name: None,
            count: 1,
            vendor: Some("NVIDIA".to_string()),
            slot_ids: None,
        },
        switch: RackCapabilitySwitch {
            name: None,
            count: 0,
            vendor: Some("NVIDIA".to_string()),
            slot_ids: None,
        },
        power_shelf: RackCapabilityPowerShelf {
            name: None,
            count: 0,
            vendor: Some("LiteOn".to_string()),
            slot_ids: None,
        },
    }
}

pub(crate) fn config_with_rack_profiles() -> crate::cfg::file::CarbideConfig {
    let mut config = get_config();
    config.rack_profiles = RackProfileConfig {
        rack_profiles: [
            (
                "NVL72".to_string(),
                RackProfile {
                    product_family: Some(RackProductFamily::Gb200),
                    rack_hardware_topology: Some(RackHardwareTopology::Gb200Nvl72r1C2g4Topology),
                    rack_capabilities: test_capabilities(),
                    ..Default::default()
                },
            ),
            (
                "Simple".to_string(),
                RackProfile {
                    product_family: Some(RackProductFamily::Gb200),
                    rack_hardware_topology: Some(RackHardwareTopology::Gb200Nvl72r1C2g4Topology),
                    rack_hardware_type: Some(RackHardwareType::any()),
                    rack_hardware_class: Some(RackHardwareClass::Prod),
                    rack_capabilities: simple_capabilities(),
                },
            ),
            (
                "Single".to_string(),
                RackProfile {
                    product_family: Some(RackProductFamily::Gb200),
                    rack_hardware_topology: Some(RackHardwareTopology::Gb200Nvl72r1C2g4Topology),
                    rack_hardware_type: Some(RackHardwareType::any()),
                    rack_hardware_class: Some(RackHardwareClass::Prod),
                    rack_capabilities: single_capabilities(),
                },
            ),
            ("Empty".to_string(), RackProfile::default()),
        ]
        .into_iter()
        .collect(),
    };
    config
}

fn config_with_nmx_cluster_profile() -> crate::cfg::file::CarbideConfig {
    let mut config = config_with_rack_profiles();
    config.rack_profiles.rack_profiles.insert(
        "NmxCluster".to_string(),
        RackProfile {
            product_family: Some(RackProductFamily::Gb200),
            rack_hardware_topology: Some(RackHardwareTopology::Gb200Nvl72r1C2g4Topology),
            rack_capabilities: test_capabilities(),
            ..Default::default()
        },
    );
    config
}

async fn create_single_compute_rack(
    env: &TestEnv,
    pool: &sqlx::PgPool,
) -> Result<(RackId, model::machine::ManagedHostStateSnapshot), Box<dyn std::error::Error>> {
    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Single")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);

    let host = new_host(
        env,
        ManagedHostConfig::default().with_expected_machine_data(ExpectedMachineData {
            rack_id: Some(rack_id.clone()),
            ..Default::default()
        }),
    )
    .await?;

    Ok((rack_id, host))
}

async fn create_two_compute_rack(
    env: &TestEnv,
    pool: &sqlx::PgPool,
) -> Result<
    (
        RackId,
        model::machine::ManagedHostStateSnapshot,
        model::machine::ManagedHostStateSnapshot,
    ),
    Box<dyn std::error::Error>,
> {
    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Simple")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);

    let host_a = new_host(
        env,
        ManagedHostConfig::default().with_expected_machine_data(ExpectedMachineData {
            rack_id: Some(rack_id.clone()),
            ..Default::default()
        }),
    )
    .await?;
    let host_b = new_host(
        env,
        ManagedHostConfig::default().with_expected_machine_data(ExpectedMachineData {
            rack_id: Some(rack_id.clone()),
            ..Default::default()
        }),
    )
    .await?;

    Ok((rack_id, host_a, host_b))
}

async fn attach_switches_with_nvos_credentials(
    env: &TestEnv,
    rack_id: &RackId,
    count: usize,
) -> Result<Vec<SwitchId>, Box<dyn std::error::Error>> {
    let mut txn = env.pool.begin().await?;
    let expected_switches = create_expected_switches(txn.as_mut()).await;
    let selected_switches = expected_switches
        .into_iter()
        .take(count)
        .collect::<Vec<_>>();
    if selected_switches.len() != count {
        return Err(eyre::eyre!("expected at least {} switch fixtures", count).into());
    }

    let mut switch_ids = Vec::with_capacity(selected_switches.len());
    for (index, expected_switch) in selected_switches.iter().enumerate() {
        let switch_id = model::switch::switch_id::from_hardware_info(
            &expected_switch.serial_number,
            "NVIDIA",
            "Switch",
            carbide_uuid::switch::SwitchIdSource::ProductBoardChassisSerial,
            carbide_uuid::switch::SwitchType::NvLink,
        )?;

        let new_switch = NewSwitch {
            id: switch_id,
            config: SwitchConfig {
                name: expected_switch.metadata.name.clone(),
                enable_nmxc: false,
                fabric_manager_config: None,
            },
            bmc_mac_address: Some(expected_switch.bmc_mac_address),
            metadata: None,
            rack_id: Some(rack_id.clone()),
            slot_number: Some(index as i32),
            tray_index: Some(0),
        };
        db_switch::create(txn.as_mut(), &new_switch).await?;
        switch_ids.push(switch_id);
    }
    txn.commit().await?;

    for expected_switch in selected_switches {
        env.api
            .credential_manager
            .set_credentials(
                &CredentialKey::BmcCredentials {
                    credential_type: BmcCredentialType::BmcRoot {
                        bmc_mac_address: expected_switch.bmc_mac_address,
                    },
                },
                &Credentials::UsernamePassword {
                    username: "root".to_string(),
                    password: "notforprod".to_string(),
                },
            )
            .await
            .map_err(|error| eyre::eyre!("failed to set switch BMC credentials: {}", error))?;
        env.api
            .credential_manager
            .set_credentials(
                &CredentialKey::SwitchNvosAdmin {
                    bmc_mac_address: expected_switch.bmc_mac_address,
                },
                &Credentials::UsernamePassword {
                    username: "nvos-admin".to_string(),
                    password: "nvos-pass".to_string(),
                },
            )
            .await
            .map_err(|error| eyre::eyre!("failed to set switch NVOS credentials: {}", error))?;
    }

    Ok(switch_ids)
}

async fn attach_switch_with_nvos_credentials(
    env: &TestEnv,
    rack_id: &RackId,
) -> Result<SwitchId, Box<dyn std::error::Error>> {
    let mut switch_ids = attach_switches_with_nvos_credentials(env, rack_id, 1).await?;
    switch_ids
        .pop()
        .ok_or_else(|| eyre::eyre!("expected one switch fixture").into())
}

pub(crate) fn new_rack_id() -> RackId {
    RackId::new(uuid::Uuid::new_v4().to_string())
}

async fn create_ready_rack_with_switch(
    env: &TestEnv,
    pool: &sqlx::PgPool,
) -> Result<(RackId, SwitchId), Box<dyn std::error::Error>> {
    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("NVL72")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);

    let switch_id = attach_switch_with_nvos_credentials(env, &rack_id).await?;

    let mut txn = pool.begin().await?;
    let rack = get_db_rack(txn.as_mut(), &rack_id).await;
    db_rack::try_update_controller_state(
        txn.as_mut(),
        &rack_id,
        rack.controller_state.version,
        rack.controller_state.version.increment(),
        &RackState::Ready,
    )
    .await?;
    txn.commit().await?;

    Ok((rack_id, switch_id))
}

async fn create_expected_rack(pool: &sqlx::PgPool, rack_id: &RackId, rack_profile_id: &str) {
    let mut txn = pool.acquire().await.unwrap();
    let er = ExpectedRack {
        rack_id: rack_id.clone(),
        rack_profile_id: RackProfileId::new(rack_profile_id),
        ..Default::default()
    };
    db_expected_rack::create(&mut txn, &er).await.unwrap();
}

pub(crate) fn new_machine_id(seed: u8) -> MachineId {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    MachineId::new(
        MachineIdSource::ProductBoardChassisSerial,
        hash,
        MachineType::Host,
    )
}

#[crate::sqlx_test]
async fn test_on_demand_rack_maintenance_schedules_nvos_only_scope(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;
    let (rack_id, switch_id) = create_ready_rack_with_switch(&env, &pool).await?;

    crate::handlers::rack::on_demand_rack_maintenance(
        env.api.as_ref(),
        Request::new(rpc::forge::RackMaintenanceOnDemandRequest {
            rack_id: Some(rack_id.clone()),
            scope: Some(rpc::forge::RackMaintenanceScope {
                machine_ids: vec![],
                switch_ids: vec![switch_id.to_string()],
                power_shelf_ids: vec![],
                activities: vec![rpc::forge::MaintenanceActivityConfig {
                    activity: Some(
                        rpc::forge::maintenance_activity_config::Activity::NvosUpdate(
                            rpc::forge::NvosUpdateActivity {
                                config_json: r#"{"Id":"fw-nvos"}"#.to_string(),
                                access_token: Some("token".to_string()),
                            },
                        ),
                    ),
                }],
            }),
        }),
    )
    .await?;

    let rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let scope = rack
        .config
        .maintenance_requested
        .expect("maintenance should be scheduled");
    assert_eq!(scope.switch_ids, vec![switch_id]);
    assert_eq!(scope.activities.len(), 1);
    assert!(matches!(
        &scope.activities[0],
        MaintenanceActivity::NvosUpdate {
            config_json,
        } if config_json == r#"{"Id":"fw-nvos"}"#
    ));

    Ok(())
}

#[crate::sqlx_test]
async fn test_on_demand_rack_maintenance_schedules_configure_nmx_cluster_only_scope(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;
    let (rack_id, switch_id) = create_ready_rack_with_switch(&env, &pool).await?;

    crate::handlers::rack::on_demand_rack_maintenance(
        env.api.as_ref(),
        Request::new(rpc::forge::RackMaintenanceOnDemandRequest {
            rack_id: Some(rack_id.clone()),
            scope: Some(rpc::forge::RackMaintenanceScope {
                machine_ids: vec![],
                switch_ids: vec![switch_id.to_string()],
                power_shelf_ids: vec![],
                activities: vec![rpc::forge::MaintenanceActivityConfig {
                    activity: Some(
                        rpc::forge::maintenance_activity_config::Activity::ConfigureNmxCluster(
                            rpc::forge::ConfigureNmxClusterActivity {},
                        ),
                    ),
                }],
            }),
        }),
    )
    .await?;

    let rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let scope = rack
        .config
        .maintenance_requested
        .expect("maintenance should be scheduled");
    assert_eq!(scope.switch_ids, vec![switch_id]);
    assert_eq!(scope.activities.len(), 1);
    assert!(matches!(
        &scope.activities[0],
        MaintenanceActivity::ConfigureNmxCluster
    ));

    Ok(())
}

#[crate::sqlx_test]
async fn test_on_demand_rack_maintenance_schedules_firmware_and_nvos_scope(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;
    let (rack_id, switch_id) = create_ready_rack_with_switch(&env, &pool).await?;

    crate::handlers::rack::on_demand_rack_maintenance(
        env.api.as_ref(),
        Request::new(rpc::forge::RackMaintenanceOnDemandRequest {
            rack_id: Some(rack_id.clone()),
            scope: Some(rpc::forge::RackMaintenanceScope {
                machine_ids: vec![],
                switch_ids: vec![switch_id.to_string()],
                power_shelf_ids: vec![],
                activities: vec![
                    rpc::forge::MaintenanceActivityConfig {
                        activity: Some(
                            rpc::forge::maintenance_activity_config::Activity::FirmwareUpgrade(
                                rpc::forge::FirmwareUpgradeActivity {
                                    firmware_version: r#"{"Id":"fw-mixed"}"#.to_string(),
                                    components: vec!["BMC".to_string()],
                                    access_token: Some("token".to_string()),
                                    force_update: false,
                                },
                            ),
                        ),
                    },
                    rpc::forge::MaintenanceActivityConfig {
                        activity: Some(
                            rpc::forge::maintenance_activity_config::Activity::NvosUpdate(
                                rpc::forge::NvosUpdateActivity {
                                    config_json: r#"{"Id":"fw-mixed"}"#.to_string(),
                                    access_token: Some("token".to_string()),
                                },
                            ),
                        ),
                    },
                ],
            }),
        }),
    )
    .await?;

    let rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let scope = rack
        .config
        .maintenance_requested
        .expect("maintenance should be scheduled");
    assert_eq!(scope.switch_ids, vec![switch_id]);
    assert_eq!(scope.activities.len(), 2);
    assert!(matches!(
        &scope.activities[0],
        MaintenanceActivity::FirmwareUpgrade {
            firmware_version: Some(id),
            components,
            ..
        } if id == r#"{"Id":"fw-mixed"}"# && components == &vec!["BMC".to_string()]
    ));
    assert!(matches!(
        &scope.activities[1],
        MaintenanceActivity::NvosUpdate {
            config_json,
        } if config_json == r#"{"Id":"fw-mixed"}"#
    ));
    let token_credentials = env
        .test_credential_manager
        .get_credentials(&CredentialKey::RackMaintenanceAccessToken {
            rack_id: rack_id.clone(),
        })
        .await
        .expect("credential lookup should succeed")
        .expect("access token should be stored as a credential");
    assert_eq!(
        token_credentials,
        Credentials::UsernamePassword {
            username: "access_token".to_string(),
            password: "token".to_string(),
        }
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_on_demand_rack_maintenance_defaults_missing_access_token_to_noauth(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;
    let (rack_id, switch_id) = create_ready_rack_with_switch(&env, &pool).await?;

    crate::handlers::rack::on_demand_rack_maintenance(
        env.api.as_ref(),
        Request::new(rpc::forge::RackMaintenanceOnDemandRequest {
            rack_id: Some(rack_id.clone()),
            scope: Some(rpc::forge::RackMaintenanceScope {
                machine_ids: vec![],
                switch_ids: vec![switch_id.to_string()],
                power_shelf_ids: vec![],
                activities: vec![rpc::forge::MaintenanceActivityConfig {
                    activity: Some(
                        rpc::forge::maintenance_activity_config::Activity::FirmwareUpgrade(
                            rpc::forge::FirmwareUpgradeActivity {
                                firmware_version: r#"{"Id":"fw-mixed"}"#.to_string(),
                                components: vec!["BMC".to_string()],
                                access_token: None,
                                force_update: false,
                            },
                        ),
                    ),
                }],
            }),
        }),
    )
    .await?;

    let token_credentials = env
        .test_credential_manager
        .get_credentials(&CredentialKey::RackMaintenanceAccessToken {
            rack_id: rack_id.clone(),
        })
        .await
        .expect("credential lookup should succeed")
        .expect("access token should be stored as a credential");
    assert_eq!(
        token_credentials,
        Credentials::UsernamePassword {
            username: "access_token".to_string(),
            password: carbide_rack::firmware_object::RMS_NOAUTH_ACCESS_TOKEN.to_string(),
        }
    );

    Ok(())
}

/// test_expected_no_definition_stays_parked verifies that a rack without an
/// expected_rack record stays in Created and does not advance.
#[crate::sqlx_test]
async fn test_expected_no_definition_stays_parked(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;

    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("NVL72")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let mut rack = get_db_rack(txn.as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Created, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Rack without expected_rack record should wait in Created"
    );

    Ok(())
}

#[test]
fn test_nvos_polling_updates_node_id_and_maps_running_to_in_progress() {
    let mut switch = NvosUpdateSwitchStatus {
        node_id: "old-node-id".into(),
        mac: "00:11:22:33:44:55".into(),
        bmc_ip: "10.0.0.10".into(),
        nvos_ip: "192.168.10.10".into(),
        status: "pending".into(),
        job_id: Some("job-1".into()),
        error_message: Some("stale error".into()),
    };

    apply_nvos_job_status_response(
        &mut switch,
        "job-1",
        Ok(rms::GetSwitchSystemImageJobStatusResponse {
            status: rms::ReturnCode::Success as i32,
            state: "RUNNING".into(),
            node_id: "new-node-id".into(),
            ..Default::default()
        }),
    );

    assert_eq!(switch.node_id, "new-node-id");
    assert_eq!(switch.status, "in_progress");
    assert_eq!(switch.error_message, None);
}

#[test]
fn test_nvos_polling_maps_failed_state_and_uses_error_message() {
    let mut switch = NvosUpdateSwitchStatus {
        node_id: "node-id".into(),
        mac: "00:11:22:33:44:55".into(),
        bmc_ip: "10.0.0.10".into(),
        nvos_ip: "192.168.10.10".into(),
        status: "in_progress".into(),
        job_id: Some("job-2".into()),
        error_message: None,
    };

    apply_nvos_job_status_response(
        &mut switch,
        "job-2",
        Ok(rms::GetSwitchSystemImageJobStatusResponse {
            status: rms::ReturnCode::Success as i32,
            state: "failed".into(),
            error_message: "image install failed".into(),
            ..Default::default()
        }),
    );

    assert_eq!(switch.status, "failed");
    assert_eq!(
        switch.error_message.as_deref(),
        Some("image install failed")
    );
}

#[test]
fn test_nvos_polling_unknown_state_preserves_status_and_sets_error() {
    let mut switch = NvosUpdateSwitchStatus {
        node_id: "node-id".into(),
        mac: "00:11:22:33:44:55".into(),
        bmc_ip: "10.0.0.10".into(),
        nvos_ip: "192.168.10.10".into(),
        status: "pending".into(),
        job_id: Some("job-3".into()),
        error_message: None,
    };

    apply_nvos_job_status_response(
        &mut switch,
        "job-3",
        Ok(rms::GetSwitchSystemImageJobStatusResponse {
            status: rms::ReturnCode::Success as i32,
            state: "mystery".into(),
            ..Default::default()
        }),
    );

    assert_eq!(switch.status, "pending");
    assert_eq!(
        switch.error_message.as_deref(),
        Some("Unknown RMS switch image job state mystery")
    );
}

/// test_expected_incomplete_device_counts_stays verifies that a rack with a
/// topology expecting more devices than currently exist stays in Created.
#[crate::sqlx_test]
#[ignore]
async fn test_expected_incomplete_device_counts_stays(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;

    // Create a rack with a definition expecting 2 compute, 1 switch, 1 PS,
    // but only register 1 compute tray.
    let mut rack = db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("NVL72")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Created, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::DoNothing { .. }),
        "Rack with incomplete device counts should stay in Expected"
    );

    Ok(())
}

/// test_expected_counts_match_but_not_linked_stays verifies that a rack with
/// all expected device counts matched but devices not yet linked stays in
/// Expected until linking completes.
#[crate::sqlx_test]
async fn test_expected_counts_match_but_not_linked_stays(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();

    let mut txn = pool.acquire().await?;

    // Create rack with correct device counts matching the definition.
    let _rack = db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("NVL72")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);

    create_expected_rack(&pool, &rack_id, "NVL72").await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Created, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Rack with incomplete device counts should wait in Created"
    );

    Ok(())
}

/// test_expected_zero_topology_transitions_to_discovering verifies that a rack
/// with zero expected devices in topology immediately transitions to Discovering.
#[crate::sqlx_test]
#[ignore]
async fn test_expected_zero_topology_transitions_to_discovering(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;

    // Create rack with a profile expecting 2 compute, 0 switches, 0 PS.
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    // Simulate that both compute trays are already linked by setting
    // compute_trays to have 2 entries matching expected_compute_trays.
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    drop(txn);

    create_expected_rack(&pool, &rack_id, "Empty").await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Created, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Discovering),
                "Zero-device topology should transition to Discovering, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Discovering, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_expected_more_discovered_than_expected_transitions verifies that a
/// rack with more discovered compute trays than expected still transitions.
#[crate::sqlx_test]
#[ignore]
async fn test_expected_more_discovered_than_expected_transitions(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    // let mac1 = MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x50]);

    let mut txn = pool.acquire().await?;

    // Rack type "Single" expects 1 compute, 0 switches, 0 PS.
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Single")),
        &RackConfig::default(),
        None,
    )
    .await?;

    // Simulate more compute_trays discovered than expected_compute_trays.

    db_rack::update(&mut txn, &rack_id, &RackConfig::default()).await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Created, &mut ctx)
        .await?;

    // The Ordering::Less branch treats this as compute_done = true.
    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Discovering),
                "Should transition to Discovering, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Discovering, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_discovering_waits_for_compute_ready verifies that the handler
/// reports an error for the Discovering state when managed hosts are missing.
#[crate::sqlx_test]
#[ignore]
async fn test_discovering_waits_for_compute_ready(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;

    // Create a rack in Discovering state with a compute tray that doesn't
    // have a managed host record yet.

    let mut rack = db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("NVL72")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    // The Discovering state should fail because the managed host doesn't exist.
    let result = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Discovering, &mut ctx)
        .await;
    assert!(
        result.is_err(),
        "Discovering should error when managed host is missing"
    );

    Ok(())
}

/// test_discovering_empty_rack_transitions_to_maintenance verifies that a
/// rack in Discovering state with no devices transitions to Maintenance.
#[crate::sqlx_test]
async fn test_discovering_empty_rack_transitions_to_maintenance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_profiles();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;

    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let cfg = RackConfig::default();
    db_rack::update(&mut txn, &rack_id, &cfg).await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Discovering, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Maintenance { .. }),
                "Empty rack in Discovering should transition to Maintenance, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Maintenance, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_error_state_does_nothing verifies that the Error state logs and does nothing.
#[crate::sqlx_test]
async fn test_error_state_does_nothing(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let error_state = RackState::Error {
        cause: "test error".to_string(),
    };
    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &error_state, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Error state should wait"
    );

    Ok(())
}

/// test_maintenance_completed_transitions_to_validation verifies that
/// Maintenance::Completed transitions to Validation(Pending).
#[crate::sqlx_test]
async fn test_maintenance_completed_transitions_to_validation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let maintenance_state = RackState::Maintenance {
        maintenance_state: model::rack::RackMaintenanceState::Completed,
    };
    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &maintenance_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Validating {
                        validating_state: RackValidationState::Pending,
                    }
                ),
                "Maintenance::Completed should transition to Validating(Pending), got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_ready_with_no_labels_stays_ready verifies that Ready with no
/// validation metadata labels on machines stays in Ready (do_nothing).
#[crate::sqlx_test]
async fn test_ready_with_no_labels_stays_ready(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let ready_state = RackState::Ready;
    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &ready_state, &mut ctx)
        .await?;

    assert!(
        matches!(
            outcome,
            StateHandlerOutcome::Wait { .. } | StateHandlerOutcome::DoNothing { .. }
        ),
        "Ready with no labels should wait or do nothing, got {:?}",
        std::mem::discriminant(&outcome)
    );

    Ok(())
}

/// test_firmware_upgrade_start_skips_without_json verifies that
/// Maintenance::FirmwareUpgrade(Start) skips firmware flashing when no
/// firmware object JSON source is configured for rack maintenance.
#[crate::sqlx_test]
async fn test_firmware_upgrade_start_skips_without_json(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host) = create_single_compute_rack(&env, &pool).await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let fw_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade: FirmwareUpgradeState::Start,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                            configure_nmx_cluster: _,
                        },
                    }
                ),
                "FirmwareUpgrade(Start) should skip firmware without JSON and advance to the next requested activity, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    let requests = env.rms_sim.submitted_apply_firmware_object_requests().await;
    assert!(
        requests.is_empty(),
        "firmware apply should not be submitted without a firmware object JSON source"
    );

    let machine = db::machine::find_one(
        &pool,
        &host.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist");
    assert!(machine.host_reprovision_requested.is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_firmware_upgrade_start_submits_json_and_deletes_access_token(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, switch_id) = create_ready_rack_with_switch(&env, &pool).await?;
    let switch_id_string = switch_id.to_string();

    crate::handlers::rack::on_demand_rack_maintenance(
        env.api.as_ref(),
        Request::new(rpc::forge::RackMaintenanceOnDemandRequest {
            rack_id: Some(rack_id.clone()),
            scope: Some(rpc::forge::RackMaintenanceScope {
                machine_ids: vec![],
                switch_ids: vec![switch_id_string.clone()],
                power_shelf_ids: vec![],
                activities: vec![rpc::forge::MaintenanceActivityConfig {
                    activity: Some(
                        rpc::forge::maintenance_activity_config::Activity::FirmwareUpgrade(
                            rpc::forge::FirmwareUpgradeActivity {
                                firmware_version: r#"{"Id":"fw-json"}"#.to_string(),
                                components: vec!["BMC".to_string()],
                                access_token: Some("token".to_string()),
                                force_update: true,
                            },
                        ),
                    ),
                }],
            }),
        }),
    )
    .await?;
    env.rms_sim
        .queue_apply_firmware_object_response(rms::ApplyFirmwareObjectResponse {
            response: Some(rms::NodeBatchResponse {
                status: rms::ReturnCode::Success as i32,
                message: "accepted".to_string(),
                job_id: "parent-job".to_string(),
                stats: Some(rms::NodeOperationStats {
                    total_nodes: 1,
                    successful_nodes: 1,
                    failed_nodes: 0,
                }),
                ..Default::default()
            }),
            object_id: "fw-json".to_string(),
            jobs: vec![rms::NodeFirmwareJobInfo {
                node_id: switch_id_string.clone(),
                job_id: "child-job".to_string(),
            }],
        })
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let fw_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade: FirmwareUpgradeState::Start,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    assert!(
        matches!(
            outcome,
            StateHandlerOutcome::Transition {
                next_state: RackState::Maintenance {
                    maintenance_state: RackMaintenanceState::FirmwareUpgrade {
                        rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
                    },
                },
                ..
            }
        ),
        "expected FirmwareUpgrade(WaitForComplete), got {:?}",
        std::mem::discriminant(&outcome),
    );
    let requests = env.rms_sim.submitted_apply_firmware_object_requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].config_json, r#"{"Id":"fw-json"}"#);
    assert_eq!(requests[0].access_token.as_deref(), Some("token"));
    assert_eq!(requests[0].firmware_type, "prod");
    assert!(requests[0].force_update);
    assert_eq!(requests[0].nodes.as_ref().unwrap().nodes.len(), 1);

    let token_after = env
        .test_credential_manager
        .get_credentials(&CredentialKey::RackMaintenanceAccessToken {
            rack_id: rack_id.clone(),
        })
        .await
        .expect("credential lookup should succeed");
    assert!(token_after.is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_firmware_upgrade_start_missing_profile_deletes_access_token(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(&mut txn, &rack_id, None, &RackConfig::default(), None).await?;
    drop(txn);

    let switch_id = attach_switch_with_nvos_credentials(&env, &rack_id).await?;
    let config = RackConfig {
        maintenance_requested: Some(MaintenanceScope {
            switch_ids: vec![switch_id],
            activities: vec![MaintenanceActivity::FirmwareUpgrade {
                firmware_version: Some(r#"{"Id":"fw-json"}"#.to_string()),
                components: vec!["BMC".to_string()],
                force_update: false,
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut txn = pool.acquire().await?;
    db_rack::update(&mut txn, &rack_id, &config).await?;
    drop(txn);

    env.api
        .credential_manager
        .set_credentials(
            &CredentialKey::RackMaintenanceAccessToken {
                rack_id: rack_id.clone(),
            },
            &Credentials::UsernamePassword {
                username: "access_token".to_string(),
                password: "token".to_string(),
            },
        )
        .await
        .map_err(|error| eyre::eyre!("failed to set maintenance access token: {}", error))?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let fw_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade: FirmwareUpgradeState::Start,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    assert!(
        matches!(
            outcome,
            StateHandlerOutcome::Transition {
                next_state: RackState::Error { .. },
                ..
            }
        ),
        "expected missing rack profile to transition to Error"
    );
    let token_after = env
        .test_credential_manager
        .get_credentials(&CredentialKey::RackMaintenanceAccessToken {
            rack_id: rack_id.clone(),
        })
        .await
        .map_err(|error| eyre::eyre!("failed to get maintenance access token: {}", error))?;

    assert!(token_after.is_none());

    Ok(())
}

/// test_firmware_upgrade_wait_for_complete_waits_while_jobs_running verifies
/// that WaitForComplete remains in a wait state while RMS child jobs are still
/// running and writes in-progress rack firmware status back to the machine.
#[crate::sqlx_test]
async fn test_firmware_upgrade_wait_for_complete_waits_while_jobs_running(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host) = create_single_compute_rack(&env, &pool).await?;
    env.rms_sim
        .set_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusResponse {
            status: librms::protos::rack_manager::ReturnCode::Success as i32,
            job_id: "child-job-1".to_string(),
            job_state: rms::FirmwareJobState::Running as i32,
            state_description: "running".to_string(),
            node_id: host.host_snapshot.id.to_string(),
            ..Default::default()
        })
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    rack.firmware_upgrade_job = Some(FirmwareUpgradeJob {
        job_id: Some("batch-job-1".to_string()),
        status: Some("in_progress".to_string()),
        started_at: Some(chrono::Utc::now()),
        batch_job_ids: vec!["batch-job-1".to_string()],
        machines: vec![FirmwareUpgradeDeviceStatus {
            node_id: host.host_snapshot.id.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            bmc_ip: "192.0.2.10".to_string(),
            status: "in_progress".to_string(),
            job_id: Some("child-job-1".to_string()),
            parent_job_id: Some("batch-job-1".to_string()),
            error_message: None,
        }],
        ..Default::default()
    });

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let fw_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Expected Wait while RMS job is running"
    );

    let machine = db::machine::find_one(
        &pool,
        &host.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist");
    let rack_fw_details = machine
        .rack_fw_details
        .expect("machine should have rack firmware status");
    assert_eq!(rack_fw_details.status, RackFirmwareUpgradeState::InProgress);
    assert!(rack_fw_details.ended_at.is_none());

    Ok(())
}

/// test_firmware_upgrade_wait_for_complete_transitions_to_error_on_job_failure
/// verifies that a failed RMS child job writes failed machine status and moves
/// the rack into Error.
#[crate::sqlx_test]
async fn test_firmware_upgrade_wait_for_complete_transitions_to_error_on_job_failure(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host) = create_single_compute_rack(&env, &pool).await?;
    env.rms_sim
        .set_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusResponse {
            status: librms::protos::rack_manager::ReturnCode::Success as i32,
            job_id: "child-job-1".to_string(),
            job_state: rms::FirmwareJobState::Failed as i32,
            state_description: "failed".to_string(),
            node_id: host.host_snapshot.id.to_string(),
            error_message: "upgrade failed".to_string(),
            ..Default::default()
        })
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    rack.firmware_upgrade_job = Some(FirmwareUpgradeJob {
        job_id: Some("batch-job-1".to_string()),
        status: Some("in_progress".to_string()),
        started_at: Some(chrono::Utc::now()),
        batch_job_ids: vec!["batch-job-1".to_string()],
        machines: vec![FirmwareUpgradeDeviceStatus {
            node_id: host.host_snapshot.id.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            bmc_ip: "192.0.2.10".to_string(),
            status: "in_progress".to_string(),
            job_id: Some("child-job-1".to_string()),
            parent_job_id: Some("batch-job-1".to_string()),
            error_message: None,
        }],
        ..Default::default()
    });

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let fw_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Error { .. }),
                "Expected rack to transition to Error, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Error, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    let machine = db::machine::find_one(
        &pool,
        &host.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist");
    let rack_fw_details = machine
        .rack_fw_details
        .expect("machine should have rack firmware status");
    assert!(matches!(
        rack_fw_details.status,
        RackFirmwareUpgradeState::Failed { .. }
    ));
    assert!(rack_fw_details.ended_at.is_some());

    Ok(())
}

/// test_firmware_upgrade_wait_for_complete_waits_for_all_nodes_to_be_terminal_before_error
/// verifies that the rack keeps polling when a mixed result contains both
/// failed and in-progress devices, then errors only after all tracked devices
/// reach a terminal state.
#[crate::sqlx_test]
async fn test_firmware_upgrade_wait_for_complete_waits_for_all_nodes_to_be_terminal_before_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host_a, host_b) = create_two_compute_rack(&env, &pool).await?;

    env.rms_sim
        .set_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusResponse {
            status: librms::protos::rack_manager::ReturnCode::Success as i32,
            job_id: "child-job-1".to_string(),
            job_state: rms::FirmwareJobState::Failed as i32,
            state_description: "failed".to_string(),
            node_id: host_a.host_snapshot.id.to_string(),
            error_message: "upgrade failed".to_string(),
            ..Default::default()
        })
        .await;
    env.rms_sim
        .set_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusResponse {
            status: librms::protos::rack_manager::ReturnCode::Success as i32,
            job_id: "child-job-2".to_string(),
            job_state: rms::FirmwareJobState::Running as i32,
            state_description: "running".to_string(),
            node_id: host_b.host_snapshot.id.to_string(),
            ..Default::default()
        })
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    rack.firmware_upgrade_job = Some(FirmwareUpgradeJob {
        job_id: Some("batch-job-1".to_string()),
        status: Some("in_progress".to_string()),
        started_at: Some(chrono::Utc::now()),
        batch_job_ids: vec!["batch-job-1".to_string()],
        machines: vec![
            FirmwareUpgradeDeviceStatus {
                node_id: host_a.host_snapshot.id.to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                bmc_ip: "192.0.2.10".to_string(),
                status: "in_progress".to_string(),
                job_id: Some("child-job-1".to_string()),
                parent_job_id: Some("batch-job-1".to_string()),
                error_message: None,
            },
            FirmwareUpgradeDeviceStatus {
                node_id: host_b.host_snapshot.id.to_string(),
                mac: "00:11:22:33:44:66".to_string(),
                bmc_ip: "192.0.2.11".to_string(),
                status: "in_progress".to_string(),
                job_id: Some("child-job-2".to_string()),
                parent_job_id: Some("batch-job-1".to_string()),
                error_message: None,
            },
        ],
        ..Default::default()
    });

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let fw_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Expected Wait while some tracked devices are still non-terminal"
    );

    let machine_a = db::machine::find_one(
        &pool,
        &host_a.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine A should exist");
    let machine_b = db::machine::find_one(
        &pool,
        &host_b.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine B should exist");
    assert!(matches!(
        machine_a
            .rack_fw_details
            .as_ref()
            .expect("machine A rack fw details")
            .status,
        RackFirmwareUpgradeState::Failed { .. }
    ));
    assert_eq!(
        machine_b
            .rack_fw_details
            .as_ref()
            .expect("machine B rack fw details")
            .status,
        RackFirmwareUpgradeState::InProgress
    );

    env.rms_sim
        .set_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusResponse {
            status: librms::protos::rack_manager::ReturnCode::Success as i32,
            job_id: "child-job-2".to_string(),
            job_state: rms::FirmwareJobState::Completed as i32,
            state_description: "completed".to_string(),
            node_id: host_b.host_snapshot.id.to_string(),
            ..Default::default()
        })
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Error { .. }),
                "Expected rack to transition to Error after all tracked devices are terminal, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Error, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    let machine_b = db::machine::find_one(
        &pool,
        &host_b.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine B should exist");
    assert_eq!(
        machine_b
            .rack_fw_details
            .as_ref()
            .expect("machine B rack fw details")
            .status,
        RackFirmwareUpgradeState::Completed
    );

    Ok(())
}

/// test_firmware_upgrade_wait_for_complete_retries_when_job_lookup_fails
/// verifies that a response-level lookup failure from GetFirmwareJobStatus does
/// not mark the device failed and instead keeps the rack waiting.
#[crate::sqlx_test]
async fn test_firmware_upgrade_wait_for_complete_retries_when_job_lookup_fails(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host) = create_single_compute_rack(&env, &pool).await?;
    env.rms_sim
        .set_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusResponse {
            status: librms::protos::rack_manager::ReturnCode::Failure as i32,
            job_id: "child-job-1".to_string(),
            state_description: "Job not found".to_string(),
            error_message: "Job not found: child-job-1".to_string(),
            ..Default::default()
        })
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    rack.firmware_upgrade_job = Some(FirmwareUpgradeJob {
        job_id: Some("batch-job-1".to_string()),
        status: Some("in_progress".to_string()),
        started_at: Some(chrono::Utc::now()),
        batch_job_ids: vec!["batch-job-1".to_string()],
        machines: vec![FirmwareUpgradeDeviceStatus {
            node_id: host.host_snapshot.id.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            bmc_ip: "192.0.2.10".to_string(),
            status: "in_progress".to_string(),
            job_id: Some("child-job-1".to_string()),
            parent_job_id: Some("batch-job-1".to_string()),
            error_message: None,
        }],
        ..Default::default()
    });

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let fw_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Expected Wait while RMS job lookup is unavailable"
    );

    let persisted_rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let job = persisted_rack
        .firmware_upgrade_job
        .expect("rack firmware job should still be persisted");
    assert_eq!(job.status.as_deref(), Some("in_progress"));
    assert_eq!(job.machines[0].status, "in_progress");
    assert_eq!(
        job.machines[0].error_message.as_deref(),
        Some("Job not found: child-job-1")
    );

    Ok(())
}

/// test_firmware_upgrade_wait_for_complete_retries_on_transient_poll_error
/// verifies that transport-level polling failures do not immediately fail the
/// rack upgrade.
#[crate::sqlx_test]
async fn test_firmware_upgrade_wait_for_complete_retries_on_transient_poll_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host) = create_single_compute_rack(&env, &pool).await?;
    env.rms_sim
        .set_firmware_job_error("child-job-1", "mock transport failure")
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    rack.firmware_upgrade_job = Some(FirmwareUpgradeJob {
        job_id: Some("batch-job-1".to_string()),
        status: Some("in_progress".to_string()),
        started_at: Some(chrono::Utc::now()),
        batch_job_ids: vec!["batch-job-1".to_string()],
        machines: vec![FirmwareUpgradeDeviceStatus {
            node_id: host.host_snapshot.id.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            bmc_ip: "192.0.2.10".to_string(),
            status: "in_progress".to_string(),
            job_id: Some("child-job-1".to_string()),
            parent_job_id: Some("batch-job-1".to_string()),
            error_message: None,
        }],
        ..Default::default()
    });

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let fw_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Expected Wait while RMS polling has a transport error"
    );

    let persisted_rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let job = persisted_rack
        .firmware_upgrade_job
        .expect("rack firmware job should still be persisted");
    assert_eq!(job.status.as_deref(), Some("in_progress"));
    assert_eq!(job.machines[0].status, "in_progress");
    assert!(
        job.machines[0]
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("mock transport failure"))
    );

    Ok(())
}

/// test_nvos_update_start_transitions_to_wait_for_complete verifies that
/// Maintenance::NVOSUpdate(Start) transitions to WaitForComplete when a
/// NVOS SOT JSON is available for RMS ApplySwitchSystemImage.
#[crate::sqlx_test]
async fn test_nvos_update_start_transitions_to_wait_for_complete(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_nmx_cluster_profile()),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("NmxCluster")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);
    let switch_id = attach_switch_with_nvos_credentials(&env, &rack_id).await?;
    let config = RackConfig {
        maintenance_requested: Some(MaintenanceScope {
            switch_ids: vec![switch_id],
            activities: vec![MaintenanceActivity::NvosUpdate {
                config_json: r#"{"Id":"fw-nvos-default"}"#.to_string(),
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut txn = pool.acquire().await?;
    db_rack::update(&mut txn, &rack_id, &config).await?;
    drop(txn);

    env.api
        .credential_manager
        .set_credentials(
            &CredentialKey::RackMaintenanceAccessToken {
                rack_id: rack_id.clone(),
            },
            &Credentials::UsernamePassword {
                username: "access_token".to_string(),
                password: "token".to_string(),
            },
        )
        .await
        .map_err(|error| eyre::eyre!("failed to set maintenance access token: {}", error))?;

    env.rms_sim
        .queue_apply_switch_system_image_response(
            librms::protos::rack_manager::ApplySwitchSystemImageResponse {
                response: Some(librms::protos::rack_manager::NodeBatchResponse {
                    status: librms::protos::rack_manager::ReturnCode::Success as i32,
                    job_id: "nvos-job-1".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let nvos_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::NVOSUpdate {
            nvos_update: NvosUpdateState::Start,
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &nvos_state, &mut ctx)
        .await?;

    assert!(
        rack.nvos_update_job.is_some(),
        "NVOSUpdate(Start) should populate rack.nvos_update_job"
    );
    let requests = env
        .rms_sim
        .submitted_apply_switch_system_image_requests()
        .await;
    assert!(
        !requests.is_empty(),
        "NVOSUpdate(Start) should submit ApplySwitchSystemImage"
    );
    assert_eq!(requests[0].config_json, r#"{"Id":"fw-nvos-default"}"#);
    assert_eq!(requests[0].access_token.as_deref(), Some("token"));
    let mut txn = pool.acquire().await?;
    let switch = db_switch::find_by_id(&mut txn, &switch_id)
        .await?
        .expect("switch should exist");
    assert!(switch.switch_reprovisioning_requested.is_none());

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::NVOSUpdate {
                            nvos_update: NvosUpdateState::WaitForComplete,
                        },
                    }
                ),
                "NVOSUpdate(Start) should transition to WaitForComplete, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_configure_nmx_cluster_start_advances_to_disable_scale_up_fabric_state(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let nmx_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
            configure_nmx_cluster: ConfigureNmxClusterState::Start,
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &nmx_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                            configure_nmx_cluster:
                                ConfigureNmxClusterState::DisableScaleUpFabricState,
                        },
                    }
                ),
                "ConfigureNmxCluster(Start) should transition to DisableScaleUpFabricState, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    assert!(
        env.rms_sim
            .submitted_batch_set_scale_up_fabric_state_requests()
            .await
            .is_empty()
    );
    assert!(
        env.rms_sim
            .submitted_batch_get_node_device_info_requests()
            .await
            .is_empty()
    );
    assert!(
        env.rms_sim
            .submitted_configure_scale_up_fabric_manager_requests()
            .await
            .is_empty()
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_configure_nmx_cluster_disable_scale_up_fabric_state_runs_on_all_switches(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_nmx_cluster_profile()),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("NmxCluster")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);

    let switch_ids = attach_switches_with_nvos_credentials(&env, &rack_id, 2).await?;
    env.rms_sim
        .queue_batch_set_scale_up_fabric_state_response(Ok(
            rms::BatchSetScaleUpFabricStateResponse {
                response: Some(rms::NodeBatchResponse {
                    status: rms::ReturnCode::Success as i32,
                    stats: Some(rms::NodeOperationStats {
                        total_nodes: switch_ids.len() as u32,
                        successful_nodes: switch_ids.len() as u32,
                        failed_nodes: 0,
                    }),
                    ..Default::default()
                }),
            },
        ))
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let nmx_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
            configure_nmx_cluster: ConfigureNmxClusterState::DisableScaleUpFabricState,
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &nmx_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                            configure_nmx_cluster:
                                ConfigureNmxClusterState::ConfigureScaleUpFabricManager,
                        },
                    }
                ),
                "DisableScaleUpFabricState should transition to ConfigureScaleUpFabricManager, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    let requests = env
        .rms_sim
        .submitted_batch_set_scale_up_fabric_state_requests()
        .await;
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert!(!request.enabled);
    let devices = request
        .nodes
        .as_ref()
        .expect("disable request should include nodes")
        .nodes
        .as_slice();

    assert_eq!(devices.len(), switch_ids.len());
    for device in devices {
        let host_endpoint = device
            .host_endpoint
            .as_ref()
            .ok_or_else(|| eyre::eyre!("disable request should include host endpoints"))?;

        assert!(host_endpoint.dangerously_accept_invalid_certs);
    }
    let node_ids = devices
        .iter()
        .map(|device| device.node_id.clone())
        .collect::<std::collections::HashSet<_>>();
    for switch_id in &switch_ids {
        assert!(node_ids.contains(&switch_id.to_string()));
    }
    assert!(
        env.rms_sim
            .submitted_batch_get_node_device_info_requests()
            .await
            .is_empty()
    );
    assert!(
        env.rms_sim
            .submitted_configure_scale_up_fabric_manager_requests()
            .await
            .is_empty()
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_configure_nmx_cluster_configure_selects_persists_and_configures_primary_switch(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_nmx_cluster_profile()),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("NmxCluster")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);

    let switch_ids = attach_switches_with_nvos_credentials(&env, &rack_id, 2).await?;
    let secondary_switch_id = switch_ids[0];
    let primary_switch_id = switch_ids[1];
    let topology_type = RackHardwareTopology::Gb200Nvl72r1C2g4Topology.to_string();

    env.rms_sim
        .queue_batch_get_node_device_info_response(Ok(rms::BatchGetNodeDeviceInfoResponse {
            status: rms::ReturnCode::Success as i32,
            node_device_details: vec![
                rms::NodeDeviceInfo {
                    node_id: secondary_switch_id.to_string(),
                    tray_index: Some(2),
                    slot_number: Some(2),
                    ..Default::default()
                },
                rms::NodeDeviceInfo {
                    node_id: primary_switch_id.to_string(),
                    tray_index: Some(1),
                    slot_number: Some(1),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }))
        .await;
    env.rms_sim
        .queue_configure_scale_up_fabric_manager_response(Ok(
            rms::ConfigureScaleUpFabricManagerResponse {
                status: rms::ReturnCode::Success as i32,
                topology_used: topology_type.clone(),
                scale_up_fabric_state_enabled: false,
                grpc_enabled: true,
                ..Default::default()
            },
        ))
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let nmx_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
            configure_nmx_cluster: ConfigureNmxClusterState::ConfigureScaleUpFabricManager,
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &nmx_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                            configure_nmx_cluster: ConfigureNmxClusterState::WaitForFabricStatus,
                        },
                    }
                ),
                "ConfigureScaleUpFabricManager should transition to WaitForFabricStatus, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    assert!(
        env.rms_sim
            .submitted_batch_set_scale_up_fabric_state_requests()
            .await
            .is_empty()
    );

    let device_info_requests = env
        .rms_sim
        .submitted_batch_get_node_device_info_requests()
        .await;
    assert_eq!(device_info_requests.len(), 1);
    let device_info_nodes = device_info_requests[0]
        .nodes
        .as_ref()
        .expect("device-info request should include nodes")
        .nodes
        .as_slice();
    assert_eq!(device_info_nodes.len(), switch_ids.len());

    let configure_requests = env
        .rms_sim
        .submitted_configure_scale_up_fabric_manager_requests()
        .await;
    assert_eq!(configure_requests.len(), 1);
    let configure_request = &configure_requests[0];
    assert_eq!(configure_request.topology_type, topology_type);
    let configure_node = configure_request
        .node
        .as_ref()
        .ok_or_else(|| eyre::eyre!("configure request should include a primary switch"))?;

    assert_eq!(configure_node.node_id, primary_switch_id.to_string());
    assert!(
        configure_node
            .host_endpoint
            .as_ref()
            .ok_or_else(|| eyre::eyre!("configure request should include a host endpoint"))?
            .dangerously_accept_invalid_certs
    );

    let mut txn = pool.acquire().await?;
    let primary_switch = db_switch::find_by_id(&mut txn, &primary_switch_id)
        .await?
        .expect("primary switch should exist");
    let secondary_switch = db_switch::find_by_id(&mut txn, &secondary_switch_id)
        .await?
        .expect("secondary switch should exist");
    assert!(primary_switch.is_primary);
    assert!(!secondary_switch.is_primary);

    Ok(())
}

#[crate::sqlx_test]
async fn test_configure_nmx_cluster_runs_start_disable_configure_to_wait_for_fabric_status(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_nmx_cluster_profile()),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("NmxCluster")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);

    let switch_ids = attach_switches_with_nvos_credentials(&env, &rack_id, 2).await?;
    let secondary_switch_id = switch_ids[0];
    let primary_switch_id = switch_ids[1];
    let topology_type = RackHardwareTopology::Gb200Nvl72r1C2g4Topology.to_string();

    env.rms_sim
        .queue_batch_set_scale_up_fabric_state_response(Ok(
            rms::BatchSetScaleUpFabricStateResponse {
                response: Some(rms::NodeBatchResponse {
                    status: rms::ReturnCode::Success as i32,
                    stats: Some(rms::NodeOperationStats {
                        total_nodes: switch_ids.len() as u32,
                        successful_nodes: switch_ids.len() as u32,
                        failed_nodes: 0,
                    }),
                    ..Default::default()
                }),
            },
        ))
        .await;
    env.rms_sim
        .queue_batch_get_node_device_info_response(Ok(rms::BatchGetNodeDeviceInfoResponse {
            status: rms::ReturnCode::Success as i32,
            node_device_details: vec![
                rms::NodeDeviceInfo {
                    node_id: secondary_switch_id.to_string(),
                    tray_index: Some(2),
                    slot_number: Some(2),
                    ..Default::default()
                },
                rms::NodeDeviceInfo {
                    node_id: primary_switch_id.to_string(),
                    tray_index: Some(1),
                    slot_number: Some(1),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }))
        .await;
    env.rms_sim
        .queue_configure_scale_up_fabric_manager_response(Ok(
            rms::ConfigureScaleUpFabricManagerResponse {
                status: rms::ReturnCode::Success as i32,
                topology_used: topology_type.clone(),
                scale_up_fabric_state_enabled: false,
                grpc_enabled: true,
                ..Default::default()
            },
        ))
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let start_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
            configure_nmx_cluster: ConfigureNmxClusterState::Start,
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &start_state, &mut ctx)
        .await?;
    let disable_state = match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                            configure_nmx_cluster:
                                ConfigureNmxClusterState::DisableScaleUpFabricState,
                        },
                    }
                ),
                "ConfigureNmxCluster(Start) should transition to DisableScaleUpFabricState, got {:?}",
                next_state
            );
            next_state
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    };

    assert!(
        env.rms_sim
            .submitted_batch_set_scale_up_fabric_state_requests()
            .await
            .is_empty()
    );
    assert!(
        env.rms_sim
            .submitted_batch_get_node_device_info_requests()
            .await
            .is_empty()
    );
    assert!(
        env.rms_sim
            .submitted_configure_scale_up_fabric_manager_requests()
            .await
            .is_empty()
    );

    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &disable_state, &mut ctx)
        .await?;
    let configure_state = match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                            configure_nmx_cluster:
                                ConfigureNmxClusterState::ConfigureScaleUpFabricManager,
                        },
                    }
                ),
                "DisableScaleUpFabricState should transition to ConfigureScaleUpFabricManager, got {:?}",
                next_state
            );
            next_state
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    };

    let disable_requests = env
        .rms_sim
        .submitted_batch_set_scale_up_fabric_state_requests()
        .await;
    assert_eq!(disable_requests.len(), 1);
    let disable_request = &disable_requests[0];
    assert!(!disable_request.enabled);
    let disable_devices = disable_request
        .nodes
        .as_ref()
        .expect("disable request should include nodes")
        .nodes
        .as_slice();

    assert_eq!(disable_devices.len(), switch_ids.len());
    for device in disable_devices {
        let host_endpoint = device
            .host_endpoint
            .as_ref()
            .ok_or_else(|| eyre::eyre!("disable request should include host endpoints"))?;

        assert!(host_endpoint.dangerously_accept_invalid_certs);
    }
    let disabled_node_ids = disable_devices
        .iter()
        .map(|device| device.node_id.clone())
        .collect::<std::collections::HashSet<_>>();
    for switch_id in &switch_ids {
        assert!(disabled_node_ids.contains(&switch_id.to_string()));
    }
    assert!(
        env.rms_sim
            .submitted_batch_get_node_device_info_requests()
            .await
            .is_empty()
    );
    assert!(
        env.rms_sim
            .submitted_configure_scale_up_fabric_manager_requests()
            .await
            .is_empty()
    );

    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &configure_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                            configure_nmx_cluster: ConfigureNmxClusterState::WaitForFabricStatus,
                        },
                    }
                ),
                "ConfigureScaleUpFabricManager should transition to WaitForFabricStatus, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    let device_info_requests = env
        .rms_sim
        .submitted_batch_get_node_device_info_requests()
        .await;
    assert_eq!(device_info_requests.len(), 1);
    let device_info_devices = device_info_requests[0]
        .nodes
        .as_ref()
        .expect("device-info request should include nodes")
        .nodes
        .as_slice();
    assert_eq!(device_info_devices.len(), switch_ids.len());

    let configure_requests = env
        .rms_sim
        .submitted_configure_scale_up_fabric_manager_requests()
        .await;
    assert_eq!(configure_requests.len(), 1);
    let configure_request = &configure_requests[0];
    assert_eq!(configure_request.topology_type, topology_type);
    let configure_node = configure_request
        .node
        .as_ref()
        .ok_or_else(|| eyre::eyre!("configure request should include a primary switch"))?;

    assert_eq!(configure_node.node_id, primary_switch_id.to_string());
    assert!(
        configure_node
            .host_endpoint
            .as_ref()
            .ok_or_else(|| eyre::eyre!("configure request should include a host endpoint"))?
            .dangerously_accept_invalid_certs
    );

    let mut txn = pool.acquire().await?;
    let primary_switch = db_switch::find_by_id(&mut txn, &primary_switch_id)
        .await?
        .expect("primary switch should exist");
    let secondary_switch = db_switch::find_by_id(&mut txn, &secondary_switch_id)
        .await?
        .expect("secondary switch should exist");
    assert!(primary_switch.is_primary);
    assert!(!secondary_switch.is_primary);

    Ok(())
}

#[crate::sqlx_test]
async fn test_configure_nmx_cluster_disable_scale_up_fabric_state_failure_stops_flow(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_nmx_cluster_profile()),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("NmxCluster")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);

    attach_switches_with_nvos_credentials(&env, &rack_id, 2).await?;
    env.rms_sim
        .queue_batch_set_scale_up_fabric_state_response(Ok(
            rms::BatchSetScaleUpFabricStateResponse {
                response: Some(rms::NodeBatchResponse {
                    status: rms::ReturnCode::Failure as i32,
                    message: "disable rejected".to_string(),
                    stats: Some(rms::NodeOperationStats {
                        total_nodes: 2,
                        successful_nodes: 1,
                        failed_nodes: 1,
                    }),
                    ..Default::default()
                }),
            },
        ))
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let nmx_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
            configure_nmx_cluster: ConfigureNmxClusterState::DisableScaleUpFabricState,
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &nmx_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => match next_state {
            RackState::Error { cause } => {
                assert!(cause.contains("RMS BatchSetScaleUpFabricState failed"));
                assert!(cause.contains("disable rejected"));
            }
            other => panic!("Expected Error state, got {:?}", other),
        },
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    assert_eq!(
        env.rms_sim
            .submitted_batch_set_scale_up_fabric_state_requests()
            .await
            .len(),
        1
    );
    assert!(
        env.rms_sim
            .submitted_batch_get_node_device_info_requests()
            .await
            .is_empty()
    );
    assert!(
        env.rms_sim
            .submitted_configure_scale_up_fabric_manager_requests()
            .await
            .is_empty()
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_configure_nmx_cluster_configure_selection_failure_stops_before_configure(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_nmx_cluster_profile()),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("NmxCluster")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);

    let switch_ids = attach_switches_with_nvos_credentials(&env, &rack_id, 2).await?;
    env.rms_sim
        .queue_batch_get_node_device_info_response(Ok(rms::BatchGetNodeDeviceInfoResponse {
            status: rms::ReturnCode::Success as i32,
            node_device_details: vec![
                rms::NodeDeviceInfo {
                    node_id: switch_ids[0].to_string(),
                    tray_index: Some(1),
                    slot_number: Some(1),
                    ..Default::default()
                },
                rms::NodeDeviceInfo {
                    node_id: switch_ids[1].to_string(),
                    tray_index: Some(1),
                    slot_number: Some(2),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }))
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let nmx_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
            configure_nmx_cluster: ConfigureNmxClusterState::ConfigureScaleUpFabricManager,
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &nmx_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => match next_state {
            RackState::Error { cause } => {
                assert!(cause.contains("duplicate tray_index 1"));
            }
            other => panic!("Expected Error state, got {:?}", other),
        },
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    assert!(
        env.rms_sim
            .submitted_batch_set_scale_up_fabric_state_requests()
            .await
            .is_empty()
    );
    assert_eq!(
        env.rms_sim
            .submitted_batch_get_node_device_info_requests()
            .await
            .len(),
        1
    );
    assert!(
        env.rms_sim
            .submitted_configure_scale_up_fabric_manager_requests()
            .await
            .is_empty()
    );

    let mut txn = pool.acquire().await?;
    for switch_id in switch_ids {
        let switch = db_switch::find_by_id(&mut txn, &switch_id)
            .await?
            .expect("switch should exist");
        assert!(!switch.is_primary);
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_configure_nmx_cluster_configure_failure_advances_to_wait_for_fabric_status(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_nmx_cluster_profile()),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("NmxCluster")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);

    let switch_ids = attach_switches_with_nvos_credentials(&env, &rack_id, 2).await?;
    let primary_switch_id = switch_ids[0];
    let topology_type = RackHardwareTopology::Gb200Nvl72r1C2g4Topology.to_string();

    env.rms_sim
        .queue_batch_get_node_device_info_response(Ok(rms::BatchGetNodeDeviceInfoResponse {
            status: rms::ReturnCode::Success as i32,
            node_device_details: vec![
                rms::NodeDeviceInfo {
                    node_id: primary_switch_id.to_string(),
                    tray_index: Some(1),
                    slot_number: Some(1),
                    ..Default::default()
                },
                rms::NodeDeviceInfo {
                    node_id: switch_ids[1].to_string(),
                    tray_index: Some(2),
                    slot_number: Some(2),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }))
        .await;
    env.rms_sim
        .queue_configure_scale_up_fabric_manager_response(Ok(
            rms::ConfigureScaleUpFabricManagerResponse {
                status: rms::ReturnCode::Failure as i32,
                message: "configure rejected".to_string(),
                ..Default::default()
            },
        ))
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let nmx_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
            configure_nmx_cluster: ConfigureNmxClusterState::ConfigureScaleUpFabricManager,
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &nmx_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                            configure_nmx_cluster: ConfigureNmxClusterState::WaitForFabricStatus,
                        },
                    }
                ),
                "ConfigureScaleUpFabricManager failure should transition to WaitForFabricStatus, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    assert!(
        env.rms_sim
            .submitted_batch_set_scale_up_fabric_state_requests()
            .await
            .is_empty()
    );
    assert_eq!(
        env.rms_sim
            .submitted_batch_get_node_device_info_requests()
            .await
            .len(),
        1
    );
    let configure_requests = env
        .rms_sim
        .submitted_configure_scale_up_fabric_manager_requests()
        .await;
    assert_eq!(configure_requests.len(), 1);
    assert_eq!(configure_requests[0].topology_type, topology_type);
    let configure_node = configure_requests[0]
        .node
        .as_ref()
        .ok_or_else(|| eyre::eyre!("configure request should include a primary switch"))?;

    assert_eq!(configure_node.node_id, primary_switch_id.to_string());
    assert!(
        configure_node
            .host_endpoint
            .as_ref()
            .ok_or_else(|| eyre::eyre!("configure request should include a host endpoint"))?
            .dangerously_accept_invalid_certs
    );

    let mut txn = pool.acquire().await?;
    let primary_switch = db_switch::find_by_id(&mut txn, &primary_switch_id)
        .await?
        .expect("primary switch should exist");
    assert!(primary_switch.is_primary);

    Ok(())
}

/// test_configure_nmx_cluster_transitions_to_completed verifies that
/// Maintenance::ConfigureNmxCluster transitions to Maintenance::Completed.
#[crate::sqlx_test]
async fn test_configure_nmx_cluster_transitions_to_completed(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let nmx_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::PowerSequence {
            rack_power: RackPowerState::PoweringOn,
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &nmx_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::Completed,
                    }
                ),
                "ConfigureNmxCluster should transition to Completed, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_ready_topology_changed_transitions_to_discovering verifies that
/// Ready with topology_changed=true transitions back to Discovering.
#[crate::sqlx_test]
async fn test_ready_topology_changed_transitions_to_discovering(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let cfg = RackConfig {
        topology_changed: true,
        ..Default::default()
    };
    db_rack::update(&mut txn, &rack_id, &cfg).await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &RackState::Ready, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Discovering),
                "Ready with topology_changed should transition to Discovering, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Discovering, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_ready_reprovision_requested_transitions_to_maintenance verifies that
/// Ready with reprovision_requested=true transitions back to Maintenance.
#[crate::sqlx_test]
async fn test_ready_reprovision_requested_transitions_to_maintenance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let cfg = RackConfig {
        reprovision_requested: true,
        ..Default::default()
    };
    db_rack::update(&mut txn, &rack_id, &cfg).await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &RackState::Ready, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Maintenance { .. }),
                "Ready with reprovision_requested should transition to Maintenance, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Maintenance, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_validation_failed_transitions_to_error verifies that
/// Validation(Failed) transitions to Error state.
#[crate::sqlx_test]
async fn test_validation_failed_transitions_to_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let failed_state = RackState::Validating {
        validating_state: RackValidationState::Failed {
            run_id: "test-run".to_string(),
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &failed_state, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::DoNothing { .. }),
        "Validation(Failed) should wait for intervention, got {:?}",
        std::mem::discriminant(&outcome)
    );

    Ok(())
}

async fn set_switch_state(
    txn: &mut sqlx::PgConnection,
    switch_id: &SwitchId,
    state: model::switch::SwitchControllerState,
) {
    sqlx::query("UPDATE switches SET controller_state = $1 WHERE id = $2")
        .bind(serde_json::to_value(state).unwrap())
        .bind(switch_id)
        .execute(txn)
        .await
        .expect("update switch controller_state");
}

async fn set_power_shelf_state(
    txn: &mut sqlx::PgConnection,
    power_shelf_id: &carbide_uuid::power_shelf::PowerShelfId,
    state: model::power_shelf::PowerShelfControllerState,
) {
    sqlx::query("UPDATE power_shelves SET controller_state = $1 WHERE id = $2")
        .bind(serde_json::to_value(state).unwrap())
        .bind(power_shelf_id)
        .execute(txn)
        .await
        .expect("update power_shelf controller_state");
}

async fn create_test_power_shelf(
    txn: &mut sqlx::PgConnection,
    rack_id: &RackId,
    seed: u8,
) -> carbide_uuid::power_shelf::PowerShelfId {
    use carbide_uuid::power_shelf::PowerShelfId;
    let mut bytes = [0u8; 16];
    bytes[0] = seed;
    let power_shelf_id = PowerShelfId::from(uuid::Uuid::from_bytes(bytes));
    let new_power_shelf = model::power_shelf::NewPowerShelf {
        id: power_shelf_id,
        config: model::power_shelf::PowerShelfConfig {
            name: format!("ps-{}", seed),
            capacity: Some(6000),
            voltage: Some(480),
        },
        bmc_mac_address: None,
        metadata: None,
        rack_id: Some(rack_id.clone()),
    };
    db::power_shelf::create(txn, &new_power_shelf)
        .await
        .expect("create power shelf");
    power_shelf_id
}

/// Ready rack moves to Error when one of its switches enters Error.
#[crate::sqlx_test]
async fn test_ready_with_failed_switch_transitions_to_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;
    let (rack_id, switch_id) = create_ready_rack_with_switch(&env, &pool).await?;

    set_switch_state(
        pool.acquire().await?.as_mut(),
        &switch_id,
        model::switch::SwitchControllerState::Error {
            cause: "synthetic switch failure".to_string(),
        },
    )
    .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Ready, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => match next_state {
            RackState::Error { cause } => {
                assert!(
                    cause.contains("switch"),
                    "Error cause should mention failing switch, got: {}",
                    cause
                );
            }
            other => panic!("Expected Transition to Error, got {:?}", other),
        },
        other => panic!(
            "Expected Transition to Error, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// Ready rack moves to Error when an attached power shelf enters Error.
#[crate::sqlx_test]
async fn test_ready_with_failed_power_shelf_transitions_to_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    {
        let mut txn = pool.begin().await?;
        db_rack::create(
            txn.as_mut(),
            &rack_id,
            Some(&RackProfileId::new("Empty")),
            &RackConfig::default(),
            None,
        )
        .await?;
        let power_shelf_id = create_test_power_shelf(txn.as_mut(), &rack_id, 0xa1).await;
        set_power_shelf_state(
            txn.as_mut(),
            &power_shelf_id,
            model::power_shelf::PowerShelfControllerState::Error {
                cause: "synthetic power shelf failure".to_string(),
            },
        )
        .await;
        let rack = get_db_rack(txn.as_mut(), &rack_id).await;
        db_rack::try_update_controller_state(
            txn.as_mut(),
            &rack_id,
            rack.controller_state.version,
            rack.controller_state.version.increment(),
            &RackState::Ready,
        )
        .await?;
        txn.commit().await?;
    }

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Ready, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => match next_state {
            RackState::Error { cause } => {
                assert!(
                    cause.contains("power shelf"),
                    "Error cause should mention failing power shelf, got: {}",
                    cause
                );
            }
            other => panic!("Expected Transition to Error, got {:?}", other),
        },
        other => panic!(
            "Expected Transition to Error, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// Ready rack with all healthy components stays in Ready.
#[crate::sqlx_test]
async fn test_ready_with_all_healthy_components_waits(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;
    let (rack_id, switch_id) = create_ready_rack_with_switch(&env, &pool).await?;

    set_switch_state(
        pool.acquire().await?.as_mut(),
        &switch_id,
        model::switch::SwitchControllerState::Ready,
    )
    .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Ready, &mut ctx)
        .await?;

    assert!(
        matches!(
            outcome,
            StateHandlerOutcome::Wait { .. } | StateHandlerOutcome::DoNothing { .. }
        ),
        "Ready with healthy components should wait, got {:?}",
        std::mem::discriminant(&outcome)
    );

    Ok(())
}

/// Rack in Error transitions back to Ready once every component is Ready.
#[crate::sqlx_test]
async fn test_error_recovers_to_ready_when_all_components_ready(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;
    let (rack_id, switch_id) = create_ready_rack_with_switch(&env, &pool).await?;

    set_switch_state(
        pool.acquire().await?.as_mut(),
        &switch_id,
        model::switch::SwitchControllerState::Ready,
    )
    .await;
    crate::tests::rack_state_controller::fixtures::rack::set_rack_controller_state(
        pool.acquire().await?.as_mut(),
        &rack_id,
        RackState::Error {
            cause: "synthetic prior failure".to_string(),
        },
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let error_state = rack.controller_state.value.clone();

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &error_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Ready),
                "Error with all-Ready components should transition to Ready, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Ready, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// Rack in Error does not auto-recover while any component is not yet Ready.
#[crate::sqlx_test]
async fn test_error_stays_in_error_when_components_not_all_ready(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;
    let (rack_id, switch_id) = create_ready_rack_with_switch(&env, &pool).await?;

    set_switch_state(
        pool.acquire().await?.as_mut(),
        &switch_id,
        model::switch::SwitchControllerState::Initializing {
            initializing_state: model::switch::InitializingState::WaitForOsMachineInterface,
        },
    )
    .await;
    crate::tests::rack_state_controller::fixtures::rack::set_rack_controller_state(
        pool.acquire().await?.as_mut(),
        &rack_id,
        RackState::Error {
            cause: "synthetic prior failure".to_string(),
        },
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let error_state = rack.controller_state.value.clone();

    let handler = RackStateHandler::default();
    let mut services = env.rack_state_handler_services();
    let mut metrics = RackMetrics::default();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &error_state, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Error with non-Ready components must not auto-recover, got {:?}",
        std::mem::discriminant(&outcome)
    );

    Ok(())
}

async fn get_db_rack<DB>(conn: &mut DB, rack_id: &RackId) -> Rack
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    db_rack::find_by(conn, ObjectColumnFilter::One(db_rack::IdColumn, rack_id))
        .await
        .unwrap()
        .pop()
        .unwrap()
}
