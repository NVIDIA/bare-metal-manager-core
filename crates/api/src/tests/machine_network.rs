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
use std::ops::DerefMut;
use std::time::SystemTime;

use ::rpc::forge::{
    CreateDpuExtensionServiceRequest, DpuExtensionServiceType, DpuNetworkStatus,
    InstanceDpuExtensionServiceConfig, InstanceDpuExtensionServicesConfig,
    ManagedHostNetworkConfigRequest, ManagedHostNetworkStatusRequest,
};
use common::api_fixtures::{self, create_managed_host, dpu, network_configured_with_health};
use model::machine::network::ManagedHostQuarantineMode;
use rpc::forge::forge_server::Forge;

use crate::tests::common;

#[crate::sqlx_test]
async fn test_managed_host_network_config(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu_machine_id = dpu::create_dpu_machine(&env, &host_config).await;

    // Fetch a Machines network config
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await;

    assert!(response.is_ok());
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_multi_dpu(pool: sqlx::PgPool) {
    // Given: A managed host with 2 DPUs
    let env = api_fixtures::create_test_env(pool).await;
    let mh = api_fixtures::create_managed_host_multi_dpu(&env, 2).await;
    let host_machine = mh.host().rpc_machine().await;
    let dpu_1_id = host_machine.associated_dpu_machine_ids[0];
    let dpu_2_id = host_machine.associated_dpu_machine_ids[1];

    // Then: Get the managed host network config version via DPU 1's ID and DPU 2's ID
    let dpu_1_network_config = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_1_id),
        }))
        .await
        .expect("Error getting DPU1 network config")
        .into_inner();
    let dpu_2_network_config = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_2_id),
        }))
        .await
        .expect("Error getting DPU1 network config")
        .into_inner();

    // Assert: They should not have the same config version, since the managed_host_config_version
    // represents the health of that particular DPU.
    assert!(
        dpu_1_network_config
            .managed_host_config_version
            .ne(&dpu_2_network_config.managed_host_config_version)
    );
}

#[crate::sqlx_test]
async fn test_managed_host_network_status(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    // Add an instance
    let instance_network = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(segment_id),
            network_details: None,
            device: None,
            device_instance: 0u32,
            virtual_function_id: None,
        }],
    };

    mh.instance_builer(&env)
        .network(instance_network)
        .build()
        .await;

    let response = env
        .api
        .get_all_managed_host_network_status(tonic::Request::new(
            ManagedHostNetworkStatusRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.all.len(), 1);

    // Tell API about latest network config and machine health
    let dpu_health = rpc::health::HealthReport {
        source: "should-get-updated".to_string(),
        observed_at: None,
        successes: vec![
            rpc::health::HealthProbeSuccess {
                id: "ContainerExists".to_string(),
                target: Some("c1".to_string()),
            },
            rpc::health::HealthProbeSuccess {
                id: "checkTwo".to_string(),
                target: None,
            },
        ],
        alerts: vec![],
    };
    network_configured_with_health(&env, &mh.dpu().id, Some(dpu_health.clone())).await;

    // Query the aggregate health.
    let reported_health = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![mh.dpu().id],
            include_history: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0)
        .health;
    let mut reported_health = reported_health.unwrap();
    assert!(reported_health.observed_at.is_some());
    reported_health.observed_at = None;
    reported_health.source = "should-get-updated".to_string();
    assert_eq!(reported_health, dpu_health);

    // Now fetch the instance and check that knows its configs have synced
    let response = env
        .api
        .find_instance_by_machine_id(tonic::Request::new(mh.id))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.instances.len(), 1);
    let instance = &response.instances[0];
    tracing::info!(
        "instance_network_config_version: {}",
        instance.network_config_version
    );
    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced,
        rpc::SyncState::Synced as i32
    );
}

fn create_extension_service_data(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {}\nspec:\n  containers:\n    - name: app\n      image: nginx:1.27",
        name
    )
}

#[crate::sqlx_test]
async fn test_managed_host_network_config_with_extension_services(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;
    let dpu_1_id = mh.dpu_ids[0];

    // Add an instance
    let instance_network = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(segment_id),
            network_details: None,
            device: None,
            device_instance: 0u32,
            virtual_function_id: None,
        }],
    };

    let default_tenant_org = "best_org";
    let _ = env
        .api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: default_tenant_org.to_string(),
            routing_profile_type: None,
            metadata: Some(rpc::forge::Metadata {
                name: default_tenant_org.to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap();

    // Create extension services and add them to the instance
    let extension_service1 = env
        .api
        .create_dpu_extension_service(tonic::Request::new(CreateDpuExtensionServiceRequest {
            service_id: None,
            service_name: "test1".to_string(),
            service_type: DpuExtensionServiceType::KubernetesPod as i32,
            tenant_organization_id: "best_org".to_string(),
            description: None,
            data: create_extension_service_data("test"),
            credential: None,
            observability: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let service1_version = extension_service1
        .latest_version_info
        .as_ref()
        .unwrap()
        .version
        .clone();

    let extension_service2 = env
        .api
        .create_dpu_extension_service(tonic::Request::new(CreateDpuExtensionServiceRequest {
            service_id: None,
            service_name: "test2".to_string(),
            service_type: DpuExtensionServiceType::KubernetesPod as i32,
            tenant_organization_id: "best_org".to_string(),
            description: None,
            data: create_extension_service_data("test2"),
            credential: None,
            observability: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let service2_version = extension_service2
        .latest_version_info
        .as_ref()
        .unwrap()
        .version
        .clone();

    let es_config = InstanceDpuExtensionServicesConfig {
        service_configs: vec![
            InstanceDpuExtensionServiceConfig {
                service_id: extension_service1.service_id.clone(),
                version: service1_version.clone(),
            },
            InstanceDpuExtensionServiceConfig {
                service_id: extension_service2.service_id.clone(),
                version: service2_version.clone(),
            },
        ],
    };

    let _ = mh
        .instance_builer(&env)
        .network(instance_network)
        .extension_services(es_config)
        .build()
        .await;

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_1_id),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.dpu_extension_services.len(), 2);
    assert_eq!(
        response.dpu_extension_services[0].service_id,
        extension_service1.service_id
    );
    assert_eq!(
        response.dpu_extension_services[0].version,
        service1_version.clone()
    );
    assert_eq!(response.dpu_extension_services[0].removed, None);

    assert_eq!(
        response.dpu_extension_services[1].service_id,
        extension_service2.service_id
    );
    assert_eq!(
        response.dpu_extension_services[1].version,
        service2_version.clone()
    );
    assert_eq!(response.dpu_extension_services[1].removed, None);
}

#[crate::sqlx_test]
async fn test_dpu_health_is_required(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let (_host_machine_id, dpu_machine_id) = create_managed_host(&env).await.into();

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await
        .unwrap()
        .into_inner();

    let admin_if = response.admin_interface.as_ref().unwrap();

    // dpu-health is not updated here
    let err = env
        .api
        .record_dpu_network_status(tonic::Request::new(DpuNetworkStatus {
            dpu_machine_id: Some(dpu_machine_id),
            dpu_agent_version: Some(dpu::TEST_DPU_AGENT_VERSION.to_string()),
            observed_at: Some(SystemTime::now().into()),
            dpu_health: None,
            network_config_version: Some(response.managed_host_config_version.clone()),
            instance_id: None,
            instance_config_version: None,
            instance_network_config_version: None,
            interfaces: vec![rpc::InstanceInterfaceStatusObservation {
                function_type: admin_if.function_type,
                virtual_function_id: None,
                mac_address: None,
                addresses: vec![admin_if.ip.clone()],
                prefixes: vec![admin_if.interface_prefix.clone()],
                gateways: vec![admin_if.gateway.clone()],
                network_security_group: None,
                internal_uuid: None,
            }],
            network_config_error: None,
            client_certificate_expiry_unix_epoch_secs: None,
            fabric_interfaces: vec![],
            last_dhcp_requests: vec![],
            dpu_extension_service_version: Some("V1-T1".to_string()),
            dpu_extension_services: vec![],
        }))
        .await
        .expect_err("Should fail");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(err.message(), "dpu_health");
}

/// Tests whether the in_alert_since field will be correctly populated
/// in case the DPU sends multiple reports using the same alarm
#[crate::sqlx_test]
async fn test_retain_in_alert_since(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let (_host_machine_id, dpu_machine_id) = create_managed_host(&env).await.into();

    let dpu_health = rpc::health::HealthReport {
        source: "should-get-updated".to_string(),
        observed_at: None,
        successes: vec![rpc::health::HealthProbeSuccess {
            id: "SuccessA".to_string(),
            target: None,
        }],
        alerts: vec![rpc::health::HealthProbeAlert {
            id: "AlertA".to_string(),
            target: None,
            in_alert_since: None,
            message: "AlertA".to_string(),
            tenant_message: None,
            classifications: vec![
                health_report::HealthAlertClassification::prevent_host_state_changes().to_string(),
            ],
        }],
    };

    network_configured_with_health(&env, &dpu_machine_id, Some(dpu_health.clone())).await;

    // Query the new HealthReport format
    let reported_health = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![dpu_machine_id],
            include_history: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0)
        .health;

    let reported_health = reported_health.unwrap();
    assert!(reported_health.observed_at.is_some());
    assert_eq!(reported_health.successes.len(), 1);
    assert_eq!(reported_health.alerts.len(), 1);
    let mut reported_alert = reported_health.alerts[0].clone();
    assert!(reported_alert.in_alert_since.is_some());
    let in_alert_since = reported_alert.in_alert_since.unwrap();
    reported_alert.in_alert_since = None;
    assert_eq!(reported_alert, dpu_health.alerts[0].clone());

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Report health again. The in_alert_since date should not have been updated
    network_configured_with_health(&env, &dpu_machine_id, Some(dpu_health.clone())).await;
    let reported_health = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![dpu_machine_id],
            include_history: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0)
        .health;
    let reported_health = reported_health.unwrap();
    assert!(reported_health.observed_at.is_some());
    assert_eq!(reported_health.successes.len(), 1);
    assert_eq!(reported_health.alerts.len(), 1);
    let mut reported_alert = reported_health.alerts[0].clone();
    assert_eq!(reported_alert.in_alert_since.unwrap(), in_alert_since);
    reported_alert.in_alert_since = None;
    assert_eq!(reported_alert, dpu_health.alerts[0].clone());
}

#[crate::sqlx_test]
async fn test_quarantine_state_crud(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

    let network_config_version =
        db::machine::get_network_config(env.pool.begin().await?.deref_mut(), &host_machine_id)
            .await?
            .version;

    // Get, make sure it's not set yet
    {
        let quarantine_state = env
            .api
            .get_managed_host_quarantine_state(tonic::Request::new(
                rpc::forge::GetManagedHostQuarantineStateRequest {
                    machine_id: Some(host_machine_id),
                },
            ))
            .await?
            .into_inner()
            .quarantine_state;

        assert!(
            quarantine_state.is_none(),
            "new host should not be quarantined"
        );
    }

    // Make sure finding machine ID's in quarantine state does not include anything yet
    {
        let ids = env
            .api
            .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
                only_quarantine: true,
                ..Default::default()
            }))
            .await?
            .into_inner()
            .machine_ids;
        assert!(
            ids.is_empty(),
            "No machine ID's should be found in quarantine state yet"
        );
    }

    // Set it, make sure we get None back for prior state
    {
        let set_result = env
            .api
            .set_managed_host_quarantine_state(tonic::Request::new(
                rpc::forge::SetManagedHostQuarantineStateRequest {
                    machine_id: Some(host_machine_id),
                    quarantine_state: Some(rpc::forge::ManagedHostQuarantineState {
                        mode: rpc::forge::ManagedHostQuarantineMode::BlockAllTraffic as i32,
                        reason: Some("test reason 1".to_string()),
                    }),
                },
            ))
            .await?
            .into_inner();

        assert!(
            set_result.prior_quarantine_state.is_none(),
            "prior quarantine state should be None"
        );
    }

    // Make sure finding machine ID's in quarantine state includes the machine ID
    {
        let ids = env
            .api
            .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
                only_quarantine: true,
                ..Default::default()
            }))
            .await?
            .into_inner()
            .machine_ids;
        assert_eq!(
            ids,
            vec![host_machine_id],
            "Finding machine ID's with only_quarantine should have returned the quarantined host"
        );
    }

    // Make sure the version got bumped
    let network_config =
        db::machine::get_network_config(env.pool.begin().await?.deref_mut(), &host_machine_id)
            .await?;
    assert_eq!(
        network_config.version.version_nr(),
        network_config_version.version_nr() + 1,
        "Setting quarantine should have bumped the network config version"
    );
    let network_config_version = network_config.version;

    // Make sure the DPU will see a mode saying to block all traffic
    assert_eq!(
        network_config.quarantine_state.as_ref().unwrap().mode,
        ManagedHostQuarantineMode::BlockAllTraffic
    );

    // Make sure we get back what we just set
    {
        let quarantine_state = env
            .api
            .get_managed_host_quarantine_state(tonic::Request::new(
                rpc::forge::GetManagedHostQuarantineStateRequest {
                    machine_id: Some(host_machine_id),
                },
            ))
            .await?
            .into_inner()
            .quarantine_state;

        assert_eq!(
            quarantine_state
                .expect("we should get a quarantine state back after setting")
                .reason
                .expect("reason should be set")
                .as_str(),
            "test reason 1",
            "getting quarantine state should return the value we just set"
        );
    }

    // Set again, make sure the prior version matches what we set last time
    {
        let set_result = env
            .api
            .set_managed_host_quarantine_state(tonic::Request::new(
                rpc::forge::SetManagedHostQuarantineStateRequest {
                    machine_id: Some(host_machine_id),
                    quarantine_state: Some(rpc::forge::ManagedHostQuarantineState {
                        mode: rpc::forge::ManagedHostQuarantineMode::BlockAllTraffic as i32,
                        reason: Some("test reason 2".to_string()),
                    }),
                },
            ))
            .await?
            .into_inner();

        assert_eq!(
            set_result
                .prior_quarantine_state
                .expect("prior quarantine state should now be set")
                .reason,
            Some("test reason 1".to_string()),
            "prior quarantine state should match the first state we set"
        );
    }

    // Make sure the version got bumped again
    let network_config =
        db::machine::get_network_config(env.pool.begin().await?.deref_mut(), &host_machine_id)
            .await?;
    assert_eq!(
        network_config.version.version_nr(),
        network_config_version.version_nr() + 1,
        "Setting quarantine should have bumped the network config version"
    );
    let network_config_version = network_config.version;

    // Make sure the DPU will (still) see a mode saying to block all traffic
    assert_eq!(
        network_config.quarantine_state.as_ref().unwrap().mode,
        ManagedHostQuarantineMode::BlockAllTraffic
    );

    // Make sure we get back what we set again
    {
        let quarantine_state = env
            .api
            .get_managed_host_quarantine_state(tonic::Request::new(
                rpc::forge::GetManagedHostQuarantineStateRequest {
                    machine_id: Some(host_machine_id),
                },
            ))
            .await?
            .into_inner()
            .quarantine_state;

        assert_eq!(
            quarantine_state
                .expect("we should get a quarantine state back after setting")
                .reason
                .expect("reason should be set")
                .as_str(),
            "test reason 2",
            "getting quarantine state should return the value we just set"
        );
    }

    // Clear, making sure we got back what we set last time
    {
        let clear_result = env
            .api
            .clear_managed_host_quarantine_state(tonic::Request::new(
                rpc::forge::ClearManagedHostQuarantineStateRequest {
                    machine_id: Some(host_machine_id),
                },
            ))
            .await?
            .into_inner();

        assert_eq!(
            clear_result
                .prior_quarantine_state
                .expect("prior quarantine state should be set when clearing")
                .reason,
            Some("test reason 2".to_string()),
            "prior quarantine state should match the second state we set"
        );
    }

    // Make sure the network config version bumps again on clear
    let network_config =
        db::machine::get_network_config(env.pool.begin().await?.deref_mut(), &host_machine_id)
            .await?;
    assert_eq!(
        network_config.version.version_nr(),
        network_config_version.version_nr() + 1,
        "Clearing quarantine should have bumped the network config version"
    );

    // Make sure the DPU no longer sees a quarantine state
    assert!(network_config.quarantine_state.is_none());

    // Make sure finding machine ID's in quarantine state does not include anything any more
    {
        let ids = env
            .api
            .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
                only_quarantine: true,
                ..Default::default()
            }))
            .await?
            .into_inner()
            .machine_ids;
        assert!(
            ids.is_empty(),
            "No machine ID's should be found in quarantine state after clearing"
        );
    }

    Ok(())
}
