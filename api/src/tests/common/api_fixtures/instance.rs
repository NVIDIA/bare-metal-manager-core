/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::ops::DerefMut;
use std::time::SystemTime;

use super::{
    TestEnv, forge_agent_control, inject_machine_measurements, persist_machine_validation_result,
};
use crate::db;
use crate::model::instance::config::network::DeviceLocator;
use crate::model::instance::status::network::InstanceNetworkStatusObservation;
use crate::model::machine::{
    CleanupState, MachineState, MachineValidatingState, ManagedHostState, ValidationState,
};
use crate::tests::common::api_fixtures::RpcInstance;
use crate::tests::common::api_fixtures::managed_host::ManagedHost;
use forge_uuid::{instance::InstanceId, machine::MachineId, network::NetworkSegmentId};
use rpc::{
    InstanceReleaseRequest, Timestamp,
    forge::{forge_server::Forge, instance_interface_config::NetworkDetails},
};

pub struct TestInstance<'a> {
    env: &'a TestEnv,
    config: rpc::InstanceConfig,
    tenant: rpc::TenantConfig,
    metadata: Option<rpc::Metadata>,
    unused_dpu_machine_ids: Vec<MachineId>,
}

impl<'a> TestInstance<'a> {
    pub fn new(env: &'a TestEnv) -> Self {
        Self {
            env,
            config: rpc::InstanceConfig {
                tenant: None,
                os: Some(default_os_config()),
                network: None,
                infiniband: None,
                storage: None,
                network_security_group_id: None,
            },
            tenant: default_tenant_config(),
            metadata: None,
            unused_dpu_machine_ids: vec![],
        }
    }

    pub fn config(mut self, config: rpc::InstanceConfig) -> Self {
        self.config = config;
        self
    }

    pub fn network(mut self, network: rpc::InstanceNetworkConfig) -> Self {
        self.config.network = Some(network);
        self
    }

    pub fn single_interface_network_config(self, segment_id: NetworkSegmentId) -> Self {
        self.network(single_interface_network_config(segment_id))
    }

    pub fn keyset_ids(mut self, ids: &[&str]) -> Self {
        self.tenant.tenant_keyset_ids = ids.iter().map(|s| (*s).into()).collect();
        self
    }

    pub fn metadata(mut self, metadata: rpc::Metadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.tenant.hostname = Some(hostname.into());
        self
    }

    pub fn tenant_org(mut self, tenant_org: impl Into<String>) -> Self {
        self.tenant.tenant_organization_id = tenant_org.into();
        self
    }

    pub fn unused_dpu_machine_ids(mut self, ids: &[MachineId]) -> Self {
        self.unused_dpu_machine_ids = ids.to_vec();
        self
    }

    pub async fn create_for_manged_host(self, mh: &ManagedHost) -> (InstanceId, RpcInstance) {
        self.create(&mh.dpu_ids, &mh.id).await
    }

    pub async fn create(
        mut self,
        dpu_machine_ids: &[MachineId],
        host_machine_id: &MachineId,
    ) -> (InstanceId, RpcInstance) {
        if self.config.tenant.is_none() {
            self.config.tenant = Some(self.tenant);
        }
        let instance_id: InstanceId = self
            .env
            .api
            .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
                instance_id: None,
                machine_id: host_machine_id.into(),
                instance_type_id: None,
                config: Some(self.config),
                metadata: self.metadata,
                allow_unhealthy_machine: false,
            }))
            .await
            .expect("Create instance failed.")
            .into_inner()
            .id
            .expect("Missing instance ID")
            .try_into()
            .unwrap();

        let instance = advance_created_instance_into_ready_state(
            self.env,
            &dpu_machine_ids
                .iter()
                .chain(self.unused_dpu_machine_ids.iter().collect::<Vec<_>>())
                .copied()
                .collect(),
            host_machine_id,
            instance_id,
        )
        .await;
        (instance_id, instance)
    }
}

pub async fn create_instance_with_ib_config(
    env: &TestEnv,
    mh: &ManagedHost,
    ib_config: rpc::forge::InstanceInfinibandConfig,
    network_segment_id: NetworkSegmentId,
) -> (InstanceId, RpcInstance) {
    TestInstance::new(env)
        .config(config_for_ib_config(ib_config, network_segment_id))
        .create_for_manged_host(mh)
        .await
}

pub fn single_interface_network_config(segment_id: NetworkSegmentId) -> rpc::InstanceNetworkConfig {
    rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(segment_id.into()),
            network_details: Some(NetworkDetails::SegmentId(segment_id.into())),
            device: None,
            device_instance: 0,
            virtual_function_id: None,
        }],
    }
}

pub fn interface_network_config_with_devices(
    segment_ids: &[NetworkSegmentId],
    device_locators: &[DeviceLocator],
) -> rpc::InstanceNetworkConfig {
    let interfaces = device_locators
        .iter()
        .zip(segment_ids)
        .map(|(dl, segment_id)| rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some((*segment_id).into()),
            network_details: Some(NetworkDetails::SegmentId((*segment_id).into())),
            device: Some(dl.device.clone()),
            device_instance: dl.device_instance as u32,
            virtual_function_id: None,
        })
        .collect();
    rpc::InstanceNetworkConfig { interfaces }
}

pub fn single_interface_network_config_with_vpc_prefix(
    prefix_id: rpc::Uuid,
) -> rpc::InstanceNetworkConfig {
    rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: None,
            network_details: Some(NetworkDetails::VpcPrefixId(prefix_id)),
            device: None,
            device_instance: 0u32,
            virtual_function_id: None,
        }],
    }
}

pub fn default_os_config() -> rpc::forge::OperatingSystem {
    rpc::forge::OperatingSystem {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData".to_string()),
        variant: Some(rpc::forge::operating_system::Variant::Ipxe(
            rpc::forge::IpxeOperatingSystem {
                ipxe_script: "SomeRandomiPxe".to_string(),
                user_data: Some("SomeRandomData".to_string()),
            },
        )),
    }
}

pub fn default_tenant_config() -> rpc::TenantConfig {
    rpc::TenantConfig {
        user_data: None,
        custom_ipxe: "".to_string(),
        phone_home_enabled: false,
        always_boot_with_custom_ipxe: false,
        tenant_organization_id: "Tenant1".to_string(),
        tenant_keyset_ids: vec![],
        hostname: None,
    }
}

pub fn config_for_ib_config(
    ib_config: rpc::forge::InstanceInfinibandConfig,
    network_segment_id: NetworkSegmentId,
) -> rpc::forge::InstanceConfig {
    rpc::forge::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(default_os_config()),
        network: Some(single_interface_network_config(network_segment_id)),
        infiniband: Some(ib_config),
        storage: None,
        network_security_group_id: None,
    }
}

pub async fn advance_created_instance_into_ready_state(
    env: &TestEnv,
    dpu_machine_ids: &Vec<MachineId>,
    host_machine_id: &MachineId,
    instance_id: InstanceId,
) -> RpcInstance {
    // Run network state machine handler here.
    env.run_network_segment_controller_iteration().await;

    // - zero run: state controller moves state to WaitingForNetworkSegmentToBeReady
    env.run_machine_state_controller_iteration().await;
    // - first run: state controller moves state to WaitingForNetworkConfig
    env.run_machine_state_controller_iteration().await;
    // - second run: state controller sets use_admin_network to false
    env.run_machine_state_controller_iteration().await;
    // - forge-dpu-agent gets an instance network to configure, reports it configured
    super::network_configured(env, dpu_machine_ids).await;
    // - simulate that the host's hardware is reported healthy
    super::simulate_hardware_health_report(
        env,
        host_machine_id,
        health_report::HealthReport::empty("hardware-health".to_string()),
    )
    .await;

    // - third run: state controller runs again, advances state to Ready
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        10,
        ManagedHostState::Assigned {
            instance_state: crate::model::machine::InstanceState::Ready,
        },
    )
    .await;

    // get the updated info with proper network config info added after the instance state is ready
    env.one_instance(instance_id).await
}

pub async fn delete_instance(
    env: &TestEnv,
    instance_id: InstanceId,
    dpu_machine_ids: &Vec<MachineId>,
    host_machine_id: &MachineId,
) {
    env.api
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance_id.into()),
            issue: None,
            is_repair_tenant: None,
        }))
        .await
        .expect("Delete instance failed.");

    // The instance should show up immediatly as terminating - even if the state handler didn't yet run
    let instance = env.one_instance(instance_id).await;
    assert_eq!(instance.status().tenant(), rpc::TenantState::Terminating);

    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        1,
        ManagedHostState::Assigned {
            instance_state: crate::model::machine::InstanceState::BootingWithDiscoveryImage {
                retry: crate::model::machine::RetryInfo { count: 0 },
            },
        },
    )
    .await;
    handle_delete_post_bootingwithdiscoveryimage(env, dpu_machine_ids, host_machine_id).await;

    assert!(
        env.find_instances(Some(instance_id.into()))
            .await
            .instances
            .is_empty()
    );

    // Run network state machine handler here.
    env.run_network_segment_controller_iteration().await;
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;
}

pub async fn handle_delete_post_bootingwithdiscoveryimage(
    env: &TestEnv,
    dpu_machine_ids: &Vec<MachineId>,
    host_machine_id: &MachineId,
) {
    let mut txn = env.pool.begin().await.unwrap();
    let machine = db::machine::find_one(
        &mut txn,
        host_machine_id,
        db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    db::machine::update_reboot_time(&machine, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    // Run state machine twice.
    // First DeletingManagedResource updates use_admin_network, transitions to WaitingForNetworkReconfig
    // Second to discover we are now in WaitingForNetworkReconfig
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        2,
        ManagedHostState::Assigned {
            instance_state: crate::model::machine::InstanceState::WaitingForNetworkReconfig,
        },
    )
    .await;

    // Apply switching back to admin network
    super::network_configured(env, dpu_machine_ids).await;

    if env.attestation_enabled {
        inject_machine_measurements(env, (*host_machine_id).into()).await;
    }

    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        3,
        ManagedHostState::WaitingForCleanup {
            cleanup_state: CleanupState::HostCleanup {
                boss_controller_id: None,
            },
        },
    )
    .await;

    let mut txn = env.pool.begin().await.unwrap();
    let machine = db::machine::find_one(
        &mut txn,
        host_machine_id,
        crate::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    db::machine::update_reboot_time(&machine, &mut txn)
        .await
        .unwrap();
    db::machine::update_cleanup_time(&machine, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        3,
        ManagedHostState::Validation {
            validation_state: ValidationState::MachineValidation {
                machine_validation: MachineValidatingState::MachineValidating {
                    context: "Cleanup".to_string(),
                    id: uuid::Uuid::default(),
                    completed: 1,
                    total: 1,
                    is_enabled: true,
                },
            },
        },
    )
    .await;

    let mut machine_validation_result = rpc::forge::MachineValidationResult {
        validation_id: None,
        name: "instance".to_string(),
        description: "desc".to_string(),
        command: "echo".to_string(),
        args: "test".to_string(),
        std_out: "".to_string(),
        std_err: "".to_string(),
        context: "Cleanup".to_string(),
        exit_code: 0,
        start_time: Some(Timestamp::from(SystemTime::now())),
        end_time: Some(Timestamp::from(SystemTime::now())),
        test_id: Some("instance".to_string()),
    };

    let response = forge_agent_control(env, host_machine_id.into()).await;
    let uuid = &response.data.unwrap().pair[1].value;

    machine_validation_result.validation_id = Some(rpc::Uuid {
        value: uuid.to_owned(),
    });
    persist_machine_validation_result(env, machine_validation_result.clone()).await;

    let mut txn = env.pool.begin().await.unwrap();
    db::machine::update_machine_validation_time(host_machine_id, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        3,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered {
                skip_reboot_wait: false,
            },
        },
    )
    .await;

    let mut txn = env.pool.begin().await.unwrap();
    let machine = db::machine::find_one(
        &mut txn,
        host_machine_id,
        crate::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    db::machine::update_reboot_time(&machine, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        3,
        ManagedHostState::Ready,
    )
    .await;
}

pub async fn update_instance_network_status_observation(
    dpu_id: &MachineId,
    obs: &InstanceNetworkStatusObservation,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) {
    let query = "UPDATE machines SET network_status_observation = jsonb_set(network_status_observation, ARRAY['instance_network_observation'], $1) WHERE id=$2";
    let _query_result = sqlx::query(query)
        .bind(sqlx::types::Json(obs))
        .bind(dpu_id.to_string())
        .execute(txn.deref_mut())
        .await
        .unwrap();
}
