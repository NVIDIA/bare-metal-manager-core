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

//use rpc::forge::NvlPartitionSearchFilter;
use ::rpc::machine_discovery::Gpu;
use common::api_fixtures::create_managed_host_with_hardware_info_template;
use common::api_fixtures::instance::{
    create_instance_with_nvlink_config, update_instance_nvlink_config,
};
use common::api_fixtures::managed_host::HardwareInfoTemplate;
use common::api_fixtures::nvl_logical_partition::create_nvl_logical_partition;
use model::instance::config::nvlink::InstanceNvLinkConfig;
use rpc::forge::TenantState;
use rpc::forge::forge_server::Forge;

// model::instance::config::nvlink::{InstanceNvLinkConfig, InstanceNvLinkGpuConfig},
use crate::tests::common;
use crate::tests::common::api_fixtures::TestEnvOverrides;
use crate::tests::common::api_fixtures::nvl_logical_partition::NvlLogicalPartitionFixture;

#[crate::sqlx_test]
async fn test_create_instance_with_nvl_config(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    if let Some(nvlink_config) = config.nvlink_config.as_mut() {
        nvlink_config.enabled = true;
    }

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config),
    )
    .await;

    let segment_id = env.create_vpc_and_tenant_segment().await;

    let NvlLogicalPartitionFixture {
        id: logical_partition_id,
        logical_partition: _logical_partition,
    } = create_nvl_logical_partition(&env, "test_partition".to_string()).await;

    let request_logical_ids =
        tonic::Request::new(rpc::forge::NvLinkLogicalPartitionSearchFilter { name: None });

    let logical_ids_list = env
        .api
        .find_nv_link_logical_partition_ids(request_logical_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(logical_ids_list.partition_ids.len(), 1);

    let mh = create_managed_host_with_hardware_info_template(
        &env,
        HardwareInfoTemplate::Custom(
            crate::tests::common::api_fixtures::host::GB200_COMPUTE_TRAY_1_INFO_JSON,
        ),
    )
    .await;
    let machine = mh.host().rpc_machine().await;

    assert_eq!(&machine.state, "Ready");
    let discovery_info = machine.discovery_info.as_ref().unwrap();

    assert_eq!(discovery_info.gpus.len(), 4);

    let gpus: Vec<Gpu> = discovery_info.gpus.to_vec();

    println!("{gpus:?}");

    let mut nvl_config = rpc::forge::InstanceNvLinkConfig {
        gpu_configs: gpus
            .iter()
            .filter_map(|gpu| {
                gpu.platform_info.as_ref().map(|platform_info| {
                    rpc::forge::InstanceNvLinkGpuConfig {
                        device_instance: platform_info.module_id,
                        logical_partition_id: Some(logical_partition_id),
                    }
                })
            })
            .collect(),
    };

    let (tinstance, instance) =
        create_instance_with_nvlink_config(&env, &mh, nvl_config.clone(), segment_id).await;

    let machine = mh.host().rpc_machine().await;
    assert_eq!(&machine.state, "Assigned/Ready");

    let check_instance = tinstance.rpc_instance().await;
    assert_eq!(instance.machine_id(), mh.id);
    assert_eq!(instance.status().tenant(), rpc::TenantState::Ready);
    assert_eq!(instance, check_instance);

    // test getting all ids
    let request_all = tonic::Request::new(rpc::forge::NvLinkPartitionSearchFilter {
        name: None,
        tenant_organization_id: None,
    });

    let ids_all = env
        .api
        .find_nv_link_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.partition_ids.len(), 1);

    nvl_config.gpu_configs.iter_mut().for_each(|gpu| {
        gpu.logical_partition_id = None;
    });
    let mut txn = pool.begin().await.unwrap();
    update_instance_nvlink_config(
        &mut txn,
        &instance.id(),
        &InstanceNvLinkConfig::try_from(nvl_config).unwrap(),
    )
    .await;
    txn.commit().await.unwrap();

    // Run twice to record observation.
    env.run_nvl_partition_monitor_iteration().await;
    env.run_nvl_partition_monitor_iteration().await;

    let request_all = tonic::Request::new(rpc::forge::NvLinkPartitionSearchFilter {
        name: None,
        tenant_organization_id: None,
    });

    let ids_all = env
        .api
        .find_nv_link_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.partition_ids.len(), 0);

    // delete logical partition. As no physical partitions are present, we expect logical partition to be
    // fully deleted after we run one iteration of monitor
    env.api
        .delete_nv_link_logical_partition(tonic::Request::new(
            rpc::forge::NvLinkLogicalPartitionDeletionRequest {
                id: Some(logical_partition_id),
            },
        ))
        .await
        .expect("expect deletion to succeed");

    let request_partitions = tonic::Request::new(rpc::forge::NvLinkLogicalPartitionsByIdsRequest {
        partition_ids: logical_ids_list.partition_ids,
        include_history: false,
    });

    let logical_partition_list = env
        .api
        .find_nv_link_logical_partitions_by_ids(request_partitions)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(logical_partition_list.partitions.len(), 1);

    let clone3 = logical_partition_list.partitions[0].clone();
    assert_eq!(logical_partition_id, clone3.id.unwrap());
    assert_eq!(
        _logical_partition.config.unwrap().metadata.unwrap().name,
        clone3.config.unwrap().metadata.unwrap().name
    );
    let status = clone3.status.unwrap();
    assert_eq!(
        TenantState::try_from(status.state).unwrap(),
        TenantState::Terminating
    );

    env.run_nvl_partition_monitor_iteration().await;
    let request_all =
        tonic::Request::new(rpc::forge::NvLinkLogicalPartitionSearchFilter { name: None });

    let logical_partition_list = env
        .api
        .find_nv_link_logical_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(logical_partition_list.partition_ids.len(), 0);
}

#[crate::sqlx_test]
async fn test_with_multiple_nv_link_logical_partitions(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    if let Some(nvlink_config) = config.nvlink_config.as_mut() {
        nvlink_config.enabled = true;
    }

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config),
    )
    .await;

    let segment_id = env.create_vpc_and_tenant_segment().await;

    // create two nvlink logical partitions
    let NvlLogicalPartitionFixture {
        id: logical_partition_id1,
        logical_partition: _logical_partition1,
    } = create_nvl_logical_partition(&env, "test_partition1".to_string()).await;
    let NvlLogicalPartitionFixture {
        id: logical_partition_id2,
        logical_partition: _logical_partition2,
    } = create_nvl_logical_partition(&env, "test_partition2".to_string()).await;

    let request_logical_ids =
        tonic::Request::new(rpc::forge::NvLinkLogicalPartitionSearchFilter { name: None });

    let logical_ids_list = env
        .api
        .find_nv_link_logical_partition_ids(request_logical_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(logical_ids_list.partition_ids.len(), 2);

    let mh = create_managed_host_with_hardware_info_template(
        &env,
        HardwareInfoTemplate::Custom(
            crate::tests::common::api_fixtures::host::GB200_COMPUTE_TRAY_1_INFO_JSON,
        ),
    )
    .await;
    let machine = mh.host().rpc_machine().await;

    assert_eq!(&machine.state, "Ready");
    let discovery_info = machine.discovery_info.as_ref().unwrap();

    assert_eq!(discovery_info.gpus.len(), 4);

    let gpus: Vec<Gpu> = discovery_info.gpus.to_vec();

    println!("{gpus:?}");

    let nvl_config = rpc::forge::InstanceNvLinkConfig {
        gpu_configs: gpus
            .iter()
            .filter_map(|gpu| {
                gpu.platform_info.as_ref().map(|platform_info| {
                    let nvl_logical_partition_id = if platform_info.module_id > 2 {
                        Some(logical_partition_id2)
                    } else {
                        Some(logical_partition_id1)
                    };
                    rpc::forge::InstanceNvLinkGpuConfig {
                        device_instance: platform_info.module_id,
                        logical_partition_id: nvl_logical_partition_id,
                    }
                })
            })
            .collect(),
    };

    let (tinstance, instance) =
        create_instance_with_nvlink_config(&env, &mh, nvl_config.clone(), segment_id).await;

    let machine = mh.host().rpc_machine().await;
    assert_eq!(&machine.state, "Assigned/Ready");

    let check_instance = tinstance.rpc_instance().await;
    assert_eq!(instance.machine_id(), mh.id);
    assert_eq!(instance.status().tenant(), rpc::TenantState::Ready);
    assert_eq!(instance, check_instance);

    env.run_nvl_partition_monitor_iteration().await;

    // get all nvlink physical partition ids
    let request_all = tonic::Request::new(rpc::forge::NvLinkPartitionSearchFilter {
        name: None,
        tenant_organization_id: None,
    });

    // if partition_monitor did its job, we expect two nvlink partitions to be created
    let ids_all = env
        .api
        .find_nv_link_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.partition_ids.len(), 2);
}

#[crate::sqlx_test]
async fn test_create_instances_with_nvl_configs_same_logical_partition_different_domains(
    pool: sqlx::PgPool,
) {
    let mut config = common::api_fixtures::get_config();
    if let Some(nvlink_config) = config.nvlink_config.as_mut() {
        nvlink_config.enabled = true;
    }

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config),
    )
    .await;

    let segment_id = env.create_vpc_and_tenant_segment().await;

    let NvlLogicalPartitionFixture {
        id: logical_partition_id,
        logical_partition: _logical_partition,
    } = create_nvl_logical_partition(&env, "test_partition".to_string()).await;

    let request_logical_ids =
        tonic::Request::new(rpc::forge::NvLinkLogicalPartitionSearchFilter { name: None });

    let logical_ids_list = env
        .api
        .find_nv_link_logical_partition_ids(request_logical_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(logical_ids_list.partition_ids.len(), 1);

    let mh1 = create_managed_host_with_hardware_info_template(
        &env,
        HardwareInfoTemplate::Custom(
            crate::tests::common::api_fixtures::host::GB200_COMPUTE_TRAY_1_INFO_JSON,
        ),
    )
    .await;
    let machine1 = mh1.host().rpc_machine().await;
    let m2 = create_managed_host_with_hardware_info_template(
        &env,
        HardwareInfoTemplate::Custom(
            crate::tests::common::api_fixtures::host::GB200_COMPUTE_TRAY_2_INFO_JSON,
        ),
    )
    .await;
    let machine2 = m2.host().rpc_machine().await;

    assert_eq!(&machine1.state, "Ready");
    assert_eq!(&machine2.state, "Ready");
    let discovery_info1 = machine1.discovery_info.as_ref().unwrap();
    let discovery_info2 = machine2.discovery_info.as_ref().unwrap();
    assert_eq!(discovery_info1.gpus.len(), 4);
    assert_eq!(discovery_info2.gpus.len(), 4);
    let gpus1: Vec<Gpu> = discovery_info1.gpus.to_vec();
    let gpus2: Vec<Gpu> = discovery_info2.gpus.to_vec();

    let mut nvl_config1 = rpc::forge::InstanceNvLinkConfig {
        gpu_configs: gpus1
            .iter()
            .filter_map(|gpu| {
                gpu.platform_info.as_ref().map(|platform_info| {
                    rpc::forge::InstanceNvLinkGpuConfig {
                        device_instance: platform_info.module_id,
                        logical_partition_id: Some(logical_partition_id),
                    }
                })
            })
            .collect(),
    };

    let mut nvl_config2 = rpc::forge::InstanceNvLinkConfig {
        gpu_configs: gpus2
            .iter()
            .filter_map(|gpu| {
                gpu.platform_info.as_ref().map(|platform_info| {
                    rpc::forge::InstanceNvLinkGpuConfig {
                        device_instance: platform_info.module_id,
                        logical_partition_id: Some(logical_partition_id),
                    }
                })
            })
            .collect(),
    };

    let (tinstance1, instance1) =
        create_instance_with_nvlink_config(&env, &mh1, nvl_config1.clone(), segment_id).await;

    let (tinstance2, instance2) =
        create_instance_with_nvlink_config(&env, &m2, nvl_config2.clone(), segment_id).await;

    let machine1 = mh1.host().rpc_machine().await;
    let machine2 = m2.host().rpc_machine().await;
    assert_eq!(&machine1.state, "Assigned/Ready");
    assert_eq!(&machine2.state, "Assigned/Ready");

    let check_instance1 = tinstance1.rpc_instance().await;
    let check_instance2 = tinstance2.rpc_instance().await;
    assert_eq!(instance1.status().tenant(), rpc::TenantState::Ready);
    assert_eq!(instance2.status().tenant(), rpc::TenantState::Ready);
    assert_eq!(instance1, check_instance1);
    assert_eq!(instance2, check_instance2);

    // test getting all ids
    let request_all = tonic::Request::new(rpc::forge::NvLinkPartitionSearchFilter {
        name: None,
        tenant_organization_id: None,
    });

    // if partition_monitor did its job, we expect two new nvlink partitions to be created
    let ids_all = env
        .api
        .find_nv_link_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.partition_ids.len(), 2);

    nvl_config1.gpu_configs.iter_mut().for_each(|gpu| {
        gpu.logical_partition_id = None;
    });
    nvl_config2.gpu_configs.iter_mut().for_each(|gpu| {
        gpu.logical_partition_id = None;
    });
    let mut txn = pool.begin().await.unwrap();
    // add or remove instance_gpus_from_logical_partition doesn't seem to update db :(
    // till we root cause that, force direct db update from here
    update_instance_nvlink_config(
        &mut txn,
        &instance1.id(),
        &InstanceNvLinkConfig::try_from(nvl_config1).unwrap(),
    )
    .await;
    update_instance_nvlink_config(
        &mut txn,
        &instance2.id(),
        &InstanceNvLinkConfig::try_from(nvl_config2).unwrap(),
    )
    .await;
    txn.commit().await.unwrap();

    env.run_nvl_partition_monitor_iteration().await;
    env.run_nvl_partition_monitor_iteration().await;

    let request_all = tonic::Request::new(rpc::forge::NvLinkPartitionSearchFilter {
        name: None,
        tenant_organization_id: None,
    });

    // if partition monitor did its job after we removed nvlink conifg from an instance, we expect
    // the nvlink partition to be deleted
    let ids_all = env
        .api
        .find_nv_link_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.partition_ids.len(), 0);

    // delete logical partition. As no physical partitions are present, we expect logical partition to be
    // fully deleted after we run one iteration of monitor
    env.api
        .delete_nv_link_logical_partition(tonic::Request::new(
            rpc::forge::NvLinkLogicalPartitionDeletionRequest {
                id: Some(logical_partition_id),
            },
        ))
        .await
        .expect("expect deletion to succeed");

    let request_partitions = tonic::Request::new(rpc::forge::NvLinkLogicalPartitionsByIdsRequest {
        partition_ids: logical_ids_list.partition_ids,
        include_history: false,
    });

    let logical_partition_list = env
        .api
        .find_nv_link_logical_partitions_by_ids(request_partitions)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(logical_partition_list.partitions.len(), 1);

    let clone3 = logical_partition_list.partitions[0].clone();
    assert_eq!(logical_partition_id, clone3.id.unwrap());
    assert_eq!(
        _logical_partition.config.unwrap().metadata.unwrap().name,
        clone3.config.unwrap().metadata.unwrap().name
    );
    let status = clone3.status.unwrap();
    assert_eq!(
        TenantState::try_from(status.state).unwrap(),
        TenantState::Terminating
    );

    env.run_nvl_partition_monitor_iteration().await;
    let request_all =
        tonic::Request::new(rpc::forge::NvLinkLogicalPartitionSearchFilter { name: None });

    let logical_partition_list = env
        .api
        .find_nv_link_logical_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(logical_partition_list.partition_ids.len(), 0);
}

#[crate::sqlx_test]
async fn test_update_instance_with_nvl_config(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    if let Some(nvlink_config) = config.nvlink_config.as_mut() {
        nvlink_config.enabled = true;
    }

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config),
    )
    .await;

    let segment_id = env.create_vpc_and_tenant_segment().await;

    let NvlLogicalPartitionFixture {
        id: logical_partition_id,
        logical_partition: _logical_partition,
    } = create_nvl_logical_partition(&env, "test_partition".to_string()).await;

    let request_logical_ids =
        tonic::Request::new(rpc::forge::NvLinkLogicalPartitionSearchFilter { name: None });

    let logical_ids_list = env
        .api
        .find_nv_link_logical_partition_ids(request_logical_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(logical_ids_list.partition_ids.len(), 1);

    let mh = create_managed_host_with_hardware_info_template(
        &env,
        HardwareInfoTemplate::Custom(
            crate::tests::common::api_fixtures::host::GB200_COMPUTE_TRAY_1_INFO_JSON,
        ),
    )
    .await;
    let machine = mh.host().rpc_machine().await;

    assert_eq!(&machine.state, "Ready");
    let discovery_info = machine.discovery_info.as_ref().unwrap();

    assert_eq!(discovery_info.gpus.len(), 4);

    let gpus: Vec<Gpu> = discovery_info.gpus.to_vec();

    println!("{gpus:?}");

    let nvl_config = rpc::forge::InstanceNvLinkConfig {
        gpu_configs: gpus
            .iter()
            .filter_map(|gpu| {
                gpu.platform_info.as_ref().map(|platform_info| {
                    rpc::forge::InstanceNvLinkGpuConfig {
                        device_instance: platform_info.module_id,
                        logical_partition_id: None,
                    }
                })
            })
            .collect(),
    };

    let (tinstance, instance) =
        create_instance_with_nvlink_config(&env, &mh, nvl_config.clone(), segment_id).await;

    let machine = mh.host().rpc_machine().await;
    assert_eq!(&machine.state, "Assigned/Ready");

    let check_instance = tinstance.rpc_instance().await;
    assert_eq!(instance.machine_id(), mh.id);
    assert_eq!(instance.status().tenant(), rpc::TenantState::Ready);
    assert_eq!(instance, check_instance);

    env.run_nvl_partition_monitor_iteration().await;

    let new_nvl_config = rpc::forge::InstanceNvLinkConfig {
        gpu_configs: gpus
            .iter()
            .filter_map(|gpu| {
                gpu.platform_info.as_ref().map(|platform_info| {
                    rpc::forge::InstanceNvLinkGpuConfig {
                        device_instance: platform_info.module_id,
                        logical_partition_id: Some(logical_partition_id),
                    }
                })
            })
            .collect(),
    };

    // Update the instance with the new NVL config
    let mut new_config = instance.config().inner().clone();
    new_config.nvlink = Some(new_nvl_config.clone());
    let instance = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: instance.id().into(),
                if_version_match: None,
                config: Some(new_config.clone()),
                metadata: Some(instance.metadata().clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let instance_status = instance.status.as_ref().unwrap();
    assert_eq!(instance_status.configs_synced(), rpc::SyncState::Pending);
    assert_eq!(
        instance_status.tenant.as_ref().unwrap().state(),
        rpc::TenantState::Configuring
    );

    env.run_nvl_partition_monitor_iteration().await;
    env.run_nvl_partition_monitor_iteration().await;

    let instance = env.one_instance(instance.id.unwrap()).await;
    let instance_status = instance.status();
    let _nvl_status = instance_status.inner().nvlink.as_ref().unwrap();
    assert_eq!(_nvl_status.configs_synced(), rpc::SyncState::Synced);

    // test getting all ids
    let request_all = tonic::Request::new(rpc::forge::NvLinkPartitionSearchFilter {
        name: None,
        tenant_organization_id: None,
    });

    // if partition_monitor did its job, we expect one new nvlink partition to be created
    let ids_all = env
        .api
        .find_nv_link_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.partition_ids.len(), 1);

    let new_nvl_config = rpc::forge::InstanceNvLinkConfig {
        gpu_configs: gpus
            .iter()
            .filter_map(|gpu| {
                gpu.platform_info.as_ref().map(|platform_info| {
                    let lp_id = if platform_info.module_id > 2 {
                        None
                    } else {
                        Some(logical_partition_id)
                    };

                    rpc::forge::InstanceNvLinkGpuConfig {
                        device_instance: platform_info.module_id,
                        logical_partition_id: lp_id,
                    }
                })
            })
            .collect(),
    };

    let mut new_config = instance.config().inner().clone();
    new_config.nvlink = Some(new_nvl_config.clone());

    let instance = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: instance.id().into(),
                if_version_match: None,
                config: Some(new_config.clone()),
                metadata: Some(instance.metadata().clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let instance_status = instance.status.as_ref().unwrap();
    assert_eq!(instance_status.configs_synced(), rpc::SyncState::Pending);
    assert_eq!(
        instance_status.tenant.as_ref().unwrap().state(),
        rpc::TenantState::Configuring
    );

    let applied_nvl_config = instance.config.as_ref().unwrap().nvlink.as_ref().unwrap();

    assert_eq!(*applied_nvl_config, new_nvl_config);

    let nvl_status = instance_status.nvlink.as_ref().unwrap();
    assert_eq!(nvl_status.configs_synced(), rpc::SyncState::Pending);

    env.run_nvl_partition_monitor_iteration().await;
    env.run_nvl_partition_monitor_iteration().await;

    let instance = env.one_instance(instance.id.unwrap()).await;
    let instance_status = instance.status();

    let _nvl_status = instance_status.inner().nvlink.as_ref().unwrap();
    assert_eq!(_nvl_status.configs_synced(), rpc::SyncState::Synced);
}

#[crate::sqlx_test]
async fn test_instance_delete_with_nvl_config(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    if let Some(nvlink_config) = config.nvlink_config.as_mut() {
        nvlink_config.enabled = true;
    }

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config),
    )
    .await;

    let segment_id = env.create_vpc_and_tenant_segment().await;

    let NvlLogicalPartitionFixture {
        id: logical_partition_id,
        logical_partition: _logical_partition,
    } = create_nvl_logical_partition(&env, "test_partition".to_string()).await;

    let request_logical_ids =
        tonic::Request::new(rpc::forge::NvLinkLogicalPartitionSearchFilter { name: None });

    let logical_ids_list = env
        .api
        .find_nv_link_logical_partition_ids(request_logical_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(logical_ids_list.partition_ids.len(), 1);

    let mh = create_managed_host_with_hardware_info_template(
        &env,
        HardwareInfoTemplate::Custom(
            crate::tests::common::api_fixtures::host::GB200_COMPUTE_TRAY_1_INFO_JSON,
        ),
    )
    .await;
    let machine = mh.host().rpc_machine().await;

    assert_eq!(&machine.state, "Ready");
    let discovery_info = machine.discovery_info.as_ref().unwrap();

    assert_eq!(discovery_info.gpus.len(), 4);

    let gpus: Vec<Gpu> = discovery_info.gpus.to_vec();

    println!("{gpus:?}");

    let nvl_config = rpc::forge::InstanceNvLinkConfig {
        gpu_configs: gpus
            .iter()
            .filter_map(|gpu| {
                gpu.platform_info.as_ref().map(|platform_info| {
                    rpc::forge::InstanceNvLinkGpuConfig {
                        device_instance: platform_info.module_id,
                        logical_partition_id: Some(logical_partition_id),
                    }
                })
            })
            .collect(),
    };

    let (tinstance, instance) =
        create_instance_with_nvlink_config(&env, &mh, nvl_config.clone(), segment_id).await;

    let machine = mh.host().rpc_machine().await;
    assert_eq!(&machine.state, "Assigned/Ready");

    let check_instance = tinstance.rpc_instance().await;
    assert_eq!(instance.machine_id(), mh.id);
    assert_eq!(instance.status().tenant(), rpc::TenantState::Ready);
    assert_eq!(instance, check_instance);

    // test getting all ids
    let request_all = tonic::Request::new(rpc::forge::NvLinkPartitionSearchFilter {
        name: None,
        tenant_organization_id: None,
    });
    let ids_all = env
        .api
        .find_nv_link_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.partition_ids.len(), 1);

    // delete the instance. This should force the partition monitor to remove gpus
    // from that instance from physical nvlink partition
    tinstance.delete().await;

    // Run twice to record observation.
    env.run_nvl_partition_monitor_iteration().await;
    env.run_nvl_partition_monitor_iteration().await;

    let request_all = tonic::Request::new(rpc::forge::NvLinkPartitionSearchFilter {
        name: None,
        tenant_organization_id: None,
    });

    let ids_all = env
        .api
        .find_nv_link_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.partition_ids.len(), 0);
}

#[crate::sqlx_test]
async fn test_update_instance_with_nvl_config_new_logical_partition(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    if let Some(nvlink_config) = config.nvlink_config.as_mut() {
        nvlink_config.enabled = true;
    }

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config),
    )
    .await;

    let segment_id = env.create_vpc_and_tenant_segment().await;

    let NvlLogicalPartitionFixture {
        id: logical_partition_id1,
        logical_partition: _logical_partition1,
    } = create_nvl_logical_partition(&env, "test_partition1".to_string()).await;
    let NvlLogicalPartitionFixture {
        id: logical_partition_id2,
        logical_partition: _logical_partition2,
    } = create_nvl_logical_partition(&env, "test_partition2".to_string()).await;

    let request_logical_ids =
        tonic::Request::new(rpc::forge::NvLinkLogicalPartitionSearchFilter { name: None });

    let logical_ids_list = env
        .api
        .find_nv_link_logical_partition_ids(request_logical_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(logical_ids_list.partition_ids.len(), 2);

    let mh = create_managed_host_with_hardware_info_template(
        &env,
        HardwareInfoTemplate::Custom(
            crate::tests::common::api_fixtures::host::GB200_COMPUTE_TRAY_1_INFO_JSON,
        ),
    )
    .await;
    let machine = mh.host().rpc_machine().await;

    assert_eq!(&machine.state, "Ready");
    let discovery_info = machine.discovery_info.as_ref().unwrap();

    assert_eq!(discovery_info.gpus.len(), 4);

    let gpus: Vec<Gpu> = discovery_info.gpus.to_vec();

    println!("{gpus:?}");

    let nvl_config = rpc::forge::InstanceNvLinkConfig {
        gpu_configs: gpus
            .iter()
            .filter_map(|gpu| {
                gpu.platform_info.as_ref().map(|platform_info| {
                    rpc::forge::InstanceNvLinkGpuConfig {
                        device_instance: platform_info.module_id,
                        logical_partition_id: Some(logical_partition_id1),
                    }
                })
            })
            .collect(),
    };

    let (tinstance, instance) =
        create_instance_with_nvlink_config(&env, &mh, nvl_config.clone(), segment_id).await;

    let machine = mh.host().rpc_machine().await;
    assert_eq!(&machine.state, "Assigned/Ready");

    let check_instance = tinstance.rpc_instance().await;
    assert_eq!(instance.machine_id(), mh.id);
    assert_eq!(instance.status().tenant(), rpc::TenantState::Ready);
    assert_eq!(instance, check_instance);

    env.run_nvl_partition_monitor_iteration().await;

    // test getting all ids
    let request_all = tonic::Request::new(rpc::forge::NvLinkPartitionSearchFilter {
        name: None,
        tenant_organization_id: None,
    });

    let ids_all = env
        .api
        .find_nv_link_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.partition_ids.len(), 1);

    let new_nvl_config = rpc::forge::InstanceNvLinkConfig {
        gpu_configs: gpus
            .iter()
            .filter_map(|gpu| {
                gpu.platform_info.as_ref().map(|platform_info| {
                    rpc::forge::InstanceNvLinkGpuConfig {
                        device_instance: platform_info.module_id,
                        logical_partition_id: Some(logical_partition_id2),
                    }
                })
            })
            .collect(),
    };

    let mut new_config = instance.config().inner().clone();
    new_config.nvlink = Some(new_nvl_config.clone());

    // This should fail.
    let err = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: instance.id().into(),
                if_version_match: None,
                config: Some(new_config.clone()),
                metadata: Some(instance.metadata().clone()),
            },
        ))
        .await
        .expect_err("This should fail");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[crate::sqlx_test]
async fn test_create_instance_with_nvl_config_remove_from_default_partition(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    if let Some(nvlink_config) = config.nvlink_config.as_mut() {
        nvlink_config.enabled = true;
    }

    let mut test_overrides = TestEnvOverrides::with_config(config);
    test_overrides.nmxm_default_partition = Some(true);

    let env =
        common::api_fixtures::create_test_env_with_overrides(pool.clone(), test_overrides).await;

    let segment_id = env.create_vpc_and_tenant_segment().await;

    let NvlLogicalPartitionFixture {
        id: logical_partition_id,
        logical_partition: _logical_partition,
    } = create_nvl_logical_partition(&env, "test_partition".to_string()).await;

    let request_logical_ids =
        tonic::Request::new(rpc::forge::NvLinkLogicalPartitionSearchFilter { name: None });

    let logical_ids_list = env
        .api
        .find_nv_link_logical_partition_ids(request_logical_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(logical_ids_list.partition_ids.len(), 1);

    let mh = create_managed_host_with_hardware_info_template(
        &env,
        HardwareInfoTemplate::Custom(
            crate::tests::common::api_fixtures::host::GB200_COMPUTE_TRAY_1_INFO_JSON,
        ),
    )
    .await;
    let machine = mh.host().rpc_machine().await;

    assert_eq!(&machine.state, "Ready");
    let discovery_info = machine.discovery_info.as_ref().unwrap();

    assert_eq!(discovery_info.gpus.len(), 4);

    // There should be no partitions in the DB, but one in NMX-M
    let request_all = tonic::Request::new(rpc::forge::NvLinkPartitionSearchFilter {
        name: None,
        tenant_organization_id: None,
    });
    let ids_all = env
        .api
        .find_nv_link_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.partition_ids.len(), 0);

    let nmxm_sim_client = env
        .nmxm_sim
        .create_client("localhost:4010", None)
        .await
        .unwrap();
    let nmx_m_partitions = nmxm_sim_client.get_partitions_list().await.unwrap();
    assert_eq!(nmx_m_partitions.len(), 1);
    assert_eq!(nmx_m_partitions[0].partition_id, 32766);
    let members = match nmx_m_partitions[0].members.as_ref() {
        libnmxm::nmxm_model::PartitionMembers::Ids(ids) => ids,
        _ => panic!("Expected IDs partition members"),
    };
    assert_eq!(members.len(), 12);

    let gpus: Vec<Gpu> = discovery_info.gpus.to_vec();
    println!("{gpus:?}");

    let nvl_config = rpc::forge::InstanceNvLinkConfig {
        gpu_configs: gpus
            .iter()
            .filter_map(|gpu| {
                gpu.platform_info.as_ref().map(|platform_info| {
                    rpc::forge::InstanceNvLinkGpuConfig {
                        device_instance: platform_info.module_id,
                        logical_partition_id: Some(logical_partition_id),
                    }
                })
            })
            .collect(),
    };

    let (tinstance, instance) =
        create_instance_with_nvlink_config(&env, &mh, nvl_config.clone(), segment_id).await;

    let machine = mh.host().rpc_machine().await;
    assert_eq!(&machine.state, "Assigned/Ready");

    let check_instance = tinstance.rpc_instance().await;
    assert_eq!(instance.machine_id(), mh.id);
    assert_eq!(instance.status().tenant(), rpc::TenantState::Ready);
    assert_eq!(instance, check_instance);

    env.run_nvl_partition_monitor_iteration().await;

    let request_all = tonic::Request::new(rpc::forge::NvLinkPartitionSearchFilter {
        name: None,
        tenant_organization_id: None,
    });
    let ids_all = env
        .api
        .find_nv_link_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.partition_ids.len(), 1);

    // Should be two partitions in NMX-M, one for the default partition and one for the carbide-created one
    let nmx_m_partitions = nmxm_sim_client.get_partitions_list().await.unwrap();
    assert_eq!(nmx_m_partitions.len(), 2);
    let default_partition = nmx_m_partitions
        .iter()
        .find(|p| p.partition_id == 32766)
        .unwrap();
    let members = match default_partition.members.as_ref() {
        libnmxm::nmxm_model::PartitionMembers::Ids(ids) => ids,
        _ => panic!("Expected IDs partition members"),
    };
    assert_eq!(members.len(), 8);
}
