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

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use ::rpc::forge::forge_server::Forge;
use ::rpc::forge::{
    AdminForceDeleteMachineRequest, IbPartitionStatus, InstancesByIdsRequest, TenantState,
};
use carbide_uuid::infiniband::IBPartitionId;
use carbide_uuid::machine::{MachineId, MachineType};
use common::api_fixtures::dpu::create_dpu_machine;
use common::api_fixtures::host::host_discover_dhcp;
use common::api_fixtures::ib_partition::{DEFAULT_TENANT, create_ib_partition};
use common::api_fixtures::instance::create_instance_with_ib_config;
use common::api_fixtures::tpm_attestation::EK_CERT_SERIALIZED;
use common::api_fixtures::{
    TestEnv, TestEnvOverrides, create_managed_host, create_managed_host_multi_dpu, create_test_env,
    get_instance_type_fixture_id,
};
use model::hardware_info::TpmEkCertificate;
use model::ib::DEFAULT_IB_FABRIC_NAME;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{InstanceState, ManagedHostState};
use sqlx::{PgConnection, Row};
use tonic::Request;

use crate::api::Api;
use crate::attestation as attest;
use crate::cfg::file::IBFabricConfig;
use crate::ib::{self, IBFabricManager};
use crate::tests::common;

async fn get_partition_status(api: &Api, ib_partition_id: IBPartitionId) -> IbPartitionStatus {
    let segment = api
        .find_ib_partitions_by_ids(Request::new(rpc::forge::IbPartitionsByIdsRequest {
            ib_partition_ids: vec![ib_partition_id],
            include_history: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .ib_partitions
        .remove(0);

    segment.status.unwrap()
}

#[crate::sqlx_test]
async fn test_admin_force_delete_dpu_only(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine =
        db::machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();
    assert!(
        !db::machine_state_history::find_by_machine_ids(&mut txn, &[dpu_machine_id])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        !db::machine_topology::find_by_machine_ids(&mut txn, &[dpu_machine_id])
            .await
            .unwrap()
            .is_empty()
    );

    let host = db::machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .unwrap();

    txn.rollback().await.unwrap();

    let response = force_delete(&env, &dpu_machine_id).await;
    validate_delete_response(&response, Some(&host.id), &dpu_machine_id);
    assert_eq!(
        response.dpu_machine_interface_id,
        dpu_machine.interfaces[0].id.to_string()
    );

    assert!(response.all_done, "DPU must be deleted");

    // Validate that the DPU is gone
    validate_machine_deletion(&env, &dpu_machine_id, None).await;
}

#[crate::sqlx_test]
async fn test_admin_force_delete_dpu_and_host_by_dpu_machine_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await.into();

    let response = force_delete(&env, &dpu_machine_id).await;
    validate_delete_response(&response, Some(&host_machine_id), &dpu_machine_id);
    assert!(response.all_done, "Host must be deleted");

    for id in [host_machine_id, dpu_machine_id] {
        validate_machine_deletion(&env, &id, None).await;
    }
}

async fn is_ek_cert_status_entry_present(txn: &mut PgConnection) -> bool {
    let query = "SELECT COUNT(1)::integer from ek_cert_verification_status;";
    let all_ek_cert_status_count: i32 = sqlx::query(query)
        .fetch_one(txn)
        .await
        .expect("Could not get ek cert statuses")
        .try_get("count")
        .expect("Could not get ek cert status count");

    all_ek_cert_status_count > 0
}

#[crate::sqlx_test]
async fn test_admin_force_delete_dpu_and_host_by_host_machine_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await.into();

    let bmc_addrs = vec![
        IpAddr::from_str(
            env.find_machine(host_machine_id)
                .await
                .first()
                .unwrap()
                .bmc_info
                .as_ref()
                .unwrap()
                .ip
                .as_ref()
                .unwrap(),
        )
        .unwrap(),
        IpAddr::from_str(
            env.find_machine(dpu_machine_id)
                .await
                .first()
                .unwrap()
                .bmc_info
                .as_ref()
                .unwrap()
                .ip
                .as_ref()
                .unwrap(),
        )
        .unwrap(),
    ];

    let mut txn = env.pool.begin().await.unwrap();

    // create entry in ek_cert_verification_status table
    let ek_cert = TpmEkCertificate::from(EK_CERT_SERIALIZED.to_vec());

    attest::match_insert_new_ek_cert_status_against_ca(&mut txn, &ek_cert, &host_machine_id)
        .await
        .expect("Could not insert EK status");

    // Fake some explored endpoints
    for addr in &bmc_addrs {
        db::explored_endpoints::insert(*addr, &Default::default(), false, &mut txn)
            .await
            .unwrap();
    }

    assert!(
        !db::explored_endpoints::find_all_by_ip(bmc_addrs[0], &mut txn)
            .await
            .unwrap()
            .is_empty()
    );

    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    assert!(
        is_ek_cert_status_entry_present(&mut txn).await,
        "FAILURE: EK cert status entry should have been created"
    );

    let response = force_delete(&env, &host_machine_id).await;
    validate_delete_response(&response, Some(&host_machine_id), &dpu_machine_id);

    assert!(env.find_machine(host_machine_id).await.is_empty());
    assert!(env.find_machine(dpu_machine_id).await.is_empty());

    assert!(response.all_done, "Host and DPU must be deleted");
    assert!(
        !is_ek_cert_status_entry_present(&mut txn).await,
        "FAILURE: EK cert status entry should have been deleted"
    );

    // Everything should be gone now
    for id in [host_machine_id, dpu_machine_id] {
        validate_machine_deletion(&env, &id, Some(&bmc_addrs)).await;
    }
}

#[crate::sqlx_test]
async fn test_admin_force_delete_dpu_and_partially_discovered_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;
    let host_machine_interface_id = host_discover_dhcp(&env, &host_config, &dpu_machine_id).await;

    // The MachineInterface for the host should now exist and be linked to the DPU
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(host_machine_interface_id),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    assert_eq!(iface.attached_dpu_machine_id, Some(dpu_machine_id));

    let mut txn = env.pool.begin().await.unwrap();
    let host = db::machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    let response = force_delete(&env, &dpu_machine_id).await;
    validate_delete_response(&response, Some(&host.id), &dpu_machine_id);
    assert!(response.all_done, "DPU must be deleted");

    validate_machine_deletion(&env, &dpu_machine_id, None).await;

    // The MachineInterface for the host should still exist
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(host_machine_interface_id),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    assert_eq!(iface.attached_dpu_machine_id, None);
}

async fn force_delete(
    env: &TestEnv,
    machine_id: &MachineId,
) -> rpc::forge::AdminForceDeleteMachineResponse {
    env.api
        .admin_force_delete_machine(tonic::Request::new(AdminForceDeleteMachineRequest {
            host_query: machine_id.to_string(),
            delete_interfaces: false,
            delete_bmc_interfaces: false,
            delete_bmc_credentials: false,
        }))
        .await
        .unwrap()
        .into_inner()
}

fn validate_delete_response(
    response: &rpc::forge::AdminForceDeleteMachineResponse,
    host_machine_id: Option<&MachineId>,
    dpu_machine_id: &MachineId,
) {
    assert_eq!(response.dpu_machine_id, dpu_machine_id.to_string());
    assert_eq!(
        response.managed_host_machine_id,
        host_machine_id.map(|id| id.to_string()).unwrap_or_default()
    );
    assert!(!response.dpu_bmc_ip.is_empty());
    if let Some(host_machine_id) = host_machine_id {
        if host_machine_id.machine_type() == MachineType::Host {
            assert!(!response.managed_host_bmc_ip.is_empty());
        }
    } else {
        assert!(response.managed_host_bmc_ip.is_empty());
    }
}

fn validate_delete_response_multi_dpu(
    response: &rpc::forge::AdminForceDeleteMachineResponse,
    host_machine_id: Option<&MachineId>,
    dpu_machine_ids: &[carbide_uuid::machine::MachineId],
) {
    assert_eq!(
        response
            .dpu_machine_ids
            .iter()
            .map(|i| i.to_owned())
            .collect::<HashSet<_>>(),
        dpu_machine_ids
            .iter()
            .map(|i| i.to_string())
            .collect::<HashSet<_>>()
    );
    assert_eq!(
        response.managed_host_machine_id,
        host_machine_id.map(|id| id.to_string()).unwrap_or_default()
    );
    assert!(!response.dpu_bmc_ip.is_empty());
    if let Some(host_machine_id) = host_machine_id {
        if host_machine_id.machine_type() == MachineType::Host {
            assert!(!response.managed_host_bmc_ip.is_empty());
        }
    } else {
        assert!(response.managed_host_bmc_ip.is_empty());
    }
}

/// Validates that the Machine has been fully deleted
async fn validate_machine_deletion(
    env: &TestEnv,
    machine_id: &MachineId,
    bmc_addrs: Option<&Vec<IpAddr>>,
) {
    // The machine should be now be gone in the API
    let response = env.find_machine(*machine_id).await;
    assert!(response.is_empty());

    // And it should also be gone on the DB layer
    let mut txn = env.pool.begin().await.unwrap();
    assert!(
        db::machine::find_one(&mut txn, machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db::machine_topology::find_by_machine_ids(&mut txn, &[*machine_id])
            .await
            .unwrap()
            .is_empty()
    );

    // The history should remain in table.
    assert!(
        !db::machine_state_history::find_by_machine_ids(&mut txn, &[*machine_id])
            .await
            .unwrap()
            .is_empty()
    );

    if let Some(bmc_addrs) = bmc_addrs {
        for bmc_addr in bmc_addrs {
            assert!(
                db::explored_endpoints::find_all_by_ip(*bmc_addr, &mut txn)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }
    txn.rollback().await.unwrap();
}

// TODO: Test deletion for machines with active instances on them

#[crate::sqlx_test]
async fn test_admin_force_delete_host_with_ib_instance(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (ib_partition_id, ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;

    env.run_ib_partition_controller_iteration().await;

    let ib_partition_status = get_partition_status(&env.api, ib_partition_id).await;
    assert_eq!(
        TenantState::try_from(ib_partition_status.state).unwrap(),
        TenantState::Ready
    );
    assert_eq!(
        ib_partition.status.clone().unwrap().state,
        ib_partition_status.state
    );
    assert_eq!(
        ib_partition.status.clone().unwrap().pkey,
        ib_partition_status.pkey
    );
    assert!(ib_partition_status.pkey.is_some());
    assert!(ib_partition_status.mtu.is_none());
    assert!(ib_partition_status.rate_limit.is_none());
    assert!(ib_partition_status.service_level.is_none());

    let mh = create_managed_host(&env).await;

    env.run_machine_state_controller_iteration().await;

    let mut txn = env
        .pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let machine = mh.host().db_machine(&mut txn).await;
    txn.commit().await.unwrap();

    let ib_fabric = env
        .ib_fabric_manager
        .new_client(DEFAULT_IB_FABRIC_NAME)
        .await
        .unwrap();

    assert_eq!(machine.current_state(), &ManagedHostState::Ready);
    assert!(!machine.is_dpu());
    assert!(machine.hardware_info.as_ref().is_some());
    assert_eq!(
        machine
            .hardware_info
            .as_ref()
            .unwrap()
            .infiniband_interfaces
            .len(),
        6
    );
    assert!(machine.infiniband_status_observation.as_ref().is_some());
    assert_eq!(
        machine
            .infiniband_status_observation
            .as_ref()
            .unwrap()
            .ib_interfaces
            .len(),
        6
    );
    assert_eq!(ib_fabric.find_ib_port(None).await.unwrap().len(), 6);

    let ib_config = rpc::forge::InstanceInfinibandConfig {
        ib_interfaces: vec![rpc::forge::InstanceIbInterfaceConfig {
            function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
            virtual_function_id: None,
            ib_partition_id: Some(ib_partition_id),
            device: "MT2910 Family [ConnectX-7]".to_string(),
            vendor: None,
            device_instance: 1,
        }],
    };

    let (tinstance, instance) =
        create_instance_with_ib_config(&env, &mh, ib_config, segment_id).await;

    let mut txn = env
        .pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    assert!(matches!(
        mh.host().db_machine(&mut txn).await.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.commit().await.unwrap();

    let check_instance = tinstance.rpc_instance().await;
    assert_eq!(check_instance.machine_id(), mh.id);
    assert_eq!(check_instance.status().tenant(), rpc::TenantState::Ready);
    assert_eq!(instance, check_instance);

    let ib_config = check_instance.config().infiniband();
    assert_eq!(ib_config.ib_interfaces.len(), 1);

    let ib_status = check_instance.status().infiniband();
    assert_eq!(ib_status.ib_interfaces.len(), 1);

    // one ib port in UFM
    let hex_pkey = ib_partition.status.clone().unwrap().pkey.unwrap();
    let pkey: u16 = u16::from_str_radix(hex_pkey.strip_prefix("0x").unwrap(), 16)
        .expect("Failed to parse string to integer");
    let guids = HashSet::from_iter([ib_status.ib_interfaces[0].guid.clone().unwrap()]);
    let filter = ib::Filter {
        guids: Some(guids.clone()),
        pkey: Some(pkey),
        state: Some(model::ib::IBPortState::Active),
    };
    assert_eq!(ib_fabric.find_ib_port(Some(filter)).await.unwrap().len(), 1);

    let response = force_delete(&env, &mh.id).await;
    validate_delete_response(&response, Some(&mh.id), &mh.dpu().id);

    // after host deleted, ib port should be removed from UFM
    let filter = ib::Filter {
        guids: Some(guids.iter().cloned().collect()),
        pkey: Some(pkey),
        state: Some(model::ib::IBPortState::Active),
    };
    assert_eq!(ib_fabric.find_ib_port(Some(filter)).await.unwrap().len(), 0);

    assert!(env.find_machine(mh.id).await.is_empty());
    assert!(env.find_machine(mh.dpu().id).await.is_empty());

    assert_eq!(response.ufm_unregistrations, 1);
    assert!(response.all_done, "Host and DPU must be deleted");

    // Everything should be gone now
    for id in [mh.id, mh.dpu().id] {
        validate_machine_deletion(&env, &id, None).await;
    }
}

#[crate::sqlx_test]
async fn test_admin_force_delete_managed_host_multi_dpu(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host_multi_dpu(&env, 2).await;
    let host_machine = mh.host().rpc_machine().await;
    let dpu_ids = host_machine.associated_dpu_machine_ids;
    assert_eq!(
        dpu_ids.len(),
        2,
        "Should have gotten 2 DPUs from the managed host we created"
    );

    assert!(
        env.api
            .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
                machine_ids: dpu_ids.clone(),
                ..Default::default()
            }))
            .await
            .is_ok_and(|response| response.into_inner().machines.len() == 2),
        "Expected to find 2 dpu machines when looking up by ID"
    );

    // Delete the *host* machine
    let response = force_delete(&env, &mh.host().id).await;

    validate_delete_response_multi_dpu(&response, Some(&mh.host().id), dpu_ids.as_slice());

    for id in [&[mh.host().id], dpu_ids.as_slice()].concat().iter() {
        validate_machine_deletion(&env, id, None).await;
    }
}

#[crate::sqlx_test]
async fn test_admin_force_delete_dpu_from_managed_host_multi_dpu(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host_multi_dpu(&env, 2).await;
    let dpu_0_id = mh.dpu_n(0).id;
    let rpc_dpu_ids = mh
        .dpu_ids
        .clone()
        .into_iter()
        .collect::<Vec<carbide_uuid::machine::MachineId>>();
    assert_eq!(
        mh.dpu_ids.len(),
        2,
        "Should have gotten 2 DPUs from the managed host we created"
    );

    assert!(
        env.api
            .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
                machine_ids: rpc_dpu_ids.clone(),
                ..Default::default()
            }))
            .await
            .is_ok_and(|response| response.into_inner().machines.len() == 2),
        "Expected to find 2 dpu machines when looking up by ID"
    );

    // Delete one of the *dpu* machines, which should cascade and delete the host and other DPU machines
    let response = force_delete(&env, &dpu_0_id).await;

    validate_delete_response_multi_dpu(&response, Some(&mh.host().id), &rpc_dpu_ids);

    for id in mh.dpu_ids.iter().chain([&mh.id]) {
        validate_machine_deletion(&env, id, None).await;
    }
}

// test_admin_force_delete_tenant_state verifies that an instance containing a host machine in a ForceDeletion state will have a TenantState of Terminating.
#[crate::sqlx_test]
async fn test_admin_force_delete_tenant_state(pool: sqlx::PgPool) {
    // 1) setup
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    let tinstance = mh
        .instance_builer(&env)
        .single_interface_network_config(segment_id)
        .build()
        .await;

    // 2) mock force-delete

    // If we use the RPC API to try to force delete this instance, everything is probably going to be cleaned up and we will likely not be able to retrieve the host's machine.
    // The simplest solution to test how we map ManagedHostState::ForceDeletion -->  TenantState::Terminating is to manually set the machine's
    // ManagedHostState to ForceDeletion in the DB.

    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = env.pool.begin().await.unwrap();

    let host_machine = mh.host().db_machine(&mut txn).await;

    db::machine::advance(
        &host_machine,
        &mut txn,
        &ManagedHostState::ForceDeletion,
        None,
    )
    .await
    .unwrap();

    txn.commit().await.unwrap();

    // 3) verify instance's tenant state is rpc::forge::TenantState::Terminating
    let request_instances = tonic::Request::new(InstancesByIdsRequest {
        instance_ids: vec![tinstance.id],
    });
    let mut instance_list = env
        .api
        .find_instances_by_ids(request_instances)
        .await
        .map(|response| response.into_inner())
        .unwrap();

    assert_eq!(instance_list.instances.len(), 1);
    let instance = instance_list.instances.pop().unwrap();

    let current_tenant_state = instance
        .status
        .as_ref()
        .unwrap()
        .tenant
        .as_ref()
        .unwrap()
        .state();
    let expected_tenant_state = rpc::forge::TenantState::Terminating;
    assert_eq!(
        current_tenant_state, expected_tenant_state,
        "The instance has a tenant state of {current_tenant_state:#?} instead of {expected_tenant_state:#?}"
    );
}

#[crate::sqlx_test]
async fn test_admin_force_delete_with_instance_type(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let instance_type_id = get_instance_type_fixture_id(&env).await;

    let (tmp_machine_id, _) = create_managed_host(&env).await.into();

    // Associate the machine with the instance type
    let _ = env
        .api
        .associate_machines_with_instance_type(tonic::Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![tmp_machine_id.to_string()],
            },
        ))
        .await
        .unwrap();

    // The request should fail because the machine is associated with an
    // instance type.
    env.api
        .admin_force_delete_machine(tonic::Request::new(AdminForceDeleteMachineRequest {
            host_query: tmp_machine_id.to_string(),
            delete_interfaces: false,
            delete_bmc_interfaces: false,
            delete_bmc_credentials: false,
        }))
        .await
        .unwrap_err();

    // Now clear the instance type
    let _ = env
        .api
        .remove_machine_instance_type_association(tonic::Request::new(
            rpc::forge::RemoveMachineInstanceTypeAssociationRequest {
                machine_id: tmp_machine_id.to_string(),
            },
        ))
        .await
        .unwrap();

    // Delete should succeed now.
    _ = force_delete(&env, &tmp_machine_id);
}
