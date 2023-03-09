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

use log::LevelFilter;

use carbide::{
    db::{
        machine::Machine, machine_interface::MachineInterface,
        machine_state_history::MachineStateHistory, machine_topology::MachineTopology,
        vpc_resource_leaf::VpcResourceLeaf,
    },
    model::machine::machine_id::try_parse_machine_id,
};

use ::rpc::forge::{forge_server::Forge, AdminForceDeleteMachineRequest};

pub mod common;
use common::api_fixtures::{
    create_test_env,
    dpu::{create_dpu_machine, FIXTURE_DPU_BMC_IP_ADDRESS},
};

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_admin_force_delete_dpu_only(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone(), Default::default());

    let dpu_machine_id = try_parse_machine_id(&create_dpu_machine(&env).await).unwrap();

    let mut txn = pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(&mut txn, dpu_machine_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !MachineStateHistory::find_by_machine_ids(&mut txn, &[dpu_machine_id])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        !MachineTopology::find_by_machine_ids(&mut txn, &[dpu_machine_id])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(VpcResourceLeaf::find(&mut txn, dpu_machine_id)
        .await
        .is_ok());
    txn.rollback().await.unwrap();

    let response = env
        .api
        .admin_force_delete_machine(tonic::Request::new(AdminForceDeleteMachineRequest {
            host_query: dpu_machine_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.dpu_machine_id, dpu_machine_id.to_string());
    assert_eq!(
        response.dpu_machine_interface_id,
        dpu_machine.interfaces()[0].id().to_string()
    );
    assert_eq!(response.managed_host_machine_id, "");
    assert_eq!(response.dpu_bmc_ip, FIXTURE_DPU_BMC_IP_ADDRESS);

    // The machine should be now be gone in the API
    let response = env
        .api
        .find_machines(tonic::Request::new(rpc::forge::MachineSearchQuery {
            id: Some(dpu_machine_id.to_string().into()),
            fqdn: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.machines.is_empty());

    // And it should also be gone on the DB layer
    let mut txn = pool.begin().await.unwrap();
    assert!(Machine::find_one(&mut txn, dpu_machine_id)
        .await
        .unwrap()
        .is_none());

    // The history should remain in table.
    assert!(
        !MachineStateHistory::find_by_machine_ids(&mut txn, &[dpu_machine_id])
            .await
            .unwrap()
            .is_empty()
    );
    // And the topology
    assert!(
        MachineTopology::find_by_machine_ids(&mut txn, &[dpu_machine_id])
            .await
            .unwrap()
            .is_empty()
    );
    // And the leaf table entry
    assert!(VpcResourceLeaf::find(&mut txn, dpu_machine_id)
        .await
        .is_err());

    // The associated interface should not point to any machine anymore
    let iface = MachineInterface::find_one(&mut txn, *dpu_machine.interfaces()[0].id())
        .await
        .unwrap();
    assert!(iface.attached_dpu_machine_id().is_none());
    txn.rollback().await.unwrap();

    // TODO: Check that the leaf is released
}

// TODO: Test deletion for Machines with hosts and instances
