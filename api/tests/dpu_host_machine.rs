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

use carbide::{
    db::{dpu_machine::DpuMachine, host_machine::HostMachine},
    model::machine::machine_id::try_parse_machine_id,
};

pub mod common;
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine};

use crate::common::api_fixtures::create_managed_host;
use rpc::forge::forge_server::Forge;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

/// This is just a random MachineId to simulate fetching a Machine that doesn't exist
const UNKNOWN_MACHINE_ID: &str = "fm100htaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00";

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_find_dpu_machine(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_rpc_machine_id = create_dpu_machine(&env, &host_sim.config).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_rpc_machine_id).unwrap();

    let mut txn = env.pool.begin().await?;

    let mut machines = env
        .find_machines(Some(dpu_rpc_machine_id), None, true)
        .await;
    assert_eq!(machines.machines.len(), 1);
    let machine = machines.machines.remove(0);

    let dpu_machine = DpuMachine::find_by_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap();

    assert_eq!(
        dpu_machine._machine_interface_id().to_string(),
        machine.interfaces[0].id.as_ref().unwrap().to_string(),
    );

    let machine =
        DpuMachine::find_by_machine_id(&mut txn, &UNKNOWN_MACHINE_ID.parse().unwrap()).await;
    assert!(machine.is_err());

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_find_host_machine(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await?;

    let mut machines = env
        .find_machines(Some(host_machine_id.to_string().into()), None, true)
        .await;
    assert_eq!(machines.machines.len(), 1);
    let machine = machines.machines.remove(0);

    let host_machine = HostMachine::find_by_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    assert_eq!(
        host_machine._machine_interface_id().to_string(),
        machine.interfaces[0].id.as_ref().unwrap().to_string(),
    );

    let machine =
        HostMachine::find_by_machine_id(&mut txn, &UNKNOWN_MACHINE_ID.parse().unwrap()).await;
    assert!(machine.is_err());

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_find_temp_host_machine(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_rpc_machine_id = create_dpu_machine(&env, &host_sim.config).await;

    let machine = env
        .api
        .find_machines(tonic::Request::new(rpc::forge::MachineSearchQuery {
            search_config: Some(rpc::forge::MachineSearchConfig {
                include_dpus: true,
                include_associated_machine_id: true,
                include_predicted_host: true,
                include_history: true,
                ..Default::default()
            }),
            id: Some(dpu_rpc_machine_id),
            fqdn: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0);
    let host_rpc_machine_id = machine.associated_host_machine_id.clone().unwrap();
    let host_machine_id = try_parse_machine_id(&host_rpc_machine_id).unwrap();
    assert!(host_machine_id.machine_type().is_predicted_host());

    let _host_machine = env
        .api
        .find_machines(tonic::Request::new(rpc::forge::MachineSearchQuery {
            search_config: Some(rpc::forge::MachineSearchConfig {
                include_dpus: true,
                include_associated_machine_id: true,
                include_predicted_host: true,
                include_history: true,
                ..Default::default()
            }),
            id: Some(host_rpc_machine_id),
            fqdn: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0);

    Ok(())
}
