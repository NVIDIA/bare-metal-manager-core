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
use crate::db::{self};
use crate::model::machine::MachineStateHistory;
use crate::model::machine::{ManagedHostState, machine_id::try_parse_machine_id};
use common::api_fixtures::create_managed_host;
use config_version::ConfigVersion;
use rpc::forge::forge_server::Forge;

use crate::tests::common;
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine};

#[crate::sqlx_test]
async fn test_machine_state_history(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let dpu_machine_id_string = dpu_machine_id.to_string();

    let expected_initial_states_json = serde_json::json!([
        {"state": "created"},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"dpudiscoverystate": "initializing"}}}},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"dpudiscoverystate": "configuring"}}}},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"dpudiscoverystate": "enablershim"}}}},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"count": 0, "dpudiscoverystate": "disablesecureboot", "disable_secure_boot_state": {"disablesecurebootstate": "checksecurebootstatus"}}}}},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"dpudiscoverystate": "setuefihttpboot"}}}},
        {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id_string: {"dpudiscoverystate": "rebootalldpus"}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "init"}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "waitingforplatformpowercycle", "substate": {"state": "off"}}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "waitingforplatformpowercycle", "substate": {"state": "on"}}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "waitingforplatformconfiguration"}}}},
        {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id_string: {"dpustate": "waitingfornetworkconfig"}}}},
        {"state": "hostinit", "machine_state": {"state": "enableipmioverlan"}},
        {"state": "hostinit", "machine_state": {"state": "waitingforplatformconfiguration"}},
        {"state": "hostinit", "machine_state": {"state": "waitingfordiscovery"}},
    ]);
    let expected_initial_states: Vec<serde_json::Value> =
        expected_initial_states_json.as_array().unwrap().clone();

    for machine_id in &[host_machine_id, dpu_machine_id] {
        let mut txn = env.pool.begin().await?;

        let machine = db::machine::find_one(
            &mut txn,
            &dpu_machine_id,
            crate::db::machine::MachineSearchConfig {
                include_history: true,
                ..Default::default()
            },
        )
        .await?
        .unwrap();

        assert_eq!(
            json_history(&machine.history[..expected_initial_states.len()])?,
            expected_initial_states
        );

        let machine = db::machine::find_one(
            &mut txn,
            &dpu_machine_id,
            crate::db::machine::MachineSearchConfig::default(),
        )
        .await?
        .unwrap();
        assert!(machine.history.is_empty());
        txn.commit().await?;

        // Check that RPC APIs returns the History if asked for
        // - GetMachine always returns history
        // - FindMachines and FindMachinesById should do so if asked for it
        let rpc_machine = env
            .api
            .get_machine(tonic::Request::new(machine_id.to_string().into()))
            .await?
            .into_inner();
        let rpc_history: Vec<serde_json::Value> = rpc_machine
            .events
            .into_iter()
            .map(|ev| serde_json::from_str::<serde_json::Value>(&ev.event))
            .collect::<Result<_, _>>()?;
        assert_eq!(
            rpc_history[..expected_initial_states.len()].to_vec(),
            expected_initial_states,
        );

        let rpc_machine = env
            .api
            .find_machines(tonic::Request::new(rpc::forge::MachineSearchQuery {
                id: Some(machine_id.to_string().into()),
                fqdn: None,
                search_config: Some(rpc::forge::MachineSearchConfig {
                    include_dpus: true,
                    include_history: true,
                    include_predicted_host: false,
                    only_maintenance: false,
                    exclude_hosts: false,
                    only_quarantine: false,
                }),
            }))
            .await?
            .into_inner()
            .machines
            .remove(0);
        let rpc_history: Vec<serde_json::Value> = rpc_machine
            .events
            .into_iter()
            .map(|ev| serde_json::from_str::<serde_json::Value>(&ev.event))
            .collect::<Result<_, _>>()?;
        assert_eq!(
            rpc_history[..expected_initial_states.len()].to_vec(),
            expected_initial_states
        );

        let rpc_machine = env
            .api
            .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
                machine_ids: vec![machine_id.to_string().into()],
                include_history: true,
            }))
            .await?
            .into_inner()
            .machines
            .remove(0);
        let rpc_history: Vec<serde_json::Value> = rpc_machine
            .events
            .into_iter()
            .map(|ev| serde_json::from_str::<serde_json::Value>(&ev.event))
            .collect::<Result<_, _>>()?;
        assert_eq!(
            rpc_history[..expected_initial_states.len()].to_vec(),
            expected_initial_states
        );
    }

    // Check if older history entries get deleted

    let mut txn = env.pool.begin().await?;

    let machine = db::machine::find_one(
        &mut txn,
        &host_machine_id,
        crate::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await?
    .unwrap();

    for _ in 1..300 {
        db::machine::advance(&machine, &mut txn, ManagedHostState::Ready, None)
            .await
            .unwrap();
    }

    txn.commit().await?;

    let mut txn = env.pool.begin().await?;
    let result = db::machine_state_history::for_machine(&mut txn, &host_machine_id)
        .await
        .unwrap();

    // Count should not go beyond 250.
    assert_eq!(result.len(), 250);

    let machine = db::machine::find_one(
        &mut txn,
        &host_machine_id,
        crate::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await?
    .unwrap();

    assert_eq!(machine.history.len(), 250);
    Ok(())
}

/// Check that we can handle old / unknown states in the history.
/// This allows us to change MachineState enum.
#[crate::sqlx_test]
async fn test_old_machine_state_history(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let mut txn = env.pool.begin().await?;

    let query = "INSERT INTO machine_state_history (machine_id, state, state_version) VALUES ($1, $2::jsonb, $3)";
    sqlx::query(query)
        .bind(dpu_machine_id.to_string())
        .bind(r#"{"state": "dpuinit", "machine_state": {"state": "nolongerarealstate"}}"#)
        .bind(ConfigVersion::initial())
        .execute(&mut *txn)
        .await?;

    let machine = db::machine::find_one(
        &mut txn,
        &dpu_machine_id,
        crate::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await?
    .unwrap();

    let states = machine
        .history
        .into_iter()
        .map(|m| serde_json::from_str::<serde_json::Value>(&m.state))
        .collect::<Result<Vec<_>, _>>()?;
    let dpu_machine_id = dpu_machine_id.to_string();
    assert_eq!(
        serde_json::Value::Array(states),
        serde_json::json!([
            {"state": "created"},
            {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id: {"dpudiscoverystate": "initializing"}}}},
            {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id: {"dpudiscoverystate": "configuring"}}}},
            {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id: {"dpudiscoverystate": "enablershim"}}}},
            {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id: {"count": 0, "dpudiscoverystate": "disablesecureboot", "disable_secure_boot_state": {"disablesecurebootstate": "checksecurebootstatus"}}}}},
            {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id: {"dpudiscoverystate": "setuefihttpboot"}}}},
            {"state": "dpudiscoveringstate", "dpu_states": {"states": {&dpu_machine_id: {"dpudiscoverystate": "rebootalldpus"}}}},
            {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id: {"dpustate": "init"}}}},
            {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id: {"dpustate": "waitingforplatformpowercycle", "substate": {"state": "off"}}}}},
            {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id: {"dpustate": "waitingforplatformpowercycle", "substate": {"state": "on"}}}}},
            {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id: {"dpustate": "waitingforplatformconfiguration"}}}},
            {"state": "dpuinit", "dpu_states": {"states": {&dpu_machine_id: {"dpustate": "waitingfornetworkconfig"}}}},
            {"state": "hostinit", "machine_state": {"state": "enableipmioverlan"}},
            {"state": "dpuinit", "machine_state": {"state": "nolongerarealstate"}},
        ]),
    );

    Ok(())
}

fn json_history(history: &[MachineStateHistory]) -> serde_json::Result<Vec<serde_json::Value>> {
    // // Check that version numbers are always incrementing by 1
    if !history.is_empty() {
        let mut version = history[0].state_version.version_nr();
        for entry in &history[1..] {
            assert_eq!(entry.state_version.version_nr(), version + 1);
            version += 1;
        }
    }

    history
        .iter()
        .map(|h| serde_json::from_str::<serde_json::Value>(&h.state))
        .collect::<Result<Vec<_>, _>>()
}
