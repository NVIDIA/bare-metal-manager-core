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
use crate::db::{self, machine::Machine};
use crate::model::machine::MachineStateHistory;
use crate::model::machine::{machine_id::try_parse_machine_id, ManagedHostState};
use common::api_fixtures::create_managed_host;
use config_version::ConfigVersion;
use rpc::forge::forge_server::Forge;

use crate::tests::common;
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine};

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_machine_state_history(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let expected_initial_states = vec![
        "{\"state\": \"created\"}".to_string(), 
        format!("{{\"state\": \"dpuinit\", \"dpu_states\": {{\"states\": {{\"{}\": {{\"dpustate\": \"init\"}}}}}}}}", dpu_machine_id),
        format!("{{\"state\": \"dpuinit\", \"dpu_states\": {{\"states\": {{\"{}\": {{\"dpustate\": \"waitingforplatformpowercycle\", \"substate\": {{\"state\": \"off\"}}}}}}}}}}", dpu_machine_id),
        format!("{{\"state\": \"dpuinit\", \"dpu_states\": {{\"states\": {{\"{}\": {{\"dpustate\": \"waitingforplatformpowercycle\", \"substate\": {{\"state\": \"on\"}}}}}}}}}}", dpu_machine_id),
        format!("{{\"state\": \"dpuinit\", \"dpu_states\": {{\"states\": {{\"{}\": {{\"dpustate\": \"waitingforplatformconfiguration\"}}}}}}}}", dpu_machine_id),
        format!("{{\"state\": \"dpuinit\", \"dpu_states\": {{\"states\": {{\"{}\": {{\"dpustate\": \"waitingfornetworkconfig\"}}}}}}}}", dpu_machine_id),
        "{\"state\": \"hostinit\", \"machine_state\": {\"state\": \"enableipmioverlan\"}}".to_string(),
        "{\"state\": \"hostinit\", \"machine_state\": {\"state\": \"waitingforplatformconfiguration\"}}".to_string(),
        "{\"state\": \"hostinit\", \"machine_state\": {\"state\": \"waitingfordiscovery\"}}".to_string()];

    for machine_id in &[host_machine_id.clone(), dpu_machine_id.clone()] {
        let mut txn = env.pool.begin().await?;

        let machine = Machine::find_one(
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
            text_history(&machine.history()[..expected_initial_states.len()].to_vec()),
            expected_initial_states
        );

        let machine = Machine::find_one(
            &mut txn,
            &dpu_machine_id,
            crate::db::machine::MachineSearchConfig::default(),
        )
        .await?
        .unwrap();
        assert!(machine.history().is_empty());
        txn.commit().await?;

        // Check that RPC APIs returns the History if asked for
        // - GetMachine always returns history
        // - FindMachines and FindMachinesById should do so if asked for it
        let rpc_machine = env
            .api
            .get_machine(tonic::Request::new(machine_id.to_string().into()))
            .await?
            .into_inner();
        let rpc_history: Vec<String> = rpc_machine.events.into_iter().map(|ev| ev.event).collect();
        assert_eq!(
            rpc_history[..expected_initial_states.len()].to_vec(),
            expected_initial_states
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
                }),
            }))
            .await?
            .into_inner()
            .machines
            .remove(0);
        let rpc_history: Vec<String> = rpc_machine.events.into_iter().map(|ev| ev.event).collect();
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
        let rpc_history: Vec<String> = rpc_machine.events.into_iter().map(|ev| ev.event).collect();
        assert_eq!(
            rpc_history[..expected_initial_states.len()].to_vec(),
            expected_initial_states
        );
    }

    // Check if older history entries get deleted

    let mut txn = env.pool.begin().await?;

    let machine = Machine::find_one(
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
        machine
            .advance(&mut txn, ManagedHostState::Ready, None)
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

    let machine = Machine::find_one(
        &mut txn,
        &host_machine_id,
        crate::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await?
    .unwrap();

    assert_eq!(machine.history().len(), 250);
    Ok(())
}

/// Check that we can handle old / unknown states in the history.
/// This allows us to change MachineState enum.
#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_old_machine_state_history(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let mut txn = env.pool.begin().await?;

    let query =
        "INSERT INTO machine_state_history (machine_id, state, state_version) VALUES ($1, $2::jsonb, $3)";
    sqlx::query(query)
        .bind(dpu_machine_id.to_string())
        .bind(r#"{"state": "dpuinit", "machine_state": {"state": "nolongerarealstate"}}"#)
        .bind(ConfigVersion::initial())
        .execute(&mut *txn)
        .await?;

    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        crate::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await?
    .unwrap();

    let mut states: Vec<&str> = Vec::with_capacity(machine.history().len());
    for e in machine.history() {
        states.push(e.state.as_ref());
    }
    assert_eq!(
        states,
        vec![
            "{\"state\": \"created\"}", 
            &format!("{{\"state\": \"dpuinit\", \"dpu_states\": {{\"states\": {{\"{}\": {{\"dpustate\": \"init\"}}}}}}}}", dpu_machine_id),
            &format!("{{\"state\": \"dpuinit\", \"dpu_states\": {{\"states\": {{\"{}\": {{\"dpustate\": \"waitingforplatformpowercycle\", \"substate\": {{\"state\": \"off\"}}}}}}}}}}", dpu_machine_id),
            &format!("{{\"state\": \"dpuinit\", \"dpu_states\": {{\"states\": {{\"{}\": {{\"dpustate\": \"waitingforplatformpowercycle\", \"substate\": {{\"state\": \"on\"}}}}}}}}}}", dpu_machine_id),
            &format!("{{\"state\": \"dpuinit\", \"dpu_states\": {{\"states\": {{\"{}\": {{\"dpustate\": \"waitingforplatformconfiguration\"}}}}}}}}", dpu_machine_id),
            &format!("{{\"state\": \"dpuinit\", \"dpu_states\": {{\"states\": {{\"{}\": {{\"dpustate\": \"waitingfornetworkconfig\"}}}}}}}}", dpu_machine_id),
            "{\"state\": \"hostinit\", \"machine_state\": {\"state\": \"enableipmioverlan\"}}",
            "{\"state\": \"dpuinit\", \"machine_state\": {\"state\": \"nolongerarealstate\"}}",
        ],
    );

    Ok(())
}

fn text_history(history: &Vec<MachineStateHistory>) -> Vec<&str> {
    // // Check that version numbers are always incrementing by 1
    if !history.is_empty() {
        let mut version = history[0].state_version.version_nr();
        for entry in &history[1..] {
            assert_eq!(entry.state_version.version_nr(), version + 1);
            version += 1;
        }
    }

    let mut states = Vec::with_capacity(history.len());
    for e in history {
        states.push(e.state.as_ref());
    }
    states
}
