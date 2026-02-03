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

use std::str::FromStr;
use std::sync::Arc;

use carbide_uuid::machine::MachineId;
use model::machine::{Machine, ManagedHostState};
use rpc::forge::forge_server::Forge;
use tonic::Request;

use crate::tests::common::api_fixtures::{Api, TestEnv};

pub mod interface;

pub type TestMachineInterface = interface::TestMachineInterface;

pub struct TestMachine {
    pub id: MachineId,
    api: Arc<Api>,
}

type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

impl TestMachine {
    pub fn new(id: MachineId, api: Arc<Api>) -> Self {
        Self { id, api }
    }

    pub async fn rpc_machine(&self) -> rpc::Machine {
        self.api
            .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
                machine_ids: vec![self.id],
                include_history: true,
            }))
            .await
            .unwrap()
            .into_inner()
            .machines
            .remove(0)
    }

    pub async fn next_iteration_machine(&self, env: &TestEnv) -> Machine {
        env.run_machine_state_controller_iteration().await;
        let mut txn = env.pool.begin().await.unwrap();
        let dpu = self.db_machine(&mut txn).await;
        txn.commit().await.unwrap();
        dpu
    }

    pub async fn db_machine(&self, txn: &mut Txn<'_>) -> Machine {
        db::machine::find_one(txn, &self.id, Default::default())
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn first_interface(&self, txn: &mut Txn<'_>) -> TestMachineInterface {
        TestMachineInterface::new(
            db::machine_interface::find_by_machine_ids(txn, &[self.id])
                .await
                .unwrap()
                .get(&self.id)
                .unwrap()[0]
                .id,
            self.api.clone(),
        )
    }

    pub async fn reboot_completed(&self) -> rpc::forge::MachineRebootCompletedResponse {
        tracing::info!("Machine ={} rebooted", self.id);
        self.api
            .reboot_completed(Request::new(rpc::forge::MachineRebootCompletedRequest {
                machine_id: self.id.into(),
            }))
            .await
            .unwrap()
            .into_inner()
    }

    pub async fn forge_agent_control(&self) -> rpc::forge::ForgeAgentControlResponse {
        self.reboot_completed().await;
        self.api
            .forge_agent_control(Request::new(rpc::forge::ForgeAgentControlRequest {
                machine_id: self.id.into(),
            }))
            .await
            .unwrap()
            .into_inner()
    }

    pub async fn discovery_completed(&self) {
        self.api
            .discovery_completed(Request::new(rpc::forge::MachineDiscoveryCompletedRequest {
                machine_id: self.id.into(),
            }))
            .await
            .unwrap()
            .into_inner();
    }

    pub async fn trigger_dpu_reprovisioning(
        &self,
        mode: rpc::forge::dpu_reprovisioning_request::Mode,
        update_firmware: bool,
    ) {
        self.api
            .trigger_dpu_reprovisioning(tonic::Request::new(
                ::rpc::forge::DpuReprovisioningRequest {
                    dpu_id: None,
                    machine_id: self.id.into(),
                    mode: mode as i32,
                    initiator: ::rpc::forge::UpdateInitiator::AdminCli as i32,
                    update_firmware,
                },
            ))
            .await
            .unwrap();
    }

    pub async fn bmc_ip(&self, txn: &mut Txn<'_>) -> String {
        let machine = self.db_machine(txn).await;
        machine
            .bmc_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "".to_string())
    }

    pub async fn json_history(&self, limit: Option<usize>) -> Vec<serde_json::Value> {
        let machine = self.rpc_machine().await;
        let mut states: Vec<serde_json::Value> = machine
            .events
            .into_iter()
            .map(|e| serde_json::Value::from_str(&e.event).unwrap())
            .collect();
        if let Some(limit) = limit {
            if states.len() >= limit {
                states.split_off(states.len() - limit)
            } else {
                states
            }
        } else {
            states
        }
    }

    pub async fn parsed_history(&self, limit: Option<usize>) -> Vec<ManagedHostState> {
        let json_states = self.json_history(limit).await;
        json_states
            .into_iter()
            .map(|s| serde_json::from_value::<ManagedHostState>(s).unwrap())
            .collect()
    }
}
