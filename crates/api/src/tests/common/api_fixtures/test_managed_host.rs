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

use std::collections::HashMap;
use std::sync::Arc;

use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::MachineId;
use model::machine::{
    InstanceState, LoadSnapshotOptions, Machine, ManagedHostState, ManagedHostStateSnapshot,
    ReprovisionState,
};
use rpc::forge::forge_agent_control_response::Action;
use rpc::forge::forge_server::Forge;
use tonic::Request;

use crate::tests::common::api_fixtures::instance::TestInstanceBuilder;
use crate::tests::common::api_fixtures::{Api, TestEnv, TestMachine};

pub struct TestManagedHost {
    pub id: MachineId,
    pub dpu_ids: Vec<MachineId>,
    pub api: Arc<Api>,
}

impl From<TestManagedHost> for (MachineId, MachineId) {
    fn from(mut v: TestManagedHost) -> Self {
        (v.id, v.dpu_ids.remove(0))
    }
}

type Txn<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

impl TestManagedHost {
    pub fn dpu(&self) -> TestMachine {
        TestMachine::new(self.dpu_ids[0], self.api.clone())
    }

    pub fn dpu_n(&self, n: usize) -> TestMachine {
        assert!(n < self.dpu_ids.len());
        TestMachine::new(self.dpu_ids[n], self.api.clone())
    }

    pub fn host(&self) -> TestMachine {
        TestMachine::new(self.id, self.api.clone())
    }

    pub async fn snapshot(&self, txn: &mut Txn<'_>) -> ManagedHostStateSnapshot {
        db::managed_host::load_snapshot(txn, &self.id, Default::default())
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn dpu_db_machines(&self, txn: &mut Txn<'_>) -> Vec<Machine> {
        db::machine::find_dpus_by_host_machine_id(txn, &self.id)
            .await
            .unwrap()
    }

    pub fn new_dpu_reprovision_state(&self, state: ReprovisionState) -> ManagedHostState {
        ManagedHostState::DPUReprovision {
            dpu_states: model::machine::DpuReprovisionStates {
                states: HashMap::from([(self.dpu().id, state)]),
            },
        }
    }

    pub fn new_dpus_reprovision_state(&self, states: &[&ReprovisionState]) -> ManagedHostState {
        assert_eq!(states.len(), self.dpu_ids.len());
        ManagedHostState::DPUReprovision {
            dpu_states: model::machine::DpuReprovisionStates {
                states: self
                    .dpu_ids
                    .iter()
                    .zip(states.iter())
                    .map(|(id, state)| (*id, (*state).clone()))
                    .collect(),
            },
        }
    }

    pub fn new_dpu_assigned_reprovision_state(&self, state: ReprovisionState) -> ManagedHostState {
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: model::machine::DpuReprovisionStates {
                    states: HashMap::from([(self.dpu().id, state)]),
                },
            },
        }
    }

    pub async fn network_configured(&self, test_env: &TestEnv) {
        crate::tests::common::api_fixtures::network_configured(test_env, &self.dpu_ids).await
    }

    pub async fn machine_validation_completed(&self) {
        let response = self.host().forge_agent_control().await;
        assert_eq!(response.action, Action::MachineValidation as i32);
        let uuid = &response.data.unwrap().pair[1].value;
        self.api
            .machine_validation_completed(Request::new(
                rpc::forge::MachineValidationCompletedRequest {
                    machine_id: self.id.into(),
                    machine_validation_error: None,
                    validation_id: Some(rpc::Uuid {
                        value: uuid.to_owned(),
                    }),
                },
            ))
            .await
            .unwrap()
            .into_inner();
    }

    pub fn instance_builer<'a, 'b>(&'b self, test_env: &'a TestEnv) -> TestInstanceBuilder<'a, 'b> {
        TestInstanceBuilder::new(test_env, self)
    }

    pub async fn delete_instance(&self, env: &TestEnv, instance_id: InstanceId) {
        crate::tests::common::api_fixtures::instance::delete_instance(env, instance_id, self).await
    }
}

pub(crate) trait TestManagedHostSnapshots {
    async fn snapshots(
        &self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        load_options: LoadSnapshotOptions,
    ) -> HashMap<MachineId, ManagedHostStateSnapshot>;
}

impl TestManagedHostSnapshots for Vec<TestManagedHost> {
    async fn snapshots(
        &self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        load_options: LoadSnapshotOptions,
    ) -> HashMap<MachineId, ManagedHostStateSnapshot> {
        db::managed_host::load_by_machine_ids(
            txn,
            &self.iter().map(|m| m.id).collect::<Vec<_>>(),
            load_options,
        )
        .await
        .unwrap()
    }
}
