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

use carbide_api_core::test_support::ApiMetricsEmitter;
use carbide_api_core::test_support::builder::TestApiBuilder;
use carbide_utils::test_support::test_meter::TestMeter;
use db::work_lock_manager;
use model::resource_pool;
use sqlx::PgPool;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::{ApiHandle, TestHarness};

pub struct TestHarnessBuilder {
    pub(crate) db_pool: PgPool,
    pub(crate) test_meter: Option<TestMeter>,
    pub(crate) api: Option<ApiHandle>,
}

impl TestHarnessBuilder {
    pub async fn build(self) -> TestHarness {
        let test_meter = self.test_meter.unwrap_or_default();
        let api = match self.api {
            Some(v) => v,
            None => Self::build_default_api(self.db_pool, &test_meter).await,
        };

        TestHarness {
            api: api.into(),
            test_meter,
            processor_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    async fn build_default_api(db_pool: PgPool, test_meter: &TestMeter) -> ApiHandle {
        let cancel_token = CancellationToken::new();
        let mut join_set = JoinSet::new();

        let int_range_pool = |ranges: &[(u32, u32)]| resource_pool::ResourcePoolDef {
            pool_type: resource_pool::ResourcePoolType::Integer,
            ranges: ranges
                .iter()
                .map(|(start, end)| resource_pool::Range {
                    start: start.to_string(),
                    end: end.to_string(),
                    auto_assign: true,
                })
                .collect(),
            prefix: None,
            delegate_prefix_len: None,
        };

        let pools = [
            (
                resource_pool::common::LOOPBACK_IP.to_string(),
                resource_pool::ResourcePoolDef {
                    pool_type: resource_pool::ResourcePoolType::Ipv4,
                    prefix: Some("172.20.0.0/24".to_string()),
                    ranges: vec![],
                    delegate_prefix_len: None,
                },
            ),
            (
                resource_pool::common::VLANID.to_string(),
                int_range_pool(&[(1, 2)]),
            ),
            (
                resource_pool::common::VNI.to_string(),
                int_range_pool(&[(10001, 10002)]),
            ),
            (
                resource_pool::common::VPC_VNI.to_string(),
                int_range_pool(&[(20001, 20002), (60001, 60002)]),
            ),
        ];
        let mut txn = db_pool.begin().await.unwrap();
        db::resource_pool::define_all_from(&mut txn, &pools.into_iter().collect())
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let ib_fabric_ids = ["default"];
        let common_pools = db::resource_pool::create_common_pools(
            db_pool.clone(),
            HashSet::from_iter(ib_fabric_ids.into_iter().map(ToString::to_string)),
        )
        .await
        .expect("common pool creation must succeed");

        let work_lock_manager_handle = db::work_lock_manager::start(
            &mut join_set,
            db_pool.clone(),
            work_lock_manager::KeepaliveConfig::default(),
        )
        .await
        .expect("work_lock_manager failed to start: no available connections?");

        let api = TestApiBuilder::new(db_pool, common_pools, work_lock_manager_handle)
            .with_metric_emitter(ApiMetricsEmitter::new(&test_meter.meter()))
            .build();
        ApiHandle {
            api,
            _drop_guard: cancel_token.clone().drop_guard(),
            cancel_token,
            _js: join_set,
        }
    }
}
