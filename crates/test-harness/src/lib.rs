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

use std::ops::Deref;
use std::sync::Arc;

use carbide_api_core::test_support::rpc::forge::forge_server::Forge;
pub use carbide_api_core::test_support::{self, Api, rpc};
use carbide_utils::test_support::test_meter::TestMeter;
use sqlx::PgPool;
use tokio::task::JoinSet;
use tokio_util::sync::{CancellationToken, DropGuard};
use tonic::Request;

use crate::builder::TestHarnessBuilder;
use crate::dns::TestDomain;
use crate::network::controller::TestNetworkController;

pub mod builder;
pub mod dns;
pub mod network;
pub mod prelude;

pub struct TestHarness {
    api: Arc<ApiHandle>,
    pub test_meter: TestMeter,
    processor_id: String,
}

impl TestHarness {
    pub fn builder(db_pool: PgPool) -> TestHarnessBuilder {
        builder::TestHarnessBuilder {
            db_pool,
            api: None,
            test_meter: None,
        }
    }

    pub fn api(&self) -> &Api {
        self.api.deref()
    }

    pub async fn test_domain(&self) -> TestDomain {
        let name = "testharness.example.com";
        let id = self
            .api
            .create_domain(Request::new(rpc::protos::dns::CreateDomainRequest {
                name: name.to_string(),
            }))
            .await
            .unwrap()
            .into_inner()
            .id
            .map(::carbide_uuid::domain::DomainId::try_from)
            .unwrap()
            .unwrap();
        TestDomain { id, name }
    }

    pub fn network_controller(&self) -> TestNetworkController {
        TestNetworkController::new(
            self.api.clone(),
            self.processor_id.clone(),
            &self.test_meter,
        )
    }
}

struct ApiHandle {
    api: Api,
    cancel_token: CancellationToken,
    _drop_guard: DropGuard,
    _js: JoinSet<()>,
}

impl Deref for ApiHandle {
    type Target = Api;
    fn deref(&self) -> &Self::Target {
        &self.api
    }
}

#[ctor::ctor(unsafe)]
fn setup_test_logging() {
    carbide_api_core::test_support::setup_test_logging()
}
