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

use std::sync::Arc;

use carbide_site_explorer::SiteExplorer;
use carbide_site_explorer::config::SiteExplorerConfig;
use carbide_test_harness::network::segment::TestNetworkSegment;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::endpoint_explorer::MockEndpointExplorer;

pub struct Env {
    pub pool: PgPool,
    pub underlay_segment: TestNetworkSegment,
    pub test_harness: TestHarness,
}

impl Env {
    pub async fn new(pool: PgPool) -> Self {
        let test_harness = TestHarness::builder(pool.clone()).build().await;
        let domain = test_harness.test_domain().await;
        let nc = test_harness.network_controller();
        let underlay_segment = nc.create_underlay_segment(&domain).await;
        Self {
            pool,
            underlay_segment,
            test_harness,
        }
    }

    pub fn api(&self) -> &Api {
        self.test_harness.api()
    }

    pub fn new_site_explorer(
        &self,
        explorer_config: SiteExplorerConfig,
        endpoint_explorer: &Arc<MockEndpointExplorer>,
    ) -> SiteExplorer {
        SiteExplorer::new(
            self.api().database_connection.clone(),
            explorer_config,
            self.test_harness.test_meter.meter(),
            endpoint_explorer.clone(),
            Arc::new(self.api().runtime_config.get_firmware_config()),
            self.api().common_pools().clone(),
            self.api().work_lock_manager_handle(),
            None,
            self.api().credential_manager().clone(),
        )
    }
}
