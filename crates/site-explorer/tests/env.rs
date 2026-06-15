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
use carbide_site_explorer::test_support::{MockEndpointExplorer, TestSiteExplorer};
use carbide_test_harness::network::segment::TestNetworkSegment;
use carbide_test_harness::prelude::*;

/// Keep this shared env to the setup common to most site-explorer tests.
/// Tests that need extra domains, segments, or other one-off objects should
/// create those objects locally instead of adding fields here.
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

    pub fn test_site_explorer(&self, explorer_config: SiteExplorerConfig) -> TestSiteExplorer {
        test_site_explorer(&self.test_harness, explorer_config)
    }
}

pub fn test_site_explorer(
    test_harness: &TestHarness,
    explorer_config: SiteExplorerConfig,
) -> TestSiteExplorer {
    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let api = test_harness.api();
    let site_explorer = SiteExplorer::new(
        api.database_connection.clone(),
        explorer_config,
        test_harness.test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(api.runtime_config.get_firmware_config()),
        api.common_pools().clone(),
        api.work_lock_manager_handle(),
        None,
        api.credential_manager().clone(),
    );
    TestSiteExplorer::new(site_explorer, endpoint_explorer)
}
