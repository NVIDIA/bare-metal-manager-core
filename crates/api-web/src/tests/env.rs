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

use carbide_test_harness::dns::TestDomain;
use carbide_test_harness::network::segment::TestNetworkSegment;
use carbide_test_harness::prelude::*;
use model::machine::ManagedHostState;

pub struct TestEnv {
    pub test_harness: TestHarness,
    site_explorer: TestSiteExplorer,
    domain: TestDomain,
    underlay_segment: TestNetworkSegment,
    admin_segment: TestNetworkSegment,
}

impl TestEnv {
    pub async fn new(pool: PgPool) -> Self {
        let test_harness = TestHarness::builder(pool)
            .with_resource_pools(
                ResourcePoolBuilder::default()
                    .with_vlan_ids(1, 64)
                    .with_vnis(10001, 10064)
                    .with_secondary_vtep_ip("192.0.7.0/24")
                    .build(),
            )
            .build()
            .await;
        let domain = test_harness.test_domain().await;
        let network_controller = test_harness.network_controller();
        let underlay_segment = network_controller.create_underlay_segment(&domain).await;
        let admin_segment = network_controller.create_admin_segment(&domain).await;
        let site_explorer = test_harness.default_test_site_explorer();
        Self {
            test_harness,
            site_explorer,
            domain,
            underlay_segment,
            admin_segment,
        }
    }

    pub fn api(&self) -> &Api {
        self.test_harness.api()
    }

    pub fn domain(&self) -> &TestDomain {
        &self.domain
    }

    pub async fn create_ready_managed_host(&self, dpu_count: usize) -> TestManagedHost {
        let mut host = self
            .test_harness
            .managed_host_builder(&self.site_explorer, self.underlay_segment)
            .with_dpu_count(dpu_count)
            .build()
            .await;

        host.discover_host_primary_iface(self.api(), self.admin_segment)
            .await;
        host.discover_dpu_oob_ifaces(self.api(), self.admin_segment)
            .await;
        host.report_dpu_network_status(self.api()).await;
        host.insert_empty_host_health_report(self.api(), "test-harness-health")
            .await;
        host.advance_host_state(&self.test_harness, ManagedHostState::Ready)
            .await;
        host
    }
}
