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

use arc_swap::ArcSwap;
use carbide_ib_fabric::ib::IBFabricManager;
use carbide_machine_controller::dpf::DpfOperations;
use carbide_nvlink_manager::nvlink::test_support::NmxcSimClient;
use carbide_redfish::libredfish::RedfishClientPool;
use carbide_redfish::libredfish::test_support::RedfishSim;
use carbide_site_explorer::config::SiteExplorerExploreMode;
use carbide_utils::test_support::test_meter::TestMeter;
use db::work_lock_manager::WorkLockManagerHandle;
use forge_secrets::credentials::CredentialManager;
use forge_secrets::test_support::certificates::TestCertificateProvider;
use forge_secrets::test_support::credentials::TestCredentialManager;
use libnmxc::NmxcPool;
use librms::RmsApi;
use model::resource_pool::common::CommonPools;
use sqlx::PgPool;
use state_controller::controller::Enqueuer;
use tracing_subscriber::EnvFilter;

use super::Api;
use crate::api::metrics::ApiMetricsEmitter;
use crate::cfg::file::CarbideConfig;
use crate::dynamic_settings::DynamicSettings;
use crate::ethernet_virtualization::EthVirtData;
use crate::logging::level_filter::ActiveLevel;
use crate::logging::log_limiter::LogLimiter;
use crate::scout_stream::ConnectionRegistry;
use crate::test_support::default_config;
use crate::test_support::ib_fabric::ib_fabric_test_manager;
use crate::test_support::network::default_test_eth_virt_data;

pub struct TestApiBuilder {
    db_pool: PgPool,
    common_pools: Arc<CommonPools>,
    work_lock_manager: WorkLockManagerHandle,
    runtime_config: Option<Arc<CarbideConfig>>,
    credential_manager: Option<Arc<dyn CredentialManager>>,
    redfish_pool: Option<Arc<dyn RedfishClientPool>>,
    rms_client: Option<Arc<dyn RmsApi>>,
    nmxc_client_pool: Option<Arc<dyn NmxcPool>>,
    eth_data: Option<EthVirtData>,
    dpf_sdk: Option<Arc<dyn DpfOperations>>,
    metric_emitter: Option<ApiMetricsEmitter>,
    ib_fabric_manager: Option<Arc<dyn IBFabricManager>>,
}

impl TestApiBuilder {
    pub fn new(
        db_pool: PgPool,
        common_pools: Arc<CommonPools>,
        work_lock_manager: WorkLockManagerHandle,
    ) -> Self {
        TestApiBuilder {
            db_pool,
            common_pools,
            work_lock_manager,
            runtime_config: None,
            credential_manager: None,
            redfish_pool: None,
            rms_client: None,
            nmxc_client_pool: None,
            eth_data: None,
            dpf_sdk: None,
            metric_emitter: None,
            ib_fabric_manager: None,
        }
    }

    pub fn with_runtime_config(self, runtime_config: Arc<CarbideConfig>) -> Self {
        Self {
            runtime_config: Some(runtime_config),
            ..self
        }
    }

    pub fn with_credential_manager(self, credential_manager: Arc<dyn CredentialManager>) -> Self {
        Self {
            credential_manager: Some(credential_manager),
            ..self
        }
    }

    pub fn with_redfish_pool(self, redfish_pool: Arc<dyn RedfishClientPool>) -> Self {
        Self {
            redfish_pool: Some(redfish_pool),
            ..self
        }
    }

    pub fn with_nmxc_client_pool(self, nmxc_client_pool: Arc<dyn NmxcPool>) -> Self {
        Self {
            nmxc_client_pool: Some(nmxc_client_pool),
            ..self
        }
    }

    pub fn with_eth_data(self, eth_data: EthVirtData) -> Self {
        Self {
            eth_data: Some(eth_data),
            ..self
        }
    }

    pub fn with_dpf_sdk(self, dpf_sdk: Arc<dyn DpfOperations>) -> Self {
        Self {
            dpf_sdk: Some(dpf_sdk),
            ..self
        }
    }

    pub fn with_rms_client(self, rms_client: Arc<dyn RmsApi>) -> Self {
        Self {
            rms_client: Some(rms_client),
            ..self
        }
    }

    pub fn with_metric_emitter(self, metric_emitter: ApiMetricsEmitter) -> Self {
        Self {
            metric_emitter: Some(metric_emitter),
            ..self
        }
    }

    pub fn with_ib_fabric_manager(self, ib_fabric_manager: Arc<dyn IBFabricManager>) -> Self {
        Self {
            ib_fabric_manager: Some(ib_fabric_manager),
            ..self
        }
    }

    pub fn build(self) -> Api {
        let runtime_config = self
            .runtime_config
            .unwrap_or_else(|| Arc::new(default_config::get()));

        let scout_stream_registry = ConnectionRegistry::new();
        let credential_manager = self
            .credential_manager
            .unwrap_or_else(|| Arc::new(TestCredentialManager::default()));

        let certificate_provider = Arc::new(TestCertificateProvider::new());
        let machine_state_handler_enqueuer = Enqueuer::new(self.db_pool.clone());
        let dpu_health_log_limiter = LogLimiter::default();

        let redfish_pool = self
            .redfish_pool
            .unwrap_or_else(|| Arc::new(RedfishSim::default()));

        let eth_data = self.eth_data.unwrap_or_else(default_test_eth_virt_data);
        let ib_fabric_manager = self
            .ib_fabric_manager
            .unwrap_or_else(|| ib_fabric_test_manager(&runtime_config, credential_manager.clone()));

        let bmc_proxy = Arc::new(ArcSwap::new(None.into()));
        let nv_redfish_pool = carbide_redfish::nv_redfish::new_pool(bmc_proxy);
        let bmc_session_store: Arc<dyn crate::credentials::BmcSessionStore> = Arc::new(
            crate::credentials::PgBmcSessionStore::new(self.db_pool.clone()),
        );
        let bmc_session_manager = Arc::new(crate::credentials::BmcSessionManager::new(
            nv_redfish_pool.clone(),
            credential_manager.clone(),
            bmc_session_store,
            runtime_config.bmc_session_lockout_threshold,
            runtime_config.allow_bmc_basic_auth_fallback,
        ));

        let endpoint_explorer = carbide_site_explorer::new_bmc_explorer(
            redfish_pool.clone(),
            nv_redfish_pool,
            carbide_ipmi::test_support(),
            credential_manager.clone(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            // Tests use MockEndpointExplorer. So this doesn't affect anything.
            SiteExplorerExploreMode::NvRedfish,
        );

        let metric_emitter = self.metric_emitter.unwrap_or_else(|| {
            let test_meter = TestMeter::default();
            ApiMetricsEmitter::new(&test_meter.meter())
        });

        let dynamic_settings = DynamicSettings {
            log_filter: Arc::new(ActiveLevel::new(
                EnvFilter::builder()
                    .parse(std::env::var("RUST_LOG").unwrap_or("trace".to_string()))
                    .unwrap(),
                None,
            )),
            site_explorer_enabled: runtime_config.site_explorer.enabled.clone(),
            create_machines: runtime_config.site_explorer.create_machines.clone(),
            bmc_proxy: runtime_config.site_explorer.bmc_proxy.clone(),
            tracing_enabled: Arc::new(false.into()),
            log_stream: Default::default(),
        };

        let nmxc_client_pool = self
            .nmxc_client_pool
            .unwrap_or_else(|| Arc::new(NmxcSimClient::default()));

        Api {
            dpf_sdk: self.dpf_sdk,
            runtime_config,
            credential_manager,
            certificate_provider,
            database_connection: self.db_pool,
            redfish_pool,
            eth_data,
            common_pools: self.common_pools,
            ib_fabric_manager,
            dynamic_settings,
            endpoint_explorer,
            dpu_health_log_limiter,
            scout_stream_registry,
            rms_client: self.rms_client,
            nmxc_client_pool,
            work_lock_manager_handle: self.work_lock_manager,
            machine_state_handler_enqueuer,
            metric_emitter,
            component_manager: None,
            bmc_session_manager,
            bms_client: std::sync::OnceLock::new(),
        }
    }
}
