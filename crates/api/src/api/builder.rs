/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::sync::Arc;

use db::work_lock_manager::WorkLockManagerHandle;
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;
use model::resource_pool::common::CommonPools;
use opentelemetry::metrics::Meter;
use sqlx::PgPool;

use super::{Api, ApiMetrics};
use crate::cfg::file::CarbideConfig;
use crate::dynamic_settings::DynamicSettings;
use crate::ethernet_virtualization::EthVirtData;
use crate::ib::IBFabricManager;
use crate::logging::log_limiter::LogLimiter;
use crate::nvlink::NmxmClientPool;
use crate::rack::rms_client::RmsApi;
use crate::redfish::RedfishClientPool;
use crate::scout_stream::ConnectionRegistry;
use crate::site_explorer::EndpointExplorer;

/// Builder for creating Api instances with all dependencies
pub struct ApiBuilder {
    database_connection: PgPool,
    credential_provider: Arc<dyn CredentialProvider>,
    certificate_provider: Arc<dyn CertificateProvider>,
    redfish_pool: Arc<dyn RedfishClientPool>,
    eth_data: EthVirtData,
    common_pools: Arc<CommonPools>,
    ib_fabric_manager: Arc<dyn IBFabricManager>,
    runtime_config: Arc<CarbideConfig>,
    dynamic_settings: DynamicSettings,
    endpoint_explorer: Arc<dyn EndpointExplorer>,
    rms_client: Option<Arc<Box<dyn RmsApi>>>,
    nmxm_pool: Arc<dyn NmxmClientPool>,
    work_lock_manager_handle: WorkLockManagerHandle,
}

impl ApiBuilder {
    /// Creates a new ApiBuilder with required dependencies
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database_connection: PgPool,
        credential_provider: Arc<dyn CredentialProvider>,
        certificate_provider: Arc<dyn CertificateProvider>,
        redfish_pool: Arc<dyn RedfishClientPool>,
        eth_data: EthVirtData,
        common_pools: Arc<CommonPools>,
        ib_fabric_manager: Arc<dyn IBFabricManager>,
        runtime_config: Arc<CarbideConfig>,
        dynamic_settings: DynamicSettings,
        endpoint_explorer: Arc<dyn EndpointExplorer>,
        nmxm_pool: Arc<dyn NmxmClientPool>,
        work_lock_manager_handle: WorkLockManagerHandle,
    ) -> Self {
        Self {
            database_connection,
            credential_provider,
            certificate_provider,
            redfish_pool,
            eth_data,
            common_pools,
            ib_fabric_manager,
            runtime_config,
            dynamic_settings,
            endpoint_explorer,
            rms_client: None,
            nmxm_pool,
            work_lock_manager_handle,
        }
    }

    /// Sets the RMS client (optional)
    pub fn with_rms_client(mut self, rms_client: Option<Arc<Box<dyn RmsApi>>>) -> Self {
        self.rms_client = rms_client;
        self
    }

    /// Builds the Api instance with all metrics initialized
    pub fn build(self, meter: &Meter) -> Api {
        let metrics = ApiMetrics::new(meter);

        Api {
            database_connection: self.database_connection,
            credential_provider: self.credential_provider,
            certificate_provider: self.certificate_provider,
            redfish_pool: self.redfish_pool,
            eth_data: self.eth_data,
            common_pools: self.common_pools,
            ib_fabric_manager: self.ib_fabric_manager,
            runtime_config: self.runtime_config,
            dpu_health_log_limiter: LogLimiter::default(),
            dynamic_settings: self.dynamic_settings,
            endpoint_explorer: self.endpoint_explorer,
            scout_stream_registry: ConnectionRegistry::new(),
            rms_client: self.rms_client,
            nmxm_pool: self.nmxm_pool,
            work_lock_manager_handle: self.work_lock_manager_handle,
            metrics,
        }
    }
}
