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

use std::sync::Arc;

use model::resource_pool::common::IbPools;
use sqlx::PgPool;

use crate::cfg::file::CarbideConfig;
use crate::dpa::DpaInfo;
use crate::ib::IBFabricManager;
use crate::ipmitool::IPMITool;
use crate::rack::rms_client::RmsApi;
use crate::redfish::RedfishClientPool;

/// Services that are accessible to all statehandlers within carbide-core
#[derive(Clone)]
pub struct CommonStateHandlerServices {
    /// Postgres database pool
    pub db_pool: PgPool,

    /// API for interaction with Libredfish
    pub redfish_client_pool: Arc<dyn RedfishClientPool>,

    /// API for interaction with Forge IBFabricManager
    pub ib_fabric_manager: Arc<dyn IBFabricManager>,

    /// Resource pools for ib pkey allocation/release.
    pub ib_pools: IbPools,

    /// An implementation of the IPMITool that understands how to reboot a machine
    pub ipmi_tool: Arc<dyn IPMITool>,

    /// Access to the site config
    pub site_config: Arc<CarbideConfig>,

    pub dpa_info: Option<Arc<DpaInfo>>,

    /// Rack Manager Service client
    /// Optional for now, but will be required in the future.
    #[allow(dead_code)]
    pub rms_client: Option<Arc<dyn RmsApi>>,
}
