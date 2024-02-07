/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use async_trait::async_trait;
use std::sync::Arc;

use crate::ib::types::{IBNetwork, IBPort};
use crate::ib::IBFabricManagerConfig;
use crate::CarbideError;

#[derive(Default)]
pub struct Filter {
    pub guids: Option<Vec<String>>,
    pub pkey: Option<i32>,
}

#[async_trait]
pub trait IBFabricManager: Send + Sync {
    async fn connect(&self, fabric_name: String) -> Result<Arc<dyn IBFabric>, CarbideError>;
    fn get_config(&self) -> IBFabricManagerConfig;
}

#[async_trait]
pub trait IBFabric: Send + Sync {
    /// Delete IBNetwork
    async fn delete_ib_network(&self, id: &str) -> Result<(), CarbideError>;

    /// Get IBNetwork by ID
    async fn get_ib_network(&self, id: &str) -> Result<IBNetwork, CarbideError>;

    /// Find IBNetwork
    async fn find_ib_network(&self) -> Result<Vec<IBNetwork>, CarbideError>;

    /// Create IBPort
    async fn bind_ib_ports(
        &self,
        ibnetwork: IBNetwork,
        ports: Vec<String>,
    ) -> Result<(), CarbideError>;

    /// Delete IBPort
    async fn unbind_ib_ports(&self, pkey: i32, id: Vec<String>) -> Result<(), CarbideError>;

    /// Find IBPort
    async fn find_ib_port(&self, filter: Option<Filter>) -> Result<Vec<IBPort>, CarbideError>;
}
