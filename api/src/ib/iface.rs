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

use crate::ib::types::{IBNetwork, IBPort};
use crate::CarbideError;

#[async_trait]
pub trait IBFabricManager: Send + Sync {
    /// Create IBNetwork
    async fn create_ib_network(&self, ib: IBNetwork) -> Result<(), CarbideError>;

    /// Delete IBNetwork
    async fn delete_ib_network(&self, id: &str) -> Result<(), CarbideError>;

    /// Get IBNetwork by ID
    async fn get_ib_network(&self, id: &str) -> Result<IBNetwork, CarbideError>;

    /// Find IBNetwork
    async fn find_ib_network(&self) -> Result<Vec<IBNetwork>, CarbideError>;

    /// Create IBPort
    async fn create_ib_port(&self, port: IBPort) -> Result<(), CarbideError>;

    /// Get IBPort
    async fn get_ib_port(&self, id: &str) -> Result<IBPort, CarbideError>;

    /// Find IBPort
    async fn find_ib_port(&self) -> Result<Vec<IBPort>, CarbideError>;

    /// Delete IBPort
    async fn delete_ib_port(&self, id: &str) -> Result<(), CarbideError>;
}
