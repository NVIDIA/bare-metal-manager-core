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

use super::iface::Filter;
use super::types::{IBNetwork, IBPort};
use super::IBFabric;
use crate::CarbideError;

pub struct DisableIBFabric {}

#[async_trait]
impl IBFabric for DisableIBFabric {
    /// Delete IBNetwork
    async fn delete_ib_network(&self, _: &str) -> Result<(), CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }

    /// Get IBNetwork by ID
    async fn get_ib_network(&self, _: &str) -> Result<IBNetwork, CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }

    /// Find IBSubnet
    async fn find_ib_network(&self) -> Result<Vec<IBNetwork>, CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }

    async fn bind_ib_ports(&self, _: IBNetwork, _: Vec<String>) -> Result<(), CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }

    /// Find IBPort
    async fn find_ib_port(&self, _: Option<Filter>) -> Result<Vec<IBPort>, CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }

    /// Delete IBPort
    async fn unbind_ib_ports(&self, _: i32, _: Vec<String>) -> Result<(), CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }
}
