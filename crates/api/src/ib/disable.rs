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

use std::collections::HashMap;

use async_trait::async_trait;
use model::ib::{IBNetwork, IBPort, IBQosConf};

use super::iface::{Filter, GetPartitionOptions, IBFabricRawResponse};
use super::{IBFabric, IBFabricConfig, IBFabricVersions};
use crate::CarbideError;

pub struct DisableIBFabric {}

#[async_trait]
impl IBFabric for DisableIBFabric {
    /// Get fabric configuration
    async fn get_fabric_config(&self) -> Result<IBFabricConfig, CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }

    /// Get IBNetwork by ID
    async fn get_ib_network(
        &self,
        _: u16,
        _options: GetPartitionOptions,
    ) -> Result<IBNetwork, CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }

    async fn get_ib_networks(
        &self,
        _options: GetPartitionOptions,
    ) -> Result<HashMap<u16, IBNetwork>, CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }

    async fn bind_ib_ports(&self, _: IBNetwork, _: Vec<String>) -> Result<(), CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }

    /// Update an IB Partitions QoS configuration
    async fn update_partition_qos_conf(
        &self,
        _pkey: u16,
        _qos_conf: &IBQosConf,
    ) -> Result<(), CarbideError> {
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
    async fn unbind_ib_ports(&self, _: u16, _: Vec<String>) -> Result<(), CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }

    /// Returns IB fabric related versions
    async fn versions(&self) -> Result<IBFabricVersions, CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }

    /// Make a raw HTTP GET request to the Fabric Manager using the given path,
    /// and return the response body.
    async fn raw_get(&self, _path: &str) -> Result<IBFabricRawResponse, CarbideError> {
        Err(CarbideError::IBFabricError(
            "ib fabric is disabled".to_string(),
        ))
    }
}
