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
