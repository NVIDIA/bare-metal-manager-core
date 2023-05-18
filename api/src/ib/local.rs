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
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::ib::types::{IBNetwork, IBPort, IBPortState};
use crate::ib::IBFabricManager;
use crate::model::ib_subnet::IBSubnetControllerState;
use crate::CarbideError;

pub struct LocalIBFabricManager {
    pub ibsubnets: Arc<Mutex<HashMap<String, IBNetwork>>>,
    pub ibports: Arc<Mutex<HashMap<String, IBPort>>>,
}

#[async_trait]
impl IBFabricManager for LocalIBFabricManager {
    /// Create IBNetwork
    async fn create_ib_network(&self, ib: IBNetwork) -> Result<(), CarbideError> {
        let mut ibsubnets = self
            .ibsubnets
            .lock()
            .map_err(|_| CarbideError::IBFabricError("create_ib_network mutex lock".to_string()))?;

        if ibsubnets.contains_key(&ib.name) {
            return Err(CarbideError::IBFabricError(
                "duplicated ib subnet".to_string(),
            ));
        }

        ibsubnets.insert(
            ib.name.clone(),
            IBNetwork {
                state: Some(IBSubnetControllerState::Ready),
                ..ib
            },
        );

        Ok(())
    }

    /// Delete IBNetwork
    async fn delete_ib_network(&self, id: &str) -> Result<(), CarbideError> {
        let mut ibsubnets = self
            .ibsubnets
            .lock()
            .map_err(|_| CarbideError::IBFabricError("delete_ib_network mutex lock".to_string()))?;

        if !ibsubnets.contains_key(id) {
            return Err(CarbideError::NotFoundError {
                kind: "",
                id: id.to_string(),
            });
        }

        ibsubnets.remove(id);

        Ok(())
    }

    /// Get IBNetwork by ID
    async fn get_ib_network(&self, id: &str) -> Result<IBNetwork, CarbideError> {
        let ibsubnets = self
            .ibsubnets
            .lock()
            .map_err(|_| CarbideError::IBFabricError("get_ib_network mutex lock".to_string()))?;

        match ibsubnets.get(id) {
            None => Err(CarbideError::NotFoundError {
                kind: "",
                id: id.to_string(),
            }),
            Some(ib) => Ok(ib.clone()),
        }
    }

    /// Find IBSubnet
    async fn find_ib_network(&self) -> Result<Vec<IBNetwork>, CarbideError> {
        let ibsubnets = self
            .ibsubnets
            .lock()
            .map_err(|_| CarbideError::IBFabricError("find_ib_network mutex lock".to_string()))?;

        let mut ibs = vec![];
        for ib in ibsubnets.values() {
            ibs.push(ib.clone());
        }

        Ok(ibs)
    }

    /// Create IBPort
    async fn create_ib_port(&self, port: IBPort) -> Result<(), CarbideError> {
        let mut ibports = self
            .ibports
            .lock()
            .map_err(|_| CarbideError::IBFabricError("create_ib_port mutex lock".to_string()))?;

        if ibports.contains_key(&port.guid) {
            return Err(CarbideError::IBFabricError(
                "duplicated ib port".to_string(),
            ));
        }

        ibports.insert(
            port.guid.clone(),
            IBPort {
                state: Some(IBPortState::Active),
                ..port
            },
        );

        Ok(())
    }

    /// Get IBPort
    async fn get_ib_port(&self, id: &str) -> Result<IBPort, CarbideError> {
        let ibports = self
            .ibports
            .lock()
            .map_err(|_| CarbideError::IBFabricError("get_ib_port mutex lock".to_string()))?;

        match ibports.get(id) {
            None => Err(CarbideError::NotFoundError {
                kind: "",
                id: id.to_string(),
            }),
            Some(ib) => Ok(ib.clone()),
        }
    }

    /// Find IBPort
    async fn find_ib_port(&self) -> Result<Vec<IBPort>, CarbideError> {
        let ibports = self
            .ibports
            .lock()
            .map_err(|_| CarbideError::IBFabricError("find_ib_port mutex lock".to_string()))?;

        let mut ibs = vec![];
        for ib in ibports.values() {
            ibs.push(ib.clone());
        }

        Ok(ibs)
    }

    /// Delete IBPort
    async fn delete_ib_port(&self, id: &str) -> Result<(), CarbideError> {
        let mut ibports = self
            .ibports
            .lock()
            .map_err(|_| CarbideError::IBFabricError("delete_ib_port mutex lock".to_string()))?;

        if !ibports.contains_key(id) {
            return Err(CarbideError::NotFoundError {
                kind: "",
                id: id.to_string(),
            });
        }

        ibports.remove(id);

        Ok(())
    }
}
