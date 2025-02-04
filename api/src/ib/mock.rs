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
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use super::iface::Filter;
use super::types::{IBNetwork, IBPort, IBPortState};
use super::{IBFabric, IBFabricVersions};
use crate::CarbideError;

pub struct MockIBFabric {
    pub ibsubnets: Arc<Mutex<HashMap<String, IBNetwork>>>,
    pub ibports: Arc<Mutex<HashMap<String, IBPort>>>,
    pub ibdesc: HashMap<String, IBPort>,
}

#[async_trait]
impl IBFabric for MockIBFabric {
    /// Get all IB Networks
    async fn get_ib_networks(&self) -> Result<HashMap<u16, IBNetwork>, CarbideError> {
        let ibsubnets = self
            .ibsubnets
            .lock()
            .map_err(|_| CarbideError::IBFabricError("get_ib_network mutex lock".to_string()))?;

        let mut results = HashMap::new();
        for (pkey, subnet) in &*ibsubnets {
            let pkey: u16 = pkey
                .parse()
                .map_err(|_| CarbideError::IBFabricError("pkey is not a u16".to_string()))?;
            results.insert(pkey, subnet.clone());
        }

        Ok(results)
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

    async fn bind_ib_ports(&self, ib: IBNetwork, ports: Vec<String>) -> Result<(), CarbideError> {
        {
            let mut ibports = self.ibports.lock().map_err(|_| {
                CarbideError::IBFabricError("create_ib_port mutex lock".to_string())
            })?;
            for port in ports {
                if !ibports.contains_key(&port) {
                    ibports.insert(
                        port.clone(),
                        IBPort {
                            name: port.clone(),
                            guid: port.clone(),
                            lid: 1,
                            state: Some(IBPortState::Active),
                        },
                    );
                }
            }
        }
        {
            let mut ibsubnets = self
                .ibsubnets
                .lock()
                .map_err(|_| CarbideError::IBFabricError("bind_ib_ports mutex lock".to_string()))?;

            let pkey = ib.clone().pkey.clone().to_string();
            if !ibsubnets.contains_key(&pkey) {
                ibsubnets.insert(pkey.clone(), ib);
            }
        }

        Ok(())
    }

    /// Update IBNetwork, e.g. QoS
    async fn update_ib_network(&self, ibnetwork: &IBNetwork) -> Result<(), CarbideError> {
        let mut ibsubnets = self
            .ibsubnets
            .lock()
            .map_err(|_| CarbideError::IBFabricError("update_ib_network mutex lock".to_string()))?;

        match ibsubnets.get_mut(&ibnetwork.pkey.to_string()) {
            Some(ib) => {
                // Update QoS accordingly
                ib.mtu = ibnetwork.mtu.clone();
                ib.rate_limit = ibnetwork.rate_limit.clone();
                ib.service_level = ibnetwork.service_level.clone();
                Ok(())
            }
            None => Err(CarbideError::IBFabricError(
                "ib subnet not found".to_string(),
            )),
        }
    }

    /// Find IBPort
    async fn find_ib_port(&self, filter: Option<Filter>) -> Result<Vec<IBPort>, CarbideError> {
        let ibports_pkey = self
            .ibports
            .lock()
            .map_err(|_| CarbideError::IBFabricError("find_ib_port mutex lock".to_string()))?;

        let mut ports = vec![];
        for ib in self.ibdesc.values() {
            ports.push(ib.clone());
        }

        let f = filter.unwrap_or_default();
        let pkey_guids = match &f.pkey {
            Some(pkey) => {
                let ibsubnets = self.ibsubnets.lock().map_err(|_| {
                    CarbideError::IBFabricError("find_ib_port mutex lock".to_string())
                })?;
                let mut pkey_guids = HashSet::new();
                if ibsubnets.contains_key(&pkey.to_string()) {
                    for ib in ibports_pkey.values() {
                        pkey_guids.insert(ib.guid.clone());
                    }
                }
                Some(pkey_guids)
            }
            None => None,
        };

        Ok(filter_ports(ports, pkey_guids, f.guids, f.state))
    }

    /// Delete IBPort
    async fn unbind_ib_ports(&self, _pkey: u16, ids: Vec<String>) -> Result<(), CarbideError> {
        let mut ibports = self
            .ibports
            .lock()
            .map_err(|_| CarbideError::IBFabricError("delete_ib_port mutex lock".to_string()))?;

        for id in &ids {
            if !ibports.contains_key(id) {
                return Err(CarbideError::NotFoundError {
                    kind: "",
                    id: id.to_string(),
                });
            }

            ibports.remove(id);
        }

        Ok(())
    }

    /// Returns IB fabric related versions
    async fn versions(&self) -> Result<IBFabricVersions, CarbideError> {
        let ufm_version = "mock_ufm_1.0".to_string();

        Ok(IBFabricVersions { ufm_version })
    }
}

pub fn mock_ibfabric_desc(ibports: Option<HashMap<String, IBPort>>) -> HashMap<String, IBPort> {
    match ibports {
        Some(ibports) => {
            assert!(!ibports.is_empty());
            ibports
        }
        None => {
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/model/hardware_info/test_data/x86_info.json"
            )
            .to_string();

            let data = std::fs::read(path).unwrap();
            let hw_info =
                serde_json::from_slice::<crate::model::hardware_info::HardwareInfo>(&data).unwrap();
            assert!(!hw_info.infiniband_interfaces.is_empty());

            let mut ibports: HashMap<String, IBPort> = HashMap::new();
            for ib in hw_info.infiniband_interfaces {
                if !ibports.contains_key(&ib.guid) {
                    ibports.insert(
                        ib.guid.clone(),
                        IBPort {
                            name: ib.guid.clone(),
                            guid: ib.guid.clone(),
                            lid: (ibports.len() + 1) as i32,
                            state: Some(IBPortState::Active),
                        },
                    );
                }
            }
            assert!(!ibports.is_empty());
            ibports
        }
    }
}

fn filter_ports(
    ports: Vec<IBPort>,
    pkey_guids: Option<HashSet<String>>,
    guids: Option<HashSet<String>>,
    state: Option<IBPortState>,
) -> Vec<IBPort> {
    let guid_filter = match (pkey_guids, guids) {
        // If both are None, means no filter, return all ports.
        (None, None) => None,
        // If just one is None, filter ports by the other guids set.
        (Some(pkey_guids), None) => Some(pkey_guids),
        (None, Some(guids)) => Some(guids),
        // If both are Some, filter ports by the intersection.
        (Some(pkey_guids), Some(guids)) => Some(pkey_guids.intersection(&guids).cloned().collect()),
    };

    let ports = match guid_filter {
        // If no filter, return all ports;
        None => ports,
        // otherwise, filter ports accordingly.
        Some(filter) => ports
            .into_iter()
            .filter(|p: &IBPort| filter.contains(&p.guid))
            .collect(),
    };

    let ports = match state {
        None => ports,
        Some(state) => ports
            .into_iter()
            .filter(|v| v.state.as_ref() == Some(&state))
            .collect(),
    };

    ports
}
