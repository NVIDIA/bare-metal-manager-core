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

use std::sync::Arc;

use async_trait::async_trait;

use super::iface::Filter;
use super::types::{IBNetwork, IBPort, IBNETWORK_DEFAULT_INDEX0, IBNETWORK_DEFAULT_MEMBERSHIP};
use super::ufmclient::{
    self, Partition, PartitionKey, PartitionQoS, Port, PortConfig, PortMembership, UFMConfig,
    UFMError, Ufm,
};
use super::{IBFabric, IBFabricVersions};
use crate::CarbideError;

pub struct RestIBFabric {
    ufm: Ufm,
}

const DEFAULT_INDEX0: bool = true;
const DEFAULT_MEMBERSHIP: PortMembership = PortMembership::Full;

pub async fn connect(addr: &str, token: &str) -> Result<Arc<dyn IBFabric>, CarbideError> {
    let conf = UFMConfig {
        address: addr.to_string(),
        username: None,
        password: None,
        token: Some(token.to_string()),
    };

    let ufm = ufmclient::connect(conf).map_err(CarbideError::from)?;

    Ok(Arc::new(RestIBFabric { ufm }))
}

#[async_trait]
impl IBFabric for RestIBFabric {
    /// Delete IBNetwork
    async fn delete_ib_network(&self, pkey: &str) -> Result<(), CarbideError> {
        self.ufm
            .delete_partition(pkey)
            .await
            .map_err(CarbideError::from)
    }

    /// Get IBNetwork by ID
    async fn get_ib_network(&self, pkey: &str) -> Result<IBNetwork, CarbideError> {
        self.ufm
            .get_partition(pkey)
            .await
            .map(IBNetwork::from)
            .map_err(CarbideError::from)
    }

    /// Find IBSubnet
    async fn find_ib_network(&self) -> Result<Vec<IBNetwork>, CarbideError> {
        self.ufm
            .list_partition()
            .await
            .map(|p| p.iter().map(IBNetwork::from).collect())
            .map_err(CarbideError::from)
    }

    /// Create IBPort
    async fn bind_ib_ports(
        &self,
        ibnetwork: IBNetwork,
        ports: Vec<String>,
    ) -> Result<(), CarbideError> {
        let partition = Partition::try_from(ibnetwork)?;
        let ports = ports.iter().map(PortConfig::from).collect();

        self.ufm
            .bind_ports(partition, ports)
            .await
            .map_err(CarbideError::from)
    }

    /// Delete IBPort
    async fn unbind_ib_ports(&self, pkey: i32, ids: Vec<String>) -> Result<(), CarbideError> {
        let pkey = PartitionKey::try_from(pkey).map_err(CarbideError::from)?;

        self.ufm
            .unbind_ports(pkey, ids)
            .await
            .map_err(CarbideError::from)
    }

    /// Find IBPort
    async fn find_ib_port(&self, filter: Option<Filter>) -> Result<Vec<IBPort>, CarbideError> {
        let filter = filter.map(ufmclient::Filter::try_from).transpose()?;
        self.ufm
            .list_port(filter)
            .await
            .map(|p| p.iter().map(IBPort::from).collect())
            .map_err(CarbideError::from)
    }

    /// Returns IB fabric related versions
    async fn versions(&self) -> Result<IBFabricVersions, CarbideError> {
        let ufm_version = self.ufm.version().await?;

        Ok(IBFabricVersions { ufm_version })
    }
}

impl From<UFMError> for CarbideError {
    fn from(e: UFMError) -> Self {
        match e {
            UFMError::NotFound(id) => CarbideError::NotFoundError { kind: "", id },
            _ => CarbideError::IBFabricError(e.to_string()),
        }
    }
}

impl From<Partition> for IBNetwork {
    fn from(p: Partition) -> Self {
        IBNetwork::from(&p)
    }
}

impl From<&Partition> for IBNetwork {
    fn from(p: &Partition) -> Self {
        IBNetwork {
            name: p.name.clone(),
            pkey: p.pkey.clone().into(),
            enable_sharp: false,
            mtu: p.qos.mtu_limit,
            ipoib: p.ipoib,
            service_level: p.qos.service_level,
            rate_limit: p.qos.rate_limit,
            membership: IBNETWORK_DEFAULT_MEMBERSHIP,
            index0: IBNETWORK_DEFAULT_INDEX0,
        }
    }
}

impl TryFrom<Filter> for ufmclient::Filter {
    type Error = CarbideError;
    fn try_from(filter: Filter) -> Result<Self, Self::Error> {
        Ok(Self {
            guids: filter.guids.clone(),
            pkey: filter
                .pkey
                .map(ufmclient::PartitionKey::try_from)
                .transpose()?,
        })
    }
}

impl TryFrom<IBNetwork> for Partition {
    type Error = CarbideError;
    fn try_from(p: IBNetwork) -> Result<Self, Self::Error> {
        Partition::try_from(&p)
    }
}

impl TryFrom<&IBNetwork> for Partition {
    type Error = CarbideError;
    fn try_from(p: &IBNetwork) -> Result<Self, Self::Error> {
        Ok(Partition {
            name: p.name.clone(),
            pkey: PartitionKey::try_from(p.pkey)
                .map_err(|_| CarbideError::IBFabricError("invalid pkey".to_string()))?,
            ipoib: p.ipoib,
            qos: PartitionQoS {
                mtu_limit: p.mtu,
                service_level: p.service_level,
                rate_limit: p.rate_limit,
            },
        })
    }
}

impl From<&Port> for IBPort {
    fn from(p: &Port) -> Self {
        IBPort {
            name: p.name.clone(),
            guid: p.guid.clone(),
            lid: p.lid,
            state: None,
        }
    }
}

impl From<Port> for IBPort {
    fn from(p: Port) -> Self {
        IBPort::from(&p)
    }
}

impl From<&IBPort> for PortConfig {
    fn from(p: &IBPort) -> Self {
        PortConfig {
            guid: p.guid.clone(),
            index0: DEFAULT_INDEX0,
            membership: DEFAULT_MEMBERSHIP,
        }
    }
}

impl From<IBPort> for PortConfig {
    fn from(p: IBPort) -> Self {
        PortConfig::from(&p)
    }
}

impl From<&String> for PortConfig {
    fn from(guid: &String) -> Self {
        PortConfig {
            guid: guid.clone(),
            index0: DEFAULT_INDEX0,
            membership: DEFAULT_MEMBERSHIP,
        }
    }
}

impl From<String> for PortConfig {
    fn from(guid: String) -> Self {
        PortConfig::from(&guid)
    }
}
