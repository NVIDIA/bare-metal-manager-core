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

use mac_address::MacAddress;
use model::site_explorer::NetworkAdapter as ModelNetworkAdapter;
use nv_redfish::chassis::{Chassis, NetworkAdapter};
use nv_redfish::network_device_function::NetworkDeviceFunction;
use nv_redfish::{Bmc, Resource};

use crate::Error;

pub(crate) struct Config {
    pub(crate) need_network_device_fns: bool,
}

pub(crate) struct ExploredNetworkAdapterCollection<B: Bmc> {
    members: Vec<ExploredNetworkAdapter<B>>,
}

impl<B: Bmc> ExploredNetworkAdapterCollection<B> {
    pub(crate) async fn explore(chassis: &Chassis<B>, config: &Config) -> Result<Self, Error<B>> {
        match chassis.network_adapters().await {
            Ok(Some(network_adapters)) => {
                let mut members = Vec::new();
                for na in network_adapters {
                    members.push(ExploredNetworkAdapter::explore(na, config).await?);
                }
                Ok(Self { members })
            }
            Ok(None) => Ok(Self { members: vec![] }),
            Err(err) => Err(Error::NvRedfish {
                context: "chassis network adapters",
                err,
            }),
        }
    }

    // Find adapater by MAC address. To make it work network adapters
    // must be explored with need_network_device_fns set to true.
    pub(crate) fn find_by_mac(
        &self,
        mac: MacAddress,
    ) -> Option<(&ExploredNetworkAdapter<B>, &NetworkDeviceFunction<B>)> {
        self.members
            .iter()
            .find_map(|a| a.find_by_mac(mac).map(|f| (a, f)))
    }

    pub(crate) fn to_model(&self) -> Vec<ModelNetworkAdapter> {
        self.members.iter().map(|v| v.to_model()).collect()
    }

    pub(crate) fn members(&self) -> &[ExploredNetworkAdapter<B>] {
        &self.members
    }
}

pub(crate) struct ExploredNetworkAdapter<B: Bmc> {
    pub(crate) adapter: NetworkAdapter<B>,
    pub(crate) functions: Option<Vec<NetworkDeviceFunction<B>>>,
}

impl<B: Bmc> ExploredNetworkAdapter<B> {
    async fn explore(adapter: NetworkAdapter<B>, config: &Config) -> Result<Self, Error<B>> {
        let functions = if config.need_network_device_fns {
            if let Some(collection) = adapter
                .network_device_functions()
                .await
                .map_err(Error::nv_redfish("network device function collection"))?
            {
                Some(collection.members().await.map_err(Error::nv_redfish(
                    "network device function collection members",
                ))?)
            } else {
                None
            }
        } else {
            None
        };
        Ok(Self { adapter, functions })
    }

    fn find_by_mac(&self, mac: MacAddress) -> Option<&NetworkDeviceFunction<B>> {
        self.functions.iter().flatten().find(|f| {
            f.ethernet_permanent_mac_address()
                .and_then(|mac| mac.as_str().parse::<MacAddress>().ok())
                .is_some_and(|v| v == mac)
        })
    }

    fn to_model(&self) -> ModelNetworkAdapter {
        let hw_id = self.adapter.hardware_id();
        ModelNetworkAdapter {
            id: self.adapter.id().to_string(),
            manufacturer: hw_id.manufacturer.map(|v| v.to_string()),
            model: hw_id.model.map(|v| v.to_string()),
            part_number: hw_id.part_number.map(|v| v.to_string()),
            serial_number: Some(
                hw_id
                    .serial_number
                    .map(|v| v.inner().trim())
                    .unwrap_or("")
                    .to_owned(),
            ),
        }
    }
}
