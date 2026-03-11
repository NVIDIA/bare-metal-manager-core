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

use std::convert::identity;

use model::site_explorer::Chassis;
use nv_redfish::assembly::Model as AssemblyModel;
use nv_redfish::chassis::Chassis as NvChassis;
use nv_redfish::hardware_id::{Manufacturer, Model};
use nv_redfish::pcie_device::PcieDevice;
use nv_redfish::resource::ResourceIdRef;
use nv_redfish::{Bmc, Resource, ServiceRoot};

use crate::network_adapter::ExploredNetworkAdapterCollection;
use crate::{Error, network_adapter};

type AssemblyModelFilterFn = fn(Option<AssemblyModel<&str>>) -> bool;
pub struct Config {
    pub network_adapter: network_adapter::Config,
    pub need_assembly_sn: fn(ResourceIdRef) -> Option<AssemblyModelFilterFn>,
}

pub struct ExploredChassisCollection<B: Bmc> {
    pub members: Vec<ExploredChassis<B>>,
}

impl<B: Bmc> ExploredChassisCollection<B> {
    pub async fn explore(root: &ServiceRoot<B>, config: &Config) -> Result<Self, Error<B>> {
        let nv_members = root
            .chassis()
            .await
            .map_err(Error::nv_redfish("chassis collection"))?
            .ok_or_else(Error::bmc_not_provided("chassis collection"))?
            .members()
            .await
            .map_err(Error::nv_redfish("chassis collection members"))?;
        let mut members = Vec::new();
        for m in nv_members {
            members.push(ExploredChassis::explore(m, config).await?);
        }
        Ok(Self { members })
    }

    pub fn to_model(&self) -> Vec<Chassis> {
        self.members.iter().map(|v| v.to_model()).collect()
    }

    pub fn is_liteon_powershelf(&self) -> bool {
        self.members
            .iter()
            .any(|m| m.chassis.id().into_inner() == "powershelf")
    }

    pub fn is_bluefield2(&self) -> bool {
        self.members
            .iter()
            .find(|c| c.chassis.id().into_inner() == "Card1")
            .is_some_and(|c| {
                let hw_id = c.chassis.hardware_id();
                hw_id.manufacturer == Some(Manufacturer::new("Nvidia"))
                    && hw_id.model == Some(Model::new("Bluefield 2 SmartNIC Main Card"))
            })
    }

    pub fn dpu_card1_serial_number(&self) -> Result<Option<&str>, Error<B>> {
        let maybe_sn = self
            .members
            .iter()
            .find(|c| c.chassis.id().into_inner() == "Card1")
            .ok_or_else(Error::bmc_not_provided("chassis with id Card1"))?
            .chassis
            .hardware_id()
            .serial_number
            .map(|v| v.into_inner());
        Ok(maybe_sn)
    }

    pub async fn pcie_devices(
        &self,
        chassis_filter: impl Fn(&ExploredChassis<B>) -> bool,
    ) -> Result<Vec<PcieDevice<B>>, Error<B>> {
        let mut pcie_devices = Vec::new();
        for c in &self.members {
            if chassis_filter(c)
                && let Some(collection) = c
                    .chassis
                    .pcie_devices()
                    .await
                    .map_err(Error::nv_redfish("chassis pcie devices"))?
            {
                let mut chassis_pcie_devices = collection
                    .members()
                    .await
                    .map_err(Error::nv_redfish("chassis pcie devices members"))?;
                pcie_devices.append(&mut chassis_pcie_devices);
            }
        }
        Ok(pcie_devices)
    }
}

pub struct ExploredChassis<B: Bmc> {
    pub chassis: NvChassis<B>,
    pub network_adapters: ExploredNetworkAdapterCollection<B>,
    pub assembly_sn: Option<String>,
}

impl<B: Bmc> ExploredChassis<B> {
    async fn explore(chassis: NvChassis<B>, config: &Config) -> Result<Self, Error<B>> {
        let network_adapters =
            ExploredNetworkAdapterCollection::explore(&chassis, &config.network_adapter).await?;
        let assembly_sn = if let Some(model_check_fn) = (config.need_assembly_sn)(chassis.id()) {
            match chassis.assembly().await {
                Ok(Some(assembly)) => {
                    let assembly_data = assembly
                        .assemblies()
                        .await
                        .map_err(Error::nv_redfish("chassis assemblies"))?;
                    assembly_data
                        .iter()
                        .find(|asm| model_check_fn(asm.hardware_id().model))
                        .and_then(|asm| asm.hardware_id().serial_number)
                        .map(|v| v.to_string())
                }
                Ok(None) => None,
                Err(err) => {
                    return Err(Error::NvRedfish {
                        context: "chassis assembly",
                        err,
                    });
                }
            }
        } else {
            None
        };

        Ok(Self {
            chassis,
            network_adapters,
            assembly_sn,
        })
    }

    fn to_model(&self) -> Chassis {
        let network_adapters = self.network_adapters.to_model();
        let chassis_id = self.chassis.id();
        let hw_id = self.chassis.hardware_id();
        let serial_number = self
            .assembly_sn
            .clone()
            .or(hw_id.serial_number.map(|v| v.to_string()));

        let nvidia_oem = self
            .chassis
            .oem_nvidia_baseboard_cbc()
            .ok()
            .and_then(identity);
        Chassis {
            id: chassis_id.to_string(),
            manufacturer: hw_id.manufacturer.map(|v| v.to_string()),
            model: hw_id.model.map(|v| v.to_string()),
            part_number: hw_id.part_number.map(|v| v.to_string()),
            serial_number,
            network_adapters,
            physical_slot_number: nvidia_oem
                .as_ref()
                .and_then(|x| x.chassis_physical_slot_number())
                .map(|v| v.into_inner() as i32),
            compute_tray_index: nvidia_oem
                .as_ref()
                .and_then(|x| x.compute_tray_index())
                .map(|v| v.into_inner() as i32),
            topology_id: nvidia_oem
                .as_ref()
                .and_then(|x| x.topology_id())
                .map(|v| v.into_inner() as i32),
            revision_id: nvidia_oem
                .as_ref()
                .and_then(|x| x.revision_id())
                .map(|v| v.into_inner() as i32),
        }
    }
}
