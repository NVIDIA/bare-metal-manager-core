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
use std::sync::Arc;

use bmc_mock::injection::InjectionStore;
use carbide_uuid::machine::MachineId;
use uuid::Uuid;

use crate::DeviceHandle;
use crate::device_simulator::{DeviceSimulator, SimulatorLifecycle};

#[derive(Debug, Clone)]
pub struct SimulatorRegistry {
    inner: Arc<SimulatorRegistryInner>,
}

#[derive(Debug)]
struct SimulatorRegistryInner {
    devices: Vec<DeviceSimulator>,
    by_mat_id: HashMap<Uuid, usize>,
}

impl SimulatorRegistry {
    pub fn try_from_handles(handles: Vec<DeviceHandle>) -> eyre::Result<Self> {
        Self::try_from_simulators(
            handles
                .into_iter()
                .map(DeviceSimulator::from_handle)
                .collect(),
        )
    }

    pub fn try_from_simulators(devices: Vec<DeviceSimulator>) -> eyre::Result<Self> {
        let mut by_mat_id = HashMap::with_capacity(devices.len());

        for (index, device) in devices.iter().enumerate() {
            if by_mat_id.insert(device.mat_id(), index).is_some() {
                for device in &devices {
                    device.abort();
                }
                eyre::bail!("duplicate simulator identity: {}", device.mat_id());
            }
        }

        Ok(Self {
            inner: Arc::new(SimulatorRegistryInner { devices, by_mat_id }),
        })
    }

    pub fn devices(&self) -> &[DeviceSimulator] {
        &self.inner.devices
    }

    pub fn get(&self, mat_id: Uuid) -> Option<&DeviceSimulator> {
        self.inner
            .by_mat_id
            .get(&mat_id)
            .map(|index| &self.inner.devices[*index])
    }

    pub fn provisionable_handles(&self) -> Vec<DeviceHandle> {
        self.inner
            .devices
            .iter()
            .filter_map(DeviceSimulator::machine)
            .map(|simulator| simulator.handle().clone())
            .collect()
    }

    pub fn find_injection_store(&self, id: &str) -> Option<Arc<InjectionStore>> {
        if let Ok(mat_id) = Uuid::parse_str(id) {
            if let Some(device) = self.get(mat_id) {
                return Some(device.bmc_injection_store());
            }
            for device in self.devices() {
                let Some(machine) = device.machine() else {
                    continue;
                };
                if let Some(dpu) = machine
                    .handle()
                    .dpus()
                    .iter()
                    .find(|dpu| dpu.mat_id() == mat_id)
                {
                    return Some(dpu.bmc_injection_store());
                }
            }
        }

        let machine_id = id.parse::<MachineId>().ok()?;
        for device in self.devices() {
            let Some(machine) = device.machine() else {
                continue;
            };
            if machine.handle().observed_machine_id().as_ref() == Some(&machine_id) {
                return Some(machine.bmc_injection_store());
            }
            if let Some(dpu) = machine
                .handle()
                .dpus()
                .iter()
                .find(|dpu| dpu.observed_machine_id().as_ref() == Some(&machine_id))
            {
                return Some(dpu.bmc_injection_store());
            }
        }
        None
    }
}
