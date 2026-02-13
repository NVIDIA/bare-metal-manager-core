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

pub mod account_service;
pub mod assembly;
pub mod bios;
pub mod boot_option;
pub mod chassis;
pub mod collection;
pub mod computer_system;
pub mod ethernet_interface;
pub mod log_service;
pub mod manager;
pub mod manager_network_protocol;
pub mod network_adapter;
pub mod network_device_function;
pub mod oem;
pub mod pcie_device;
pub mod resource;
pub mod secure_boot;
pub mod sensor;
pub mod service_root;
pub mod software_inventory;
pub mod task_service;
pub mod update_service;

pub mod expander_router;

pub use collection::Collection;
pub use resource::Resource;

trait Builder {
    fn maybe_with<T, V>(self, f: fn(Self, &V) -> Self, v: &Option<T>) -> Self
    where
        T: AsRef<V>,
        V: ?Sized,
        Self: Sized,
    {
        if let Some(v) = v {
            f(self, v.as_ref())
        } else {
            self
        }
    }

    fn add_str_field(self, name: &str, value: &str) -> Self
    where
        Self: Sized,
    {
        self.apply_patch(serde_json::json!({ name: value }))
    }

    fn apply_patch(self, patch: serde_json::Value) -> Self;
}
