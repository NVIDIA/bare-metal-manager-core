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

pub mod dell;
pub mod nvidia;

use crate::redfish::Resource;

#[derive(Clone, Copy, Debug)]
pub enum BmcVendor {
    Dell,
    Nvidia,
}

impl BmcVendor {
    pub fn service_root_value(&self) -> &'static str {
        match self {
            BmcVendor::Nvidia => "Nvidia",
            BmcVendor::Dell => "Dell",
        }
    }
    // This function creates settings of the resource from the resource
    // id. Real identifier is different for different BMC vendors.
    pub fn make_settings_odata_id(&self, resource: &Resource<'_>) -> String {
        match self {
            BmcVendor::Nvidia | BmcVendor::Dell => format!("{}/Settings", resource.odata_id),
        }
    }
}

#[derive(Clone)]
pub enum State {
    NvidiaBluefield(nvidia::bluefield::BluefieldState),
    DellIdrac(dell::idrac::IdracState),
    Other,
}
