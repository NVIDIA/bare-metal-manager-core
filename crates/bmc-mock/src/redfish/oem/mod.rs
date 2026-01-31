/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
