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

#[derive(Clone, Copy, Debug)]
pub enum BmcVendor {
    Dell,
    Nvidia,
}

impl BmcVendor {
    // This function creates settings of the resource from the resource
    // id. Real identifier is different for different BMC vendors.
    pub fn make_settings_odata_id(&self, resource_odata_id: &str) -> String {
        match self {
            BmcVendor::Nvidia | BmcVendor::Dell => format!("{resource_odata_id}/Settings"),
        }
    }
}
