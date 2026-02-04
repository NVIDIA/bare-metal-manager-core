/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use crate::bug::InjectedBugs;
use crate::redfish;
use crate::redfish::chassis::ChassisState;
use crate::redfish::computer_system::SystemState;
use crate::redfish::manager::ManagerState;
use crate::redfish::update_service::UpdateServiceState;

#[derive(Clone)]
pub struct BmcState {
    pub bmc_vendor: redfish::oem::BmcVendor,
    pub oem_state: redfish::oem::State,
    pub manager: Arc<ManagerState>,
    pub system_state: Arc<SystemState>,
    pub chassis_state: Arc<ChassisState>,
    pub update_service_state: Arc<UpdateServiceState>,
    pub injected_bugs: Arc<InjectedBugs>,
}

#[derive(Debug, Clone)]
pub enum JobState {
    Scheduled,
    Completed,
}

impl BmcState {
    pub fn complete_all_bios_jobs(&self) {
        if let redfish::oem::State::DellIdrac(v) = &self.oem_state {
            v.complete_all_bios_jobs()
        }
    }
}
