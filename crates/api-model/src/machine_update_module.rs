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
use std::fmt::{Display, Formatter};

use lazy_static::lazy_static;

lazy_static! {
    pub static ref HOST_UPDATE_HEALTH_PROBE_ID: health_report::HealthProbeId =
        "HostUpdateInProgress".parse().unwrap();
}

/// The name of the Health Override which will be used to indicate an ongoing host update
pub const HOST_UPDATE_HEALTH_REPORT_SOURCE: &str = "host-update";
pub const HOST_FW_UPDATE_HEALTH_REPORT_SOURCE: &str = "host-fw-update";
pub const DPU_FIRMWARE_UPDATE_TARGET: &str = "DpuFirmware";

pub struct AutomaticFirmwareUpdateReference {
    pub from: String,
    pub to: String,
}

impl AutomaticFirmwareUpdateReference {
    pub const REF_NAME: &'static str = "AutomaticDpuFirmwareUpdate";
}

pub enum DpuReprovisionInitiator {
    Automatic(AutomaticFirmwareUpdateReference),
}

impl Display for DpuReprovisionInitiator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DpuReprovisionInitiator::Automatic(x) => write!(
                f,
                "{}/{}/{}",
                AutomaticFirmwareUpdateReference::REF_NAME,
                x.from,
                x.to
            ),
        }
    }
}
