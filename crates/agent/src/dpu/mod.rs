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
use std::fmt;
use std::fmt::{Display, Formatter};
use std::time::Duration;

use carbide_host_support::agent_config::FmdsDpuNetworkingConfig;
use ipnetwork::IpNetwork;

pub mod interface;
pub mod link;
pub mod route;

pub(crate) const ARMOS_TEST_DATA_DIR: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../dev/docker-env");
pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct DpuNetworkInterfaces {
    pub desired: Vec<IpNetwork>,
}

#[derive(PartialOrd, PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum Action {
    Add,
    Remove,
}

impl Display for Action {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Action::Add => write!(f, "Add"),
            Action::Remove => write!(f, "Remove"),
        }
    }
}

impl DpuNetworkInterfaces {
    pub fn new(fmds_interface_config: &FmdsDpuNetworkingConfig) -> Self {
        DpuNetworkInterfaces {
            desired: fmds_interface_config.config.addresses.clone(),
        }
    }
}
