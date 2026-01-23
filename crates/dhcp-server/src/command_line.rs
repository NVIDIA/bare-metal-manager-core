/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use clap::{Parser, ValueEnum};

#[derive(Parser, Debug, Clone)]
#[clap(name = "forge-dhcp-server")]
#[clap(author = "Slack channel #swngc-forge-dev")]
pub struct Args {
    #[arg(long, help = "Interface name where to bind this server.")]
    pub interfaces: Vec<String>,

    #[arg(long, help = "DHCP Config file path.")]
    pub dhcp_config: String,

    #[arg(long, help = "DPU Agent provided input file path for IP selection.")]
    pub host_config: Option<String>,

    #[arg(short, long, value_enum, default_value_t=ServerMode::Dpu)]
    pub mode: ServerMode,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ServerMode {
    Dpu,
    Controller,
}

impl Args {
    pub fn load() -> Self {
        Self::parse()
    }
}
