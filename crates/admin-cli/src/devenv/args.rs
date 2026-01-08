/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
pub enum Cmd {
    #[clap(about = "Config related handling", visible_alias = "c", subcommand)]
    Config(DevEnvConfig),
}

#[derive(Parser, Debug, Clone)]
pub enum DevEnvConfig {
    #[clap(about = "Apply devenv config", visible_alias = "a")]
    Apply(DevEnvApplyConfig),
}

#[derive(Parser, Debug, Clone)]
pub struct DevEnvApplyConfig {
    #[clap(
        help = "Path to devenv config file. Usually this is in forged repo at envs/local-dev/site/site-controller/files/generated/devenv_config.toml"
    )]
    pub path: String,

    #[clap(long, short, help = "Vpc prefix or network segment?")]
    pub mode: NetworkChoice,
}

#[derive(ValueEnum, Parser, Debug, Clone, PartialEq)]
pub enum NetworkChoice {
    NetworkSegment,
    VpcPrefix,
}
