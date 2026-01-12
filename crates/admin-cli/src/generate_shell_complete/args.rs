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

use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct Cmd {
    #[clap(subcommand)]
    pub shell: Shell,
}

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum Shell {
    Bash,
    Fish,
    Zsh,
}
