/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use clap::{ArgGroup, Parser};

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(
        about = "Add capacity to one or more resource pools from a TOML file. See carbide-api admin_grow_resource_pool docs for example TOML."
    )]
    Grow(GrowResourcePool),
    #[clap(about = "List all resource pools with stats")]
    List,
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("grow")
        .required(true)
        .args(&["filename"])))]
pub struct GrowResourcePool {
    #[clap(short, long)]
    pub filename: String,
}
