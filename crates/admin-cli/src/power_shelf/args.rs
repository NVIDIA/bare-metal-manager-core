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

use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Show power shelf information")]
    Show(ShowPowerShelf),
    #[clap(about = "List all power shelves")]
    List,
}

#[derive(Parser, Debug)]
pub struct ShowPowerShelf {
    #[clap(help = "Power shelf ID or name to show (leave empty for all)")]
    pub identifier: Option<String>,
}
