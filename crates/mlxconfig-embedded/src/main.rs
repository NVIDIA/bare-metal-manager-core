/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use mlxconfig_embedded::cmd::{Cli, run_cli};

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run_cli(cli) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
