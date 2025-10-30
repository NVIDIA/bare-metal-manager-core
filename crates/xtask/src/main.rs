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
mod move_deps_to_workspace;

use std::env::args;

use crate::move_deps_to_workspace::move_deps_to_workspace;

fn main() -> eyre::Result<()> {
    match args().nth(1).as_deref() {
        Some("move-deps-to-workspace") => move_deps_to_workspace()?,
        _ => eprintln!("Usage: cargo xtask move-deps-to-workspace"),
    };

    Ok(())
}
