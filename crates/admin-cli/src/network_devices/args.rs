/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
    #[clap(about = "Display network device information")]
    Show(ShowNetworkDevice),
}

#[derive(Parser, Debug)]
pub struct ShowNetworkDevice {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "id",
        help = "Show all network devices (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "Show data for the given network device (e.g. `mac=<mac>`), leave empty for all (default)"
    )]
    pub id: String,
}
