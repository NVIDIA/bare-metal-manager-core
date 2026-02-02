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

use std::path::PathBuf;

use carbide_uuid::rack::RackId;
use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Create a new Rack firmware configuration from JSON file")]
    Create(Create),

    #[clap(about = "Get a Rack firmware configuration by ID")]
    Get(Get),

    #[clap(about = "List all Rack firmware configurations")]
    List(List),

    #[clap(about = "Delete a Rack firmware configuration")]
    Delete(Delete),

    #[clap(about = "Apply firmware to all devices in a rack")]
    Apply(Apply),
}

#[derive(Parser, Debug)]
pub struct Create {
    #[clap(help = "Path to JSON configuration file")]
    pub json_file: PathBuf,
    #[clap(help = "Artifactory token for downloading firmware files")]
    pub artifactory_token: String,
}

#[derive(Parser, Debug)]
pub struct Get {
    #[clap(help = "ID of the configuration to retrieve")]
    pub id: String,
}

#[derive(Parser, Debug)]
pub struct List {
    #[clap(long, help = "Show only available configurations")]
    pub only_available: bool,
}

#[derive(Parser, Debug)]
pub struct Delete {
    #[clap(help = "ID of the configuration to delete")]
    pub id: String,
}

#[derive(Parser, Debug)]
pub struct Apply {
    #[clap(help = "Rack ID to apply firmware to")]
    pub rack_id: RackId,

    #[clap(help = "Firmware configuration ID to apply")]
    pub firmware_id: String,

    #[clap(help = "Firmware type: dev or prod", value_parser = ["dev", "prod"])]
    pub firmware_type: String,
}
