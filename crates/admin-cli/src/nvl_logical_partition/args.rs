/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Display logical partition information")]
    Show(ShowLogicalPartition),
    #[clap(about = "Create logical partition")]
    Create(CreateLogicalPartition),
    #[clap(about = "Delete logical partition")]
    Delete(DeleteLogicalPartition),
}

#[derive(Parser, Debug)]
pub struct ShowLogicalPartition {
    #[clap(
        default_value(""),
        help = "Optional, Logical Partition ID to search for"
    )]
    pub id: String,
    #[clap(short, long, help = "Optional, Logical Partition Name to search for")]
    pub name: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct CreateLogicalPartition {
    #[clap(short = 'n', long, help = "name of the partition")]
    pub name: String,
    #[clap(short = 't', long, help = "tenant organization id of the partition")]
    pub tenant_organization_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct DeleteLogicalPartition {
    #[clap(short = 'n', long, help = "name of the partition")]
    pub name: String,
}
